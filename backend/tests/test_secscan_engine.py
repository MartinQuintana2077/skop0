import os
import sys
import json
import time
import uuid
import sqlite3
import tempfile
import threading
import ipaddress
import unittest
import concurrent.futures
from unittest.mock import patch, MagicMock

# Asegurar que backend/ esté en sys.path
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from core import scanner as scanner_mod
from core.scanner import (
    ScannerEngine,
    SECSCAN_AUDIT_PORTS,
    _clean_hostname,
    _extract_mdns_hostnames,
    verify_host_alive,
)
from core.cve_client import CVEClient
from core.device_classifier import classify_device, detect_connection_medium
from core.telemetry import measure_device_telemetry
from core import subnet_bridge
from services.db_service import DatabaseService
from services import scan_service as scan_service_mod
from api.v1.endpoints import scans as scans_ep


class _TempLocalDB:
    """Base SQLite temporal aislada para probar caché CVE con TTL sin tocar datos del usuario."""
    def __init__(self):
        self._fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(self._fd)
        self._lock = threading.Lock()
        conn = sqlite3.connect(self.path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS cve_cache (keyword TEXT PRIMARY KEY, cves_json TEXT, cached_at TEXT)"
        )
        conn.commit()
        conn.close()

    def execute_read(self, query, params=()):
        with self._lock:
            conn = sqlite3.connect(self.path)
            conn.row_factory = sqlite3.Row
            try:
                cur = conn.cursor()
                cur.execute(query, params)
                return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    def execute_write(self, query, params=()):
        with self._lock:
            conn = sqlite3.connect(self.path)
            try:
                cur = conn.cursor()
                cur.execute(query, params)
                conn.commit()
                return cur.lastrowid
            finally:
                conn.close()

    def close(self):
        try:
            os.remove(self.path)
        except Exception:
            pass


# ==============================================================================
# PLAN 1: MOTOR THREAD-SAFE XML, INTERFACES, SUBNET BRIDGE Y SQLITE ATÓMICO
# ==============================================================================

class TestPlan1ScannerAndSubnet(unittest.TestCase):

    def _make_sample_xml(self, ip: str, port: int, product: str, version: str, cpe: str, srtt_us: int = 1800) -> str:
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="arp-response"/>
    <address addr="{ip}" addrtype="ipv4"/>
    <address addr="AA:BB:CC:11:22:33" addrtype="mac" vendor="TestVendor Corp"/>
    <hostnames><hostname name="host-{ip.replace('.', '-')}" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="{port}">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="{product}" version="{version}" extrainfo="Ubuntu">
          <cpe>{cpe}</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="23">
        <state state="filtered" reason="no-response"/>
        <service name="telnet"/>
      </port>
    </ports>
    <times srtt="{srtt_us}" rttvar="500" to="100000"/>
  </host>
</nmaprun>"""

    def test_nmap_xml_parser_extracts_product_version_cpe_and_rtt(self):
        eng = ScannerEngine.__new__(ScannerEngine)
        eng.nmap_bin = "nmap"
        eng.nmap_installed = True

        xml = self._make_sample_xml("192.168.10.50", 80, "Apache httpd", "2.4.49", "cpe:/a:apache:http_server:2.4.49", 2400)
        fake_proc = MagicMock()
        fake_proc.communicate.return_value = (xml, "")

        with patch("core.scanner.subprocess.Popen", return_value=fake_proc):
            parsed = eng._run_nmap_xml(["192.168.10.50"], ["-sV"])

        self.assertIn("192.168.10.50", parsed)
        h = parsed["192.168.10.50"]
        self.assertEqual(h["mac"], "AA:BB:CC:11:22:33")
        self.assertEqual(h["vendor"], "TestVendor Corp")
        self.assertEqual(h["hostname"], "host-192-168-10-50")
        self.assertEqual(h["srtt_ms"], 2.4)
        self.assertEqual(len(h["ports"]), 2)
        p80 = h["ports"][0]
        self.assertEqual(p80["port"], 80)
        self.assertEqual(p80["product"], "Apache httpd")
        self.assertEqual(p80["version"], "2.4.49")
        self.assertEqual(p80["cpes"], ["cpe:/a:apache:http_server:2.4.49"])

    def test_nmap_xml_thread_safety_no_shared_state(self):
        eng = ScannerEngine.__new__(ScannerEngine)
        eng.nmap_bin = "nmap"
        eng.nmap_installed = True

        def fake_popen(cmd, **kwargs):
            ip = cmd[-1]
            port = 8000 + int(ip.split(".")[-1])
            xml = self._make_sample_xml(ip, port, f"App-{ip}", "1.0.0", f"cpe:/a:test:app_{port}:1.0.0")
            p = MagicMock()
            p.communicate.return_value = (xml, "")
            time.sleep(0.01)
            return p

        ips = [f"10.0.0.{i}" for i in range(1, 13)]
        with patch("core.scanner.subprocess.Popen", side_effect=fake_popen):
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
                results = list(ex.map(lambda ip: (ip, eng._run_nmap_xml([ip], ["-sV"])), ips))

        for ip, res in results:
            self.assertEqual(list(res.keys()), [ip])
            expected_port = 8000 + int(ip.split(".")[-1])
            self.assertEqual(res[ip]["ports"][0]["port"], expected_port)
            self.assertEqual(res[ip]["ports"][0]["product"], f"App-{ip}")

    def test_resolve_nmap_interface_maps_windows_to_npcap(self):
        eng = ScannerEngine.__new__(ScannerEngine)
        eng.nmap_bin = "nmap"
        eng.nmap_installed = True

        fake_ifmap = {
            "ip_to_dev": {"192.168.1.7": "eth0", "192.168.56.1": "eth1"},
            "mac_to_dev": {"04:7C:16:4A:66:B7": "eth0", "0A:00:27:00:00:07": "eth1"},
            "devs": {"eth0", "eth1"},
        }
        fake_addr = MagicMock(family=scanner_mod.socket.AF_INET, address="192.168.56.1")
        fake_mac = MagicMock(family=scanner_mod.psutil.AF_LINK, address="0A-00-27-00-00-07")

        with patch.object(eng, "_get_nmap_iflist_map", return_value=fake_ifmap), \
             patch("core.scanner.psutil.net_if_addrs", return_value={"Ethernet 4": [fake_addr, fake_mac]}):
            self.assertEqual(eng._resolve_nmap_interface("Ethernet 4"), "eth1")
            self.assertEqual(eng._resolve_nmap_interface("eth0"), "eth0")
            self.assertIsNone(eng._resolve_nmap_interface("all"))
            self.assertIsNone(eng._resolve_nmap_interface("InterfazInexistente"))

    def test_single_ip_discovery_does_not_sweep_254(self):
        eng = ScannerEngine.__new__(ScannerEngine)
        eng.nmap_bin = "nmap"
        eng.nmap_installed = True

        probed_ips = []
        def fake_arp(ip, retries=2, src_ip=None):
            probed_ips.append(ip)
            return True, "11:22:33:44:55:66"

        with patch("core.scanner.send_arp_native", side_effect=fake_arp), \
             patch.object(eng, "_intento_snmp") as mock_snmp, \
             patch.object(eng, "_run_nmap_xml", return_value={}), \
             patch("core.scanner.get_all_local_ips", return_value=set()), \
             patch("core.scanner.subprocess.check_output", return_value=b""), \
             patch("core.scanner.socket.gethostbyaddr", side_effect=OSError()):
            res = eng.discover_network("192.168.18.42")

        mock_snmp.assert_not_called()
        self.assertEqual(probed_ips, ["192.168.18.42"])
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["ip"], "192.168.18.42")

    def test_subnet_bridge_non_24_masks_and_containment(self):
        fake_ifaces = [
            {
                "name": "Ethernet",
                "tipo": "ethernet",
                "is_up": True,
                "has_internet": True,
                "primary_ip": "192.168.10.5",
                "ipv4": [{"ip": "192.168.10.5", "netmask": "255.255.255.128"}],  # /25 -> .0..127
            }
        ]
        with patch("core.subnet_bridge.get_available_network_interfaces", return_value=fake_ifaces):
            # .50 está dentro de 192.168.10.0/25
            in_sub, iface, _ = subnet_bridge.is_target_in_local_subnets("192.168.10.50")
            self.assertTrue(in_sub)
            self.assertEqual(iface, "Ethernet")
            # .200 está FUERA de 192.168.10.0/25 (aunque comparta los primeros 3 octetos!)
            out_sub, _, _ = subnet_bridge.is_target_in_local_subnets("192.168.10.200")
            self.assertFalse(out_sub)
            # Sub-bloque /26 dentro del /25 local
            sub_ok, _, _ = subnet_bridge.is_target_in_local_subnets("192.168.10.0/26")
            self.assertTrue(sub_ok)

        # find_free_ip_in_subnet debe respetar límites reales de /25, /26 y /28
        with patch("core.subnet_bridge.subprocess.run", return_value=MagicMock(stdout="Tiempo de espera agotado")):
            for cidr in ("192.168.20.0/24", "192.168.20.0/25", "192.168.20.64/26", "10.0.0.16/28"):
                free_ip = subnet_bridge.find_free_ip_in_subnet(cidr)
                net = ipaddress.IPv4Network(cidr, strict=False)
                self.assertIn(ipaddress.IPv4Address(free_ip), net)
                self.assertNotEqual(free_ip, str(net.network_address))
                self.assertNotEqual(free_ip, str(net.broadcast_address))

    def test_subnet_bridge_fails_honestly_when_netsh_fails(self):
        failed_proc = MagicMock(returncode=1, stdout="", stderr="Acceso denegado")
        with patch("core.subnet_bridge.is_target_in_local_subnets", return_value=(False, None, None)), \
             patch("core.subnet_bridge.unbind_subnet_bridge"), \
             patch("core.subnet_bridge.get_active_interface_name", return_value="Ethernet"), \
             patch("core.subnet_bridge.find_free_ip_in_subnet", return_value="192.168.99.250"), \
             patch("core.subnet_bridge.subprocess.run", return_value=failed_proc), \
             patch("core.subnet_bridge._verify_ip_bound_on_interface", return_value=False), \
             patch("core.subnet_bridge._save_active_bridge_state") as mock_save:
            res = subnet_bridge.bind_subnet_bridge("192.168.99.0/25", preferred_interface="Ethernet")

        self.assertEqual(res["status"], "error")
        self.assertIn("255.255.255.128", res["message"])
        mock_save.assert_not_called()

    def test_atomic_sqlite_append_scan_log_concurrency(self):
        db = DatabaseService()
        sid = f"unit-log-{uuid.uuid4().hex[:8]}"
        uid = "unit_test_user"
        db.init_scan(uid, sid, "127.0.0.1")
        try:
            def writer(tid):
                for j in range(10):
                    db.append_scan_log(uid, sid, f"W{tid}-{j}")
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
                list(ex.map(writer, range(16)))
            details = db.get_scan_details(uid, sid)
            self.assertEqual(len(details.get("logs", [])), 160)
        finally:
            db.delete_scan(uid, sid)


# ==============================================================================
# PLAN 2: MOTOR CVE CON CPE 2.3, DEDUPLICACIÓN EN VUELO, TTL Y RATE LIMITER
# ==============================================================================

class TestPlan2CVEEngine(unittest.TestCase):

    def setUp(self):
        self.tmp_db = _TempLocalDB()
        self.client = CVEClient(api_key="", db_manager=self.tmp_db)
        CVEClient._request_timestamps.clear()
        CVEClient._inflight_entries.clear()

    def tearDown(self):
        self.tmp_db.close()

    def test_cpe_to_v23_converts_valid_versioned_cpes(self):
        self.assertEqual(
            CVEClient.cpe_to_v23("cpe:/a:apache:http_server:2.4.49"),
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        )
        self.assertEqual(
            CVEClient.cpe_to_v23("cpe:/a:openbsd:openssh:8.9p1"),
            "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
        )
        self.assertEqual(
            CVEClient.cpe_to_v23("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"),
            "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
        )

    def test_cpe_to_v23_rejects_unversioned_os_and_products(self):
        # Evitar falsos positivos masivos con OS/productos sin versión concreta
        self.assertIsNone(CVEClient.cpe_to_v23("cpe:/o:microsoft:windows"))
        self.assertIsNone(CVEClient.cpe_to_v23("cpe:/o:linux:linux_kernel"))
        self.assertIsNone(CVEClient.cpe_to_v23("cpe:/a:openbsd:openssh"))
        self.assertIsNone(CVEClient.cpe_to_v23("cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"))
        self.assertIsNone(CVEClient.cpe_to_v23(""))

    def test_select_best_query_prefers_cpe_and_blocks_generic_protocols(self):
        # 1. Prefiere CPE de aplicación versionado sobre keyword
        q = CVEClient.select_best_query(
            nombre_servicio="http",
            version="2.4.49",
            producto="Apache httpd",
            cpes=["cpe:/o:linux:linux_kernel", "cpe:/a:apache:http_server:2.4.49"],
        )
        self.assertEqual(q[0], "cpe")
        self.assertEqual(q[1], "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")

        # 2. Sin CPE, usa producto + versión real
        q2 = CVEClient.select_best_query(nombre_servicio="http", version="1.24.0", producto="nginx", cpes=[])
        self.assertEqual(q2[0], "keyword")
        self.assertEqual(q2[1], "nginx 1.24.0")

        # 3. Rechaza protocolos genéricos sin producto concreto (evita falsos positivos)
        self.assertIsNone(CVEClient.select_best_query(nombre_servicio="http", version="1.1", producto="", cpes=[]))
        self.assertIsNone(CVEClient.select_best_query(nombre_servicio="msrpc", version="", producto="Microsoft Windows RPC", cpes=["cpe:/o:microsoft:windows"]))
        self.assertIsNone(CVEClient.select_best_query(nombre_servicio="tcpwrapped", version="2.0", producto="", cpes=[]))

    def test_cve_inflight_deduplication_and_cvss_sorting(self):
        call_count = {"n": 0}
        fake_nvd_payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-42013",
                        "descriptions": [{"lang": "es", "value": "Traversal crítico en Apache"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                    }
                },
                {
                    "cve": {
                        "id": "CVE-2021-41773",
                        "descriptions": [{"lang": "es", "value": "Fallo medio de ejemplo"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.3, "baseSeverity": "MEDIUM"}}]},
                    }
                },
            ]
        }

        def fake_get(url, params=None, headers=None, timeout=18):
            call_count["n"] += 1
            time.sleep(0.15)
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = fake_nvd_payload
            return resp

        with patch("core.cve_client.requests.get", side_effect=fake_get), \
             patch.object(self.client, "_acquire_rate_slot"):
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                results = list(
                    ex.map(
                        lambda _: self.client.buscar_vulnerabilidades(
                            "http", "2.4.49", "Apache httpd", ["cpe:/a:apache:http_server:2.4.49"]
                        ),
                        range(8),
                    )
                )

        # Solo 1 de los 8 hilos concurrentes debió golpear NVD
        self.assertEqual(call_count["n"], 1)
        for r in results:
            self.assertEqual(len(r), 2)
            self.assertEqual(r[0]["cve_id"], "CVE-2021-42013")
            self.assertEqual(r[0]["score"], 9.8)
            self.assertEqual(r[1]["score"], 5.3)
            self.assertEqual(r[0]["match_source"], "cpe")

    def test_cve_cache_ttl_and_no_error_caching(self):
        key = "cpe|cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"
        # Insertar entrada vencida (hace 10 días > 7 días TTL)
        old_ts = "2020-01-01T00:00:00"
        self.tmp_db.execute_write(
            "INSERT INTO cve_cache (keyword, cves_json, cached_at) VALUES (?, ?, ?)",
            (key, json.dumps([{"cve_id": "CVE-OLD", "score": 4.0}]), old_ts),
        )
        self.assertIsNone(self.client._read_cache(key))

        # Si hay error de red/timeout, NO debe guardarse [] en caché
        with patch("core.cve_client.requests.get", side_effect=TimeoutError("network down")), \
             patch.object(self.client, "_acquire_rate_slot"):
            res = self.client.buscar_vulnerabilidades("http", "1.20.0", "nginx", ["cpe:/a:nginx:nginx:1.20.0"])
        self.assertEqual(res, [])
        # La fila vencida sigue sin ser sobrescrita por una respuesta vacía fresca
        self.assertIsNone(self.client._read_cache(key))


# ==============================================================================
# PLAN 3: PUERTOS CURADOS, mDNS, ARP REAL, TELEMETRÍA FALLBACK Y CLASIFICADOR
# ==============================================================================

class TestPlan3DiscoveryClassificationTelemetry(unittest.TestCase):

    def test_curated_ports_cover_all_classifier_signatures(self):
        ports = {int(p) for p in SECSCAN_AUDIT_PORTS.split(",")}
        required = {
            554, 8899, 37777, 34567,        # CCTV / NVR
            8008, 8009, 8060, 7000, 7676,   # Smart TV / Cast / Roku
            9100, 515, 631,                 # Impresoras
            5060, 5061,                     # VoIP SIP
            1883, 5683, 8883,               # IoT MQTT / CoAP
            62078,                          # Apple iOS Lockdown
            135, 139, 445, 3389, 5357,      # Windows
            22, 53, 80, 443, 3306, 5432,    # Core / DB
        }
        self.assertTrue(required.issubset(ports), f"Faltan puertos: {required - ports}")

    def test_verify_host_alive_rejects_stale_arp_false_positive(self):
        # Si SendARP, ping y TCP fallan todos, NO debe devolver True aunque tenga known_mac vieja
        with patch("core.scanner.send_arp_native", return_value=(False, "")), \
             patch("core.scanner.subprocess.run", return_value=MagicMock(returncode=1, stdout=b"")), \
             patch("core.scanner.socket.socket") as mock_sock_cls:
            sock_inst = MagicMock()
            sock_inst.connect.side_effect = OSError("timed out")
            mock_sock_cls.return_value = sock_inst

            alive, mac = verify_host_alive("192.168.1.99", known_mac="AA:BB:CC:DD:EE:FF")

        self.assertFalse(alive)
        self.assertEqual(mac, "")

    def test_mdns_label_parser_and_clean_hostname(self):
        # Paquete mDNS mínimo con 1 respuesta tipo A: "iPhone-Martin.local"
        header = b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00"
        name = b"\x0diPhone-Martin\x05local\x00"
        rr_meta = b"\x00\x01\x00\x01\x00\x00\x00\x78\x00\x04\xc0\xa8\x01\x14"
        names = _extract_mdns_hostnames(header + name + rr_meta)
        self.assertEqual(names, ["iPhone-Martin"])

        self.assertEqual(_clean_hostname("none", "192.168.1.7"), "")
        self.assertEqual(_clean_hostname("localhost", "192.168.1.7"), "")
        self.assertEqual(_clean_hostname("192.168.1.7", "192.168.1.7"), "")
        self.assertEqual(_clean_hostname("Roku-LivingRoom.local.", "192.168.1.50"), "Roku-LivingRoom.local")

    def test_classifier_resolves_all_priority_conflicts(self):
        with patch("core.scanner.get_all_local_ips", return_value={"192.168.1.7"}):
            # 1. Conflicto resuelto: Samsung Smart TV con puerto 8001 -> TV (NO Cámara)
            c_tv = classify_device("192.168.1.40", "10:20:30:40:50:60", "Samsung Electronics", "", [{"puerto": 8001, "servicio": "http"}])
            self.assertEqual(c_tv["tipo"], "tv")

            # 2. Conflicto resuelto: Servidor dev web en puerto 8000 (sin marca CCTV) -> Server (NO Cámara Hikvision)
            c_dev = classify_device("192.168.1.41", "10:20:30:40:50:61", "Desconocido", "app-backend", [{"puerto": 8000, "servicio": "http"}])
            self.assertEqual(c_dev["tipo"], "server")

            # 3. Cámara IP real (RTSP 554 o Hikvision + 8000) -> camera
            c_cam1 = classify_device("192.168.1.42", "10:20:30:40:50:62", "Hikvision Digital", "", [{"puerto": 8000, "servicio": "http"}])
            c_cam2 = classify_device("192.168.1.43", "10:20:30:40:50:63", "Desconocido", "", [{"puerto": 554, "servicio": "rtsp"}])
            self.assertEqual(c_cam1["tipo"], "camera")
            self.assertEqual(c_cam2["tipo"], "camera")

            # 4. Conflicto resuelto: IoT Espressif con puerto 80 -> iot (NO Servidor)
            c_iot = classify_device("192.168.1.44", "10:20:30:40:50:64", "Espressif Inc.", "", [{"puerto": 80, "servicio": "http"}])
            self.assertEqual(c_iot["tipo"], "iot")

            # 5. Conflicto resuelto: Teléfono Huawei no-gateway con puerto 8080 -> phone (NO Extensor)
            c_hua = classify_device("192.168.1.45", "10:20:30:40:50:65", "Huawei Technologies", "", [{"puerto": 8080, "servicio": "http"}])
            self.assertEqual(c_hua["tipo"], "phone")

            # 6. Conflicto resuelto: Impresora HP con puerto 9100 -> printer (NO PC)
            c_prt = classify_device("192.168.1.46", "10:20:30:40:50:66", "Hewlett-Packard", "", [{"puerto": 9100, "servicio": "jetdirect"}])
            self.assertEqual(c_prt["tipo"], "printer")

            # 7. Apple iOS Lockdown 62078 -> phone
            c_ios = classify_device("192.168.1.47", "10:20:30:40:50:67", "Apple Inc.", "", [{"puerto": 62078, "servicio": "iphone-sync"}])
            self.assertEqual(c_ios["tipo"], "phone")

            # 8. Host local detectado correctamente
            c_loc = classify_device("192.168.1.7", "04:7C:16:4A:66:B7", "Micro-Star Intl", "PC-LOCAL", [])
            self.assertTrue(c_loc.get("es_scanner"))
            self.assertEqual(c_loc["tipo"], "pc")

    def test_connection_medium_uses_telemetry_for_hybrid_devices(self):
        # Impresora Wi-Fi con latencia 18ms -> Wi-Fi (no forzada a Ethernet)
        med_wifi_prt = detect_connection_medium(
            ip="192.168.1.60",
            mac="00:11:22:33:44:55",
            fabricante="Epson",
            puertos_abiertos=[{"puerto": 9100}],
            dispositivo_tipo="printer",
            telemetria={"latency_ms": 18.0, "latency_min": 14.0, "latency_max": 24.0, "packet_loss": 0},
        )
        self.assertEqual(med_wifi_prt["medio"], "wifi")

        # Laptop cableada con latencia 0.8ms y jitter 0.2ms -> Ethernet
        med_wired_lap = detect_connection_medium(
            ip="192.168.1.61",
            mac="00:11:22:33:44:56",
            fabricante="Lenovo",
            hostname="LAPTOP-OFICINA",
            dispositivo_tipo="pc",
            telemetria={"latency_ms": 0.8, "latency_min": 0.7, "latency_max": 0.9, "packet_loss": 0},
        )
        self.assertEqual(med_wired_lap["medio"], "ethernet")

    def test_telemetry_fallback_tcp_and_nmap_when_icmp_blocked(self):
        dead_ping = MagicMock(returncode=1, stdout="Enviados = 3, recibidos = 0, perdidos = 3 (100% perdidos)")

        # Fallback 1: TCP RTT
        with patch("core.telemetry.subprocess.run", return_value=dead_ping), \
             patch("core.telemetry._measure_tcp_rtt", return_value={"sent": 3, "recv": 3, "loss": 0, "avg_ms": 2.3, "min_ms": 2.0, "max_ms": 2.8, "port": 445}):
            res_tcp = measure_device_telemetry("192.168.1.70", count=3, open_ports=[{"puerto": 445}])
        self.assertEqual(res_tcp["method"], "tcp")
        self.assertTrue(res_tcp["icmp_blocked"])
        self.assertEqual(res_tcp["latency_ms"], 2.3)
        self.assertIn("(TCP)", res_tcp["status_label"])

        # Fallback 2: Nmap SRTT cuando TCP también es filtrado
        with patch("core.telemetry.subprocess.run", return_value=dead_ping), \
             patch("core.telemetry._measure_tcp_rtt", return_value=None):
            res_nmap = measure_device_telemetry("192.168.1.71", count=3, nmap_rtt_ms=4.5)
        self.assertEqual(res_nmap["method"], "nmap")
        self.assertEqual(res_nmap["latency_ms"], 4.5)
        self.assertIn("(Nmap)", res_nmap["status_label"])

    def test_deep_scan_active_ignores_stale_passive_cache(self):
        svc = scan_service_mod.ScanService()
        # Inyectar caché pasiva obsoleta
        scan_service_mod._passive_device_cache["192.168.1.88"] = {
            "deep_scan_status": "completed",
            "puertos_abiertos": [{"puerto": 9999, "servicio": "stale"}],
            "total_vulnerabilidades": 99,
            "mac": "00:00:00:00:00:01",
            "fabricante": "StaleVendor",
            "hostname": "stale-host",
        }
        fresh_ports = {
            "ip": "192.168.1.88",
            "mac": "10:20:30:40:50:88",
            "hostname": "fresh-host",
            "fabricante": "FreshVendor",
            "puertos_abiertos": [{"puerto": 80, "protocolo": "TCP", "servicio": "http", "producto": "nginx", "version": "1.24.0", "cpe": []}],
            "puertos_bloqueados": [],
            "nmap_rtt_ms": 1.5,
        }
        try:
            with patch.object(svc.scanner, "scan_ports", return_value=fresh_ports) as mock_scan, \
                 patch.object(svc.cve_client, "buscar_vulnerabilidades", return_value=[]) as mock_cve, \
                 patch.object(svc.db_service, "get_historial_doc", return_value=MagicMock(exists=False)), \
                 patch.object(svc.db_service, "save_historial_doc"), \
                 patch.object(svc.db_service, "save_device"), \
                 patch.object(svc.db_service, "save_scan_device"), \
                 patch("core.telemetry.measure_device_telemetry", return_value={"latency_ms": 1.5, "latency_min": 1.2, "latency_max": 1.8, "packet_loss": 0, "ttl": 64, "status": "excellent", "status_label": "1.5 ms"}):
                doc = svc.deep_scan("192.168.1.88", user_id="u1", scan_id="s1", force_refresh=True)

            mock_scan.assert_called_once()
            mock_cve.assert_called_once_with(nombre_servicio="http", version="1.24.0", producto="nginx", cpes=[])
            self.assertEqual(doc["hostname"], "fresh-host")
            self.assertEqual(doc["puertos_abiertos"][0]["puerto"], 80)
        finally:
            scan_service_mod._passive_device_cache.pop("192.168.1.88", None)


# ==============================================================================
# PLAN 4: BLOQUEO DE ESCANEO ÚNICO, CANCELACIÓN INMEDIATA Y LIMPIEZA LEGACY
# ==============================================================================

class TestPlan4ControlCancellationAndCleanup(unittest.TestCase):

    def tearDown(self):
        with scans_ep._active_scans_lock:
            scans_ep._active_scans.clear()

    def test_single_active_scan_lock_prevents_concurrent_duplicate(self):
        ok1, sid1, ev1 = scans_ep.register_active_scan("user_a", "scan-1", "192.168.1.0/24")
        self.assertTrue(ok1)
        self.assertEqual(sid1, "scan-1")
        self.assertIsNotNone(ev1)

        # Segundo intento simultáneo para el mismo usuario -> rechazado
        ok2, existing, ev2 = scans_ep.register_active_scan("user_a", "scan-2", "192.168.1.0/24")
        self.assertFalse(ok2)
        self.assertEqual(existing, "scan-1")
        self.assertIsNone(ev2)

        # Otro usuario distinto sí puede escanear
        ok3, sid3, _ = scans_ep.register_active_scan("user_b", "scan-3", "192.168.1.0/24")
        self.assertTrue(ok3)
        self.assertEqual(sid3, "scan-3")

        # Al finalizar scan-1, user_a queda libre nuevamente
        scans_ep.unregister_active_scan("scan-1")
        ok4, sid4, _ = scans_ep.register_active_scan("user_a", "scan-4", "192.168.1.0/24")
        self.assertTrue(ok4)
        self.assertEqual(sid4, "scan-4")

    def test_cancel_active_scan_aborts_running_subprocess_quickly(self):
        ok, sid, cancel_ev = scans_ep.register_active_scan("user_cancel", "scan-cancel-1", "192.168.1.0/24")
        self.assertTrue(ok)

        eng = ScannerEngine.__new__(ScannerEngine)
        # Usar python sleep para simular un proceso nmap largo y comprobar cancelación en < 1.5s
        eng.nmap_bin = sys.executable
        eng.nmap_installed = True

        def _trigger_cancel():
            time.sleep(0.25)
            with patch.object(scans_ep.db_service, "append_scan_log"):
                res = scans_ep.cancel_active_scan(sid, user_id="user_cancel")
                self.assertEqual(res["status"], "cancelling")

        t0 = time.perf_counter()
        t_cancel = threading.Thread(target=_trigger_cancel, daemon=True)
        t_cancel.start()
        # _run_nmap_xml construye [nmap_bin, '-oX', '-', *extra_args, *targets];
        # aquí simulamos un proceso de larga duración interceptando Popen a `python -c "import time; time.sleep(15)"`
        real_popen = scanner_mod.subprocess.Popen
        with patch("core.scanner.subprocess.Popen", side_effect=lambda cmd, **kw: real_popen([sys.executable, "-c", "import time; time.sleep(15)"], **kw)):
            res_xml = eng._run_nmap_xml(["192.168.1.1"], ["-sV"], timeout=15.0, cancel_event=cancel_ev)
        elapsed = time.perf_counter() - t0
        t_cancel.join(timeout=2.0)

        self.assertEqual(res_xml, {})
        self.assertLess(elapsed, 2.0, f"La cancelación tardó demasiado: {elapsed:.2f}s")

    def test_two_stage_scan_ports_skips_sv_and_preserves_ports_on_sv_timeout(self):
        eng = ScannerEngine.__new__(ScannerEngine)
        eng.nmap_bin = "nmap"
        eng.nmap_installed = True

        # Caso 1: Host con 0 puertos abiertos en Stage-A -> NO debe ejecutar Stage-B (-sV)
        pre_zero = {"ip": "192.168.1.2", "state": "up", "mac": "AA:BB:CC:00:00:02", "vendor": "", "hostname": "", "srtt_ms": 1.2, "ports": []}
        with patch.object(eng, "_run_nmap_xml") as mock_xml:
            res0 = eng.scan_ports("192.168.1.2", pre_sweep_host=pre_zero, skip_rdns=True)
        mock_xml.assert_not_called()
        self.assertEqual(res0["puertos_abiertos"], [])
        self.assertEqual(res0["nmap_rtt_ms"], 1.2)

        # Caso 2: Host tipo Roku con 2 puertos en Stage-A donde Stage-B (-sV) agota timeout -> conserva 100% puertos + banner HTTP
        pre_roku = {
            "ip": "192.168.1.9", "state": "up", "mac": "A8:B5:7C:DB:32:3C", "vendor": "Roku", "hostname": "", "srtt_ms": 3.5,
            "ports": [
                {"port": 8060, "protocol": "tcp", "state": "open", "reason": "syn-ack", "name": "http", "product": "", "version": "", "extrainfo": "", "cpes": []},
                {"port": 7000, "protocol": "tcp", "state": "open", "reason": "syn-ack", "name": "afs3-fileserver", "product": "", "version": "", "extrainfo": "", "cpes": []},
            ],
        }
        with patch.object(eng, "_run_nmap_xml", return_value={}), \
             patch.object(eng, "_grab_http_server_banner", side_effect=lambda ip, p: ("Roku", "12.5") if p == 8060 else ("", "")):
            res_roku = eng.scan_ports("192.168.1.9", pre_sweep_host=pre_roku, skip_rdns=True)

        self.assertEqual(len(res_roku["puertos_abiertos"]), 2)
        p8060 = [p for p in res_roku["puertos_abiertos"] if p["puerto"] == 8060][0]
        self.assertEqual(p8060["producto"], "Roku")
        self.assertEqual(p8060["version"], "12.5")

    def test_legacy_dead_files_removed(self):
        self.assertFalse(os.path.exists(os.path.join(BACKEND_DIR, "core", "scan_service.py")))
        self.assertFalse(os.path.exists(os.path.join(BACKEND_DIR, "core", "api.py")))
        self.assertFalse(os.path.exists(os.path.join(BACKEND_DIR, "services", "n8n_service.py")))


if __name__ == "__main__":
    unittest.main(verbosity=2)
