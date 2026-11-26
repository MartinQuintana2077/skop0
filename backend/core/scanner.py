import os
import sys
import subprocess

if sys.platform == 'win32':
    _orig_popen = subprocess.Popen
    class _PatchedPopen(_orig_popen):
        def __init__(self, *args, **kwargs):
            if 'creationflags' not in kwargs:
                kwargs['creationflags'] = 0x08000000
            else:
                kwargs['creationflags'] |= 0x08000000
            super().__init__(*args, **kwargs)
    subprocess.Popen = _PatchedPopen

import socket
import re
import ipaddress
import time
import threading
import concurrent.futures
import ctypes
import xml.etree.ElementTree as ET
import psutil

for nmap_dir in [r'C:\Program Files (x86)\Nmap', r'C:\Program Files\Nmap']:
    if os.path.exists(nmap_dir) and nmap_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = nmap_dir + os.pathsep + os.environ.get("PATH", "")

CREATE_NO_WINDOW = 0x08000000 if sys.platform == 'win32' else 0

# Perfil curado de 78 puertos TCP de alto valor: combina servicios core (Web, SSH, SMB, RDP, DBs)
# con todos los puertos de huella usados por el clasificador (CCTV/RTSP/ONVIF, Smart TV/Cast/Roku,
# Impresoras IPP/RAW, VoIP SIP, IoT MQTT/CoAP, Apple iOS Lockdown 62078 y gestión de switches).
SECSCAN_AUDIT_PORTS = (
    "21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,465,515,548,554,587,"
    "631,636,993,995,1433,1521,1723,1883,1900,2049,2121,3000,3074,3306,3389,"
    "3478,3479,3480,5000,5001,5060,5061,5357,5432,5683,5900,5985,5986,6379,"
    "7000,7676,7678,8000,8001,8002,8008,8009,8060,8080,8081,8200,8443,8554,"
    "8883,8899,8999,9000,9090,9100,9197,10000,10554,27017,34567,37777,37778,"
    "49152,62078"
)

INVALID_HOSTNAMES = {"", "none", "null", "localhost", "unknown", "dispositivo de red", "caché arp pasiva", "cache arp pasiva"}

_thread_local = threading.local()
_iflist_cache_lock = threading.Lock()
_iflist_cache = {"ts": 0.0, "ip_to_dev": {}, "mac_to_dev": {}, "devs": set()}

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


def get_all_local_ips() -> set:
    """Retorna todas las direcciones IPv4 activas (no loopback) asignadas a esta máquina."""
    ips = set()
    try:
        for _iface, addr_list in psutil.net_if_addrs().items():
            for a in addr_list:
                if a.family == socket.AF_INET and a.address and not a.address.startswith("127."):
                    ips.add(a.address)
    except Exception:
        pass
    primary = get_local_ip()
    if primary and primary != "127.0.0.1":
        ips.add(primary)
    return ips


def get_local_mac_for_ip(ip: str) -> str:
    """Retorna la MAC física de la interfaz local que posee la IP indicada."""
    if ip:
        try:
            for _iface, addr_list in psutil.net_if_addrs().items():
                has_ip = any(a.family == socket.AF_INET and a.address == ip for a in addr_list)
                if has_ip:
                    for a in addr_list:
                        if a.family == psutil.AF_LINK and a.address:
                            mac = a.address.replace('-', ':').upper()
                            if len(mac) == 17 and mac != '00:00:00:00:00:00':
                                return mac
        except Exception:
            pass
    return get_local_mac()


def get_interface_network_info(interface: str = None) -> dict:
    """
    Obtiene IP, máscara real, MAC y CIDR real para una interfaz específica o para la ruta por defecto.
    Si la máscara real es más amplia que /20 (ej. /16 en redes virtuales), acota el barrido automático a /24
    para evitar sondeos de decenas de miles de direcciones.
    """
    def _build_cidr(ip_str: str, netmask_str: str) -> str:
        try:
            net = ipaddress.IPv4Network(f"{ip_str}/{netmask_str or '255.255.255.0'}", strict=False)
            if net.prefixlen < 20:
                net = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
            return str(net)
        except Exception:
            parts = ip_str.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    try:
        addrs = psutil.net_if_addrs()
        # 1. Si el usuario eligió una interfaz específica (ej. "Ethernet", "Wi-Fi"), respetarla estrictamente
        if interface and interface not in ('all', 'auto', ''):
            matched_name = None
            for name in addrs.keys():
                if name.lower() == interface.lower():
                    matched_name = name
                    break
            if matched_name:
                ipv4s = [
                    (a.address, a.netmask or "255.255.255.0")
                    for a in addrs[matched_name]
                    if a.family == socket.AF_INET and a.address and not a.address.startswith("127.") and not a.address.startswith("169.254.")
                ]
                mac = ""
                for a in addrs[matched_name]:
                    if a.family == psutil.AF_LINK and a.address:
                        mac = a.address.replace('-', ':').upper()
                        break
                if ipv4s:
                    ip_sel, mask_sel = ipv4s[0]
                    return {
                        "interface": matched_name,
                        "ip": ip_sel,
                        "netmask": mask_sel,
                        "cidr": _build_cidr(ip_sel, mask_sel),
                        "mac": mac,
                        "all_ipv4": ipv4s,
                    }

        # 2. Modo 'all'/'auto': usar la interfaz dueña de get_local_ip() con su máscara real
        primary_ip = get_local_ip()
        if primary_ip and primary_ip != '127.0.0.1':
            for name, addr_list in addrs.items():
                for a in addr_list:
                    if a.family == socket.AF_INET and a.address == primary_ip:
                        mask = a.netmask or "255.255.255.0"
                        mac = ""
                        for la in addr_list:
                            if la.family == psutil.AF_LINK and la.address:
                                mac = la.address.replace('-', ':').upper()
                                break
                        return {
                            "interface": name,
                            "ip": primary_ip,
                            "netmask": mask,
                            "cidr": _build_cidr(primary_ip, mask),
                            "mac": mac,
                            "all_ipv4": [(primary_ip, mask)],
                        }
            return {
                "interface": None,
                "ip": primary_ip,
                "netmask": "255.255.255.0",
                "cidr": _build_cidr(primary_ip, "255.255.255.0"),
                "mac": get_local_mac(),
                "all_ipv4": [(primary_ip, "255.255.255.0")],
            }
    except Exception:
        pass

    return {
        "interface": None,
        "ip": "127.0.0.1",
        "netmask": "255.255.255.0",
        "cidr": "192.168.1.0/24",
        "mac": get_local_mac(),
        "all_ipv4": [],
    }


def get_local_cidr(interface: str = None):
    return get_interface_network_info(interface)["cidr"]


def get_local_mac():
    import uuid
    return ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1]).upper()

def get_active_network_name(fallback_target: str = ""):
    """Detecta el nombre real de la red conectada (SSID Wi-Fi, Perfil de Red de Windows o Subred Destino)."""
    # 1. Intentar obtener el SSID de la tarjeta Wi-Fi activa
    try:
        output = subprocess.check_output(
            "netsh wlan show interfaces",
            shell=True,
            stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW
        ).decode("cp1252", errors="ignore")
        for line in output.splitlines():
            m = re.search(r"^\s*SSID\s*:\s*(.+)$", line, re.IGNORECASE)
            if m:
                ssid = m.group(1).strip()
                if ssid and not ssid.lower().startswith("bssid") and ssid.lower() != "none":
                    return f"Red {ssid}" if not ssid.lower().startswith("red") else ssid
    except Exception:
        pass

    # 2. Intentar obtener el perfil de red de Windows (Ethernet o Wi-Fi con Internet)
    try:
        ps_cmd = (
            "$p = @(Get-NetConnectionProfile); "
            "$net = ($p | Where-Object { $_.IPv4Connectivity -eq 'Internet' } | Select-Object -ExpandProperty Name -First 1); "
            "if (-not $net -and $p.Count -gt 0) { $net = $p[0].Name }; "
            "if ($net) { Write-Output $net }"
        )
        out = subprocess.check_output(
            ['powershell', '-NoProfile', '-Command', ps_cmd],
            stderr=subprocess.DEVNULL,
            creationflags=CREATE_NO_WINDOW
        ).decode("utf-8", errors="ignore").strip()
        if out:
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            for line in lines:
                if line and line.lower() not in ("red", "network", "red no identificada", "unidentified network", "identificando...", "identifying..."):
                    return f"Red {line}" if not line.lower().startswith("red") else line
    except Exception:
        pass

    # 3. Fallback inteligente a target específico (ej: 192.168.1.0/24) en lugar de genérico "Red Local"
    if fallback_target and fallback_target.strip().lower() not in ("auto", "", "local", "127.0.0.1"):
        clean_target = fallback_target.strip()
        return f"Red {clean_target}" if not clean_target.lower().startswith("red") else clean_target

    return "Red Local"


def send_arp_native(ip: str, retries: int = 2, src_ip: str = None):
    """
    Consulta directa de Capa 2 (ARP) en Windows sin necesidad de privilegios de administrador.
    Incorpora reintentos inteligentes espaciados para sincronizar con la ventana DTIM
    de ahorro de energia / suspension de los dispositivos moviles (Android / iOS).
    Permite especificar src_ip para forzar la salida por una tarjeta de red específica.
    Retorna (is_alive: bool, mac: str).
    """
    if sys.platform != 'win32':
        return False, ""
    try:
        inet_addr = ctypes.windll.ws2_32.inet_addr
        inet_addr.restype = ctypes.c_ulong
        ip_addr = inet_addr(ip.encode('ascii'))
        src_ip_addr = 0
        if src_ip:
            try:
                src_ip_addr = inet_addr(src_ip.encode('ascii'))
            except Exception:
                src_ip_addr = 0
        mac_buffer = (ctypes.c_ubyte * 6)()
        
        for attempt in range(max(1, retries)):
            mac_len = ctypes.c_ulong(6)
            res = ctypes.windll.iphlpapi.SendARP(ip_addr, src_ip_addr, ctypes.byref(mac_buffer), ctypes.byref(mac_len))
            if res == 0:
                raw_bytes = bytes(mac_buffer)
                if len(raw_bytes) == 6 and any(b != 0 for b in raw_bytes):
                    return True, ':'.join(f'{b:02X}' for b in raw_bytes)
            if attempt < retries - 1:
                time.sleep(0.12)
        return False, ""
    except Exception:
        return False, ""

_oui_cache = {}
def get_vendor_from_mac(mac: str) -> str:
    """Busca el fabricante (OUI) a partir de la direccion MAC en nmap-mac-prefixes."""
    global _oui_cache
    if not mac or mac in ('Desconocida', '00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'):
        return ''
    clean_mac = mac.replace(':', '').replace('-', '').upper()[:6]
    if not _oui_cache:
        for p in [r'C:\Program Files (x86)\Nmap\nmap-mac-prefixes', r'C:\Program Files\Nmap\nmap-mac-prefixes']:
            if os.path.exists(p):
                try:
                    with open(p, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                parts = line.split(None, 1)
                                if len(parts) == 2:
                                    _oui_cache[parts[0].upper()] = parts[1]
                except Exception:
                    pass
                break
    return _oui_cache.get(clean_mac, '')

def _clean_hostname(raw_name: str, ip: str = "") -> str:
    """Descarta nombres rDNS basura devueltos por routers ISP (ej. 'none', 'localhost' o la propia IP)."""
    if not raw_name or not isinstance(raw_name, str):
        return ""
    clean = raw_name.strip().rstrip(".")
    if clean.lower() in INVALID_HOSTNAMES or clean == ip:
        return ""
    return clean


def _decode_dns_labels(packet: bytes, offset: int, max_hops: int = 12):
    """Decodifica nombres DNS/mDNS (RFC 1035 con punteros de compresión)."""
    labels = []
    jumped = False
    orig_offset = offset
    hops = 0
    pkt_len = len(packet)
    while offset < pkt_len and hops < max_hops:
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= pkt_len:
                break
            ptr = ((length & 0x3F) << 8) | packet[offset + 1]
            if not jumped:
                orig_offset = offset + 2
                jumped = True
            offset = ptr
            hops += 1
            continue
        offset += 1
        if offset + length > pkt_len:
            break
        try:
            labels.append(packet[offset:offset + length].decode("utf-8", errors="ignore"))
        except Exception:
            break
        offset += length
    return ".".join(labels), (orig_offset if jumped else offset)


def _extract_mdns_hostnames(packet: bytes) -> list:
    """Extrae nombres `.local` legibles de una respuesta mDNS (ignora nombres de servicio `_tcp`/`_udp`)."""
    found = []
    if len(packet) < 12:
        return found
    qdcount = int.from_bytes(packet[4:6], "big")
    ancount = int.from_bytes(packet[6:8], "big")
    nscount = int.from_bytes(packet[8:10], "big")
    arcount = int.from_bytes(packet[10:12], "big")
    offset = 12

    for _ in range(qdcount):
        if offset >= len(packet):
            return found
        _name, offset = _decode_dns_labels(packet, offset)
        offset += 4

    total_rr = min(ancount + nscount + arcount, 30)
    for _ in range(total_rr):
        if offset >= len(packet):
            break
        name, offset = _decode_dns_labels(packet, offset)
        if offset + 10 > len(packet):
            break
        rtype = int.from_bytes(packet[offset:offset + 2], "big")
        rdlength = int.from_bytes(packet[offset + 8:offset + 10], "big")
        rdata_start = offset + 10
        offset = rdata_start + rdlength

        # Registros A (1), AAAA (28), PTR (12), SRV (33)
        candidates = []
        if rtype in (1, 28) and name:
            candidates.append(name)
        elif rtype == 12 and rdata_start < len(packet):
            ptr_name, _ = _decode_dns_labels(packet, rdata_start)
            if ptr_name:
                candidates.append(ptr_name)
        elif rtype == 33 and rdata_start + 6 < len(packet):
            srv_target, _ = _decode_dns_labels(packet, rdata_start + 6)
            if srv_target:
                candidates.append(srv_target)

        for cand in candidates:
            low = cand.lower()
            if low.endswith(".local") and not low.startswith("_"):
                # Si es instancia PTR tipo "Mi-Impresora._ipp._tcp.local", tomar solo el prefijo limpio
                first_part = cand.split("._")[0]
                clean = first_part[:-6] if first_part.lower().endswith(".local") else first_part
                clean = clean.strip()
                if clean and clean.lower() not in INVALID_HOSTNAMES and len(clean) >= 2:
                    if clean not in found:
                        found.append(clean)
    return found


def discover_mdns_ssdp_info(timeout: float = 0.7) -> dict:
    """
    Escucha activamente respuestas SSDP/UPnP (puerto 1900) y mDNS/Bonjour (puerto 5353)
    para obtener nombres reales (`friendlyName`, `.local`) y fabricantes de Smart TVs,
    Roku, Chromecast, iPhones, Macs, impresoras y routers en < 1 segundo.
    Retorna dict keyed por IP: `{ip: {"hostname": str, "vendor": str, "model": str}}`.
    """
    results = {}
    ssdp_locations = {}

    def _run_ssdp():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(0.15)
            msg = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 1\r\n"
                "ST: ssdp:all\r\n\r\n"
            ).encode("ascii")
            sock.sendto(msg, ("239.255.255.250", 1900))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]
                    text = data.decode("utf-8", errors="ignore")
                    loc_m = re.search(r"^\s*LOCATION\s*:\s*(\S+)", text, re.I | re.M)
                    srv_m = re.search(r"^\s*SERVER\s*:\s*(.+)$", text, re.I | re.M)
                    if loc_m and ip not in ssdp_locations:
                        ssdp_locations[ip] = loc_m.group(1).strip()
                    if srv_m:
                        srv = srv_m.group(1).strip()
                        results.setdefault(ip, {})
                        if srv and not results[ip].get("server"):
                            results[ip]["server"] = srv
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def _run_mdns():
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(0.15)
            # Consultas PTR mDNS para servicios comunes (AirPlay, Chromecast, Impresoras, Workstations)
            queries = [
                b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01',
                b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0b_googlecast\x04_tcp\x05local\x00\x00\x0c\x00\x01',
                b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08_airplay\x04_tcp\x05local\x00\x00\x0c\x00\x01',
                b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04_ipp\x04_tcp\x05local\x00\x00\x0c\x00\x01',
            ]
            for q in queries:
                try:
                    sock.sendto(q, ("224.0.0.251", 5353))
                except Exception:
                    pass
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                    ip = addr[0]
                    names = _extract_mdns_hostnames(data)
                    if names:
                        results.setdefault(ip, {})
                        if not results[ip].get("hostname"):
                            results[ip]["hostname"] = names[0]
                except socket.timeout:
                    continue
                except Exception:
                    break
        except Exception:
            pass
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    t1 = threading.Thread(target=_run_ssdp, daemon=True)
    t2 = threading.Thread(target=_run_mdns, daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout=timeout + 0.3)
    t2.join(timeout=timeout + 0.3)

    # Resolver XML UPnP (friendlyName / manufacturer / modelName) para hasta 10 dispositivos SSDP en paralelo
    if ssdp_locations:
        import urllib.request

        def _fetch_upnp(item):
            ip, url = item
            try:
                if not url.lower().startswith("http://"):
                    return
                req = urllib.request.Request(url, headers={"User-Agent": "Skop0-UPnP/1.3"})
                with urllib.request.urlopen(req, timeout=0.45) as resp:
                    body = resp.read(16384).decode("utf-8", errors="ignore")
                fn = re.search(r"<friendlyName>([^<]{2,80})</friendlyName>", body, re.I)
                mf = re.search(r"<manufacturer>([^<]{2,80})</manufacturer>", body, re.I)
                md = re.search(r"<modelName>([^<]{2,80})</modelName>", body, re.I)
                entry = results.setdefault(ip, {})
                if fn and fn.group(1).strip():
                    entry["hostname"] = fn.group(1).strip()
                if mf and mf.group(1).strip():
                    entry["vendor"] = mf.group(1).strip()
                if md and md.group(1).strip():
                    entry["model"] = md.group(1).strip()
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(_fetch_upnp, list(ssdp_locations.items())[:10]))

    return results


def verify_host_alive(ip: str, known_mac: str = None) -> tuple:
    """
    Verifica con certeza real si un host está encendido y conectado (sin falsos positivos de caché ARP vieja):
    1. SendARP nativo (3 reintentos espaciados para sincronizar con ventanas DTIM de móviles).
    2. Ping ICMP de sondeo complementario.
    3. Sondeo TCP rápido en puertos estándar (conexión exitosa o TCP RST prueban que el host vive).
    Si las 3 capas fallan, confirma que el host está desconectado (retorna False, '').
    """
    if sys.platform == 'win32':
        is_alive, arp_mac = send_arp_native(ip, retries=3)
        if is_alive:
            return True, arp_mac or known_mac or 'Desconocida'

    try:
        r = subprocess.run(
            ['ping', '-n', '1', '-w', '450', ip],
            capture_output=True,
            creationflags=CREATE_NO_WINDOW,
            timeout=1.5
        )
        if r.returncode == 0 and b'TTL=' in r.stdout.upper():
            return True, known_mac or 'Desconocida'
    except Exception:
        pass

    for p_test in (80, 443, 135, 445, 8080, 8443, 5357, 62078, 8008, 7000, 8009, 8060, 554, 9100, 22, 53):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            s.connect((ip, p_test))
            s.close()
            return True, known_mac or 'Desconocida'
        except socket.error as err:
            if getattr(err, 'errno', None) in (10061, 111):
                s.close()
                return True, known_mac or 'Desconocida'
            s.close()
        except Exception:
            s.close()

    return False, ''


class ScannerEngine:
    def __init__(self):
        self.nmap_bin = 'nmap'
        self.reload_engine()

    def _log(self, msg: str):
        try:
            print(msg)
        except Exception:
            try:
                print(msg.encode('ascii', 'replace').decode('ascii'))
            except Exception:
                pass
        cb = getattr(_thread_local, 'log_cb', None)
        if cb:
            try:
                cb(msg)
            except Exception:
                pass

    def reload_engine(self):
        nmap_paths = [
            r'C:\Program Files (x86)\Nmap\nmap.exe',
            r'C:\Program Files\Nmap\nmap.exe',
            'nmap'
        ]
        self.nmap_bin = 'nmap'
        for p in nmap_paths:
            if os.path.exists(p):
                self.nmap_bin = p
                break

        self.nm = None
        try:
            ver_proc = subprocess.run(
                [self.nmap_bin, '--version'],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5,
                creationflags=CREATE_NO_WINDOW
            )
            if ver_proc.returncode == 0 and 'nmap' in (ver_proc.stdout or '').lower():
                self.nmap_installed = True
                return True
            raise RuntimeError(ver_proc.stderr.strip() or f"exit code {ver_proc.returncode}")
        except Exception as e:
            self.nmap_installed = False
            self._log(f"Soft Error: Nmap no detectado ({e}). El sistema requerirá instalación autónoma.")
            return False

    def _get_nmap_iflist_map(self, force_refresh: bool = False) -> dict:
        """
        Ejecuta `nmap --iflist` (cacheado 10s con lock) y mapea cada IPv4 y MAC al nombre
        de dispositivo interno que Nmap/Npcap entiende en Windows (ej. 'eth0', 'eth1').
        """
        now = time.time()
        with _iflist_cache_lock:
            if not force_refresh and (now - _iflist_cache["ts"]) < 10.0 and _iflist_cache["devs"]:
                return {
                    "ip_to_dev": dict(_iflist_cache["ip_to_dev"]),
                    "mac_to_dev": dict(_iflist_cache["mac_to_dev"]),
                    "devs": set(_iflist_cache["devs"]),
                }

        ip_to_dev = {}
        mac_to_dev = {}
        devs = set()
        try:
            proc = subprocess.run(
                [self.nmap_bin, '--iflist'],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=5,
                creationflags=CREATE_NO_WINDOW
            )
            in_ifaces = False
            for raw_line in (proc.stdout or '').splitlines():
                line = raw_line.strip()
                if "INTERFACES" in line and "****" in line:
                    in_ifaces = True
                    continue
                if "ROUTES" in line and "****" in line:
                    break
                if not in_ifaces or not line or line.startswith("DEV"):
                    continue
                parts = line.split()
                if len(parts) >= 3 and parts[1].startswith("(") and parts[1].endswith(")"):
                    dev = parts[0]
                    ip_mask = parts[2]
                    devs.add(dev)
                    if '/' in ip_mask and ':' not in ip_mask:
                        ip_only = ip_mask.split('/')[0]
                        ip_to_dev[ip_only] = dev
                    mac_m = re.search(r'\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b', line)
                    if mac_m:
                        mac_to_dev[mac_m.group(0).upper()] = dev
        except Exception:
            pass

        with _iflist_cache_lock:
            _iflist_cache["ts"] = time.time()
            _iflist_cache["ip_to_dev"] = ip_to_dev
            _iflist_cache["mac_to_dev"] = mac_to_dev
            _iflist_cache["devs"] = devs

        return {"ip_to_dev": ip_to_dev, "mac_to_dev": mac_to_dev, "devs": devs}

    def _resolve_nmap_interface(self, interface: str, src_ip: str = None):
        """
        Convierte un nombre de interfaz Windows/psutil (ej. 'Ethernet', 'Wi-Fi') al nombre
        nativo de Nmap/Npcap (ej. 'eth0') comparando por IPv4 o MAC. Retorna None si no resuelve.
        """
        if not interface or interface in ('all', 'auto', ''):
            return None

        ifmap = self._get_nmap_iflist_map()
        if interface in ifmap["devs"]:
            return interface

        if src_ip and src_ip in ifmap["ip_to_dev"]:
            return ifmap["ip_to_dev"][src_ip]

        try:
            addrs = psutil.net_if_addrs()
            matched = None
            for name, addr_list in addrs.items():
                if name.lower() == interface.lower():
                    matched = addr_list
                    break
            if matched:
                # 1. Buscar por cualquier IPv4 de esa interfaz
                for a in matched:
                    if a.family == socket.AF_INET and a.address in ifmap["ip_to_dev"]:
                        return ifmap["ip_to_dev"][a.address]
                # 2. Buscar por MAC (funciona incluso justo tras agregar una IP secundaria/bridge)
                for a in matched:
                    if a.family == psutil.AF_LINK and a.address:
                        mac = a.address.replace('-', ':').upper()
                        if mac in ifmap["mac_to_dev"]:
                            return ifmap["mac_to_dev"][mac]
        except Exception:
            pass

        # Reintentar con caché fresca por si un Subnet Bridge acaba de añadir una IP
        if src_ip:
            ifmap_fresh = self._get_nmap_iflist_map(force_refresh=True)
            if src_ip in ifmap_fresh["ip_to_dev"]:
                return ifmap_fresh["ip_to_dev"][src_ip]
        return None

    def _run_nmap_xml(self, targets: list, extra_args: list, timeout: float = 60.0, cancel_event=None) -> dict:
        """
        Ejecuta Nmap en subproceso aislado con salida XML (`-oX -`) y parsea el resultado
        en un diccionario local 100% thread-safe (sin estado compartido mutable).
        Soporta cancelación cooperativa inmediata (`cancel_event`) terminando nmap.exe en <200ms.
        Extrae estado, MAC, fabricante, hostnames, RTT y puertos con product/version/extrainfo/CPE.
        """
        if not self.nmap_installed:
            return {}
        if cancel_event is not None and cancel_event.is_set():
            return {}
        if isinstance(targets, str):
            targets = [t for t in targets.split() if t]
        if not targets:
            return {}

        cmd = [self.nmap_bin, '-oX', '-'] + list(extra_args) + list(targets)
        xml_out = ""
        stderr_out = ""
        proc = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace',
                creationflags=CREATE_NO_WINDOW,
            )
            if cancel_event is None:
                xml_out, stderr_out = proc.communicate(timeout=timeout)
            else:
                # Lectura no bloqueante con chequeo de cancel_event cada 150ms
                out_chunks = []
                err_chunks = []
                def _reader(stream, sink):
                    try:
                        sink.append(stream.read())
                    except Exception:
                        pass
                t_out = threading.Thread(target=_reader, args=(proc.stdout, out_chunks), daemon=True)
                t_err = threading.Thread(target=_reader, args=(proc.stderr, err_chunks), daemon=True)
                t_out.start()
                t_err.start()

                deadline = time.monotonic() + timeout
                while proc.poll() is None:
                    if cancel_event.is_set():
                        try:
                            proc.terminate()
                            proc.wait(timeout=1.0)
                        except Exception:
                            try:
                                proc.kill()
                            except Exception:
                                pass
                        return {}
                    if time.monotonic() >= deadline:
                        try:
                            proc.kill()
                        except Exception:
                            pass
                        self._log(f"  [Nmap XML] Timeout ({timeout}s) ejecutando sondeo sobre {' '.join(targets[:3])}")
                        return {}
                    time.sleep(0.15)

                t_out.join(timeout=2.0)
                t_err.join(timeout=2.0)
                xml_out = "".join(out_chunks)
                stderr_out = "".join(err_chunks)

            if not xml_out.strip() or '<nmaprun' not in xml_out:
                if stderr_out and stderr_out.strip():
                    self._log(f"  [Nmap XML] Aviso: {stderr_out.strip()[:220]}")
                return {}
        except subprocess.TimeoutExpired:
            if proc:
                try:
                    proc.kill()
                except Exception:
                    pass
            self._log(f"  [Nmap XML] Timeout ({timeout}s) ejecutando sondeo sobre {' '.join(targets[:3])}")
            return {}
        except Exception as e:
            self._log(f"  [Nmap XML] Error ejecutando Nmap: {e}")
            return {}
        finally:
            if proc is not None:
                for stream in (proc.stdout, proc.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except Exception:
                            pass

        parsed = {}
        try:
            root = ET.fromstring(xml_out)
        except ET.ParseError as e:
            self._log(f"  [Nmap XML] Error parseando salida XML: {e}")
            return {}

        for host_el in root.findall('host'):
            status_el = host_el.find('status')
            state = status_el.get('state', 'unknown') if status_el is not None else 'unknown'

            ipv4 = ""
            mac = ""
            vendor = ""
            for addr_el in host_el.findall('address'):
                atype = addr_el.get('addrtype', '')
                if atype == 'ipv4':
                    ipv4 = addr_el.get('addr', '')
                elif atype == 'mac':
                    mac = (addr_el.get('addr', '') or '').upper()
                    vendor = addr_el.get('vendor', '') or ''

            if not ipv4:
                continue

            hostname = ""
            hostnames_el = host_el.find('hostnames')
            if hostnames_el is not None:
                for hn_el in hostnames_el.findall('hostname'):
                    hn = (hn_el.get('name', '') or '').strip()
                    if hn:
                        hostname = hn
                        break

            srtt_ms = None
            times_el = host_el.find('times')
            if times_el is not None and times_el.get('srtt'):
                try:
                    srtt_ms = round(int(times_el.get('srtt')) / 1000.0, 2)
                except Exception:
                    srtt_ms = None

            ports_list = []
            ports_el = host_el.find('ports')
            if ports_el is not None:
                for p_el in ports_el.findall('port'):
                    try:
                        port_num = int(p_el.get('portid', '0'))
                    except ValueError:
                        continue
                    proto = (p_el.get('protocol', 'tcp') or 'tcp').lower()
                    p_state_el = p_el.find('state')
                    p_state = p_state_el.get('state', '') if p_state_el is not None else ''
                    p_reason = p_state_el.get('reason', '') if p_state_el is not None else ''

                    svc_el = p_el.find('service')
                    svc_name = ''
                    svc_product = ''
                    svc_version = ''
                    svc_extrainfo = ''
                    cpes = []
                    if svc_el is not None:
                        svc_name = svc_el.get('name', '') or ''
                        svc_product = svc_el.get('product', '') or ''
                        svc_version = svc_el.get('version', '') or ''
                        svc_extrainfo = svc_el.get('extrainfo', '') or ''
                        for cpe_el in svc_el.findall('cpe'):
                            if cpe_el.text and cpe_el.text.strip():
                                cpes.append(cpe_el.text.strip())

                    ports_list.append({
                        "port": port_num,
                        "protocol": proto,
                        "state": p_state,
                        "reason": p_reason,
                        "name": svc_name,
                        "product": svc_product,
                        "version": svc_version,
                        "extrainfo": svc_extrainfo,
                        "cpes": cpes,
                    })

            parsed[ipv4] = {
                "ip": ipv4,
                "state": state,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
                "srtt_ms": srtt_ms,
                "ports": ports_list,
            }

        return parsed

    def _is_private_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False

    def _get_mac_from_arp(self, ip_target: str) -> str:
        """Intenta obtener la MAC de una IP mediante el comando arp -a local."""
        if sys.platform == 'win32':
            alive, mac = send_arp_native(ip_target)
            if alive and mac:
                return mac
        try:
            arp_output = subprocess.check_output(['arp', '-a', ip_target], shell=True, creationflags=CREATE_NO_WINDOW).decode('cp1252', errors='ignore')
            for line in arp_output.split('\n'):
                parts = line.split()
                if len(parts) >= 2 and parts[0] == ip_target:
                    mac = parts[1].replace('-', ':').upper()
                    if mac != 'FF:FF:FF:FF:FF:FF':
                        return mac
        except Exception:
            pass
        return "Desconocida"

    def fallback_to_gateway(self, extra_warning=None) -> dict:
        """Obtiene la Puerta de Enlace Predeterminada de Windows como fallback si el traceroute falla."""
        self._log("  [Fallback] Usando ipconfig para extraer el Default Gateway...")
        advertencias = ["Se ejecutó Fallback de Puerta de Enlace debido a falta de permisos o bloqueo de red."]
        if extra_warning:
            advertencias.append(extra_warning)
            
        try:
            output = subprocess.check_output('ipconfig', shell=True, creationflags=CREATE_NO_WINDOW).decode('cp1252', errors='ignore')
            for line in output.split('\n'):
                if 'Puerta de enlace predeterminada' in line or 'Default Gateway' in line:
                    match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    if match:
                        ip = match.group(0)
                        mac = self._get_mac_from_arp(ip)
                        vendor = get_vendor_from_mac(mac)
                        raw_net = get_active_network_name(fallback_target=ip)
                        clean_net = re.sub(r'^(?:Red\s+|Network\s+)', '', raw_net, flags=re.I).strip()
                        router_name = clean_net if (clean_net and clean_net != "Local") else (f"Router {vendor}" if vendor and vendor != "Desconocido" else "Router Principal")
                        return {
                            "hops_privados": [{
                                "ip": ip,
                                "mac": mac,
                                "tipo": "router_principal",
                                "hostname": router_name,
                                "ssid": clean_net if clean_net != "Local" else "",
                                "fabricante": vendor if vendor != "Desconocido" else "Router Gateway"
                            }],
                            "router_isp": None,
                            "advertencias": advertencias
                        }
        except Exception as e:
            self._log(f"  [Fallback Error] No se pudo obtener gateway: {e}")
            
        return {"hops_privados": [], "router_isp": None, "advertencias": advertencias}

    def fase1_traceroute(self) -> dict:
        """
        FASE 1: Ejecuta traceroute hacia 8.8.8.8 para descubrir el 'esqueleto' de la red.
        Retorna:
            - hops_privados: Nodos internos (ej. Extensores, Router Principal).
            - router_isp: Primer salto con IP pública (Internet).
        """
        self._log("[FASE 1] Iniciando Nmap Traceroute hacia 8.8.8.8 para descubrir la columna vertebral...")
        _t_fase1 = time.perf_counter()
        hops_privados = []
        router_isp = None
        advertencias = []
        
        try:
            result = subprocess.run(
                [self.nmap_bin, '--traceroute', '-sn', '-T4', '--max-retries', '0', '--host-timeout', '1.5s', '8.8.8.8'], 
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=2.5,
                creationflags=CREATE_NO_WINDOW
            )
            
            if result.returncode != 0 and result.stderr:
                self._log(f"  [Nmap Error] Falta de permisos o error: {result.stderr.strip()}")
                return self.fallback_to_gateway()
                
            output = result.stdout
            
            if "TRACEROUTE" not in output:
                self._log("  [Nmap Error] El bloque TRACEROUTE no se encontró en la salida.")
                return self.fallback_to_gateway("El comando Nmap falló o no retornó un bloque TRACEROUTE válido.")
                
            traceroute_block = output.split("TRACEROUTE")[1]
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            
            for line in traceroute_block.splitlines():
                line = line.strip()
                if not line or "HOP" in line:
                    continue
                    
                if "..." in line:
                    parts = line.split("...")
                    try:
                        start_hop = int(parts[0].strip())
                        end_hop = int(parts[1].strip())
                        for h in range(start_hop, end_hop + 1):
                            hops_privados.append({
                                "ip": "unknown",
                                "tipo": "invisible",
                                "rtt_ms": None,
                                "hostname": "Hop Invisible (Bloqueado)"
                            })
                            if "Se detectaron saltos invisibles o bloqueos de ICMP en la ruta." not in advertencias:
                                advertencias.append("Se detectaron saltos invisibles o bloqueos de ICMP en la ruta.")
                            self._log("  -> [HOP INVISIBLE] (ICMP Bloqueado / Tiempo Agotado)")
                    except Exception:
                        pass
                    continue
                
                if "*    *    *" in line or "* * *" in line:
                    hops_privados.append({
                        "ip": "unknown",
                        "tipo": "invisible",
                        "rtt_ms": None,
                        "hostname": "Hop Invisible (Bloqueado)"
                    })
                    if "Se detectaron saltos invisibles o bloqueos de ICMP en la ruta." not in advertencias:
                        advertencias.append("Se detectaron saltos invisibles o bloqueos de ICMP en la ruta.")
                    self._log("  -> [HOP INVISIBLE] (ICMP Bloqueado / Tiempo Agotado)")
                    continue
                    
                match = ip_pattern.search(line)
                if match:
                    ip = match.group(0)
                    
                    if ip == '8.8.8.8':
                        continue
                        
                    if self._is_private_ip(ip):
                        mac = self._get_mac_from_arp(ip)
                        
                        nat_habilitado = False
                        try:
                            local_cidr = get_local_cidr()
                            nat_habilitado = not (ipaddress.ip_address(ip) in ipaddress.ip_network(local_cidr, strict=False))
                            if nat_habilitado and "Se detectó Doble NAT en uno o más extensores, posibles subredes ocultas." not in advertencias:
                                advertencias.append("Se detectó Doble NAT en uno o más extensores, posibles subredes ocultas.")
                        except Exception:
                            pass
                            
                        hops_privados.append({
                            "ip": ip,
                            "mac": mac,
                            "tipo": "extensor", # Todos inician como extensor hasta llegar al final
                            "hostname": "Extensor / Router Intermedio",
                            "nat_habilitado": nat_habilitado
                        })
                        self._log(f"  -> [HOP PRIVADO] {ip} (MAC: {mac}) {'[NAT DETECTADO]' if nat_habilitado else ''}")
                    else:
                        router_isp = {"ip": ip, "tipo": "router_isp", "hostname": "ISP Público"}
                        self._log(f"  -> [HOP PÚBLICO - ISP] {ip} (Fin de la red local)")
                        break
                        
        except subprocess.TimeoutExpired:
            self._log("  [Traceroute] Timeout de 30s expirado.")
            return self.fallback_to_gateway()
        except Exception as e:
            self._log(f"  [Traceroute] Excepción crítica: {e}")
            return self.fallback_to_gateway()
            
        if not hops_privados:
            return self.fallback_to_gateway("La topología está ciega (posible switch pasivo). Se activó el Fallback.")

        if hops_privados:
            first_gw_ip = hops_privados[0].get("ip")
            first_gw_mac = hops_privados[0].get("mac") or self._get_mac_from_arp(first_gw_ip)
            vendor = get_vendor_from_mac(first_gw_mac)
            raw_net = get_active_network_name(fallback_target=first_gw_ip)
            clean_net = re.sub(r'^(?:Red\s+|Network\s+)', '', raw_net, flags=re.I).strip()
            router_name = clean_net if (clean_net and clean_net != "Local") else (f"Router {vendor}" if vendor and vendor != "Desconocido" else "Router Principal")

            hops_privados[0]["hostname"] = router_name
            hops_privados[0]["ssid"] = clean_net if clean_net != "Local" else ""
            hops_privados[0]["fabricante"] = vendor if vendor != "Desconocido" else "Router Gateway"
            hops_privados[0]["mac"] = first_gw_mac
            hops_privados[0]["tipo"] = "router_principal" 
            for hop in hops_privados[1:]:
                if hop.get("tipo") != "invisible":
                    hop_ip = hop.get("ip", "")
                    if self._is_private_ip(hop_ip) and not hop_ip.startswith("100."):
                        hop_mac = hop.get("mac") or self._get_mac_from_arp(hop_ip)
                        hop_vendor = get_vendor_from_mac(hop_mac)
                        hop["tipo"] = "extensor"
                        hop["hostname"] = f"Router Secundario / Gateway Intermedio ({hop_vendor})" if hop_vendor != "Desconocido" else "Router Secundario / Gateway Intermedio"
                        hop["fabricante"] = hop_vendor
                        hop["mac"] = hop_mac
                    else:
                        hop["hostname"] = "Nodo ISP / CGNAT Intermedio"
                        hop["tipo"] = "cgnat_isp"
            
        _elapsed_fase1 = time.perf_counter() - _t_fase1
        self._log(f"[FASE 1] ✅ Completada en {_elapsed_fase1:.2f}s")
        return {
            "hops_privados": hops_privados,
            "router_isp": router_isp,
            "advertencias": advertencias
        }
    

    def _parse_snmp_output(self, output: str, parent_ip: str, method: str) -> list:
        """Extrae pares IP+MAC de la salida de los scripts snmp-interfaces / snmp-arp de Nmap."""
        devices = []
        found_ips = set()
        ip_pattern  = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        mac_pattern = re.compile(r'(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}')

        current_ip  = None
        current_mac = None

        for line in output.splitlines():
            line = line.strip()
            ip_match  = ip_pattern.search(line)
            mac_match = mac_pattern.search(line)

            if ip_match:
                candidate = ip_match.group(0)
                if self._is_private_ip(candidate) and candidate != parent_ip:
                    current_ip = candidate
            if mac_match:
                current_mac = mac_match.group(0).upper().replace('-', ':')

            if current_ip and current_mac and current_ip not in found_ips:
                devices.append({
                    "ip": current_ip,
                    "mac": current_mac,
                    "hostname": "",
                    "vendor": "",
                    "discovery_method": method,
                    "parent_ip": parent_ip
                })
                found_ips.add(current_ip)
                current_ip  = None
                current_mac = None

        return devices

    def _intento_snmp(self, target_ip: str, network_range: str, advertencias: list) -> list:
        """
        Intento 1: SNMP nativo vía pysnmp.
        Consulta la tabla ARP (ipNetToMediaPhysAddress) con OID '1.3.6.1.2.1.4.22.1.2'.
        Timeout estricto de 3 s; si no responde, añade advertencia y retorna [].
        """
        self._log(f"  [Fase 2 - Intento 1] SNMP Nativo (pysnmp) sobre {target_ip}...")
        _t_snmp = time.perf_counter()
        
        try:
            from pysnmp.hlapi import (
                SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
                ObjectType, ObjectIdentity, nextCmd
            )
        except ImportError as e:
            msg = f"Librería pysnmp no instalada. Fallando al fallback. Error: {e}"
            advertencias.append(msg)
            self._log(f"  [SNMP Error] {msg}")
            return []

        devices = []
        found_ips = set()
        communities = ["public", "private"]
        
        for community in communities:
            self._log(f"    -> Probando comunidad '{community}'...")
            try:
                for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                    SnmpEngine(),
                    CommunityData(community),
                    UdpTransportTarget((target_ip, 161), timeout=0.5, retries=0),
                    ContextData(),
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.4.22.1.2')),
                    lexicographicMode=False
                ):
                    if errorIndication:
                        # Si no hay respuesta UDP en el puerto 161 (timeout), no malgastar tiempo probando más comunidades
                        if "timeout" in str(errorIndication).lower() or "timed out" in str(errorIndication).lower():
                            msg = f"SNMP sin respuesta en {target_ip} ({time.perf_counter() - _t_snmp:.2f}s)."
                            advertencias.append(msg)
                            self._log(f"  [SNMP] {msg}")
                            return []
                        break
                    if errorStatus:
                        break
                    
                    for varBind in varBinds:
                        oid = varBind[0].prettyPrint()
                        val = varBind[1]
                        
                        parts = oid.split('.')
                        if len(parts) >= 4:
                            candidate_ip = ".".join(parts[-4:])
                            if self._is_private_ip(candidate_ip) and candidate_ip != target_ip:
                                try:
                                    raw_bytes = val.asOctets()
                                    if len(raw_bytes) == 6:
                                        mac_str = ":".join(f"{b:02X}" for b in raw_bytes)
                                    else:
                                        mac_str = val.prettyPrint().upper().replace('-', ':')
                                        if mac_str.startswith("0X"):
                                            hex_val = mac_str[2:]
                                            mac_str = ":".join(hex_val[i:i+2] for i in range(0, len(hex_val), 2))
                                except Exception:
                                    mac_str = "Desconocida"
                                    
                                if candidate_ip not in found_ips:
                                    devices.append({
                                        "ip": candidate_ip,
                                        "mac": mac_str,
                                        "hostname": "",
                                        "vendor": "",
                                        "discovery_method": "snmp_arp",
                                        "parent_ip": target_ip
                                    })
                                    found_ips.add(candidate_ip)
                
                if devices:
                    self._log(f"  [SNMP] Éxito: {len(devices)} dispositivos extraídos con comunidad '{community}'.")
                    return devices
                    
            except Exception as e:
                self._log(f"    [SNMP] Error con comunidad '{community}': {e}")
                
        msg = f"SNMP sin respuesta o bloqueado en {target_ip} con comunidades comunes."
        advertencias.append(msg)
        self._log(f"  [SNMP] {msg} ({time.perf_counter() - _t_snmp:.2f}s)")
        return []

    def _intento_dhcp_server(self, network_range: str, advertencias: list) -> list:
        """
        Intento 2: Buscar servidor DHCP (UDP 67) en la subred y consultar SNMP sobre él.
        Timeout optimizado: 1.5 s para no frenar redes sin DHCP accesible.
        """
        self._log(f"  [Fase 2 - Intento 2] Buscando servidor DHCP en {network_range}...")
        _t_dhcp = time.perf_counter()
        try:
            dhcp_result = subprocess.run(
                [self.nmap_bin, '-sU', '-p', '67', '-T4', '--max-retries', '0', '--host-timeout', '1.5s', network_range],
                capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=3,
                creationflags=CREATE_NO_WINDOW
            )
            dhcp_output = dhcp_result.stdout

            ip_pattern = re.compile(r'Nmap scan report for ([\d\.]+)')
            state_pattern = re.compile(r'67/udp\s+open')

            dhcp_server_ip = None
            current_ip = None
            for line in dhcp_output.splitlines():
                ip_match = ip_pattern.search(line)
                if ip_match:
                    current_ip = ip_match.group(1)
                if state_pattern.search(line) and current_ip:
                    dhcp_server_ip = current_ip
                    break

            if not dhcp_server_ip:
                msg = f"No se encontró servidor DHCP activo en {network_range}."
                advertencias.append(msg)
                self._log(f"  [DHCP] {msg}")
                return []

            self._log(f"  [DHCP] Servidor DHCP encontrado en {dhcp_server_ip}. Consultando SNMP...")
            devices = self._intento_snmp(dhcp_server_ip, network_range, advertencias)
            for d in devices:
                d["discovery_method"] = "dhcp_server"
            return devices

        except subprocess.TimeoutExpired:
            msg = f"Timeout buscando servidor DHCP en {network_range}."
            advertencias.append(msg)
            self._log(f"  [DHCP] {msg} ({time.perf_counter() - _t_dhcp:.2f}s)")
            return []
        except Exception as e:
            msg = f"Error buscando servidor DHCP: {e}"
            advertencias.append(msg)
            self._log(f"  [DHCP] {msg}")
            return []

    def _intento_nmap_fallback(self, network_range: str, parent_ip: str, active_ips: list = None, interface: str = 'all', cancel_event=None) -> list:
        """
        Intento 3: Descubrimiento híbrido thread-safe de máxima estabilidad.
        Soporta tanto IP única (/32) como cualquier máscara CIDR (/20../31), sin asumir /24.
        Combina:
          1. Wake-up burst UDP & escucha real mDNS/SSDP-UPnP en paralelo (nombres reales friendlyName / .local).
          2. Sondeo nativo Layer-2 SendARP (Windows) usando la IP origen de la interfaz / puente activo.
          3. Barrido Nmap XML thread-safe con resolución correcta de interfaz Npcap (`ethX`).
          4. Verificación estricta (sin falsos positivos ARP) para candidatos pertenecientes exactamente al rango.
        """
        if cancel_event is not None and cancel_event.is_set():
            return []

        self._log(f"  [Fase 2 - Intento 3] Barrido de red de alta fidelidad en {network_range}...")
        _t_nmap = time.perf_counter()

        discovered = []
        found_ips  = set()
        devices_by_ip = {}

        # Parsear exactamente el rango o IP única (nunca asumir /24)
        clean_range = (network_range or "").strip()
        try:
            target_net = ipaddress.IPv4Network(clean_range, strict=False)
        except Exception:
            fallback_cidr = get_local_cidr(interface)
            target_net = ipaddress.IPv4Network(fallback_cidr, strict=False)
            clean_range = str(target_net)

        is_single_host = (target_net.num_addresses == 1)
        if is_single_host:
            target_ips = [str(target_net.network_address)]
            self._log(f"  [Objetivo Único] Auditando directamente la IP {target_ips[0]} (sin barrer otras IPs)...")
        else:
            target_ips = [str(h) for h in target_net.hosts()]
            self._log(f"  [Barrido Activo] Iniciando sondeo para {target_net} ({len(target_ips)} direcciones)...")

        def _ip_in_target(ip_str: str) -> bool:
            try:
                return ipaddress.IPv4Address(ip_str) in target_net
            except Exception:
                return False

        # Determinar IP origen óptima en la interfaz elegida (priorizando la IP que pertenezca a target_net, ej. Subnet Bridge)
        src_ip_force = None
        if interface and interface not in ('all', 'auto', ''):
            try:
                for name, addr_list in psutil.net_if_addrs().items():
                    if name.lower() == interface.lower():
                        ipv4_candidates = [
                            a.address for a in addr_list
                            if a.family == socket.AF_INET and a.address and not a.address.startswith('127.')
                        ]
                        for cand in ipv4_candidates:
                            if _ip_in_target(cand):
                                src_ip_force = cand
                                break
                        if not src_ip_force and is_single_host:
                            try:
                                single_24 = ipaddress.IPv4Network(f"{target_ips[0]}/24", strict=False)
                                for cand in ipv4_candidates:
                                    if ipaddress.IPv4Address(cand) in single_24:
                                        src_ip_force = cand
                                        break
                            except Exception:
                                pass
                        if not src_ip_force and ipv4_candidates:
                            src_ip_force = ipv4_candidates[0]
                        break
            except Exception:
                pass
        else:
            try:
                for _name, addr_list in psutil.net_if_addrs().items():
                    for a in addr_list:
                        if a.family == socket.AF_INET and a.address and not a.address.startswith('127.'):
                            if _ip_in_target(a.address):
                                src_ip_force = a.address
                                break
                    if src_ip_force:
                        break
            except Exception:
                pass

        # 0. Ráfaga de despertar UDP + escucha mDNS/SSDP en paralelo (0ms de penalización al correr con L2 ARP)
        mdns_ssdp_result = {}
        mdns_thread = None
        if not is_single_host:
            def _bg_mdns_ssdp():
                try:
                    mdns_ssdp_result.update(discover_mdns_ssdp_info(timeout=0.75))
                except Exception:
                    pass
            mdns_thread = threading.Thread(target=_bg_mdns_ssdp, daemon=True)
            mdns_thread.start()

        try:
            def _send_wake_probe(target_host):
                if cancel_event is not None and cancel_event.is_set():
                    return
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(0.05)
                    sock.sendto(b'\x00', (target_host, 137))
                    sock.sendto(b'\x00', (target_host, 5353))
                    sock.sendto(b'\x00', (target_host, 1900))
                    sock.close()
                except Exception:
                    pass

            if len(target_ips) == 1:
                _send_wake_probe(target_ips[0])
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(64, max(4, len(target_ips)))) as executor:
                    list(executor.map(_send_wake_probe, target_ips))
            time.sleep(0.1)
        except Exception:
            pass

        if cancel_event is not None and cancel_event.is_set():
            return []

        # 1. Barrido Layer-2 ultra-rápido:
        #    - Para IP única (/32): SendARP nativo directo (~0.1s).
        #    - Para subred (/20../31): Nmap ARP asíncrono (-n -sn -PR --min-rate 250 --max-retries 3),
        #      que barre 254 IPs en ~1.5-2.2s en lugar de ~45s de SendARP síncrono, con la misma fidelidad L2 + MAC + OUI.
        local_ips_all = get_all_local_ips()
        nmap_dev = self._resolve_nmap_interface(interface, src_ip=src_ip_force)

        if is_single_host and sys.platform == 'win32':
            self._log(f"  [L2 ARP Sweep] Ejecutando verificación nativa de Capa 2 en 1 dirección...")
            try:
                is_alive, mac = send_arp_native(target_ips[0], retries=2, src_ip=src_ip_force)
                if is_alive and mac and mac not in ('00:00:00:00:00:00', 'FF:FF:FF:FF:FF:FF'):
                    found_ips.add(target_ips[0])
                    vendor = get_vendor_from_mac(mac)
                    devices_by_ip[target_ips[0]] = {
                        "ip": target_ips[0],
                        "mac": mac,
                        "hostname": "",
                        "vendor": vendor,
                        "discovery_method": "l2_arp_sweep",
                        "parent_ip": parent_ip
                    }
                    self._log(f"  [L2 Confirmado] Activo en tiempo real: {target_ips[0]} (MAC: {mac}) | {vendor or 'Sin vendor'}")
            except Exception as e:
                self._log(f"  [L2 ARP Sweep Error] {e}")

        if cancel_event is not None and cancel_event.is_set():
            return []

        # 2. Barrido Nmap XML asíncrono (100% thread-safe) con resolución real de interfaz Npcap (`ethX`)
        try:
            if not is_single_host:
                self._log(f"  [L2 ARP Sweep] Ejecutando barrido ARP asíncrono Npcap en {clean_range} ({len(target_ips)} direcciones)...")
                arp_args = ['-n', '-sn', '-PR', '--min-rate', '250', '--max-retries', '3', '--initial-rtt-timeout', '150ms', '--max-rtt-timeout', '500ms']
                if nmap_dev:
                    arp_args += ['-e', nmap_dev]
                    self._log(f"  [Nmap] Interfaz Npcap resuelta: '{interface}' -> '{nmap_dev}'")
                xml_hosts = self._run_nmap_xml([str(target_net)], arp_args, timeout=20.0, cancel_event=cancel_event)

                # Si ARP L2 no devolvió hosts (ej. subred remota detrás de router), hacer fallback multi-vector ICMP/TCP/UDP
                up_in_net = [h for h, d in xml_hosts.items() if d.get('state') == 'up' and _ip_in_target(h)]
                if not up_in_net and not (cancel_event is not None and cancel_event.is_set()):
                    self._log(f"  [Nmap] Subred sin respuesta L2 directa; ejecutando sondeo multi-vector en {clean_range}...")
                    mv_args = ['-n', '-sn', '-PE', '-PS22,80,443,135,445,8080,8443,5357,62078', '-PU53,137,5353,1900', '-T4', '--min-rate', '200', '--max-retries', '1', '--host-timeout', '2.5s']
                    if nmap_dev:
                        mv_args += ['-e', nmap_dev]
                    xml_hosts = self._run_nmap_xml([str(target_net)], mv_args, timeout=25.0, cancel_event=cancel_event)
            else:
                nmap_targets = [target_ips[0]]
                nmap_args = ['-n', '-sn', '-PE', '-PS80,443,135,445,8080,8443,62078', '-PU53,137,5353', '-T4', '--max-retries', '1', '--host-timeout', '2.0s']
                if nmap_dev:
                    nmap_args += ['-e', nmap_dev]
                xml_hosts = self._run_nmap_xml(nmap_targets, nmap_args, timeout=10.0, cancel_event=cancel_event)

            for host, hdata in xml_hosts.items():
                if hdata.get('state') == 'up' and _ip_in_target(host):
                    mac = hdata.get('mac') or "Desconocida"
                    if host in local_ips_all and mac == "Desconocida":
                        mac = get_local_mac_for_ip(host)
                    elif mac == "Desconocida":
                        mac = self._get_mac_from_arp(host) or "Desconocida"

                    vendor = hdata.get('vendor') or ""
                    if not vendor and mac != "Desconocida":
                        vendor = get_vendor_from_mac(mac)

                    hostname = _clean_hostname(hdata.get('hostname') or "", host)

                    if host in devices_by_ip:
                        if hostname:
                            devices_by_ip[host]["hostname"] = hostname
                        if vendor and not devices_by_ip[host]["vendor"]:
                            devices_by_ip[host]["vendor"] = vendor
                        if mac != "Desconocida":
                            devices_by_ip[host]["mac"] = mac
                        devices_by_ip[host]["discovery_method"] = "nmap_verified"
                    else:
                        found_ips.add(host)
                        devices_by_ip[host] = {
                            "ip": host,
                            "mac": mac,
                            "hostname": hostname,
                            "vendor": vendor,
                            "discovery_method": "l2_arp_npcap" if not is_single_host else "nmap_live",
                            "parent_ip": parent_ip
                        }
                    self._log(f"  [L2 Confirmado] Activo en tiempo real: {host} (MAC: {mac}) | {vendor or 'Sin vendor'}")
        except Exception as e:
            self._log(f"  [Nmap] Error en sondeo Nmap: {e}")

        if cancel_event is not None and cancel_event.is_set():
            return []

        # 3. Recopilar candidatos adicionales de la tabla ARP local y de active_ips (estrictamente dentro de target_net)
        arp_candidates = []
        try:
            arp_post = subprocess.check_output('arp -a', shell=True, creationflags=CREATE_NO_WINDOW).decode('cp1252', errors='ignore')
            for line in arp_post.split('\n'):
                parts = line.split()
                if len(parts) >= 2:
                    ip_arp = parts[0].strip()
                    mac_arp = parts[1].strip().replace('-', ':').upper()
                    if (_ip_in_target(ip_arp)
                            and ip_arp not in found_ips
                            and (is_single_host or (ip_arp != str(target_net.network_address) and ip_arp != str(target_net.broadcast_address)))
                            and not mac_arp.startswith('01:00:5E')
                            and mac_arp not in ('FF:FF:FF:FF:FF:FF', 'FF-FF-FF-FF-FF-FF', '00:00:00:00:00:00')
                            and len(mac_arp) == 17):
                        arp_candidates.append((ip_arp, mac_arp))
        except Exception:
            pass

        if active_ips:
            for ip_cached in active_ips:
                if _ip_in_target(ip_cached) and ip_cached not in found_ips:
                    arp_candidates.append((ip_cached, self._get_mac_from_arp(ip_cached)))

        # Si es objetivo único y aún no se encontró por L2 ni Nmap, forzar verificación directa (Ping + TCP)
        if is_single_host and target_ips[0] not in found_ips and target_ips[0] not in local_ips_all:
            arp_candidates.append((target_ips[0], self._get_mac_from_arp(target_ips[0])))

        # 4. Validar candidatos con verify_host_alive (SendARP + Ping + Sockets TCP)
        if arp_candidates:
            seen_cands = set()
            unique_candidates = []
            for ip_c, mac_c in arp_candidates:
                if ip_c not in seen_cands and ip_c not in found_ips:
                    seen_cands.add(ip_c)
                    unique_candidates.append((ip_c, mac_c))

            def _check_cand(item):
                ip_c, mac_c = item
                is_alive, verified_mac = verify_host_alive(ip_c, mac_c)
                return (ip_c, verified_mac or mac_c, is_alive)

            with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, max(1, len(unique_candidates)))) as executor:
                cand_results = list(executor.map(_check_cand, unique_candidates))

            for ip_c, mac_c, is_alive in cand_results:
                if is_alive:
                    found_ips.add(ip_c)
                    vendor = get_vendor_from_mac(mac_c)
                    devices_by_ip[ip_c] = {
                        "ip": ip_c,
                        "mac": mac_c or "Desconocida",
                        "hostname": "",
                        "vendor": vendor,
                        "discovery_method": "multi_verified",
                        "parent_ip": parent_ip
                    }
                    self._log(f"  [Verificacion Activa] Confirmado encendido: {ip_c} ({mac_c})")
                else:
                    self._log(f"  [Descartado] Confirmado desconectado/apagado: {ip_c}")

        # 5. Asegurar cualquier IP local de esta PC que pertenezca al rango objetivo (multi-interfaz)
        for loc_ip in local_ips_all:
            if _ip_in_target(loc_ip):
                found_ips.add(loc_ip)
                loc_mac = get_local_mac_for_ip(loc_ip)
                if loc_ip not in devices_by_ip:
                    devices_by_ip[loc_ip] = {
                        "ip": loc_ip,
                        "mac": loc_mac,
                        "hostname": socket.gethostname(),
                        "vendor": get_vendor_from_mac(loc_mac),
                        "discovery_method": "local",
                        "parent_ip": parent_ip
                    }
                else:
                    if not devices_by_ip[loc_ip].get("hostname"):
                        devices_by_ip[loc_ip]["hostname"] = socket.gethostname()
                    if devices_by_ip[loc_ip].get("mac") in ("Desconocida", "", None):
                        devices_by_ip[loc_ip]["mac"] = loc_mac
                    if not devices_by_ip[loc_ip].get("vendor"):
                        devices_by_ip[loc_ip]["vendor"] = get_vendor_from_mac(loc_mac)

        # 5.5 Fusionar nombres reales y fabricantes obtenidos por mDNS (.local) y SSDP/UPnP (friendlyName)
        if mdns_thread is not None:
            mdns_thread.join(timeout=1.2)
        if mdns_ssdp_result:
            enriched_count = 0
            for ip_m, info_m in mdns_ssdp_result.items():
                if ip_m in devices_by_ip:
                    clean_hn = _clean_hostname(info_m.get("hostname", ""), ip_m)
                    if clean_hn and (not devices_by_ip[ip_m].get("hostname") or devices_by_ip[ip_m]["hostname"] == "Dispositivo de Red"):
                        devices_by_ip[ip_m]["hostname"] = clean_hn
                        enriched_count += 1
                    if info_m.get("vendor") and (not devices_by_ip[ip_m].get("vendor") or devices_by_ip[ip_m]["vendor"] == "Desconocido"):
                        devices_by_ip[ip_m]["vendor"] = info_m["vendor"]
            if enriched_count > 0:
                self._log(f"  [mDNS/SSDP] {enriched_count} nombre(s) real(es) enriquecido(s) por Bonjour/UPnP.")

        # 6. Resolución final de Hostname (rDNS acotado a 1.2s para evitar bloqueos DNS de 4.5s en Windows) y Vendor
        if devices_by_ip:
            dev_list = list(devices_by_ip.values())
            for dev in dev_list:
                if not dev.get("vendor") and dev.get("mac") and dev["mac"] != "Desconocida":
                    dev["vendor"] = get_vendor_from_mac(dev["mac"])

            need_rdns = [d for d in dev_list if not _clean_hostname(d.get("hostname", ""), d["ip"])]
            if need_rdns:
                ex = concurrent.futures.ThreadPoolExecutor(max_workers=min(16, len(need_rdns)))
                fut_map = {ex.submit(socket.gethostbyaddr, d["ip"]): d for d in need_rdns}
                done, _not_done = concurrent.futures.wait(fut_map.keys(), timeout=1.2)
                for fut in done:
                    dev = fut_map[fut]
                    try:
                        rdns = _clean_hostname(fut.result()[0], dev["ip"])
                        dev["hostname"] = rdns if rdns else "Dispositivo de Red"
                    except Exception:
                        dev["hostname"] = "Dispositivo de Red"
                for fut, dev in fut_map.items():
                    if fut not in done:
                        dev["hostname"] = "Dispositivo de Red"
                ex.shutdown(wait=False)
            discovered = dev_list

        def _ip_sort_key(d):
            try:
                return tuple(int(p) for p in d["ip"].split('.'))
            except Exception:
                return (999, 999, 999, 999)

        discovered.sort(key=_ip_sort_key)
        self._log(f"  [Fase 2 - Intento 3] OK Completado en {time.perf_counter() - _t_nmap:.2f}s | Total dispositivos activos: {len(discovered)}")
        return discovered

    def discover_network(self, network_range: str,
                         router_principal_ip: str = None,
                         advertencias: list = None,
                         active_ips: list = None,
                         interface: str = 'all',
                         cancel_event=None) -> list:
        """
        FASE 2: Cascada optimizada de descubrimiento de dispositivos.
        - Si el objetivo es una IP única (/32), salta SNMP y verifica directamente el host.
        - Si es subred, intenta SNMP rápido en el gateway (abortando al primer timeout) y pasa
          directo al descubrimiento híbrido L2 ARP + mDNS/SSDP + Nmap XML sin el escaneo lento de DHCP.
        """
        if cancel_event is not None and cancel_event.is_set():
            return []
        if advertencias is None:
            advertencias = []
        parent_ip = router_principal_ip or network_range.split('/')[0]

        self._log(f"[FASE 2] Iniciando descubrimiento en cascada. Red: {network_range} | Router: {parent_ip} | Interfaz: {interface}")
        _t_fase2 = time.perf_counter()

        # Si es objetivo de una sola IP (/32 o sin máscara), ir directo al sondeo del host
        is_single_host = False
        try:
            is_single_host = (ipaddress.IPv4Network(network_range.strip(), strict=False).num_addresses == 1)
        except Exception:
            pass

        if is_single_host:
            result = self._intento_nmap_fallback(network_range, parent_ip, active_ips=active_ips, interface=interface, cancel_event=cancel_event)
            self._log(f"[FASE 2] ✅ Completada (IP única) en {time.perf_counter() - _t_fase2:.2f}s")
            return result

        snmp_exitosa = False
        if router_principal_ip and router_principal_ip != "unknown":
            devices = self._intento_snmp(router_principal_ip, network_range, advertencias)
            if devices:
                return devices
            snmp_exitosa = False

        if cancel_event is not None and cancel_event.is_set():
            return []

        es_subred_externa = False
        try:
            local_cidr = get_local_cidr(interface)
            if ipaddress.ip_network(network_range, strict=False) != ipaddress.ip_network(local_cidr, strict=False):
                es_subred_externa = True
        except Exception:
            pass

        if es_subred_externa and not snmp_exitosa:
            msg = f"Aviso de Red en {parent_ip}: La subred externa {network_range} no responde a SNMP. Continuando con descubrimiento híbrido L2/Nmap."
            advertencias.append(msg)
            self._log(f"  [AVISO] {msg}")

        result = self._intento_nmap_fallback(network_range, parent_ip, active_ips=active_ips, interface=interface, cancel_event=cancel_event)
        self._log(f"[FASE 2] ✅ Completada en {time.perf_counter() - _t_fase2:.2f}s")
        return result


    @staticmethod
    def _grab_http_server_banner(ip: str, port: int, timeout: float = 0.35) -> tuple:
        """
        Extrae en milisegundos el encabezado HTTP `Server:` (ej. 'Roku/12.x', 'Apache/2.4.49',
        'nginx/1.24.0') cuando el banner rápido de Nmap no identificó el producto.
        Retorna `(producto, version)`.
        """
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            req = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Skop0/1.3\r\n\r\n".encode("ascii")
            s.sendall(req)
            raw = s.recv(1024).decode("utf-8", errors="ignore")
            m = re.search(r"^\s*Server\s*:\s*([^\r\n]{2,80})", raw, re.I | re.M)
            if m:
                srv = m.group(1).strip()
                # Separar primer token producto/versión si viene tipo "nginx/1.24.0 (Ubuntu)"
                tok = srv.split()[0]
                if "/" in tok:
                    prod, ver = tok.split("/", 1)
                    return prod.strip(), ver.strip()
                return srv[:50], ""
        except Exception:
            pass
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
        return "", ""

    def fast_port_sweep(self, ips: list, interface: str = 'all', cancel_event=None) -> dict:
        """
        FASE 3A (Etapa 1): Barrido TCP SYN ultrarrápido sobre todos los hosts descubiertos
        en un único subproceso Nmap (`-n -Pn -sS -p 78 puertos curados`).
        Tarda ~0.5-1.5s para toda la LAN, descubre 100% de los puertos abiertos (incluso en
        equipos con firewall lento como Roku) y evita ejecutar `-sV` sobre equipos con 0 puertos.
        """
        if not ips or not self.nmap_installed:
            return {}
        if cancel_event is not None and cancel_event.is_set():
            return {}

        _t0 = time.perf_counter()
        nmap_args = [
            '-n', '-Pn', '-sS',
            '-p', SECSCAN_AUDIT_PORTS,
            '--min-rate', '400',
            '--max-retries', '1',
            '--initial-rtt-timeout', '100ms',
            '--max-rtt-timeout', '300ms',
            '--host-timeout', '6s',
        ]
        nmap_dev = self._resolve_nmap_interface(interface)
        if nmap_dev:
            nmap_args += ['-e', nmap_dev]

        xml_hosts = self._run_nmap_xml(list(ips), nmap_args, timeout=max(15.0, len(ips) * 1.5), cancel_event=cancel_event)
        self._log(f"[FASE 3A] Barrido SYN rápido (78 puertos) en {len(ips)} equipo(s) completado en {time.perf_counter() - _t0:.2f}s")
        return xml_hosts

    def scan_ports(self, ip_target: str, interface: str = 'all', cancel_event=None, pre_sweep_host: dict = None, skip_rdns: bool = False) -> dict:
        """
        Escaneo profundo thread-safe en 2 etapas (Nmap XML nativo):
          - Etapa A: usa `pre_sweep_host` (o ejecuta `fast_port_sweep` individual de ~0.4s) para obtener
            el inventario completo y garantizado de puertos abiertos en el perfil curado de 78 puertos.
          - Etapa B: si existen puertos abiertos, ejecuta `-sV --version-intensity 1` SOLO sobre esos
            puertos exactos y fusiona `producto/versión/CPE` sobre el inventario de Etapa A (nunca pierde
            puertos si un servicio silencioso como Cast/Roku supera el timeout).
          - Optimización de nombres: solo ejecuta `nbtstat` si hay puertos Windows (135/139/445) y evita
            rDNS redundantes de 4.5s cuando Fase 2 ya lo resolvió.
        """
        if cancel_event is not None and cancel_event.is_set():
            return {
                "ip": ip_target, "mac": "Desconocida", "hostname": "", "fabricante": "Desconocido",
                "puertos_abiertos": [], "puertos_bloqueados": [], "puertos": [], "nmap_rtt_ms": None,
                "cancelled": True,
            }

        self._log(f"Iniciando escaneo profundo en: {ip_target}...")
        _t_deep = time.perf_counter()

        # Etapa A: inventario base de puertos abiertos (ya pre-escaneado en batch o sweep individual rápido)
        host_data = pre_sweep_host
        if host_data is None:
            sweep_res = self.fast_port_sweep([ip_target], interface=interface, cancel_event=cancel_event)
            host_data = sweep_res.get(ip_target)

        if cancel_event is not None and cancel_event.is_set():
            return {
                "ip": ip_target, "mac": "Desconocida", "hostname": "", "fabricante": "Desconocido",
                "puertos_abiertos": [], "puertos_bloqueados": [], "puertos": [], "nmap_rtt_ms": None,
                "cancelled": True,
            }

        if not host_data:
            self._log(f"[DEEP-SCAN] {ip_target} no devolvió respuesta XML en escaneo de puertos.")
            return {
                "ip": ip_target,
                "mac": "Desconocida",
                "hostname": "",
                "fabricante": "Desconocido",
                "puertos_abiertos": [],
                "puertos_bloqueados": [],
                "puertos": [],
                "nmap_rtt_ms": None,
            }

        RAZONES_FILTRADO = {
            "filtered": "Bloqueado por firewall — los paquetes de sondeo son descartados sin respuesta (DROP rule activa)",
            "closed":   "Puerto cerrado — el sistema responde con TCP RST, confirmando que no hay servicio activo",
            "open|filtered": "Ambiguo — el host no respondió al sondeo UDP/TCP; posible firewall stateless o pérdida de paquetes",
        }

        open_by_port = {}
        puertos_bloqueados = []
        for port_data in host_data.get('ports', []):
            if port_data.get('protocol') != 'tcp':
                continue
            state = port_data.get('state', '')
            port = port_data.get('port')
            if state == 'open':
                open_by_port[port] = {
                    "puerto": port,
                    "protocolo": "TCP",
                    "servicio": port_data.get('name', ''),
                    "producto": port_data.get('product', ''),
                    "version": port_data.get('version', ''),
                    "extrainfo": port_data.get('extrainfo', ''),
                    "cpe": port_data.get('cpes', []),
                }
            elif state in ('filtered', 'closed', 'open|filtered'):
                puertos_bloqueados.append({
                    "puerto": port,
                    "protocolo": "TCP",
                    "servicio": port_data.get('name') or "desconocido",
                    "estado": state,
                    "razon": RAZONES_FILTRADO.get(state, f"Estado desconocido: {state}")
                })

        # Etapa B: detección de versiones (-sV) dirigida ÚNICAMENTE a los puertos abiertos encontrados
        sv_host = None
        if open_by_port and not (cancel_event is not None and cancel_event.is_set()):
            open_ports_csv = ",".join(str(p) for p in sorted(open_by_port.keys()))
            sv_args = [
                '-n', '-Pn', '-sV',
                '--version-intensity', '1',
                '-T4',
                '-p', open_ports_csv,
                '--max-retries', '1',
                '--host-timeout', '10s',
            ]
            nmap_dev = self._resolve_nmap_interface(interface)
            if nmap_dev:
                sv_args += ['-e', nmap_dev]

            sv_xml = self._run_nmap_xml([ip_target], sv_args, timeout=12.5, cancel_event=cancel_event)
            sv_host = sv_xml.get(ip_target)
            if sv_host:
                for sp in sv_host.get('ports', []):
                    if sp.get('protocol') == 'tcp' and sp.get('state') == 'open':
                        pnum = sp.get('port')
                        if pnum in open_by_port:
                            if sp.get('name'):
                                open_by_port[pnum]['servicio'] = sp['name']
                            if sp.get('product'):
                                open_by_port[pnum]['producto'] = sp['product']
                            if sp.get('version'):
                                open_by_port[pnum]['version'] = sp['version']
                            if sp.get('extrainfo'):
                                open_by_port[pnum]['extrainfo'] = sp['extrainfo']
                            if sp.get('cpes'):
                                open_by_port[pnum]['cpe'] = sp['cpes']

            # Banner HTTP ligero en 15-350ms para puertos HTTP sin producto detectado (ej. Roku :8060, routers :80)
            for pnum, pinfo in open_by_port.items():
                if not pinfo.get('producto') and pnum in (80, 8000, 8008, 8060, 8080, 8081):
                    prod_h, ver_h = self._grab_http_server_banner(ip_target, pnum)
                    if prod_h:
                        pinfo['producto'] = prod_h
                    if ver_h and not pinfo.get('version'):
                        pinfo['version'] = ver_h

        puertos_descubiertos = [open_by_port[k] for k in sorted(open_by_port.keys())]

        mac = (sv_host.get('mac') if sv_host else '') or host_data.get('mac') or 'Desconocida'
        local_ips_all = get_all_local_ips()
        if ip_target in local_ips_all and mac == 'Desconocida':
            mac = get_local_mac_for_ip(ip_target)
        elif mac == 'Desconocida':
            mac = self._get_mac_from_arp(ip_target) or 'Desconocida'

        fabricante = (sv_host.get('vendor') if sv_host else '') or host_data.get('vendor') or "Desconocido"
        if fabricante == "Desconocido" and mac != "Desconocida":
            fabricante = get_vendor_from_mac(mac) or "Desconocido"

        hostname = _clean_hostname((sv_host.get('hostname') if sv_host else '') or host_data.get('hostname') or "", ip_target)

        if not hostname and not skip_rdns:
            try:
                rdns = _clean_hostname(socket.gethostbyaddr(ip_target)[0], ip_target)
                if rdns:
                    hostname = rdns
                    self._log(f"[DNS] Hostname resuelto para {ip_target}: {hostname}")
            except Exception:
                pass

        # Solo consultar NetBIOS (nbtstat) si el host expone puertos Windows/SMB (evita 4s perdidos en TVs/móviles/Roku)
        has_windows_ports = bool({135, 139, 445}.intersection(open_by_port.keys()))
        if not hostname and has_windows_ports:
            try:
                result = subprocess.run(
                    ['nbtstat', '-A', ip_target],
                    capture_output=True, text=True, encoding='cp1252', errors='replace', timeout=1.5,
                    creationflags=CREATE_NO_WINDOW
                )
                for line in result.stdout.splitlines():
                    if '<00>' in line and 'UNIQUE' in line:
                        nb_name = _clean_hostname(line.strip().split()[0].strip(), ip_target)
                        if nb_name:
                            hostname = nb_name
                            self._log(f"[NetBIOS] Hostname resuelto para {ip_target}: {hostname}")
                        break
            except Exception:
                pass

        if puertos_descubiertos:
            self._log(f"[PUERTOS ABIERTOS] {ip_target}: {len(puertos_descubiertos)} servicio(s) expuesto(s):")
            for p in puertos_descubiertos:
                prod_ver = " ".join(x for x in (p.get('producto'), p.get('version')) if x).strip()
                detail = f" ({prod_ver})" if prod_ver else ""
                self._log(f"  [ABIERTO]   TCP/{p['puerto']}  {(p['servicio'] or 'N/A').upper()}{detail}")
        else:
            self._log(f"[PUERTOS ABIERTOS] {ip_target}: Sin servicios expuestos detectados en perfil de auditoría.")

        if puertos_bloqueados:
            self._log(f"[PUERTOS BLOQUEADOS] {ip_target}: {len(puertos_bloqueados)} puerto(s) con acceso restringido:")
            for p in puertos_bloqueados:
                self._log(f"  [BLOQUEADO] TCP/{p['puerto']}  {p['servicio'].upper() if p['servicio'] else 'N/A'}  — {p['razon']}")

        srtt_val = (sv_host.get("srtt_ms") if sv_host and sv_host.get("srtt_ms") is not None else host_data.get("srtt_ms"))
        _elapsed_deep = time.perf_counter() - _t_deep
        self._log(f"[DEEP-SCAN] Completado {ip_target} en {_elapsed_deep:.2f}s | Abiertos: {len(puertos_descubiertos)} | Bloqueados: {len(puertos_bloqueados)}")
        return {
            "ip": ip_target,
            "mac": mac,
            "hostname": hostname,
            "fabricante": fabricante,
            "puertos_abiertos": puertos_descubiertos,
            "puertos_bloqueados": puertos_bloqueados,
            "nmap_rtt_ms": srtt_val,
        }
