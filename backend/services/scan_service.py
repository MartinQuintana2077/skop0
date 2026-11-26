import datetime
import threading
import time
import subprocess
import socket
import ipaddress
import sys
import os
from core.scanner import (
    ScannerEngine,
    get_local_cidr,
    get_local_ip,
    get_all_local_ips,
    get_local_mac,
    get_interface_network_info,
    get_active_network_name,
)

CREATE_NO_WINDOW = 0x08000000 if sys.platform == 'win32' else 0
from core.cve_client import CVEClient
from services.db_service import DatabaseService

_passive_device_cache = {}
_last_subnet = None
_last_discovery_time = 0.0
_daemon_started = False
_daemon_lock = threading.Lock()

_active_scan_count = 0
_active_scan_count_lock = threading.Lock()
_last_active_time = 0.0

_deep_scan_active_count = 0
_deep_scan_start_time = 0.0
_deep_scan_lock = threading.Lock()

def start_passive_daemon():
    """Inicializa de forma segura el hilo del demonio en segundo plano."""
    global _daemon_started
    with _daemon_lock:
        if _daemon_started:
            return
        _daemon_started = True
        
    thread = threading.Thread(target=run_passive_background_worker, daemon=True, name="PassiveScanDaemon")
    thread.start()
    print("[PassiveScanDaemon] Hilo de escaneo pasivo en segundo plano iniciado correctamente.")
def run_passive_background_worker():
    """Ciclo en segundo plano del demonio pasivo."""
    global _last_subnet, _passive_device_cache, _last_discovery_time
    global _active_scan_count, _active_scan_count_lock, _last_active_time
    
    time.sleep(2)
    
    _paused_logged = False
    while True:
        with _active_scan_count_lock:
            if _active_scan_count > 0:
                _last_active_time = time.time()
            hay_escaneo_activo = (_active_scan_count > 0) or (time.time() - _last_active_time < 8.0)
            
        if hay_escaneo_activo:
            if not _paused_logged:
                print("[PassiveScanDaemon] Escaneo activo en curso. Ciclo pasivo en pausa.")
                _paused_logged = True
            time.sleep(2)
            continue
            
        if _paused_logged:
            print("[PassiveScanDaemon] Escaneo activo finalizado. Reanudando ciclos pasivos en segundo plano.")
            _paused_logged = False
 
        try:
            current_cidr = get_local_cidr()
            if not current_cidr:
                time.sleep(10)
                continue
                
            if current_cidr != _last_subnet:
                print(f"[PassiveScanDaemon] Cambio de red o nueva subred detectada: {current_cidr}. Limpiando caché anterior.")
                _last_subnet = current_cidr
                _passive_device_cache.clear()
                _last_discovery_time = 0.0
            
            ahora = time.time()
            necesita_descubrimiento = False
            
            if not _passive_device_cache:
                necesita_descubrimiento = True
            elif ahora - _last_discovery_time > 300: # 5 minutos
                necesita_descubrimiento = True
            else:
                unscanned_exists = any(not data.get("deep_scan_status") for data in _passive_device_cache.values())
                if not unscanned_exists:
                    necesita_descubrimiento = True
            
            if necesita_descubrimiento:
                print(f"[PassiveScanDaemon] Iniciando ciclo de escaneo pasivo en segundo plano en {current_cidr}...")
                _last_discovery_time = ahora
                prefix = current_cidr.split('/')[0].rsplit('.', 1)[0] + '.'
                
                try:
                    ScannerEngine()._run_nmap_xml([current_cidr], ['-sn', '-PE', '-T3'], timeout=30.0)
                except Exception:
                    pass

                found_ips = set()
                new_devices = {}
                try:
                    arp_output = subprocess.check_output('arp -a', shell=True, creationflags=CREATE_NO_WINDOW).decode('cp1252', errors='ignore')
                    for line in arp_output.split('\n'):
                        parts = line.split()
                        if len(parts) >= 2:
                            ip_arp = parts[0].strip()
                            mac_arp = parts[1].strip().replace('-', ':').upper()
                            if (ip_arp.startswith(prefix)
                                    and ip_arp not in found_ips
                                    and not ip_arp.endswith('.255')
                                    and mac_arp not in ('FF:FF:FF:FF:FF:FF', 'FF-FF-FF-FF-FF-FF')
                                    and len(mac_arp) == 17):
                                
                                cached_dev = _passive_device_cache.get(ip_arp)
                                hostname = cached_dev.get("hostname") if cached_dev else ""
                                vendor = cached_dev.get("vendor", "") if cached_dev else ""
                                
                                if not hostname or hostname == "Caché ARP Pasiva":
                                    try:
                                        hostname = socket.gethostbyaddr(ip_arp)[0]
                                    except Exception:
                                        hostname = "Caché ARP Pasiva"
                                        
                                new_devices[ip_arp] = {
                                    "ip": ip_arp,
                                    "mac": mac_arp,
                                    "hostname": hostname,
                                    "vendor": vendor,
                                    "discovery_method": "arp_cache_passive",
                                    "parent_ip": current_cidr.split('/')[0]
                                }
                                found_ips.add(ip_arp)
                except Exception as e:
                    print(f"[PassiveScanDaemon] Error leyendo tabla ARP: {e}")
 
                try:
                    local_ip = get_local_ip()
                    if local_ip not in found_ips and local_ip.startswith(prefix):
                        new_devices[local_ip] = {
                            "ip": local_ip,
                            "mac": get_local_mac(),
                            "hostname": socket.gethostname(),
                            "vendor": "",
                            "discovery_method": "local_passive",
                            "parent_ip": current_cidr.split('/')[0]
                        }
                except Exception:
                    pass
                    
                if new_devices:
                    for ip, data in new_devices.items():
                        if ip in _passive_device_cache:
                            old_data = _passive_device_cache[ip]
                            if old_data.get("deep_scan_status"):
                                data["deep_scan_status"] = old_data.get("deep_scan_status")
                                data["puertos_abiertos"] = old_data.get("puertos_abiertos", [])
                                data["total_vulnerabilidades"] = old_data.get("total_vulnerabilidades", 0)
                                data["fabricante"] = old_data.get("fabricante", data.get("vendor", ""))
                                if "mac" in old_data and old_data["mac"] != "Desconocida":
                                    data["mac"] = old_data["mac"]
                                if "hostname" in old_data and old_data["hostname"] != "Caché ARP Pasiva":
                                    data["hostname"] = old_data["hostname"]
                    for ip, d in new_devices.items():
                        if ip not in _passive_device_cache:
                            _passive_device_cache[ip] = d
                        else:
                            _passive_device_cache[ip].update(d)
                
                print(f"[PassiveScanDaemon] Ciclo de fondo finalizado. Dispositivos en caché: {len(_passive_device_cache)} | IPs: {list(_passive_device_cache.keys())}")

            # El demonio pasivo solo mantiene descubrimiento ligero en caché (NO consume cuota NVD ni bloquea red)
            # Sus datos solo se usan si se pide explícitamente modo pasivo; los escaneos activos siempre auditan en vivo.
        except Exception as e:
            print(f"[PassiveScanDaemon] Excepción en ciclo del worker: {e}")

        time.sleep(180)


class ScanService:
    def __init__(self):
        self.scanner = ScannerEngine()
        self.cve_client = CVEClient()
        self.db_service = DatabaseService()

    def set_log_cb(self, cb):
        from core.scanner import _thread_local
        _thread_local.log_cb = cb

    def _log(self, msg: str):
        try:
            print(msg)
        except Exception:
            try:
                print(msg.encode('ascii', errors='replace').decode('ascii'))
            except Exception:
                pass
        from core.scanner import _thread_local
        cb = getattr(_thread_local, 'log_cb', None)
        if cb:
            try:
                cb(msg)
            except Exception:
                pass

    def discover(self, target_ip: str, passive: bool = False, interface: str = 'all', cancel_event=None):
        ip_limpia = target_ip.replace('=', '').strip() if target_ip else ''
        is_specific_iface = bool(interface and interface not in ('all', 'auto', ''))

        if ip_limpia.lower() == "auto" or ip_limpia == "":
            iface_info = get_interface_network_info(interface if is_specific_iface else None)
            ip_real = iface_info["cidr"]
            if is_specific_iface:
                self._log(f"🌐 [Interfaz Seleccionada] Usando '{iface_info.get('interface') or interface}' -> subred real {ip_real} (IP local: {iface_info.get('ip')})")
        else:
            ip_real = ip_limpia

        if not getattr(self.scanner, 'nmap_installed', True):
            return {"error": "NMAP_MISSING", "target": ip_real}

        if passive:
            self._log(f"🤫 [SCAN PASIVO] Retornando estado en segundo plano instantáneo para {ip_real}...")
            topology = self.scanner.fallback_to_gateway("Escaneo Pasivo en segundo plano. Descubrimiento extraído de la memoria del daemon.")
            
            if ip_real == _last_subnet or ip_limpia.lower() == "auto" or ip_limpia == "":
                dispositivos = list(_passive_device_cache.values())
            else:
                prefix = ip_real.split('/')[0].rsplit('.', 1)[0] + '.'
                dispositivos = []
                found_ips = set()
                try:
                    arp_output = subprocess.check_output('arp -a', shell=True, creationflags=CREATE_NO_WINDOW).decode('cp1252', errors='ignore')
                    for line in arp_output.split('\n'):
                        parts = line.split()
                        if len(parts) >= 2:
                            ip_arp = parts[0].strip()
                            mac_arp = parts[1].strip().replace('-', ':').upper()
                            if (ip_arp.startswith(prefix)
                                    and ip_arp not in found_ips
                                    and not ip_arp.endswith('.255')
                                    and mac_arp not in ('FF:FF:FF:FF:FF:FF', 'FF-FF-FF-FF-FF-FF')
                                    and len(mac_arp) == 17):
                                hostname = ""
                                try:
                                    hostname = socket.gethostbyaddr(ip_arp)[0]
                                except Exception:
                                    hostname = "Caché ARP Pasiva"
                                dispositivos.append({
                                    "ip": ip_arp,
                                    "mac": mac_arp,
                                    "hostname": hostname,
                                    "vendor": "",
                                    "discovery_method": "arp_cache_passive",
                                    "parent_ip": ip_real.split('/')[0]
                                })
                                found_ips.add(ip_arp)
                except Exception as e:
                    self._log(f"  [Scan Pasivo Fallback Error] {e}")
            
            from core.device_classifier import classify_device
            for d in dispositivos:
                if not d.get("fabricante") or d.get("fabricante") == "Desconocido":
                    d["fabricante"] = d.get("vendor") or "Desconocido"
                if not d.get("icono") or d.get("icono") in ("help-circle", "help", "", "Desconocido"):
                    _cl = classify_device(d.get("ip") or "", d.get("mac") or "", d.get("fabricante") or "", d.get("hostname") or "", [])
                    d["icono"] = _cl["icono"]
                    d["dispositivo_tipo"] = _cl["tipo"]
                    d["categoria_nombre"] = _cl["categoria"]
                if not d.get("medio_conexion"):
                    _cl = classify_device(d.get("ip") or "", d.get("mac") or "", d.get("fabricante") or "", d.get("hostname") or "", [])
                    d["medio_conexion"] = _cl.get("medio_conexion", "ethernet")
                    d["medio_label"] = _cl.get("medio_label", "Ethernet")
                    d["medio_icono"] = _cl.get("medio_icono", "🔌")
                    d["medio_detalle"] = _cl.get("medio_detalle", "")

            topology["advertencias"].append("Auditoría Pasiva en Segundo Plano: Este mapa se generó a partir de la caché en memoria recopilada silenciosamente por el daemon de fondo.")
            topology["devices"] = dispositivos
            net_name = get_active_network_name(fallback_target=ip_real)
            return {"status": "ok", "dispositivos": dispositivos, "target": ip_real, "network_name": net_name, "topology": topology, "passive": True}

        global _active_scan_count, _active_scan_count_lock, _last_active_time

        active_ips = None
        if (ip_real == _last_subnet or ip_limpia.lower() == "auto" or ip_limpia == "") and _passive_device_cache:
            active_ips = list(_passive_device_cache.keys())
            self._log(f"⚡ [DAEMON] Caché pasiva lista con {len(active_ips)} IPs — pausando daemon durante el escaneo activo.")

        with _active_scan_count_lock:
            _active_scan_count += 1
            _last_active_time = time.time()
        bound_bridge_ip = None
        try:
            if sys.platform == 'win32' and not passive:
                try:
                    from core.subnet_bridge import is_target_in_local_subnets, bind_subnet_bridge
                    is_present, existing_iface, existing_ip = is_target_in_local_subnets(ip_real, preferred_iface=interface)
                    if not is_present:
                        self._log(f"🔌 [Subnet Bridge] Subred remota/aislada detectada ({ip_real}). Vinculando automáticamente...")
                        bridge_res = bind_subnet_bridge(ip_real, preferred_interface=interface)
                        if bridge_res.get("status") == "ok":
                            bound_bridge_ip = bridge_res.get('bound_ip')
                            self._log(f"✅ [Subnet Bridge] Enlace temporal creado con IP {bound_bridge_ip} en '{bridge_res.get('interface')}'.")
                        elif bridge_res.get("status") == "already_local":
                            self._log(f"ℹ️ [Subnet Bridge] {bridge_res.get('message')}")
                        else:
                            self._log(f"⚠️ [Subnet Bridge] No se pudo enlazar {ip_real}: {bridge_res.get('message', 'Error desconocido')}")
                    else:
                        self._log(f"ℹ️ [Subnet Bridge] Subred {ip_real} ya presente en la tarjeta '{existing_iface}' (IP: {existing_ip}). Escaneando directamente sin duplicar...")
                except Exception as e:
                    self._log(f"⚠️ [Subnet Bridge] Advertencia al vincular subred: {e}")

            is_specific_target = bool(ip_limpia and ip_limpia.lower() != "auto")
            default_cidr = get_local_cidr(None)
            is_non_default_iface = is_specific_iface and (ip_real != default_cidr)
            if is_specific_target or is_non_default_iface:
                if is_specific_target:
                    self._log(f"🎯 [Escaneo Específico] Destino fijado en {ip_real}. Omitiendo traceroute a Internet...")
                else:
                    self._log(f"🎯 [Interfaz Secundaria] Escaneando {ip_real} vía '{interface}'. Omitiendo traceroute por ruta por defecto...")
                topology = {
                    "hops_privados": [{
                        "ip": ip_real.split('/')[0] if '/' in ip_real else ip_real,
                        "tipo": "router_principal",
                        "hostname": f"Red {interface} ({ip_real})" if is_non_default_iface else f"Subred {ip_real}",
                        "mac": "Desconocida",
                        "ssid": ""
                    }],
                    "router_isp": None,
                    "advertencias": []
                }
                advertencias = []
                router_principal_ip = topology["hops_privados"][0]["ip"]
            else:
                topology = self.scanner.fase1_traceroute()
                advertencias = topology.get("advertencias", [])
                router_principal_ip = None
                for hop in topology.get("hops_privados", []):
                    if hop.get("tipo") == "router_principal" and hop.get("ip") != "unknown":
                        router_principal_ip = hop["ip"]
                        break

            dispositivos = self.scanner.discover_network(
                ip_real,
                router_principal_ip=router_principal_ip,
                advertencias=advertencias,
                active_ips=active_ips,
                interface=interface,
                cancel_event=cancel_event
            )

            # Sincronizar la memoria del daemon:
            active_found_set = {d.get("ip") for d in dispositivos if d.get("ip")}
            # 1. Descartar de la memoria del daemon solo dispositivos verificados offline
            for stale_ip in list(_passive_device_cache.keys()):
                if stale_ip not in active_found_set:
                    _passive_device_cache.pop(stale_ip, None)
            # 2. Almacenar/actualizar dispositivos activos descubiertos en la memoria persistente
            for d in dispositivos:
                ip_d = d.get("ip")
                if ip_d:
                    if ip_d not in _passive_device_cache:
                        _passive_device_cache[ip_d] = dict(d)
                    else:
                        for k, v in d.items():
                            if v and (not _passive_device_cache[ip_d].get(k) or _passive_device_cache[ip_d].get(k) in ("Desconocida", "Caché ARP Pasiva", "Dispositivo de Red", "")):
                                _passive_device_cache[ip_d][k] = v

            from core.device_classifier import classify_device
            for d in dispositivos:
                if not d.get("fabricante") or d.get("fabricante") == "Desconocido":
                    d["fabricante"] = d.get("vendor") or "Desconocido"
                if not d.get("icono") or d.get("icono") in ("help-circle", "help", "", "Desconocido"):
                    _cl = classify_device(d.get("ip") or "", d.get("mac") or "", d.get("fabricante") or "", d.get("hostname") or "", [])
                    d["icono"] = _cl["icono"]
                    d["dispositivo_tipo"] = _cl["tipo"]
                    d["categoria_nombre"] = _cl["categoria"]
                if not d.get("medio_conexion"):
                    _cl = classify_device(d.get("ip") or "", d.get("mac") or "", d.get("fabricante") or "", d.get("hostname") or "", [])
                    d["medio_conexion"] = _cl.get("medio_conexion", "ethernet")
                    d["medio_label"] = _cl.get("medio_label", "Ethernet")
                    d["medio_icono"] = _cl.get("medio_icono", "🔌")
                    d["medio_detalle"] = _cl.get("medio_detalle", "")

            topology["advertencias"] = advertencias
            topology["devices"] = dispositivos
            net_name = get_active_network_name(fallback_target=ip_real)

            return {"status": "ok", "dispositivos": dispositivos, "target": ip_real, "network_name": net_name, "topology": topology}
        finally:
            with _active_scan_count_lock:
                _active_scan_count -= 1
                _last_active_time = time.time()
                restantes = _active_scan_count
            if restantes == 0:
                print("[PassiveScanDaemon] Fase discover finalizada. Reanudando ciclos de fondo si no hay deep-scans pendientes.")




    def deep_scan(self, ip: str, user_id: str = "", scan_id: str = "", known_device: dict = None, interface: str = 'all', force_refresh: bool = True, cancel_event=None, pre_sweep_host: dict = None, skip_rdns: bool = False):
        global _active_scan_count, _active_scan_count_lock, _last_active_time
        global _deep_scan_active_count, _deep_scan_start_time, _deep_scan_lock
        
        if cancel_event is not None and cancel_event.is_set():
            return None

        with _active_scan_count_lock:
            _active_scan_count += 1
            _last_active_time = time.time()
            
        with _deep_scan_lock:
            _deep_scan_active_count += 1
            if _deep_scan_active_count == 1:
                _deep_scan_start_time = time.perf_counter()
        try:
            self._log(f"====== INICIANDO ESCANEO PARA: {ip} (user: {user_id}, scan: {scan_id}) ======")
            
            # Escaneos activos SIEMPRE auditan puertos/CVEs frescos en vivo (nunca sirven caché obsoleta)
            cached_data = None if force_refresh else _passive_device_cache.get(ip)
            es_recuperado_cache = False
            puertos_bloqueados = []
            nmap_rtt_ms = None
            
            if cached_data and cached_data.get("deep_scan_status") == "completed":
                self._log(f"[DEEP-SCAN] ✅ {ip} recuperado de caché pasiva instantáneamente.")
                puertos = cached_data.get("puertos_abiertos", [])
                puertos_bloqueados = cached_data.get("puertos_bloqueados", [])
                total_vulnerabilidades = cached_data.get("total_vulnerabilidades", 0)
                mac_real = cached_data.get("mac", "Desconocida")
                fabricante_info = cached_data.get("fabricante", "Desconocido")
                hostname_info = cached_data.get("hostname", "")
                es_recuperado_cache = True
            
            if not es_recuperado_cache:
                puertos_info = self.scanner.scan_ports(
                    ip,
                    interface=interface,
                    cancel_event=cancel_event,
                    pre_sweep_host=pre_sweep_host,
                    skip_rdns=skip_rdns,
                )
                if puertos_info.get("cancelled") or (cancel_event is not None and cancel_event.is_set()):
                    return None
                puertos = puertos_info.get("puertos_abiertos", [])
                puertos_bloqueados = puertos_info.get("puertos_bloqueados", [])
                nmap_rtt_ms = puertos_info.get("nmap_rtt_ms")
                
                total_vulnerabilidades = 0
                for puerto in puertos:
                    if cancel_event is not None and cancel_event.is_set():
                        return None
                    servicio = puerto.get("servicio", "")
                    producto = puerto.get("producto", "")
                    version = puerto.get("version", "")
                    cpes = puerto.get("cpe", [])
                    
                    cves = self.cve_client.buscar_vulnerabilidades(
                        nombre_servicio=servicio,
                        version=version,
                        producto=producto,
                        cpes=cpes,
                    )
                    puerto["vulnerabilidades"] = cves
                    total_vulnerabilidades += len(cves)
                
                mac_real = puertos_info.get("mac", "Desconocida")
                fabricante_info = puertos_info.get("fabricante", "Desconocido")
                hostname_info = puertos_info.get("hostname", "")

                if known_device:
                    if mac_real in ("Desconocida", "", None) and known_device.get("mac"):
                        mac_real = known_device["mac"]
                    if fabricante_info in ("Desconocido", "", None) and (known_device.get("fabricante") or known_device.get("vendor")):
                        fabricante_info = known_device.get("fabricante") or known_device.get("vendor")
                    if not hostname_info and known_device.get("hostname") and known_device["hostname"] not in ("Dispositivo de Red", "Caché ARP Pasiva", "unknown"):
                        hostname_info = known_device["hostname"]

            if cancel_event is not None and cancel_event.is_set():
                return None

            id_unico = mac_real if mac_real != "Desconocida" else ip
            
            doc_snap = self.db_service.get_historial_doc(id_unico, user_id)
            hora_actual = datetime.datetime.utcnow().isoformat()
            es_nuevo = False
            primera_conexion = hora_actual
            
            if not doc_snap.exists:
                es_nuevo = True
                self.db_service.save_historial_doc(id_unico, {
                    "ip_inicial": ip,
                    "mac": mac_real,
                    "primera_conexion": hora_actual,
                    "fabricante": fabricante_info
                }, user_id)
            else:
                datos_historial = doc_snap.to_dict()
                primera_conexion = datos_historial.get("primera_conexion", hora_actual)
                
            max_score = 0
            for puerto in puertos:
                for v in puerto.get("vulnerabilidades", []):
                    v_score = v.get("score", 0)
                    if v_score > max_score:
                        max_score = v_score
 
            from core.telemetry import measure_device_telemetry

            local_ips_all = get_all_local_ips()
            es_scanner = bool(ip and (ip in local_ips_all or ip in ("127.0.0.1", "localhost")))
            if es_scanner:
                telemetria = {
                    "ip": ip,
                    "packets_sent": 4,
                    "packets_recv": 4,
                    "packet_loss": 0,
                    "latency_ms": 0.0,
                    "latency_min": 0.0,
                    "latency_max": 0.0,
                    "status": "excellent",
                    "status_label": "0.0 ms",
                    "ttl": 128,
                    "method": "local",
                    "icmp_blocked": False,
                }
            else:
                telemetria = measure_device_telemetry(
                    ip,
                    count=3,
                    timeout_ms=300,
                    open_ports=puertos,
                    nmap_rtt_ms=nmap_rtt_ms,
                )

            from core.device_classifier import classify_device
            clasif = classify_device(
                ip=ip,
                mac=mac_real,
                fabricante=fabricante_info,
                hostname=hostname_info,
                puertos_abiertos=puertos,
                ttl=telemetria.get("ttl"),
                telemetria=telemetria
            )

            if clasif.get("es_host_local") or clasif.get("es_scanner"):
                es_scanner = True

            documento = {
                "ip": ip,
                "mac": mac_real,
                "hostname": hostname_info,
                "fabricante": fabricante_info,
                "dispositivo_tipo": clasif["tipo"],
                "icono": clasif["icono"],
                "categoria_nombre": clasif["categoria"],
                "confianza_clasificacion": clasif["confianza"],
                "medio_conexion": clasif.get("medio_conexion", "ethernet"),
                "medio_label": clasif.get("medio_label", "Ethernet"),
                "medio_icono": clasif.get("medio_icono", "🔌"),
                "medio_detalle": clasif.get("medio_detalle", ""),
                "es_host_local": es_scanner,
                "es_scanner": es_scanner,
                "telemetria": telemetria,
                "puertos_abiertos": puertos,
                "puertos_bloqueados": puertos_bloqueados,
                "total_vulnerabilidades": total_vulnerabilidades,
                "max_score": max_score,
                "fecha_auditoria": hora_actual,
                "estado": "Completado",
                "es_nuevo": es_nuevo,
                "primera_conexion": primera_conexion,
                "scan_id": scan_id
            }

            # Actualizar caché pasiva con el último snapshot fresco
            _passive_device_cache[ip] = {
                "ip": ip,
                "mac": mac_real,
                "hostname": hostname_info,
                "fabricante": fabricante_info,
                "puertos_abiertos": puertos,
                "puertos_bloqueados": puertos_bloqueados,
                "total_vulnerabilidades": total_vulnerabilidades,
                "deep_scan_status": "completed",
                "updated_at": time.time(),
            }
            
            self.db_service.save_device(ip, documento, user_id)
            
            if scan_id:
                self.db_service.save_scan_device(user_id, scan_id, ip, documento)
            
            if total_vulnerabilidades > 0:
                for puerto in puertos:
                    for cve in puerto.get("vulnerabilidades", []):
                        self.db_service.save_vulnerability(cve["cve_id"], {
                            **cve,
                            "ip": ip,
                            "puerto": puerto.get("puerto"),
                            "servicio": puerto.get("servicio"),
                            "version": puerto.get("version"),
                            "fecha_deteccion": datetime.datetime.utcnow().isoformat()
                        }, user_id)
            
            return documento

        finally:
            with _active_scan_count_lock:
                _active_scan_count -= 1
                _last_active_time = time.time()
                restantes = _active_scan_count
                
            with _deep_scan_lock:
                _deep_scan_active_count -= 1
                es_ultimo_deep = (_deep_scan_active_count == 0)
                deep_start = _deep_scan_start_time
                
            if es_ultimo_deep:
                elapsed_deep = time.perf_counter() - deep_start
                self._log(f"[DEEP-SCAN TOTAL] ✅ Todos los dispositivos escaneados en {elapsed_deep:.2f}s")
                if scan_id and user_id:
                    self.db_service.update_scan_metadata(user_id, scan_id, {
                        "end_time": datetime.datetime.utcnow().isoformat(),
                        "status": "completed"
                    })
                
            if restantes == 0:
                print("[PassiveScanDaemon] Todos los deep-scans finalizados. Reanudando ciclos de fondo.")
