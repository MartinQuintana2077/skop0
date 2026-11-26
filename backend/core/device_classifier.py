"""
Módulo de Clasificación Inteligente de Dispositivos e Iconos (Device Fingerprinting Engine v2).
Determina con alta precisión y SIN conflictos de prioridad el tipo de equipo, icono, categoría
y medio físico de conexión basándose en:
- Perfiles de puertos y servicios curados (78 puertos TCP + producto/servicio Nmap)
- Marcas OUI y Fabricantes IEEE + nombres reales mDNS / SSDP-UPnP / NetBIOS
- Análisis matemático de MACs aleatorias/privadas (LAA - Locally Administered Address)
- Huella del Kernel TCP/IP mediante TTL y telemetría real (ICMP / TCP / ARP)
"""
import re


def is_locally_administered_mac(mac: str) -> bool:
    """
    Determina matemáticamente si una MAC es administrada localmente (LAA) / MAC aleatoria/privada,
    conforme al estándar IEEE 802 (bit 1 del primer octeto activo -> 2, 6, A o E).
    """
    if not mac or not isinstance(mac, str):
        return False
    mac_lower = mac.lower().strip()
    if any(p in mac_lower for p in ["desconocid", "detectand", "sondeand", "unknown", "none", "null"]):
        return False
    clean = re.sub(r'[^0-9A-Fa-f]', '', mac)
    if len(clean) != 12:
        return False
    try:
        first_byte = int(clean[:2], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False


def _raw_classify_device(
    ip: str,
    mac: str = "",
    fabricante: str = "",
    hostname: str = "",
    puertos_abiertos: list = None,
    ttl: int = None
) -> dict:
    if puertos_abiertos is None:
        puertos_abiertos = []

    puertos_set = set()
    servicios_str = ""

    for p in puertos_abiertos:
        if isinstance(p, dict):
            num = p.get("puerto") or p.get("port")
            if num:
                try:
                    puertos_set.add(int(num))
                except (ValueError, TypeError):
                    pass
            serv = (p.get("servicio") or "").lower()
            prod = (p.get("producto") or "").lower()
            servicios_str += f" {serv} {prod}"
        elif isinstance(p, (int, str)) and str(p).isdigit():
            puertos_set.add(int(p))

    fab_lower = (fabricante or "").lower()
    host_lower = (hostname or "").lower()
    is_random_mac = is_locally_administered_mac(mac)

    # 0. HOST LOCAL (La computadora propia que ejecuta SecScan, en cualquiera de sus interfaces)
    try:
        try:
            from core.scanner import get_all_local_ips
        except ImportError:
            from backend.core.scanner import get_all_local_ips
        local_ips = get_all_local_ips()
        if ip and (ip in local_ips or ip in ("127.0.0.1", "localhost")):
            return {
                "tipo": "pc",
                "icono": "💻",
                "categoria": "Estación de Trabajo (Host Local)",
                "confianza": "Máxima (Host de Escaneo)",
                "es_host_local": True,
                "es_scanner": True
            }
    except Exception:
        pass

    # Conjuntos auxiliares sin ambigüedad
    windows_ports = {135, 139, 445, 3389, 5985, 5986, 5357}
    server_strong_ports = {22, 5000, 5001, 3306, 5432, 1433, 1521, 27017, 6379, 111, 2049, 389, 636, 88, 21, 25}
    printer_ports = {9100, 515, 631}
    is_printer_port = bool(printer_ports.intersection(puertos_set))

    pure_net_brands = [
        "cisco", "mikrotik", "ubiquiti", "tp-link", "netgear", "d-link", "aruba",
        "fortinet", "tenda", "mercusys", "juniper", "palo alto", "pfsense", "sophos", "zyxel",
        "linksys", "arris", "technicolor", "sagemcom", "fiberhome", "zte corp"
    ]
    all_net_brands = pure_net_brands + ["huawei"]
    is_pure_net_brand = any(k in fab_lower for k in pure_net_brands)
    is_any_net_brand = any(k in fab_lower for k in all_net_brands)
    is_net_host = any(k in host_lower for k in ["router", "gateway", "repeater", "extender", "wlan", "switch", "sw-", "firewall", "fw-", "mikrotik", "unifi"])
    is_gateway_ip = bool(ip and (ip.endswith(".1") or ip.endswith(".254")))
    is_nintendo = "nintendo" in fab_lower or "nintendo" in host_lower or host_lower == "switch"

    # 1. ROUTER / GATEWAY PRINCIPAL (.1 o .254 con evidencia de gateway/infraestructura)
    if is_gateway_ip and (53 in puertos_set or 80 in puertos_set or 443 in puertos_set or is_any_net_brand or is_net_host):
        return {
            "tipo": "router",
            "icono": "📡",
            "categoria": "Router / Gateway Principal",
            "confianza": "Máxima (Default Gateway / Infraestructura)"
        }

    # 2. SWITCH GESTIONABLE / MANAGED SWITCH (excluyendo Nintendo Switch)
    switch_keywords = ["sw-", "sw_", "edgeswitch", "catalyst", "procurve", "tl-sg", "unifi-sw", "unifiswitch", "dgs-", "gs10", "gs11", "smart-switch", "managed-switch", "switch-"]
    is_switch_by_host = (any(k in host_lower for k in switch_keywords) or ("switch" in host_lower and any(w in host_lower for w in ["managed", "smart", "cisco", "net", "l2", "l3"]))) and not is_nintendo
    is_switch_by_fab = any(k in fab_lower for k in ["cisco", "hp procurve", "aruba", "juniper", "allied telesis", "extreme networks", "hirschmann"])
    if is_switch_by_host or (is_switch_by_fab and not is_gateway_ip and not is_nintendo):
        return {
            "tipo": "switch",
            "icono": "🔀",
            "categoria": "Switch de Red Gestionable",
            "confianza": "Alta (Switch de Infraestructura / Gestión L2-L3)",
            "es_switch": True
        }

    # 3. IMPRESORAS DE RED (evaluado ANTES que PC para que impresoras HP no caigan en PC)
    printer_brands = ["epson", "brother", "lexmark", "canon", "kyocera", "ricoh", "xerox", "konica", "zebra"]
    printer_hosts = ["print", "epson", "hp-print", "brother", "printer", "laserjet", "deskjet", "officejet", "ecotank"]
    if (
        is_printer_port
        or "printer" in servicios_str
        or "ipp" in servicios_str
        or "jetdirect" in servicios_str
        or any(k in fab_lower for k in printer_brands)
        or any(k in host_lower for k in printer_hosts)
    ):
        return {
            "tipo": "printer",
            "icono": "🖨️",
            "categoria": "Impresora de Red",
            "confianza": "Alta (Puerto de Impresión / Marca)"
        }

    # 4. SMART TV / PANTALLAS / STREAMING (evaluado ANTES que Cámaras -> resuelve conflicto Samsung 8001)
    tv_exclusive_ports = {8008, 8009, 8060, 7000, 7676, 7678, 9197}
    tv_brands = ["roku", "tcl", "hisense", "lg electronics", "vizio", "wuhan", "novastar", "colorlight", "linsn", "huidu", "skyworth", "sharp", "panasonic", "sony"]
    tv_hosts = ["tv", "chromecast", "firetv", "firestick", "bravia", "shield", "appletv", "roku", "tizen", "smarttv", "webos", "living room", "sala"]
    is_samsung_tv = "samsung" in fab_lower and (
        bool(puertos_set.intersection({8001, 8002, 7676, 7678, 9197, 8080, 1900}))
        or any(k in host_lower for k in ["tv", "tizen", "smart", "screen", "qled", "crystal"])
    )
    is_sony_non_console = "sony" in fab_lower and not any(k in host_lower for k in ["ps4", "ps5", "playstation"]) and not bool({3478, 3479, 3480}.intersection(puertos_set))

    if (
        tv_exclusive_ports.intersection(puertos_set)
        or is_samsung_tv
        or any(k in fab_lower for k in tv_brands if k != "sony")
        or (is_sony_non_console and (bool({8008, 8009, 1900, 80, 443}.intersection(puertos_set)) or "bravia" in host_lower or "tv" in host_lower))
        or any(k in host_lower for k in tv_hosts)
    ):
        conf = "Alta (Samsung Smart TV / Tizen OS)" if is_samsung_tv else "Alta (Puerto Cast / Marca Display)"
        return {
            "tipo": "tv",
            "icono": "📺",
            "categoria": "Smart TV (Samsung)" if is_samsung_tv else "Smart TV / Pantalla / Display",
            "confianza": conf
        }

    # 5. CÁMARAS IP / DVR / NVR (sin falsos positivos en puertos web genéricos 8000/8001)
    camera_strict_ports = {554, 8554, 8899, 8999, 37777, 37778, 34567, 10554}
    camera_brands = [
        "hikvision", "dahua", "axis", "reolink", "amcrest", "foscam", "uniview", "vivotek",
        "ezviz", "imou", "tiandy", "hanwha", "lorex", "swann", "arlo", "wyze", "xiongmai",
        "netatmo", "tapo", "tp-link tapo", "bosch security", "flir", "pelco", "vstarcam",
        "yi technology", "eufy", "ring", "blink", "mobotix", "anran", "zosi", "wansview"
    ]
    camera_hosts = ["cam", "nvr", "dvr", "ipcam", "tapo", "cctv", "camera", "hik", "dahua", "xm_", "ipc", "vision"]
    camera_services = ["rtsp", "onvif", "hikvision", "dahua", "dvr", "camera", "ipcam"]

    is_camera_strict_port = bool(camera_strict_ports.intersection(puertos_set))
    is_camera_by_brand = any(k in fab_lower for k in camera_brands)
    is_camera_by_host = any(k in host_lower for k in camera_hosts)
    is_camera_by_service = any(k in servicios_str for k in camera_services)
    is_hikvision_port = bool({8000, 8001, 8200}.intersection(puertos_set)) and (is_camera_by_brand or is_camera_by_host or is_camera_by_service or 554 in puertos_set)

    if is_camera_strict_port or is_hikvision_port or is_camera_by_brand or is_camera_by_host or is_camera_by_service:
        conf = "Alta (RTSP / ONVIF / Puerto CCTV)" if (is_camera_strict_port or is_hikvision_port) else "Alta (Marca / Servicio de Video)"
        return {
            "tipo": "camera",
            "icono": "📷",
            "categoria": "Cámara IP / NVR de Seguridad",
            "confianza": conf
        }

    # 6. CONSOLAS DE VIDEOJUEGOS (Xbox 3074, PSN 3478-3480, Nintendo)
    if (
        {3074, 3478, 3479, 3480}.intersection(puertos_set)
        or any(k in fab_lower for k in ["nintendo", "playstation"])
        or any(k in host_lower for k in ["xbox", "playstation", "ps4", "ps5", "nintendo", "switch"])
    ):
        return {
            "tipo": "game_console",
            "icono": "🎮",
            "categoria": "Consola de Videojuegos",
            "confianza": "Alta (Puertos Gaming / Fabricante)"
        }

    # 7. TELEFONÍA IP / VOIP (SIP 5060/5061, marcas VoIP)
    voip_ports = {5060, 5061}
    voip_brands = ["yealink", "grandstream", "polycom", "poly", "avaya", "fanvil", "snom", "cisco voip"]
    voip_hosts = ["sip", "voip", "phone-ip", "yealink", "ipphone"]
    if voip_ports.intersection(puertos_set) or any(k in fab_lower for k in voip_brands) or any(k in host_lower for k in voip_hosts):
        return {
            "tipo": "phone",
            "icono": "📞",
            "categoria": "Teléfono IP / VoIP",
            "confianza": "Alta (Protocolo SIP / Marca VoIP)"
        }

    # 8. DISPOSITIVOS IOT / DOMÓTICA (evaluado ANTES que Servidores web 80/443)
    iot_brands = ["tuya", "sonoff", "shelly", "espressif", "esp8266", "esp32", "philips hue", "signify", "lifx", "broadlink", "aqara", "meross", "wemo"]
    iot_hosts = ["iot", "smart-plug", "bulb", "sensor", "sonoff", "shelly", "esp32", "esp8266", "tasmota"]
    if {1883, 5683, 8883}.intersection(puertos_set) or any(k in fab_lower for k in iot_brands) or any(k in host_lower for k in iot_hosts):
        return {
            "tipo": "iot",
            "icono": "💡",
            "categoria": "Dispositivo IoT / Domótica",
            "confianza": "Alta (Protocolos IoT / Chipset Embebido)"
        }

    # 9. SMARTPHONES / TABLETS / DISPOSITIVOS MÓVILES (evaluado ANTES que Extensores y Servidores web)
    is_ios_lockdown = 62078 in puertos_set
    is_apple_pc = "apple" in fab_lower and (
        any(k in host_lower for k in ["macbook", "imac", "mac-", "macmini", "macpro"])
        or bool({548, 22, 5900, 445}.intersection(puertos_set))
    )
    strict_mobile_brands = ["xiaomi", "redmi", "poco", "motorola", "oppo", "vivo", "oneplus", "realme", "honor", "nokia", "meizu", "tecno", "infinix", "alcatel", "wingtech", "tinno"]
    mobile_hosts = ["iphone", "ipad", "android", "galaxy", "redmi", "pixel", "phone", "mobile", "celular", "movil", "honor", "xiaomi", "oneplus"]
    is_huawei_mobile = "huawei" in fab_lower and not is_gateway_ip and not is_net_host and not bool({53, 67, 161}.intersection(puertos_set))
    is_samsung_mobile = "samsung" in fab_lower and not is_samsung_tv and not bool(windows_ports.intersection(puertos_set))
    is_apple_mobile = ("apple" in fab_lower and not is_apple_pc) or is_ios_lockdown

    if (
        is_ios_lockdown
        or any(k in host_lower for k in mobile_hosts)
        or any(k in fab_lower for k in strict_mobile_brands)
        or is_huawei_mobile
        or is_samsung_mobile
        or is_apple_mobile
    ):
        conf = "Máxima (Apple iOS Lockdown 62078)" if is_ios_lockdown else "Alta (Marca / Hostname Móvil)"
        return {
            "tipo": "phone",
            "icono": "📱",
            "categoria": "Teléfono Móvil / Tablet",
            "confianza": conf
        }

    # 9.B MAC Aleatoria / Privada (LAA) sin puertos de PC/servidor fuerte
    if is_random_mac and not bool(windows_ports.intersection(puertos_set)) and not bool(server_strong_ports.intersection(puertos_set)):
        return {
            "tipo": "phone",
            "icono": "📱",
            "categoria": "Smartphone / Móvil (MAC Privada)",
            "confianza": "Alta (Dirección MAC Aleatoria / Móvil)",
            "es_mac_aleatoria": True
        }

    # 10. EXTENSOR WI-FI / REPETIDOR / ACCESS POINT (solo marcas de red puras o hostname explícito)
    extender_keywords = ["extender", "repeater", "re2", "re3", "re4", "re5", "re6", "wa8", "wa9", "accesspoint", "mesh", "wlan-ap", "unifi-ap", "eap"]
    is_extender_host = any(k in host_lower for k in extender_keywords)
    if is_extender_host or (is_pure_net_brand and not is_gateway_ip and not is_nintendo and bool({80, 443, 8080}.intersection(puertos_set)) and not bool({53, 67}.intersection(puertos_set))):
        return {
            "tipo": "extender",
            "icono": "📡",
            "categoria": "Extensor / Punto de Acceso Wi-Fi",
            "confianza": "Alta (Web de Configuración / AP)"
        }

    # 11. ESTACIONES DE TRABAJO / PC / LAPTOP CONFIRMADAS
    pc_brands = ["dell", "lenovo", "asus", "acer", "msi", "micro-star", "gigabyte", "microsoft", "toshiba", "fujitsu", "intel", "hewlett-packard", "hp", "asrock", "razer"]
    pc_hostnames = ["pc", "desktop", "laptop", "macbook", "imac", "win", "workstation", "ws-", "desk", "nb-"]
    is_nas_brand = any(k in fab_lower for k in ["synology", "qnap", "western digital", "asustor", "terramaster"])
    if not is_nas_brand:
        if (
            bool(windows_ports.intersection(puertos_set))
            or is_apple_pc
            or any(k in fab_lower for k in pc_brands)
            or any(k in host_lower for k in pc_hostnames)
        ):
            return {
                "tipo": "pc",
                "icono": "💻",
                "categoria": "Estación de Trabajo / Laptop",
                "confianza": "Alta (Puertos Windows / Marca PC)"
            }

    # 12. ROUTER / INFRAESTRUCTURA RESTANTE (DNS+DHCP o SNMP en IP no .1)
    if (53 in puertos_set and (67 in puertos_set or 68 in puertos_set or 80 in puertos_set or 443 in puertos_set)) or (161 in puertos_set and is_any_net_brand):
        return {
            "tipo": "router",
            "icono": "📡",
            "categoria": "Router / Switch / Punto de Acceso",
            "confianza": "Alta (Servicios Infraestructura / Marca Red)"
        }

    # 13. SERVIDORES / NAS / CONTROLADORES (puertos fuertes de servidor o marca/hostname NAS/Server)
    server_brands = ["synology", "qnap", "vmware", "proxmox", "supermicro", "dell emc", "hpe", "red hat", "canonical", "asustor", "terramaster"]
    server_hosts = ["server", "srv", "nas", "proxmox", "esxi", "docker", "ubiquiti-controller", "dc-", "ad-", "sql", "db-", "mail", "cloud"]
    if (
        server_strong_ports.intersection(puertos_set)
        or any(k in fab_lower for k in server_brands)
        or any(k in host_lower for k in server_hosts)
        or bool({80, 443, 8000, 8080, 8443}.intersection(puertos_set))
    ):
        return {
            "tipo": "server",
            "icono": "🗄️",
            "categoria": "Servidor / Servidor NAS / DB",
            "confianza": "Alta (Servicios Servidor / SSH / Web / DB)"
        }

    # 14. ANÁLISIS DE TTL (Time-To-Live ICMP)
    if ttl is not None and ttl > 0:
        if 64 < ttl <= 128:
            return {
                "tipo": "pc",
                "icono": "💻",
                "categoria": "Estación de Trabajo (Windows / TTL 128)",
                "confianza": "Media (Kernel Windows TTL=128)"
            }
        elif ttl <= 64:
            if is_random_mac:
                return {
                    "tipo": "phone",
                    "icono": "📱",
                    "categoria": "Smartphone / Móvil (MAC Privada)",
                    "confianza": "Media (MAC Aleatoria / TTL<=64)",
                    "es_mac_aleatoria": True
                }
            return {
                "tipo": "network",
                "icono": "🌐",
                "categoria": "Dispositivo Linux / Sistema Embebido",
                "confianza": "Media (Kernel Linux TTL<=64)"
            }

    # 15. FALLBACK INTELIGENTE
    if len(puertos_set) > 0:
        return {
            "tipo": "network",
            "icono": "🌐",
            "categoria": "Dispositivo Conectado",
            "confianza": "Básica (Puertos Activos)"
        }

    return {
        "tipo": "network",
        "icono": "🌐",
        "categoria": "Periférico / Dispositivo de Red",
        "confianza": "Estimada (Sin puertos expuestos)"
    }


def get_local_active_medium() -> tuple:
    """Detecta si la máquina local (el escáner) está conectada por Wi-Fi o Ethernet."""
    for mod_path in ("core.subnet_bridge", "backend.core.subnet_bridge"):
        try:
            mod = __import__(mod_path, fromlist=["get_active_interface_name"])
            iface = mod.get_active_interface_name().lower()
            if any(w in iface for w in ["wi-fi", "wlan", "wireless", "inalámbrico", "inalambrico"]):
                return "wifi", "Wi-Fi", "📶", f"Adaptador Local ({iface.title()})"
            if any(w in iface for w in ["ethernet", "eth", "lan", "cable"]):
                return "ethernet", "Ethernet", "🔌", f"Adaptador Local ({iface.title()})"
        except Exception:
            continue
    return "ethernet", "Ethernet", "🔌", "Adaptador Local de Red"


def detect_connection_medium(
    ip: str = "",
    mac: str = "",
    fabricante: str = "",
    hostname: str = "",
    puertos_abiertos: list = None,
    telemetria: dict = None,
    dispositivo_tipo: str = "",
    es_scanner: bool = False,
    es_gateway: bool = False
) -> dict:
    """
    Determina si un dispositivo está conectado por Wi-Fi o Ethernet combinando señales deterministas
    (adaptador local, MAC aleatoria, chipsets Wi-Fi, infraestructura PoE) con telemetría real
    de latencia/jitter para dispositivos híbridos (impresoras, TVs, PCs).
    """
    if es_scanner:
        medio, label, icono, detalle = get_local_active_medium()
        return {"medio": medio, "label": label, "icono": icono, "detalle": detalle}

    if es_gateway:
        return {"medio": "ethernet", "label": "Ethernet / AP", "icono": "📡", "detalle": "Router Gateway (Enlace Central)"}

    f = (fabricante or "").lower()
    h = (hostname or "").lower()
    tipo = (dispositivo_tipo or "").lower()

    ports = set()
    if puertos_abiertos:
        for p in puertos_abiertos:
            if isinstance(p, dict):
                num = p.get("puerto") or p.get("port")
                if num:
                    try:
                        ports.add(int(num))
                    except (ValueError, TypeError):
                        pass
            elif isinstance(p, (int, str)) and str(p).isdigit():
                ports.add(int(p))

    # 1. Señales 100% Wi-Fi (MAC Aleatoria LAA, chipsets IoT Wi-Fi, streaming, móviles)
    if is_locally_administered_mac(mac):
        return {"medio": "wifi", "label": "Wi-Fi", "icono": "📶", "detalle": "Dirección MAC Privada (Wi-Fi)"}

    wifi_chips = ["espressif", "tuya", "sonoff", "shelly", "broadlink", "smart life", "azurewave", "murata", "liteon", "fn-link", "chiun mai", "ampak"]
    if any(k in f for k in wifi_chips):
        return {"medio": "wifi", "label": "Wi-Fi", "icono": "📶", "detalle": "Chipset Wi-Fi Integrado (IoT)"}

    if any(k in f or k in h for k in ["roku", "chromecast", "firestick", "fire tv", "google nest", "google home", "amazon echo", "echo dot", "echo show"]):
        return {"medio": "wifi", "label": "Wi-Fi", "icono": "📶", "detalle": "Streaming / Asistente Inteligente (Wi-Fi)"}

    if any(k in f or k in h for k in ["tapo", "wyze", "eufy", "ring", "blink", "imou", "yi technology"]):
        return {"medio": "wifi", "label": "Wi-Fi", "icono": "📶", "detalle": "Cámara Wi-Fi Residencial"}

    if 62078 in ports or any(k in tipo for k in ["phone", "mobile", "móvil", "tablet"]):
        return {"medio": "wifi", "label": "Wi-Fi", "icono": "📶", "detalle": "Dispositivo Móvil / Enlace Inalámbrico"}

    # 2. Señales de infraestructura puramente cableada (VoIP PoE, NVR/CCTV, NAS/Server, Switch)
    if {5060, 5061}.intersection(ports) or any(k in f for k in ["yealink", "grandstream", "polycom", "poly", "fanvil", "snom", "avaya"]):
        return {"medio": "ethernet", "label": "Ethernet", "icono": "🔌", "detalle": "Teléfono IP PoE Cableado"}

    if {37777, 34567}.intersection(ports) or any(k in f or k in h for k in ["hikvision", "dahua", "xiongmai", "uniview", "nvr", "dvr"]):
        return {"medio": "ethernet", "label": "Ethernet", "icono": "🔌", "detalle": "Sistema CCTV / NVR Cableado"}

    if any(k in f or k in h for k in ["synology", "qnap", "truenas", "freenas", "proxmox", "vmware", "esxi", "poweredge", "proliant", "supermicro"]) or tipo == "server":
        return {"medio": "ethernet", "label": "Ethernet", "icono": "🔌", "detalle": "Servidor / NAS Cableado"}

    if tipo == "switch" or any(k in f for k in ["cisco", "fortinet", "palo alto", "pfsense", "juniper", "edgeswitch"]):
        return {"medio": "ethernet", "label": "Ethernet", "icono": "🔌", "detalle": "Switch / Infraestructura Cableada"}

    # 3. Para equipos híbridos (PCs, Laptops, Impresoras, Smart TVs), priorizar telemetría real de latencia y jitter
    if telemetria and isinstance(telemetria, dict):
        avg = telemetria.get("latency_ms")
        min_ms = telemetria.get("latency_min")
        max_ms = telemetria.get("latency_max")
        loss = telemetria.get("packet_loss", 0)
        if avg is not None and min_ms is not None and max_ms is not None:
            jitter = max_ms - min_ms
            if avg <= 2.5 and jitter <= 2.0 and loss == 0:
                return {"medio": "ethernet", "label": "Ethernet", "icono": "🔌", "detalle": f"Enlace Cableado (Latencia {avg} ms, Jitter {jitter:.1f} ms)"}
            if avg >= 6.0 or jitter >= 8.0 or loss > 0:
                return {"medio": "wifi", "label": "Wi-Fi", "icono": "📶", "detalle": f"Enlace Inalámbrico (Latencia {avg} ms, Jitter {jitter:.1f} ms)"}

    # 4. Heurística final de respaldo si no hubo telemetría concluyente
    if any(k in h for k in ["laptop-", "notebook", "macbook", "nb-"]):
        return {"medio": "wifi", "label": "Wi-Fi", "icono": "📶", "detalle": "Computadora Portátil (Wi-Fi)"}

    if any(k in h for k in ["desktop-", "ws-", "workstation", "pc-"]) or any(k in f for k in ["gigabyte", "asrock", "biostar", "micro-star", "msi"]):
        return {"medio": "ethernet", "label": "Ethernet", "icono": "🔌", "detalle": "PC de Escritorio / Estación Fija"}

    if {9100, 515, 631}.intersection(ports) or tipo == "printer":
        return {"medio": "ethernet", "label": "Ethernet", "icono": "🔌", "detalle": "Impresora de Red"}

    return {"medio": "ethernet", "label": "Ethernet", "icono": "🔌", "detalle": "Enlace de Red Local"}


def classify_device(
    ip: str,
    mac: str = "",
    fabricante: str = "",
    hostname: str = "",
    puertos_abiertos: list = None,
    ttl: int = None,
    telemetria: dict = None
) -> dict:
    """
    Clasifica un dispositivo de red determinando:
    - tipo, icono representativo y categoría funcional (sin conflictos de prioridad)
    - medio físico de conexión (Wi-Fi 📶 vs Ethernet 🔌) y detalles
    """
    res = _raw_classify_device(
        ip=ip,
        mac=mac,
        fabricante=fabricante,
        hostname=hostname,
        puertos_abiertos=puertos_abiertos,
        ttl=ttl
    )

    telem = telemetria or ({"ttl": ttl} if ttl else None)
    med = detect_connection_medium(
        ip=ip,
        mac=mac,
        fabricante=fabricante,
        hostname=hostname,
        puertos_abiertos=puertos_abiertos,
        telemetria=telem,
        dispositivo_tipo=res.get("tipo", ""),
        es_scanner=res.get("es_scanner", False),
        es_gateway=(res.get("tipo") == "router")
    )

    res["medio_conexion"] = med["medio"]
    res["medio_label"] = med["label"]
    res["medio_icono"] = med["icono"]
    res["medio_detalle"] = med["detalle"]
    return res
