"""
Módulo de Enlace Inteligente de Subredes (Subnet Bridge Engine) y Multi-Interfaz.
Permite auditar subredes lógicas aisladas (cámaras CCTV, VoIP, IoT, VLANs secundarias)
sin que el usuario tenga que configurar nada en Windows y SIN perder la conexión a Internet.
Implementa detección multi-tarjeta, prevención de colisiones (no duplica subredes ya existentes)
y desvinculación automática total.
"""
import os
import sys
import re
import json
import socket
import ipaddress
import subprocess
import time
import psutil

CREATE_NO_WINDOW = 0x08000000 if sys.platform == 'win32' else 0

STATE_DIR = os.path.expandvars(r"%APPDATA%\SecScan")
BRIDGE_STATE_FILE = os.path.join(STATE_DIR, "active_bridge.json")


def _save_active_bridge_state(data: dict):
    try:
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(BRIDGE_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        pass


def _load_active_bridge_state() -> dict:
    try:
        if os.path.exists(BRIDGE_STATE_FILE):
            with open(BRIDGE_STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _clear_active_bridge_state():
    try:
        if os.path.exists(BRIDGE_STATE_FILE):
            os.remove(BRIDGE_STATE_FILE)
    except Exception:
        pass


def get_available_network_interfaces() -> list:
    """
    Retorna la lista de todas las interfaces de red físicas y lógicas activas en la máquina,
    con sus nombres legibles, tipo (Ethernet, Wi-Fi, etc.), estado físico, IP actual y máscara.
    """
    interfaces = []
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    default_gw_iface = None
    if sys.platform == 'win32':
        try:
            out = subprocess.check_output('ipconfig', shell=True, creationflags=CREATE_NO_WINDOW).decode('cp1252', errors='ignore')
            current_sec = None
            for line in out.splitlines():
                if "adaptador" in line.lower() or "adapter" in line.lower():
                    m = re.search(r'(?:Ethernet|Wi-Fi|Conexión|Wireless)[^:]*', line, re.I)
                    if m:
                        current_sec = m.group(0).strip()
                if ("Puerta de enlace" in line or "Default Gateway" in line) and current_sec:
                    m_ip = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    if m_ip:
                        default_gw_iface = current_sec
        except Exception:
            pass

    for iface_name, addr_list in addrs.items():
        lower_name = iface_name.lower()
        if "loopback" in lower_name or "pseudo" in lower_name:
            continue

        stat = stats.get(iface_name)
        is_up = stat.isup if stat else True

        ipv4_info = []
        mac_addr = None
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                if not addr.address.startswith("127."):
                    ipv4_info.append({
                        "ip": addr.address,
                        "netmask": addr.netmask or "255.255.255.0"
                    })
            elif addr.family == psutil.AF_LINK:
                mac_addr = addr.address

        tipo = "ethernet"
        label = "Ethernet"
        icono = "🔌"
        if "wi-fi" in lower_name or "wireless" in lower_name or "wlan" in lower_name:
            tipo = "wifi"
            label = "Wi-Fi"
            icono = "📶"
        elif "vmware" in lower_name or "virtual" in lower_name or "vbox" in lower_name:
            tipo = "virtual"
            label = "Virtual"
            icono = "🖥️"
        elif "bluetooth" in lower_name:
            tipo = "bluetooth"
            label = "Bluetooth"
            icono = "🔹"

        has_internet = bool(default_gw_iface and any(k.lower() in iface_name.lower() for k in default_gw_iface.split()))

        interfaces.append({
            "id": iface_name,
            "name": iface_name,
            "tipo": tipo,
            "type": tipo,
            "label": label,
            "icono": icono,
            "is_up": is_up,
            "mac": mac_addr,
            "ipv4": ipv4_info,
            "primary_ip": ipv4_info[0]["ip"] if ipv4_info else None,
            "has_internet": has_internet
        })

    # Ordenar: primero las que están Up, con IP y con Internet/Ethernet
    def _sort_key(item):
        score = 0
        if item["is_up"]:
            score += 10
        if item["primary_ip"]:
            score += 5
        if item["has_internet"]:
            score += 3
        if item["tipo"] == "ethernet":
            score += 2
        return -score

    interfaces.sort(key=_sort_key)
    return interfaces


def get_active_interface_name(preferred_iface: str = None) -> str:
    """
    Detecta el nombre de la interfaz adecuada para el enlace o escaneo.
    Si se especificó una interfaz preferida y está activa, la respeta.
    Si no, prioriza interfaces Ethernet conectadas antes que Wi-Fi para enlaces a equipos aislados.
    """
    if preferred_iface and preferred_iface not in ("all", "auto", ""):
        avail = [i["name"] for i in get_available_network_interfaces()]
        if preferred_iface in avail:
            return preferred_iface

    all_ifaces = get_available_network_interfaces()
    if not all_ifaces:
        return "Ethernet"

    # Si hay una interfaz Ethernet cableada sin default gateway (típica de cámaras aisladas), preferirla
    for iface in all_ifaces:
        if iface["is_up"] and iface["tipo"] == "ethernet" and not iface["has_internet"]:
            return iface["name"]

    # De lo contrario, usar la primera conectada
    for iface in all_ifaces:
        if iface["is_up"]:
            return iface["name"]

    return all_ifaces[0]["name"]


def get_local_interfaces_info() -> list:
    """
    Retorna la lista de todas las IPs locales y subredes configuradas en la máquina
    mediante psutil (100% certero y multiplataforma) con prefijo CIDR real.
    """
    results = []
    all_ifaces = get_available_network_interfaces()
    for iface in all_ifaces:
        for ipv4 in iface.get("ipv4", []):
            mask = ipv4.get("netmask", "255.255.255.0")
            try:
                prefix = str(ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen)
            except Exception:
                prefix = "24"
            results.append({
                "ip": ipv4["ip"],
                "interface": iface["name"],
                "netmask": mask,
                "prefix": prefix
            })
    return results


def is_target_in_local_subnets(target_str: str, preferred_iface: str = None) -> tuple:
    """
    Comprueba de forma estricta si una IP única o CIDR (ej: '192.168.20.80' o '192.168.20.0/25')
    ya pertenece a una de las subredes locales existentes de la PC (respetando la máscara real).
    Retorna (is_present: bool, iface_name: str or None, existing_ip: str or None).
    """
    if not target_str or target_str.lower() in ("auto", "local", "127.0.0.1", ""):
        return True, "Local", "127.0.0.1"

    clean_target = target_str.strip()
    is_single_ip = "/" not in clean_target
    try:
        if is_single_ip:
            target_ip_obj = ipaddress.IPv4Address(clean_target)
            target_net = None
        else:
            target_net = ipaddress.IPv4Network(clean_target, strict=False)
            target_ip_obj = None
    except Exception:
        return True, "Local", "127.0.0.1"

    all_ifaces = get_available_network_interfaces()
    for iface in all_ifaces:
        if preferred_iface and preferred_iface not in ("all", "auto", ""):
            if iface["name"].lower() != preferred_iface.lower():
                continue

        for ipv4 in iface.get("ipv4", []):
            try:
                mask = ipv4.get("netmask") or "255.255.255.0"
                loc_net = ipaddress.IPv4Network(f"{ipv4['ip']}/{mask}", strict=False)
                if is_single_ip:
                    if target_ip_obj in loc_net:
                        return True, iface["name"], ipv4["ip"]
                else:
                    if target_net == loc_net or target_net.subnet_of(loc_net):
                        return True, iface["name"], ipv4["ip"]
            except Exception:
                continue

    return False, None, None


def find_free_ip_in_subnet(subnet_cidr: str) -> str:
    """
    Busca una IP disponible en el rango alto dentro de los límites REALES de la subred
    (ej. para /24 prueba .250..246; para /25 o /26 usa los últimos hosts válidos del bloque)
    mediante sondeo rápido para evitar colisiones.
    """
    try:
        net = ipaddress.IPv4Network(subnet_cidr, strict=False)
        all_hosts = list(net.hosts())
        if not all_hosts:
            return str(net.network_address)
        # Preferir direcciones altas evitando los últimos 4 hosts (broadcast/gateways .254/.253) si hay espacio
        if len(all_hosts) >= 12:
            # ej. en /24 (254 hosts: .1..254) -> índices -5..-11 => .250, .249, .248, .247, .246...
            high_slice = list(reversed(all_hosts[-12:-4]))
            candidate_ips = [str(ip) for ip in high_slice[:7]]
        else:
            candidate_ips = [str(ip) for ip in reversed(all_hosts[-min(7, len(all_hosts)):])]
    except Exception:
        prefix_base = subnet_cidr.split('/')[0].rsplit('.', 1)[0]
        candidate_ips = [f"{prefix_base}.{n}" for n in (250, 251, 252, 249, 248, 247, 246)]

    for test_ip in candidate_ips:
        try:
            cmd = ['ping', '-n', '1', '-w', '60', test_ip]
            res = subprocess.run(cmd, capture_output=True, text=True, encoding='cp1252', errors='replace', creationflags=CREATE_NO_WINDOW, timeout=0.25)
            out = res.stdout or ""
            if "bytes=32" not in out and "bytes=64" not in out and "TTL=" not in out:
                return test_ip
        except Exception:
            return test_ip

    return candidate_ips[0]


def _verify_ip_bound_on_interface(iface: str, target_ip: str, timeout: float = 1.5) -> bool:
    """Verifica con psutil que la IP secundaria realmente quedó aplicada en el adaptador Windows."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            for name, addr_list in psutil.net_if_addrs().items():
                if name.lower() == iface.lower():
                    for a in addr_list:
                        if a.family == socket.AF_INET and a.address == target_ip:
                            return True
        except Exception:
            pass
        time.sleep(0.15)
    return False


def bind_subnet_bridge(target_str: str, preferred_interface: str = None) -> dict:
    """
    Enlaza temporalmente la tarjeta de red adecuada a la subred solicitada (ej. 192.168.20.0/24 o /25).
    1. Si la subred ya está presente en esa tarjeta o en la máquina, NO crea ninguna IP secundaria (Anti-Colisión).
    2. Retira previamente cualquier subred temporal anterior para no ralentizar la red (rotación 1 a 1).
    3. Habilita dhcpstaticipcoexistence en Windows y asigna una IP libre con la MÁSCARA REAL del bloque.
    4. Valida el código de salida de netsh y confirma en psutil que la IP realmente se vinculó.
    """
    is_present, existing_iface, existing_ip = is_target_in_local_subnets(target_str, preferred_interface)
    if is_present:
        return {
            "status": "already_local",
            "message": f"La subred {target_str} ya está configurada en la tarjeta '{existing_iface}' (IP: {existing_ip}). No es necesario crear enlace secundario.",
            "interface": existing_iface,
            "existing_ip": existing_ip,
            "target": target_str
        }

    # Rotación limpia 1 a 1: retirar puente anterior si existía
    unbind_subnet_bridge()

    # Determinar subred y máscara real (para IP única /32 se crea enlace /24 en su bloque)
    clean_target = target_str.strip()
    try:
        if "/" not in clean_target:
            net = ipaddress.IPv4Network(f"{clean_target}/24", strict=False)
        else:
            parsed_net = ipaddress.IPv4Network(clean_target, strict=False)
            net = ipaddress.IPv4Network(f"{parsed_net.network_address}/24", strict=False) if parsed_net.prefixlen >= 31 else parsed_net
        subnet_cidr = str(net)
        real_netmask = str(net.netmask)
    except Exception:
        subnet_cidr = f"{clean_target}/24" if "/" not in clean_target else clean_target
        real_netmask = "255.255.255.0"

    iface = get_active_interface_name(preferred_interface)
    free_ip = find_free_ip_in_subnet(subnet_cidr)

    try:
        # En Windows, interfaces DHCP rechazan IPs estáticas secundarias sin dhcpstaticipcoexistence=enabled
        subprocess.run(
            ['netsh', 'interface', 'ipv4', 'set', 'interface', f'interface={iface}', 'dhcpstaticipcoexistence=enabled'],
            capture_output=True, text=True, encoding='cp1252', errors='replace', creationflags=CREATE_NO_WINDOW, timeout=3.0
        )

        # Comando nativo de Windows sin shell=True para agregar IP secundaria con máscara real
        proc = subprocess.run(
            ['netsh', 'interface', 'ipv4', 'add', 'address', f'name={iface}', f'addr={free_ip}', f'mask={real_netmask}'],
            capture_output=True, text=True, encoding='cp1252', errors='replace', creationflags=CREATE_NO_WINDOW, timeout=5.0
        )

        bound_ok = (proc.returncode == 0) and _verify_ip_bound_on_interface(iface, free_ip, timeout=1.5)
        if not bound_ok:
            # Reintentar verificar por si netsh retornó 0/1 con advertencia pero sí la aplicó
            if _verify_ip_bound_on_interface(iface, free_ip, timeout=0.6):
                bound_ok = True

        if not bound_ok:
            err_detail = (proc.stderr or proc.stdout or "").strip() or f"netsh exit code {proc.returncode}"
            return {
                "status": "error",
                "interface": iface,
                "subnet": subnet_cidr,
                "message": f"Windows no permitió añadir la IP secundaria {free_ip}/{real_netmask} en '{iface}': {err_detail}"
            }

        state = {
            "bound_ip": free_ip,
            "interface": iface,
            "subnet": subnet_cidr,
            "netmask": real_netmask,
            "timestamp": time.time()
        }
        _save_active_bridge_state(state)

        return {
            "status": "ok",
            "bound_ip": free_ip,
            "interface": iface,
            "subnet": subnet_cidr,
            "netmask": real_netmask,
            "message": f"Enlace temporal activado con IP {free_ip} ({real_netmask}) en '{iface}'. Tu conexión a Internet sigue intacta."
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"No se pudo crear el enlace automático: {e}"
        }


def unbind_subnet_bridge() -> dict:
    """
    Elimina cualquier IP secundaria temporal creada por SecScan en la tarjeta de red.
    """
    state = _load_active_bridge_state()
    bound_ip = state.get("bound_ip")
    iface = state.get("interface") or get_active_interface_name()

    if bound_ip:
        cmd = f'netsh interface ipv4 delete address "{iface}" {bound_ip}'
        try:
            subprocess.run(cmd, shell=True, capture_output=True, text=True, creationflags=CREATE_NO_WINDOW, timeout=4.0)
        except Exception:
            pass
        _clear_active_bridge_state()
        return {
            "status": "ok",
            "message": f"IP secundaria {bound_ip} desvinculada exitosamente de '{iface}'."
        }

    return {"status": "ok", "message": "No había ningún enlace activo."}


def get_bridge_status(target_str: str = "", preferred_iface: str = None) -> dict:
    """
    Consulta si el target requiere crear un puente o si ya es accesible,
    y si actualmente hay un puente activo.
    """
    is_present, existing_iface, existing_ip = is_target_in_local_subnets(target_str, preferred_iface) if target_str else (True, None, None)
    current_state = _load_active_bridge_state()
    active_iface = get_active_interface_name(preferred_iface)
    all_interfaces = get_available_network_interfaces()
    current_local_ips = [item["primary_ip"] for item in all_interfaces if item.get("primary_ip")]

    return {
        "target": target_str,
        "is_local": is_present,
        "requires_bridge": not is_present,
        "active_interface": active_iface,
        "existing_interface": existing_iface,
        "existing_ip": existing_ip,
        "local_ips": current_local_ips,
        "available_interfaces": all_interfaces,
        "active_bridge": current_state if current_state.get("bound_ip") else None
    }


def cleanup_all_bridges():
    """
    Rutina de limpieza global invocada al arrancar (limpieza preventiva por cortes de luz)
    y al cerrar la aplicación (al presionar la 'X').
    """
    return unbind_subnet_bridge()
