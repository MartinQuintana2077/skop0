import subprocess
import socket
import re
import sys
import time


DEFAULT_TCP_PROBE_PORTS = (80, 443, 135, 445, 62078, 8008, 8009, 8060, 5357, 554, 9100, 22, 8080, 53)


def _measure_tcp_rtt(ip: str, candidate_ports: list = None, probes: int = 3, timeout_s: float = 0.25) -> dict:
    """
    Mide latencia real por TCP handshake / RST cuando el host bloquea ICMP (Ping).
    Tanto una conexión exitosa como ECONNREFUSED (10061/111) demuestran que el host
    está activo y entregan el RTT real en milisegundos.
    """
    ports_to_try = []
    if candidate_ports:
        for p in candidate_ports:
            pnum = p.get("puerto") if isinstance(p, dict) else p
            try:
                p_int = int(pnum)
                if 1 <= p_int <= 65535 and p_int not in ports_to_try:
                    ports_to_try.append(p_int)
            except (ValueError, TypeError):
                pass
    for p in DEFAULT_TCP_PROBE_PORTS:
        if p not in ports_to_try:
            ports_to_try.append(p)

    responsive_port = None
    first_rtt = None
    for port in ports_to_try[:10]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        t0 = time.perf_counter()
        try:
            s.connect((ip, port))
            first_rtt = round((time.perf_counter() - t0) * 1000.0, 1)
            responsive_port = port
            break
        except socket.error as err:
            if getattr(err, "errno", None) in (10061, 111):
                first_rtt = round((time.perf_counter() - t0) * 1000.0, 1)
                responsive_port = port
                break
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    if responsive_port is None:
        return None

    samples = [first_rtt]
    for _ in range(max(0, probes - 1)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        t0 = time.perf_counter()
        try:
            s.connect((ip, responsive_port))
            samples.append(round((time.perf_counter() - t0) * 1000.0, 1))
        except socket.error as err:
            if getattr(err, "errno", None) in (10061, 111):
                samples.append(round((time.perf_counter() - t0) * 1000.0, 1))
        except Exception:
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass

    avg_ms = round(sum(samples) / len(samples), 1)
    min_ms = min(samples)
    max_ms = max(samples)
    loss = int(((probes - len(samples)) / probes) * 100) if probes > 0 else 0
    return {
        "samples": samples,
        "sent": probes,
        "recv": len(samples),
        "loss": loss,
        "avg_ms": avg_ms,
        "min_ms": min_ms,
        "max_ms": max_ms,
        "port": responsive_port,
    }


def _measure_arp_rtt(ip: str, probes: int = 3) -> dict:
    """Fallback Layer-2 SendARP en Windows para hosts que filtran tanto ICMP como TCP."""
    if sys.platform != "win32":
        return None
    try:
        from core.scanner import send_arp_native
    except Exception:
        return None

    samples = []
    for _ in range(probes):
        t0 = time.perf_counter()
        alive, _mac = send_arp_native(ip, retries=1)
        if alive:
            samples.append(round((time.perf_counter() - t0) * 1000.0, 1))
    if not samples:
        return None

    return {
        "sent": probes,
        "recv": len(samples),
        "loss": int(((probes - len(samples)) / probes) * 100),
        "avg_ms": round(sum(samples) / len(samples), 1),
        "min_ms": min(samples),
        "max_ms": max(samples),
    }


def measure_device_telemetry(
    ip: str,
    count: int = 4,
    timeout_ms: int = 400,
    open_ports: list = None,
    nmap_rtt_ms: float = None
) -> dict:
    """
    Mide la telemetría real de enlace hacia una IP con cascada inteligente:
      1. ICMP Ping (obtiene latencia, pérdida de paquetes y TTL del kernel).
      2. Si el firewall del host bloquea ICMP (0 respuestas): fallback a TCP RTT.
      3. Si filtra TCP también: fallback a Nmap SRTT o Layer-2 SendARP RTT en Windows.
    Evita reportar falsamente 'Sin respuesta' en dispositivos activos con firewall estricto.
    """
    default_res = {
        "ip": ip,
        "packets_sent": count,
        "packets_recv": 0,
        "packet_loss": 100,
        "latency_ms": None,
        "latency_min": None,
        "latency_max": None,
        "status": "unreachable",
        "status_label": f"Sin respuesta (0/{count} pkts)",
        "ttl": None,
        "method": "none",
        "icmp_blocked": False,
    }

    if not ip or ip in ("unknown", "Desconocida", ""):
        return default_res

    try:
        creationflags = 0x08000000 if sys.platform == 'win32' else 0
        cmd = ['ping', '-n', str(count), '-w', str(timeout_ms), ip]
        max_timeout = (count * (timeout_ms / 1000.0)) + 2.5
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='cp1252',
            errors='ignore',
            creationflags=creationflags,
            timeout=max_timeout
        )
        output = proc.stdout or ""

        sent_m = re.search(r'(?:enviados|Sent)\s*=\s*(\d+)', output, re.I)
        recv_m = re.search(r'(?:recibidos|Received)\s*=\s*(\d+)', output, re.I)
        loss_m = re.search(r'\((\d+)%\s*(?:perdidos|loss)\)', output, re.I)

        sent = int(sent_m.group(1)) if sent_m else count
        recv = int(recv_m.group(1)) if recv_m else 0
        loss = int(loss_m.group(1)) if loss_m else (100 if recv == 0 else int(((sent - recv) / sent) * 100))

        times = [float(t) for t in re.findall(r'(?:tiempo|time)[<=](\d+)m?s?', output, re.I)]
        avg_m = re.search(r'(?:Media|Average)\s*=\s*(\d+)m?s?', output, re.I)
        min_m = re.search(r'(?:M[íi]nimo|Minimum)\s*=\s*(\d+)m?s?', output, re.I)
        max_m = re.search(r'(?:M[áa]ximo|Maximum)\s*=\s*(\d+)m?s?', output, re.I)

        if avg_m:
            avg_ms = float(avg_m.group(1))
        elif times:
            avg_ms = round(sum(times) / len(times), 1)
        else:
            avg_ms = 0.0 if recv > 0 else None

        min_ms = float(min_m.group(1)) if min_m else (min(times) if times else avg_ms)
        max_ms = float(max_m.group(1)) if max_m else (max(times) if times else avg_ms)

        ttl_m = re.search(r'TTL\s*=\s*(\d+)', output, re.I)
        ttl = int(ttl_m.group(1)) if ttl_m else None

        if recv > 0 and loss < 100:
            if loss > 0:
                status = "degraded"
                status_label = f"Pérdida {loss}% ({recv}/{sent} pkts) · {avg_ms or 0} ms"
            elif avg_ms is not None and avg_ms > 80:
                status = "slow"
                status_label = f"Latencia alta ({avg_ms} ms)"
            else:
                status = "excellent"
                status_label = f"{avg_ms if avg_ms is not None else 1.0} ms"

            return {
                "ip": ip,
                "packets_sent": sent,
                "packets_recv": recv,
                "packet_loss": loss,
                "latency_ms": avg_ms,
                "latency_min": min_ms,
                "latency_max": max_ms,
                "status": status,
                "status_label": status_label,
                "ttl": ttl,
                "method": "icmp",
                "icmp_blocked": False,
            }
    except Exception:
        pass

    # Fallback 1: Medición TCP RTT (para equipos con ICMP bloqueado por firewall)
    tcp_res = _measure_tcp_rtt(ip, candidate_ports=open_ports, probes=min(3, count))
    if tcp_res:
        avg_ms = tcp_res["avg_ms"]
        status = "slow" if avg_ms > 80 else "excellent"
        return {
            "ip": ip,
            "packets_sent": tcp_res["sent"],
            "packets_recv": tcp_res["recv"],
            "packet_loss": tcp_res["loss"],
            "latency_ms": avg_ms,
            "latency_min": tcp_res["min_ms"],
            "latency_max": tcp_res["max_ms"],
            "status": status,
            "status_label": f"{avg_ms} ms (TCP)",
            "ttl": None,
            "method": "tcp",
            "icmp_blocked": True,
        }

    # Fallback 2: Nmap SRTT ya medido durante el escaneo de puertos
    if nmap_rtt_ms is not None and nmap_rtt_ms >= 0:
        avg_ms = round(float(nmap_rtt_ms), 1)
        status = "slow" if avg_ms > 80 else "excellent"
        return {
            "ip": ip,
            "packets_sent": 1,
            "packets_recv": 1,
            "packet_loss": 0,
            "latency_ms": avg_ms,
            "latency_min": avg_ms,
            "latency_max": avg_ms,
            "status": status,
            "status_label": f"{avg_ms} ms (Nmap)",
            "ttl": None,
            "method": "nmap",
            "icmp_blocked": True,
        }

    # Fallback 3: Layer-2 SendARP RTT en Windows (para iPhones/Android/Windows en modo sigiloso)
    arp_res = _measure_arp_rtt(ip, probes=min(3, count))
    if arp_res:
        avg_ms = arp_res["avg_ms"]
        status = "slow" if avg_ms > 80 else "excellent"
        return {
            "ip": ip,
            "packets_sent": arp_res["sent"],
            "packets_recv": arp_res["recv"],
            "packet_loss": arp_res["loss"],
            "latency_ms": avg_ms,
            "latency_min": arp_res["min_ms"],
            "latency_max": arp_res["max_ms"],
            "status": status,
            "status_label": f"{avg_ms} ms (ARP)",
            "ttl": None,
            "method": "arp",
            "icmp_blocked": True,
        }

    return default_res
