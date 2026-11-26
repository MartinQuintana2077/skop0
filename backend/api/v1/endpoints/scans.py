from fastapi import APIRouter, HTTPException, Depends, Header, BackgroundTasks
from schemas.scan import ScanRequest, CVELookupRequest, BatchDeleteRequest, BridgeBindRequest
from services.scan_service import ScanService
from services.db_service import DatabaseService
from services.license_service import LicenseService
from api.deps import get_current_user
import uuid
import os
import time
import threading
import ipaddress

router = APIRouter()
scan_service = ScanService()
db_service = DatabaseService()
license_service = LicenseService()

# Registro thread-safe de escaneos activos: garantiza 1 escaneo simultáneo por usuario
# y habilita cancelación cooperativa instantánea (matando subprocesos Nmap en <200ms).
_active_scans_lock = threading.Lock()
_active_scans = {}  # scan_id -> {"user_id": str, "cancel_event": threading.Event, "started_at": float, "target_ip": str}


def register_active_scan(user_id: str, scan_id: str, target_ip: str = "auto"):
    """Registra un nuevo escaneo activo si el usuario no tiene ya uno corriendo."""
    uid = user_id or "anonymous"
    with _active_scans_lock:
        for existing_id, info in _active_scans.items():
            if info["user_id"] == uid and not info["cancel_event"].is_set():
                return False, existing_id, None
        ev = threading.Event()
        _active_scans[scan_id] = {
            "user_id": uid,
            "cancel_event": ev,
            "started_at": time.time(),
            "target_ip": target_ip,
        }
        return True, scan_id, ev


def cancel_active_scan(scan_id: str, user_id: str = None) -> dict:
    """Señaliza cancelación inmediata del escaneo activo indicado (o 'current' del usuario)."""
    uid = user_id or "anonymous"
    target_id = None
    with _active_scans_lock:
        if scan_id in _active_scans:
            info = _active_scans[scan_id]
            if user_id is None or info["user_id"] == uid:
                info["cancel_event"].set()
                target_id = scan_id
        elif scan_id in ("current", "active"):
            for sid, info in _active_scans.items():
                if info["user_id"] == uid:
                    info["cancel_event"].set()
                    target_id = sid
                    break
    if target_id:
        db_service.append_scan_log(uid, target_id, "🛑 Cancelación solicitada por el usuario. Deteniendo procesos activos...")
        return {"status": "cancelling", "scan_id": target_id, "mensaje": "Cancelación enviada al motor de escaneo."}
    return {"status": "not_found", "scan_id": scan_id, "mensaje": "No hay una auditoría activa con ese identificador."}


def unregister_active_scan(scan_id: str):
    with _active_scans_lock:
        _active_scans.pop(scan_id, None)


def get_active_scan_for_user(user_id: str):
    uid = user_id or "anonymous"
    with _active_scans_lock:
        for sid, info in _active_scans.items():
            if info["user_id"] == uid:
                return {
                    "scan_id": sid,
                    "target_ip": info.get("target_ip", "auto"),
                    "started_at": info.get("started_at"),
                    "cancelling": info["cancel_event"].is_set(),
                }
    return None


@router.get("/interfaces")
def get_interfaces_endpoint():
    from core.subnet_bridge import get_available_network_interfaces
    return {
        "status": "ok",
        "interfaces": get_available_network_interfaces()
    }


@router.post("/discover")
def discover_network(request: ScanRequest, user: dict = Depends(get_current_user)):
    user_id = user.get("uid", "")
    result = scan_service.discover(request.target_ip, passive=request.passive, interface=request.interface or "all")
    if result.get("error") == "NMAP_MISSING":
        return {"status": "error", "code": "NMAP_MISSING", "dispositivos": []}
    
    return {
        "status": "ok", 
        "total": len(result["dispositivos"]),
        "dispositivos": result["dispositivos"],
        "user_id": user_id
    }



@router.get("/device-telemetry/{ip}")
def get_device_telemetry(ip: str):
    from core.telemetry import measure_device_telemetry
    return measure_device_telemetry(ip, count=4, timeout_ms=350)


@router.post("/deep-scan/{ip}")
def deep_scan_device(ip: str, user: dict = Depends(get_current_user)):
    user_id = user.get("uid", "")
    email = user.get("email", "")
    
    lic = license_service.get_user_license(user_id=user_id, email=email)
    if not lic.get("can_scan", True):
        raise HTTPException(
            status_code=403, 
            detail="Tu cuenta no cuenta con una licencia activa. Por favor, solicita la activación con el administrador para realizar auditorías de red."
        )

    try:
        detalle = scan_service.deep_scan(ip, user_id)
        return {
            "status": "ok",
            "ip_escaneada": ip,
            "user_id": user_id,
            "puertos_encontrados": len(detalle.get("puertos_abiertos", [])),
            "vulnerabilidades_encontradas": detalle.get("total_vulnerabilidades", 0),
            "detalle": detalle
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



def validate_network_target(target: str) -> str:
    if not target or target.strip().lower() in ("auto", ""):
        return "auto"
    clean = target.strip()
    try:
        if "/" in clean:
            net = ipaddress.ip_network(clean, strict=False)
            if net.prefixlen < 20 or net.prefixlen > 32:
                raise HTTPException(
                    status_code=400,
                    detail=f"Máscara de subred /{net.prefixlen} no permitida. El rango debe estar entre /20 y /32 (ej: /24 para 254 hosts). Un prefijo menor a /20 contiene demasiadas direcciones."
                )
            return str(net)
        else:
            ip = ipaddress.ip_address(clean)
            return str(ip)
    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=f"Dirección IP o rango de subred inválido '{clean}'. En IPv4 la máscara debe ser entre /8 y /32 (ej: 192.168.1.0/24): {str(e)}"
        )


def _run_scan_bg(user_id: str, scan_id: str, target_ip: str, passive: bool, interface: str = "all", cancel_event: threading.Event = None):
    import concurrent.futures
    import datetime
    import traceback

    if cancel_event is None:
        cancel_event = threading.Event()

    def _finalize_cancelled(escaneados_so_far=0, vulns_so_far=0, target_disc=None, net_nm=None, topo=None):
        db_service.append_scan_log(user_id, scan_id, f"🛑 Auditoría detenida por el usuario ({escaneados_so_far} equipos procesados antes de cancelar).")
        db_service.update_scan_metadata(user_id, scan_id, {
            "target_ip": target_disc or target_ip,
            "network_name": net_nm or target_ip,
            "end_time": datetime.datetime.utcnow().isoformat(),
            "status": "cancelled",
            "devices_found": escaneados_so_far,
            "total_targets": escaneados_so_far,
            "vulnerabilidades_found": vulns_so_far,
            "topology": topo or {},
        })
        print(f"[BFF-BG] Escaneo CANCELADO: {scan_id} ({escaneados_so_far} equipos)")

    try:
        log_cb = lambda msg: db_service.append_scan_log(user_id, scan_id, msg)
        scan_service.set_log_cb(log_cb)
        
        print(f"[BFF-BG] Modo directo para usuario: {user_id} (Pasivo: {passive}, Interfaz: {interface})")
        db_service.append_scan_log(user_id, scan_id, f"Iniciando auditoría de red (Pasivo: {passive}, Interfaz: {interface}) en {target_ip}...")
        
        result = scan_service.discover(target_ip, passive=passive, interface=interface, cancel_event=cancel_event)

        if cancel_event.is_set():
            _finalize_cancelled(0, 0, result.get("target"), result.get("network_name"), result.get("topology"))
            return
        
        if result.get("error") == "NMAP_MISSING":
            db_service.append_scan_log(user_id, scan_id, "Error crítico: Nmap no está instalado en el sistema.")
            db_service.update_scan_metadata(user_id, scan_id, {"status": "error", "error": "NMAP_MISSING"})
            return
            
        dispositivos = result.get("dispositivos", [])
        print(f"[BFF-BG] Dispositivos encontrados: {len(dispositivos)}")
        db_service.append_scan_log(user_id, scan_id, f"Fase de descubrimiento completada. {len(dispositivos)} dispositivos detectados en la red.")
        
        target_discovered = result.get("target") or target_ip or "auto"
        net_name = result.get("network_name")
        if not net_name or net_name in ("auto", "Red Local", ""):
            from core.scanner import get_active_network_name
            net_name = get_active_network_name(fallback_target=target_discovered)

        if len(dispositivos) == 0:
            db_service.append_scan_log(user_id, scan_id, f"⚠️ No se detectaron dispositivos activos en {target_ip}. Verifica la conectividad o el rango ingresado.")
            db_service.update_scan_metadata(user_id, scan_id, {
                "target_ip": target_discovered,
                "network_name": net_name,
                "end_time": datetime.datetime.utcnow().isoformat(),
                "status": "completed",
                "devices_found": 0,
                "total_targets": 0,
                "vulnerabilidades_found": 0,
                "topology": result.get("topology", {})
            })
            db_service.append_scan_log(user_id, scan_id, f"✅ Auditoría finalizada: 0 dispositivos encontrados.")
            print(f"[BFF-BG] Escaneo completado sin dispositivos.")
            return

        db_service.update_scan_metadata(user_id, scan_id, {
            "total_targets": len(dispositivos),
            "topology": result.get("topology", {})
        })
        
        escaneados = 0
        total_vulnerabilidades = 0
        
        dispositivos_validos = [d for d in dispositivos if d.get("ip")]

        # FASE 3A: Barrido TCP SYN rápido en un solo proceso para todos los hosts (~0.5s total)
        pre_sweep_map = {}
        if not passive and dispositivos_validos and not cancel_event.is_set():
            pre_sweep_map = scan_service.scanner.fast_port_sweep(
                [d["ip"] for d in dispositivos_validos],
                interface=interface,
                cancel_event=cancel_event,
            )

        def scan_single_device(dispositivo):
            if cancel_event.is_set():
                return None
            ip = dispositivo.get("ip", "")
            if not ip:
                return None
            scan_service.set_log_cb(log_cb)
            try:
                db_service.mark_scan_processed(user_id, scan_id, ip)
                
                fabricante = dispositivo.get('fabricante') or dispositivo.get('vendor') or 'Desconocido'
                db_service.append_scan_log(user_id, scan_id, f"[HOST] Analizando {ip} ({fabricante})...")
                
                if passive:
                    from core.device_classifier import classify_device
                    clasif = classify_device(ip, dispositivo.get("mac", ""), fabricante, dispositivo.get("hostname", ""), [])
                    detalle = {
                        "ip": ip,
                        "mac": dispositivo.get("mac", "Desconocida"),
                        "hostname": dispositivo.get("hostname", ""),
                        "fabricante": fabricante,
                        "dispositivo_tipo": clasif["tipo"],
                        "icono": clasif["icono"],
                        "categoria_nombre": clasif["categoria"],
                        "confianza_clasificacion": clasif["confianza"],
                        "medio_conexion": clasif.get("medio_conexion", "ethernet"),
                        "medio_label": clasif.get("medio_label", "Ethernet"),
                        "medio_icono": clasif.get("medio_icono", "🔌"),
                        "medio_detalle": clasif.get("medio_detalle", ""),
                        "puertos_abiertos": [],
                        "puertos_bloqueados": [],
                        "total_vulnerabilidades": 0,
                        "max_score": 0.0,
                        "fecha_auditoria": datetime.datetime.utcnow().isoformat(),
                        "estado": "Completado (Pasivo)",
                        "es_nuevo": False,
                        "primera_conexion": datetime.datetime.utcnow().isoformat(),
                        "scan_id": scan_id
                    }
                    db_service.save_device(ip, detalle, user_id)
                    db_service.save_scan_device(user_id, scan_id, ip, detalle)
                else:
                    detalle = scan_service.deep_scan(
                        ip,
                        user_id,
                        scan_id,
                        known_device=dispositivo,
                        interface=interface,
                        force_refresh=True,
                        cancel_event=cancel_event,
                        pre_sweep_host=pre_sweep_map.get(ip),
                        skip_rdns=True,
                    )
                    if detalle is None or cancel_event.is_set():
                        return None
                    if detalle:
                        abiertos = detalle.get("puertos_abiertos", [])
                        bloqueados = detalle.get("puertos_bloqueados", [])
                        vulns = detalle.get("total_vulnerabilidades", 0)
                        
                        if abiertos:
                            db_service.append_scan_log(user_id, scan_id,
                                f"[OK] {ip} — {len(abiertos)} puerto(s) abierto(s): " +
                                ", ".join([f"TCP/{p['puerto']} ({p['servicio'].upper()})" for p in abiertos]))
                        else:
                            db_service.append_scan_log(user_id, scan_id,
                                f"[OK] {ip} — Sin servicios expuestos en perfil de auditoría.")

                        if bloqueados:
                            db_service.append_scan_log(user_id, scan_id,
                                f"[BLOQUEADO] {ip} — {len(bloqueados)} puerto(s) restringido(s):")
                            for p in bloqueados:
                                db_service.append_scan_log(user_id, scan_id,
                                    f"  TCP/{p['puerto']} ({p.get('servicio','N/A').upper()}) — {p['razon']}")

                        if vulns > 0:
                            db_service.append_scan_log(user_id, scan_id,
                                f"[ALERTA] {ip} — {vulns} vulnerabilidad(es) CVE detectada(s). Revisa el panel de detalles.")
                            db_service.increment_vulnerabilities(user_id, scan_id, vulns)

                print(f"[BFF-BG] GUARDADO: {ip} para user: {user_id} (Pasivo: {passive})")
                db_service.increment_devices(user_id, scan_id, 1)
                return detalle
            except Exception as e:
                print(f"[BFF-BG] Error escaneando {ip}: {e}")
                db_service.append_scan_log(user_id, scan_id, f"[ERROR] No se pudo analizar {ip}: {str(e)}")
                return None
            finally:
                scan_service.set_log_cb(None)

        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
            resultados = list(executor.map(scan_single_device, dispositivos_validos))

        for r in resultados:
            if r is not None:
                escaneados += 1
                total_vulnerabilidades += r.get("total_vulnerabilidades", 0)

        if cancel_event.is_set():
            _finalize_cancelled(escaneados, total_vulnerabilidades, target_discovered, net_name, result.get("topology"))
            return

        db_service.update_scan_metadata(user_id, scan_id, {
            "target_ip": target_discovered,
            "network_name": net_name,
            "end_time": datetime.datetime.utcnow().isoformat(),
            "status": "completed",
            "devices_found": escaneados,
            "total_targets": escaneados,
            "vulnerabilidades_found": total_vulnerabilidades,
            "topology": result.get("topology", {})
        })
        
        db_service.append_scan_log(user_id, scan_id, f"✅ Auditoría finalizada con éxito. {escaneados} equipos procesados.")
        print(f"[BFF-BG] Escaneo COMPLETADO. Total: {escaneados}")
    except Exception as e:
        import traceback
        traceback.print_exc()
        db_service.append_scan_log(user_id, scan_id, f"❌ Error crítico en auditoría: {str(e)}")
        db_service.update_scan_metadata(user_id, scan_id, {
            "status": "error",
            "error": str(e),
            "end_time": datetime.datetime.utcnow().isoformat()
        })
    finally:
        scan_service.set_log_cb(None)
        unregister_active_scan(scan_id)


@router.get("/scans/active")
def get_active_scan_endpoint(user: dict = Depends(get_current_user)):
    user_id = user.get("uid", "")
    active = get_active_scan_for_user(user_id)
    return {"status": "ok", "active": active}


@router.post("/scans/{scan_id}/cancel")
@router.post("/cancel-scan/{scan_id}")
def cancel_scan_endpoint(scan_id: str, user: dict = Depends(get_current_user)):
    user_id = user.get("uid", "")
    return cancel_active_scan(scan_id, user_id=user_id)


@router.post("/trigger-scan")
def trigger_scan(request: ScanRequest, background_tasks: BackgroundTasks, user: dict = Depends(get_current_user)):
    """
    Endpoint BFF (Backend-for-Frontend) - Versión Segura y Asíncrona.
    - Valida JWT y licencia
    - Bloquea escaneos simultáneos duplicados por usuario (HTTP 409)
    - Genera scanId único y delega a BackgroundTasks con soporte de cancelación inmediata
    """
    user_id = user.get("uid", "")
    email = user.get("email", "")
    target_ip = validate_network_target(request.target_ip if request.target_ip else "auto")
    scan_id = request.scan_id if request.scan_id else str(uuid.uuid4())

    # Verificación de Licencia y Suscripción activa
    lic = license_service.get_user_license(user_id=user_id, email=email)
    if not lic.get("can_scan", True):
        raise HTTPException(
            status_code=403, 
            detail="Tu cuenta no cuenta con una licencia activa. Por favor, solicita la activación o renovación con el administrador para realizar auditorías de red."
        )

    if db_service.scan_exists(user_id, scan_id):
        return {"status": "already_processed", "scan_id": scan_id}

    # Bloqueo anti-doble escaneo simultáneo por usuario
    ok_reg, existing_or_new_id, cancel_event = register_active_scan(user_id, scan_id, target_ip=target_ip)
    if not ok_reg:
        raise HTTPException(
            status_code=409,
            detail=f"Ya existe una auditoría en curso (ID: {existing_or_new_id[:8]}). Espera a que termine o detenla antes de iniciar otra."
        )

    print(f"[BFF] Iniciando Escaneo Global Asincrono")
    print(f"[BFF] Usuario: {user_id}")
    print(f"[BFF] ScanId: {scan_id}")
    
    db_service.clear_devices(user_id)
    db_service.clear_vulnerabilities(user_id)

    db_service.init_scan(user_id, scan_id, target_ip)
    db_service.update_scan_metadata(user_id, scan_id, {
        "devices_found": 0,
        "vulnerabilidades_found": 0,
        "total_targets": 0,
        "status": "processing",
        "logs": []
    })

    background_tasks.add_task(_run_scan_bg, user_id, scan_id, target_ip, request.passive, request.interface or "all", cancel_event)
    
    return {
        "status": "ok", 
        "modo": "directo", 
        "scan_id": scan_id,
        "user_id": user_id,
        "mensaje": "Escaneo en segundo plano iniciado"
    }


@router.get("/history")
def get_scan_history(user: dict = Depends(get_current_user)):
    user_id = user.get("uid", "")
    scans = db_service.get_user_scans(user_id)
    return {"status": "ok", "scans": scans}


@router.get("/history/{scan_id}")
def get_scan_details(scan_id: str, user: dict = Depends(get_current_user)):
    user_id = user.get("uid", "")
    details = db_service.get_scan_details(user_id, scan_id)
    if not details:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"status": "ok", "details": details}


@router.get("/history/{scan_id}/devices")
def get_scan_devices(scan_id: str, user: dict = Depends(get_current_user)):
    user_id = user.get("uid", "")
    devices = db_service.get_scan_devices(user_id, scan_id)
    return {"status": "ok", "devices": devices}


@router.post("/history/batch-delete")
def batch_delete_scans(req: BatchDeleteRequest, user: dict = Depends(get_current_user)):
    user_id = user.get("uid", "")
    deleted = db_service.delete_scans_batch(user_id, req.scan_ids)
    return {"status": "ok", "deleted_count": deleted}


@router.delete("/history/{scan_id}")
def delete_scan(scan_id: str, user: dict = Depends(get_current_user)):
    user_id = user.get("uid", "")
    success = db_service.delete_scan(user_id, scan_id)
    if not success:
        raise HTTPException(status_code=500, detail="No se pudo eliminar el escaneo")
    return {"status": "ok", "message": f"Escaneo {scan_id} eliminado exitosamente"}


@router.post("/cve-lookup")
def cve_lookup(request: CVELookupRequest, user: dict = Depends(get_current_user)):
    resultados = scan_service.cve_client.buscar_vulnerabilidades(request.servicio, request.version)
    return {
        "status": "ok",
        "servicio": request.servicio,
        "version": request.version,
        "total_cves": len(resultados),
        "vulnerabilidades": resultados
    }


@router.get("/bridge-status")
def bridge_status_endpoint(target: str = "", interface: str = None):
    from core.subnet_bridge import get_bridge_status
    return get_bridge_status(target, interface)


@router.post("/bridge-bind")
def bridge_bind_endpoint(request: BridgeBindRequest):
    from core.subnet_bridge import bind_subnet_bridge
    return bind_subnet_bridge(request.target, request.interface)


@router.post("/bridge-unbind")
def bridge_unbind_endpoint():
    from core.subnet_bridge import unbind_subnet_bridge
    return unbind_subnet_bridge()
