from fastapi import APIRouter, Depends, HTTPException, Body, Request
from api.deps import get_current_user
from core.local_db import LocalDBManager
import datetime
import json
import time

router = APIRouter()

def _safe_json_str(val, default=""):
    """Garantiza que el valor sea un string JSON válido o texto para no romper SQLite."""
    if val is None:
        return default
    if isinstance(val, (dict, list)):
        try:
            return json.dumps(val, ensure_ascii=False)
        except Exception:
            return default
    if isinstance(val, str):
        return val
    return str(val)

def _perform_export(user: dict = None):
    user_id = (user or {}).get("uid", "") if isinstance(user, dict) else ""
    if not user_id:
        user_id = "anonymous"

    local_db = LocalDBManager()
    
    # 1. Intentar obtener registros asociados al usuario actual o genéricos
    devices = local_db.execute_read(
        "SELECT * FROM devices WHERE user_id = ? OR user_id = 'anonymous' OR user_id = 'local_user' OR user_id = '' OR user_id IS NULL",
        (user_id,)
    )
    if not devices:
        devices = local_db.execute_read("SELECT * FROM devices")

    vulnerabilities = local_db.execute_read(
        "SELECT * FROM vulnerabilities WHERE user_id = ? OR user_id = 'anonymous' OR user_id = 'local_user' OR user_id = '' OR user_id IS NULL",
        (user_id,)
    )
    if not vulnerabilities:
        vulnerabilities = local_db.execute_read("SELECT * FROM vulnerabilities")

    scans = local_db.execute_read(
        "SELECT * FROM scans WHERE user_id = ? OR user_id = 'anonymous' OR user_id = 'local_user' OR user_id = '' OR user_id IS NULL",
        (user_id,)
    )
    if not scans:
        scans = local_db.execute_read("SELECT * FROM scans")

    scan_devices = local_db.execute_read(
        "SELECT * FROM scan_devices WHERE user_id = ? OR user_id = 'anonymous' OR user_id = 'local_user' OR user_id = '' OR user_id IS NULL",
        (user_id,)
    )
    if not scan_devices:
        scan_devices = local_db.execute_read("SELECT * FROM scan_devices")

    date_str = datetime.datetime.utcnow().strftime("%Y-%m-%d")
    backup_bundle = {
        "app": "Skop0",
        "format": "skop0_backup",
        "version": "1.0",
        "exported_at": datetime.datetime.utcnow().isoformat(),
        "user_id": user_id,
        "user_email": (user or {}).get("email", "") if isinstance(user, dict) else "",
        "total_records": {
            "devices": len(devices),
            "vulnerabilities": len(vulnerabilities),
            "scans": len(scans),
            "scan_devices": len(scan_devices)
        },
        "data": {
            "devices": devices,
            "vulnerabilities": vulnerabilities,
            "scans": scans,
            "scan_devices": scan_devices
        }
    }

    file_content_str = json.dumps(backup_bundle, indent=2, ensure_ascii=False)
    
    return {
        "status": "ok",
        "filename": f"Skop0_Backup_{date_str}.skop0",
        "file_content": file_content_str,
        "summary": {
            "total_dispositivos": len(devices),
            "total_escaneos": len(scans),
            "total_vulnerabilidades": len(vulnerabilities)
        },
        **backup_bundle
    }

def _perform_import(raw_payload: dict, user: dict = None):
    if not isinstance(raw_payload, dict):
        raise HTTPException(status_code=400, detail="Formato de archivo inválido.")

    # Si vino envuelto en file_content (string JSON o dict)
    payload = raw_payload
    if "file_content" in raw_payload:
        content_val = raw_payload["file_content"]
        if isinstance(content_val, str):
            try:
                payload = json.loads(content_val)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"No se pudo decodificar el archivo JSON: {e}")
        elif isinstance(content_val, dict):
            payload = content_val

    data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
    devices = data.get("devices", []) if isinstance(data, dict) else []
    vulnerabilities = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    scans = data.get("scans", []) if isinstance(data, dict) else []
    scan_devices = data.get("scan_devices", []) if isinstance(data, dict) else []

    # Blindaje de cuenta: asignar todos los registros al usuario actualmente autenticado
    target_user_id = (user or {}).get("uid", "") if isinstance(user, dict) else ""
    if not target_user_id:
        target_user_id = payload.get("user_id") or "anonymous"

    local_db = LocalDBManager()

    imported_devices = 0
    for dev in devices:
        if not isinstance(dev, dict):
            continue
        try:
            ip = dev.get("ip")
            if not ip:
                continue
            raw_data = _safe_json_str(dev.get("raw_data_json") or dev)
            local_db.execute_write(
                '''INSERT OR REPLACE INTO devices 
                   (ip, user_id, mac, hostname, fabricante, total_vulnerabilidades, max_score, 
                    fecha_auditoria, estado, es_nuevo, primera_conexion, scan_id, 
                    dispositivo_tipo, icono, categoria_nombre, raw_data_json) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (ip, target_user_id, dev.get("mac") or "", dev.get("hostname") or "", dev.get("fabricante") or "Desconocido",
                 int(dev.get("total_vulnerabilidades") or 0), float(dev.get("max_score") or 0.0), dev.get("fecha_auditoria") or "",
                 dev.get("estado") or "activo", int(dev.get("es_nuevo") or 0), dev.get("primera_conexion") or "", dev.get("scan_id") or "",
                 dev.get("dispositivo_tipo") or "", dev.get("icono") or "", dev.get("categoria_nombre") or "", 
                 raw_data)
            )
            imported_devices += 1
        except Exception as e:
            print(f"[IMPORT ERROR dev] {e}")

    imported_vulns = 0
    for v in vulnerabilities:
        if not isinstance(v, dict):
            continue
        try:
            cve_id = v.get("cve_id") or ""
            ip = v.get("ip") or ""
            puerto = int(v.get("puerto") or 0)
            vid = v.get("id") or f"{cve_id}_{target_user_id}_{ip}_{puerto}"
            local_db.execute_write(
                '''INSERT OR REPLACE INTO vulnerabilities 
                   (id, cve_id, user_id, descripcion, severidad, score, ip, puerto, servicio, version, fecha_deteccion) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (vid, cve_id, target_user_id, v.get("descripcion") or "", v.get("severidad") or "INFO",
                 float(v.get("score") or 0.0), ip, puerto, v.get("servicio") or "", v.get("version") or "",
                 v.get("fecha_deteccion") or datetime.datetime.utcnow().isoformat())
            )
            imported_vulns += 1
        except Exception as e:
            print(f"[IMPORT ERROR vuln] {e}")

    imported_scans = 0
    imported_scan_devs = 0

    for idx, s in enumerate(scans):
        if not isinstance(s, dict):
            continue
        try:
            scan_id = s.get("scan_id") or s.get("id")
            if not scan_id:
                scan_id = f"imported_scan_{int(datetime.datetime.utcnow().timestamp())}_{idx}"

            topo_val = _safe_json_str(s.get("topology_json") or s.get("topology"))
            logs_val = _safe_json_str(s.get("logs_json") or s.get("logs"))

            local_db.execute_write(
                '''INSERT OR REPLACE INTO scans 
                   (scan_id, user_id, status, devices_found, total_targets, vulnerabilidades_found, 
                    timestamp, end_time, topology_json, logs_json, target_ip, network_name) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (scan_id, target_user_id, s.get("status") or "completed", 
                 int(s.get("devices_found") or 0), int(s.get("total_targets") or 0), 
                 int(s.get("vulnerabilidades_found") or 0), s.get("timestamp") or datetime.datetime.utcnow().isoformat(), 
                 s.get("end_time") or "", topo_val, logs_val, 
                 s.get("target_ip") or "", s.get("network_name") or "")
            )
            imported_scans += 1

            # Si el escaneo incluye lista interna de 'devices' o 'topology.devices', sincronizar scan_devices
            inner_devices = s.get("devices")
            if isinstance(inner_devices, list) and inner_devices:
                for in_dev in inner_devices:
                    if isinstance(in_dev, dict) and in_dev.get("ip"):
                        in_ip = in_dev["ip"]
                        dev_json = _safe_json_str(in_dev)
                        local_db.execute_write(
                            '''INSERT OR REPLACE INTO scan_devices 
                               (scan_id, ip, user_id, device_data_json) 
                               VALUES (?, ?, ?, ?)''',
                            (scan_id, in_ip, target_user_id, dev_json)
                        )
                        imported_scan_devs += 1
        except Exception as e:
            print(f"[IMPORT ERROR scan] {e}")

    # Importar scan_devices explícitos
    for sd in scan_devices:
        if not isinstance(sd, dict):
            continue
        try:
            s_id = sd.get("scan_id") or sd.get("id")
            ip = sd.get("ip")
            if not s_id or not ip:
                continue

            dev_data = _safe_json_str(
                sd.get("device_data_json") or sd.get("device_data") or sd.get("data") or sd.get("detalle") or sd
            )
            local_db.execute_write(
                '''INSERT OR REPLACE INTO scan_devices 
                   (scan_id, ip, user_id, device_data_json) 
                   VALUES (?, ?, ?, ?)''',
                (s_id, ip, target_user_id, dev_data)
            )
            imported_scan_devs += 1
        except Exception as e:
            print(f"[IMPORT ERROR scan_dev] {e}")

    # Auto-asociar dispositivos si faltaban en scan_devices para cualquiera de los escaneos importados
    for s in scans:
        if isinstance(s, dict):
            sid = s.get("scan_id") or s.get("id")
            if sid:
                existing_sd = local_db.execute_read(
                    "SELECT ip FROM scan_devices WHERE scan_id = ?",
                    (sid,)
                )
                if not existing_sd:
                    matching_devs = local_db.execute_read(
                        "SELECT * FROM devices WHERE scan_id = ?",
                        (sid,)
                    )
                    for mdev in matching_devs:
                        mip = mdev.get("ip")
                        if mip:
                            local_db.execute_write(
                                '''INSERT OR REPLACE INTO scan_devices 
                                   (scan_id, ip, user_id, device_data_json) 
                                   VALUES (?, ?, ?, ?)''',
                                (sid, mip, target_user_id, _safe_json_str(mdev))
                            )
                            imported_scan_devs += 1

    return {
        "status": "ok",
        "restaurados": {
            "dispositivos": imported_devices,
            "escaneos": imported_scans,
            "vulnerabilidades": imported_vulns,
            "dispositivos_de_escaneo": imported_scan_devs
        },
        "imported_devices": imported_devices,
        "imported_scans": imported_scans,
        "imported_vulnerabilities": imported_vulns,
        "imported_scan_devices": imported_scan_devs,
        "message": "Copia de seguridad restaurada exitosamente."
    }

# Endpoints compatibles con frontend/src/services/api.js
@router.api_route("/export", methods=["GET", "POST"])
def export_backup_endpoint(user: dict = Depends(get_current_user)):
    return _perform_export(user)

@router.post("/import")
def import_backup_endpoint(payload: dict = Body(...), user: dict = Depends(get_current_user)):
    return _perform_import(payload, user)

# Endpoints compatibles con frontend/dist compilado
@router.api_route("/v1/system/export-backup", methods=["GET", "POST"])
def dist_export_backup_endpoint(user: dict = Depends(get_current_user)):
    return _perform_export(user)

@router.post("/v1/system/import-backup")
def dist_import_backup_endpoint(payload: dict = Body(...), user: dict = Depends(get_current_user)):
    return _perform_import(payload, user)
