import datetime
import json
import socket
import time
import threading
from core.firebase_client import FirebaseDB
from core.local_db import LocalDBManager

class NetworkChecker:
    _is_online = True
    _last_check = 0.0
    _lock = threading.Lock()

    @classmethod
    def is_online(cls) -> bool:
        now = time.time()
        if now - cls._last_check < 5.0:
            return cls._is_online
        
        with cls._lock:
            if now - cls._last_check < 5.0:
                return cls._is_online
            try:
                socket.create_connection(("8.8.8.8", 53), timeout=0.5)
                cls._is_online = True
            except OSError:
                cls._is_online = False
            cls._last_check = now
            return cls._is_online

class LocalDocumentSnapshot:
    """Helper para simular el comportamiento de DocumentSnapshot en modo local."""
    def __init__(self, exists: bool, data: dict = None):
        self.exists = exists
        self._data = data
    
    def to_dict(self):
        return self._data

class DatabaseService:
    _scan_log_lock = threading.Lock()

    def __init__(self):
        self._db = None
        self._firebase_checked = False
        self._firebase_active = False
        self.local_db = LocalDBManager()

    def _ensure_firebase(self):
        if not self._firebase_checked:
            self._firebase_checked = True
            try:
                self._db = FirebaseDB().get_db()
                self._firebase_active = self._db is not None
            except Exception as e:
                print(f"[DB SERVICE] Advertencia: Firebase no inicializado, trabajando en modo local offline: {e}")
                self._db = None
                self._firebase_active = False
        return self._db

    @property
    def db(self):
        return self._ensure_firebase()

    @db.setter
    def db(self, value):
        self._db = value
        self._firebase_checked = True
        self._firebase_active = value is not None

    @property
    def firebase_active(self):
        self._ensure_firebase()
        return self._firebase_active

    @firebase_active.setter
    def firebase_active(self, value):
        self._firebase_checked = True
        self._firebase_active = bool(value)

    def _get_user_ref(self, user_id: str):
        """Obtiene referencia al documento del usuario en Firestore (para perfil y suscripciones)."""
        if not user_id:
            user_id = "anonymous"
        if not self.db:
            raise ConnectionError("Firestore no inicializado")
        return self.db.collection("users").document(user_id)

    # =========================================================================
    # HISTORIAL DE DISPOSITIVOS Y ARP (100% LOCAL EN SQLITE)
    # =========================================================================

    def get_historial_doc(self, id_unico: str, user_id: str = ""):
        """Lee el registro previo de un dispositivo desde SQLite para determinar fecha primera conexión."""
        if not user_id:
            user_id = "anonymous"
            
        rows = self.local_db.execute_read(
            "SELECT * FROM devices WHERE (mac = ? OR ip = ?) AND user_id = ?",
            (id_unico, id_unico, user_id)
        )
        if rows:
            row = rows[0]
            historial_data = {
                "ip_inicial": row["ip"],
                "mac": row["mac"],
                "primera_conexion": row["primera_conexion"],
                "fabricante": row["fabricante"]
            }
            return LocalDocumentSnapshot(exists=True, data=historial_data)
        return LocalDocumentSnapshot(exists=False)

    def save_historial_doc(self, id_unico: str, data: dict, user_id: str = ""):
        """Guarda registro histórico en SQLite."""
        if not user_id:
            user_id = "anonymous"
            
        self.local_db.execute_write(
            "INSERT OR REPLACE INTO devices (ip, user_id, mac, fabricante, primera_conexion, estado) VALUES (?, ?, ?, ?, ?, ?)",
            (data.get("ip_inicial", id_unico), user_id, data.get("mac", id_unico), data.get("fabricante", "Desconocido"), data.get("primera_conexion"), "historial")
        )

    # =========================================================================
    # DISPOSITIVOS (100% LOCAL EN SQLITE)
    # =========================================================================

    def save_device(self, ip: str, document: dict, user_id: str = ""):
        """Guarda o actualiza un dispositivo auditado en la base de datos local."""
        if not user_id:
            user_id = "anonymous"
            
        self.local_db.execute_write(
            '''INSERT OR REPLACE INTO devices 
               (ip, user_id, mac, hostname, fabricante, total_vulnerabilidades, max_score, fecha_auditoria, 
                estado, es_nuevo, primera_conexion, scan_id, dispositivo_tipo, icono, categoria_nombre, raw_data_json) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (ip, user_id, document.get("mac"), document.get("hostname"), document.get("fabricante"),
             document.get("total_vulnerabilidades", 0), document.get("max_score", 0.0), document.get("fecha_auditoria"),
             document.get("estado"), 1 if document.get("es_nuevo") else 0, document.get("primera_conexion"), document.get("scan_id"),
             document.get("dispositivo_tipo", ""), document.get("icono", ""), document.get("categoria_nombre", ""), json.dumps(document))
        )

    def get_all_devices(self, user_id: str = "") -> list:
        """Obtiene todos los dispositivos auditados activos para el usuario desde SQLite."""
        if not user_id:
            user_id = "anonymous"
            
        rows = self.local_db.execute_read(
            "SELECT * FROM devices WHERE (user_id = ? OR user_id = 'anonymous' OR user_id = 'local_user' OR user_id = '' OR user_id IS NULL) AND estado != 'historial'",
            (user_id,)
        )
        if not rows:
            rows = self.local_db.execute_read(
                "SELECT * FROM devices WHERE estado != 'historial'"
            )
        devices = []
        for r in rows:
            dev = {
                "ip": r["ip"],
                "mac": r["mac"],
                "hostname": r["hostname"],
                "fabricante": r["fabricante"],
                "total_vulnerabilidades": r["total_vulnerabilidades"],
                "max_score": r["max_score"],
                "fecha_auditoria": r["fecha_auditoria"],
                "estado": r["estado"],
                "es_nuevo": True if r["es_nuevo"] == 1 else False,
                "primera_conexion": r["primera_conexion"],
                "scan_id": r["scan_id"],
                "dispositivo_tipo": r.get("dispositivo_tipo") or "Desconocido",
                "icono": r.get("icono") or "",
                "categoria_nombre": r.get("categoria_nombre") or "Otro",
            }
            if not dev.get("icono") or dev.get("icono") in ("help-circle", "help", "", "Desconocido"):
                try:
                    from core.device_classifier import classify_device
                    _clasif = classify_device(dev.get("ip") or "", dev.get("mac") or "", dev.get("fabricante") or "", dev.get("hostname") or "", [])
                    dev["icono"] = _clasif["icono"]
                    if not dev.get("dispositivo_tipo") or dev.get("dispositivo_tipo") == "Desconocido":
                        dev["dispositivo_tipo"] = _clasif["tipo"]
                    if not dev.get("medio_conexion"):
                        dev["medio_conexion"] = _clasif.get("medio_conexion", "ethernet")
                        dev["medio_label"] = _clasif.get("medio_label", "Ethernet")
                        dev["medio_icono"] = _clasif.get("medio_icono", "🔌")
                        dev["medio_detalle"] = _clasif.get("medio_detalle", "")
                    if not dev.get("categoria_nombre") or dev.get("categoria_nombre") == "Otro":
                        dev["categoria_nombre"] = _clasif["categoria"]
                except Exception:
                    dev["icono"] = "💻" 
            if r.get("raw_data_json"):
                try:
                    extra = json.loads(r["raw_data_json"])
                    for k, v in extra.items():
                        if k not in dev or not dev[k]:
                            dev[k] = v
                except Exception:
                    pass
            devices.append(dev)
        return devices

    def get_all_user_devices(self, user_id: str = "") -> list:
        """Obtiene la lista de dispositivos previamente conocidos para detección de modo reposo."""
        if not user_id:
            user_id = "anonymous"
        devs = []
        try:
            rows = self.local_db.execute_read("SELECT * FROM devices WHERE user_id = ?", (user_id,))
            for r in rows:
                devs.append({
                    "ip": r["ip"],
                    "mac": r["mac"],
                    "hostname": r["hostname"],
                    "fabricante": r["fabricante"],
                    "total_vulnerabilidades": r["total_vulnerabilidades"],
                    "max_score": r["max_score"],
                    "fecha_auditoria": r["fecha_auditoria"],
                    "estado": r["estado"],
                    "primera_conexion": r["primera_conexion"],
                    "scan_id": r["scan_id"],
                    "dispositivo_tipo": r.get("dispositivo_tipo") or "Desconocido",
                    "icono": r.get("icono") or "💻",
                    "categoria_nombre": r.get("categoria_nombre") or "Otro",
                })
        except Exception as e:
            print(f"[DB Error] Error obteniendo dispositivos conocidos: {e}")
        return devs

    def clear_devices(self, user_id: str = ""):
        """Limpia los dispositivos activos previos para iniciar un nuevo escaneo."""
        if not user_id:
            user_id = "anonymous"
        self.local_db.execute_write("DELETE FROM devices WHERE user_id = ?", (user_id,))

    # =========================================================================
    # VULNERABILIDADES (100% LOCAL EN SQLITE)
    # =========================================================================

    def save_vulnerability(self, cve_id: str, data: dict, user_id: str = ""):
        """Registra una vulnerabilidad CVE detectada en SQLite."""
        if not user_id:
            user_id = "anonymous"
        ip = data.get("ip", "")
        puerto = data.get("puerto", 0)
        local_id = f"{cve_id}_{user_id}_{ip}_{puerto}"
        
        self.local_db.execute_write(
            '''INSERT OR REPLACE INTO vulnerabilities 
               (id, cve_id, user_id, descripcion, severidad, score, ip, puerto, servicio, version, fecha_deteccion) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (local_id, cve_id, user_id, data.get("descripcion"), data.get("severidad"), data.get("score", 0.0),
             ip, puerto, data.get("servicio"), data.get("version"), data.get("fecha_deteccion"))
        )

    def get_all_vulnerabilities(self, user_id: str = "") -> list:
        """Obtiene todas las vulnerabilidades detectadas para el usuario ordenadas por score."""
        if not user_id:
            user_id = "anonymous"
            
        rows = self.local_db.execute_read(
            "SELECT * FROM vulnerabilities WHERE user_id = ? ORDER BY score DESC",
            (user_id,)
        )
        vulns = []
        for r in rows:
            vulns.append({
                "cve_id": r["cve_id"],
                "descripcion": r["descripcion"],
                "severidad": r["severidad"],
                "score": r["score"],
                "ip": r["ip"],
                "puerto": r["puerto"],
                "servicio": r["servicio"],
                "version": r["version"],
                "fecha_deteccion": r["fecha_deteccion"]
            })
        return vulns

    def clear_vulnerabilities(self, user_id: str = ""):
        """Limpia las vulnerabilidades activas del usuario."""
        if not user_id:
            user_id = "anonymous"
        self.local_db.execute_write("DELETE FROM vulnerabilities WHERE user_id = ?", (user_id,))

    # =========================================================================
    # ESCANEOS Y HISTORIAL DE AUDITORÍAS (100% LOCAL EN SQLITE)
    # =========================================================================

    def scan_exists(self, user_id: str, scan_id: str) -> bool:
        """Verifica si un scan_id ya existe en la base de datos local."""
        if not user_id:
            user_id = "anonymous"
        rows = self.local_db.execute_read(
            "SELECT scan_id FROM scans WHERE scan_id = ? AND user_id = ?",
            (scan_id, user_id)
        )
        return len(rows) > 0

    def init_scan(self, user_id: str, scan_id: str, target_ip: str = ""):
        """Inicializa un nuevo escaneo en SQLite."""
        if not user_id:
            user_id = "anonymous"
        self.local_db.execute_write(
            "INSERT OR REPLACE INTO scans (scan_id, user_id, timestamp, status, target_ip) VALUES (?, ?, ?, ?, ?)",
            (scan_id, user_id, datetime.datetime.utcnow().isoformat(), "processing", target_ip)
        )

    def mark_scan_processed(self, user_id: str, scan_id: str, ip: str = ""):
        """Marca un escaneo en estado processing en SQLite."""
        if not user_id:
            user_id = "anonymous"
        self.local_db.execute_write(
            '''INSERT INTO scans (scan_id, user_id, timestamp, status, target_ip) VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(scan_id, user_id) DO UPDATE SET status = 'processing' ''',
            (scan_id, user_id, datetime.datetime.utcnow().isoformat(), "processing", ip)
        )

    def update_scan_metadata(self, user_id: str, scan_id: str, metadata: dict):
        """Actualiza metadatos del escaneo (dispositivos, targets, topología, estado) en SQLite."""
        if not user_id:
            user_id = "anonymous"
            
        status = metadata.get("status")
        devices_found = metadata.get("devices_found")
        total_targets = metadata.get("total_targets")
        vulns_found = metadata.get("vulnerabilidades_found")
        end_time = metadata.get("end_time")
        target_ip = metadata.get("target_ip")
        network_name = metadata.get("network_name")
        topology = metadata.get("topology")
        logs = metadata.get("logs")
        
        query_parts = []
        params = []
        if status is not None:
            query_parts.append("status = ?")
            params.append(status)
        if devices_found is not None:
            query_parts.append("devices_found = ?")
            params.append(devices_found)
        if total_targets is not None:
            query_parts.append("total_targets = ?")
            params.append(total_targets)
        if vulns_found is not None:
            query_parts.append("vulnerabilidades_found = ?")
            params.append(vulns_found)
        if end_time is not None:
            query_parts.append("end_time = ?")
            params.append(end_time)
        if target_ip is not None:
            query_parts.append("target_ip = ?")
            params.append(target_ip)
        if network_name is not None:
            query_parts.append("network_name = ?")
            params.append(network_name)
        if topology is not None:
            query_parts.append("topology_json = ?")
            params.append(json.dumps(topology))
        if logs is not None:
            query_parts.append("logs_json = ?")
            params.append(json.dumps(logs))
            
        if query_parts:
            params.extend([scan_id, user_id])
            self.local_db.execute_write(
                f"UPDATE scans SET {', '.join(query_parts)} WHERE scan_id = ? AND user_id = ?",
                tuple(params)
            )

    def increment_vulnerabilities(self, user_id: str, scan_id: str, amount: int):
        """Incrementa el contador de vulnerabilidades en el escaneo local."""
        if not user_id:
            user_id = "anonymous"
        if amount <= 0:
            return
            
        self.local_db.execute_write(
            "UPDATE scans SET vulnerabilidades_found = COALESCE(vulnerabilidades_found, 0) + ? WHERE scan_id = ? AND user_id = ?",
            (amount, scan_id, user_id)
        )

    def increment_devices(self, user_id: str, scan_id: str, amount: int = 1):
        """Incrementa el contador de dispositivos procesados en el escaneo local."""
        if not user_id:
            user_id = "anonymous"
            
        self.local_db.execute_write(
            "UPDATE scans SET devices_found = COALESCE(devices_found, 0) + ? WHERE scan_id = ? AND user_id = ?",
            (amount, scan_id, user_id)
        )

    def append_scan_log(self, user_id: str, scan_id: str, message: str):
        """Agrega un mensaje de log al escaneo en SQLite de forma atómica (thread-safe)."""
        if not user_id:
            user_id = "anonymous"
        entry = f"[{datetime.datetime.utcnow().strftime('%H:%M:%S')}] {message}"
        
        with self._scan_log_lock:
            try:
                rows = self.local_db.execute_read("SELECT logs_json FROM scans WHERE scan_id = ? AND user_id = ?", (scan_id, user_id))
                logs = []
                if rows and rows[0]["logs_json"]:
                    try:
                        logs = json.loads(rows[0]["logs_json"])
                    except Exception:
                        logs = []
                logs.append(entry)
                
                self.local_db.execute_write(
                    '''INSERT INTO scans (scan_id, user_id, logs_json, status) VALUES (?, ?, ?, ?)
                       ON CONFLICT(scan_id, user_id) DO UPDATE SET logs_json = excluded.logs_json''',
                    (scan_id, user_id, json.dumps(logs), "processing")
                )
            except Exception as ex:
                print(f"[DB LOCAL LOG ERROR] Falló guardar log en SQLite: {ex}")

    def save_scan_device(self, user_id: str, scan_id: str, ip: str, data: dict):
        """Guarda el detalle completo de un dispositivo perteneciente a una auditoría específica."""
        if not user_id:
            user_id = "anonymous"
            
        self.local_db.execute_write(
            "INSERT OR REPLACE INTO scan_devices (scan_id, ip, user_id, device_data_json) VALUES (?, ?, ?, ?)",
            (scan_id, ip, user_id, json.dumps(data))
        )

    def get_user_scans(self, user_id: str) -> list:
        """Obtiene la lista histórica de auditorías del usuario desde SQLite."""
        if not user_id:
            user_id = "anonymous"
            
        rows = self.local_db.execute_read(
            "SELECT * FROM scans WHERE user_id = ? OR user_id = 'anonymous' OR user_id = 'local_user' OR user_id = '' OR user_id IS NULL ORDER BY timestamp DESC",
            (user_id,)
        )
        if not rows:
            rows = self.local_db.execute_read("SELECT * FROM scans ORDER BY timestamp DESC")

        active_net = None
        scans = []
        for r in rows:
            net_name = r.get("network_name") or ""
            target_ip = r.get("target_ip") or ""
            if not net_name or net_name.strip() in ("", "auto", "Red Local"):
                if not active_net:
                    try:
                        from core.scanner import get_active_network_name
                        active_net = get_active_network_name(fallback_target=target_ip)
                    except Exception:
                        active_net = "Red Local"
                net_name = active_net if (not target_ip or target_ip == "auto") else f"Red {target_ip}"
            scans.append({
                "id": r["scan_id"],
                "scan_id": r["scan_id"],
                "status": r["status"],
                "devices_found": r["devices_found"] or 0,
                "total_targets": r["total_targets"] or 0,
                "vulnerabilidades_found": r["vulnerabilidades_found"] or 0,
                "timestamp": r["timestamp"],
                "end_time": r["end_time"],
                "target_ip": target_ip,
                "network_name": net_name
            })
        return scans

    def get_scan_details(self, user_id: str, scan_id: str):
        """Obtiene el detalle completo de una auditoría desde SQLite."""
        if not user_id:
            user_id = "anonymous"
            
        rows = self.local_db.execute_read(
            "SELECT * FROM scans WHERE scan_id = ? AND (user_id = ? OR user_id = 'anonymous' OR user_id = 'local_user' OR user_id = '' OR user_id IS NULL)",
            (scan_id, user_id)
        )
        if not rows:
            rows = self.local_db.execute_read(
                "SELECT * FROM scans WHERE scan_id = ?",
                (scan_id,)
            )

        if rows:
            r = rows[0]
            logs = []
            topology = {}
            if r["logs_json"]:
                try:
                    logs = json.loads(r["logs_json"]) if isinstance(r["logs_json"], str) else r["logs_json"]
                except Exception:
                    logs = []
            if r["topology_json"]:
                try:
                    topology = json.loads(r["topology_json"]) if isinstance(r["topology_json"], str) else r["topology_json"]
                except Exception:
                    topology = {}
                
            return {
                "id": r["scan_id"],
                "scan_id": r["scan_id"],
                "status": r["status"],
                "devices_found": r["devices_found"] or 0,
                "total_targets": r["total_targets"] or 0,
                "vulnerabilidades_found": r["vulnerabilidades_found"] or 0,
                "timestamp": r["timestamp"],
                "end_time": r["end_time"],
                "target_ip": r.get("target_ip") or "",
                "network_name": (
                    r.get("network_name") if (r.get("network_name") and r.get("network_name") not in ("auto", "Red Local", ""))
                    else (
                        __import__("core.scanner", fromlist=["get_active_network_name"]).get_active_network_name(r.get("target_ip") or "")
                    )
                ),
                "logs": logs,
                "topology": topology
            }
        return None

    def get_scan_devices(self, user_id: str, scan_id: str) -> list:
        """Obtiene todos los dispositivos de una auditoría específica desde SQLite."""
        if not user_id:
            user_id = "anonymous"
            
        rows = self.local_db.execute_read(
            "SELECT device_data_json FROM scan_devices WHERE scan_id = ? AND (user_id = ? OR user_id = 'anonymous' OR user_id = 'local_user' OR user_id = '' OR user_id IS NULL)",
            (scan_id, user_id)
        )
        if not rows:
            rows = self.local_db.execute_read(
                "SELECT device_data_json FROM scan_devices WHERE scan_id = ?",
                (scan_id,)
            )

        devices = []
        for r in rows:
            if r["device_data_json"]:
                try:
                    dev_obj = r["device_data_json"] if isinstance(r["device_data_json"], dict) else json.loads(r["device_data_json"])
                    if not dev_obj.get("icono") or dev_obj.get("icono") in ("help-circle", "help", "", "Desconocido"):
                        try:
                            from core.device_classifier import classify_device
                            _cl = classify_device(dev_obj.get("ip") or "", dev_obj.get("mac") or "", dev_obj.get("fabricante") or dev_obj.get("vendor") or "", dev_obj.get("hostname") or "", dev_obj.get("puertos_abiertos") or [])
                            dev_obj["icono"] = _cl["icono"]
                            if not dev_obj.get("dispositivo_tipo"):
                                dev_obj["dispositivo_tipo"] = _cl["tipo"]
                            if not dev_obj.get("medio_conexion"):
                                dev_obj["medio_conexion"] = _cl.get("medio_conexion", "ethernet")
                                dev_obj["medio_label"] = _cl.get("medio_label", "Ethernet")
                                dev_obj["medio_icono"] = _cl.get("medio_icono", "🔌")
                                dev_obj["medio_detalle"] = _cl.get("medio_detalle", "")
                            if not dev_obj.get("categoria_nombre"):
                                dev_obj["categoria_nombre"] = _cl["categoria"]
                        except Exception:
                            dev_obj["icono"] = "💻"
                    devices.append(dev_obj)
                except Exception:
                    pass
        return devices

    def delete_scan(self, user_id: str, scan_id: str) -> bool:
        """Elimina una auditoría y sus dispositivos asociados de SQLite."""
        if not user_id:
            user_id = "anonymous"
        try:
            self.local_db.execute_write(
                "DELETE FROM scan_devices WHERE scan_id = ? AND (user_id = ? OR user_id = 'anonymous' OR user_id = 'local_user' OR user_id = '' OR user_id IS NULL)",
                (scan_id, user_id)
            )
            self.local_db.execute_write(
                "DELETE FROM scans WHERE scan_id = ? AND (user_id = ? OR user_id = 'anonymous' OR user_id = 'local_user' OR user_id = '' OR user_id IS NULL)",
                (scan_id, user_id)
            )
            # Fallback para eliminar por scan_id en caso de haber sido importado
            self.local_db.execute_write(
                "DELETE FROM scan_devices WHERE scan_id = ?",
                (scan_id,)
            )
            self.local_db.execute_write(
                "DELETE FROM scans WHERE scan_id = ?",
                (scan_id,)
            )
            return True
        except Exception as e:
            print(f"[SecScan DB] Error al eliminar escaneo {scan_id}: {e}")
            return False

    def delete_scans_batch(self, user_id: str, scan_ids: list) -> int:
        """Elimina múltiples auditorías y sus dispositivos asociados en bloque."""
        if not scan_ids:
            return 0
        deleted_count = 0
        for scan_id in scan_ids:
            if self.delete_scan(user_id, scan_id):
                deleted_count += 1
        return deleted_count

    def cleanup_dangling_scans(self):
        """Cancela cualquier escaneo que haya quedado en 'processing' por cierre abrupto de la aplicación."""
        now = datetime.datetime.utcnow().isoformat()
        try:
            rows = self.local_db.execute_read("SELECT scan_id, user_id FROM scans WHERE status = 'processing'")
            if rows:
                print(f"[SecScan DB] Limpiando {len(rows)} escaneo(s) interrumpidos por cierre previo...")
                for r in rows:
                    sid = r["scan_id"]
                    uid = r["user_id"]
                    self.local_db.execute_write(
                        "UPDATE scans SET status = 'cancelled', end_time = ? WHERE scan_id = ? AND user_id = ?",
                        (now, sid, uid)
                    )
                    self.append_scan_log(uid, sid, "[SYS] Escaneo cancelado automáticamente: la aplicación fue cerrada durante el proceso.")
        except Exception as e:
            print(f"[SecScan DB] Error en cleanup_dangling_scans: {e}")

    # =========================================================================
    # PERFIL Y NUBE (EXCLUSIVO PARA CUENTAS Y LICENCIAS - LIGERO)
    # =========================================================================

    def create_user_profile(self, user_id: str, email: str = ""):
        """Crea o actualiza el perfil base en Firestore (solo datos de cuenta)."""
        if not user_id:
            user_id = "anonymous"
        try:
            if self.firebase_active and NetworkChecker.is_online():
                user_ref = self._get_user_ref(user_id)
                user_ref.collection("profile").document("data").set({
                    "createdAt": datetime.datetime.utcnow().isoformat(),
                    "email": email,
                    "status": "active"
                }, merge=True)
        except Exception as e:
            print(f"[DB WRITE ERROR] No se pudo crear perfil en Firebase: {e}")

    def run_db_test(self):
        """Prueba de diagnóstico de la base de datos local SQLite."""
        test_write = self.local_db.execute_write("SELECT 1")
        print("[SecScan DB] Test de base de datos local SQLite completado exitosamente.")
        return True
