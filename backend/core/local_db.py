import os
import sqlite3
import json
import datetime
import threading

class LocalDBManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(LocalDBManager, cls).__new__(cls)
                cls._instance._init_db()
        return cls._instance

    def _init_db(self):
        import sys
        import shutil
        if getattr(sys, 'frozen', False):
            app_data = os.environ.get('LOCALAPPDATA') or os.environ.get('APPDATA') or os.path.expanduser('~')
            base_dir = os.path.join(app_data, 'Skop0')
            os.makedirs(base_dir, exist_ok=True)
            self.db_path = os.path.join(base_dir, 'skop0_local.db')
            # Migracion transparente sin perdida de historial desde SecScan previo
            legacy_db = os.path.join(app_data, 'SecScan', 'secscan_local.db')
            if not os.path.exists(self.db_path) and os.path.exists(legacy_db):
                try:
                    shutil.copy2(legacy_db, self.db_path)
                except Exception:
                    self.db_path = legacy_db
        else:
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            os.makedirs(base_dir, exist_ok=True)
            legacy_dev_db = os.path.join(base_dir, 'secscan_local.db')
            self.db_path = legacy_dev_db if os.path.exists(legacy_dev_db) else os.path.join(base_dir, 'skop0_local.db')
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT,
                user_id TEXT,
                mac TEXT,
                hostname TEXT,
                fabricante TEXT,
                total_vulnerabilidades INTEGER,
                max_score REAL,
                fecha_auditoria TEXT,
                estado TEXT,
                es_nuevo INTEGER,
                primera_conexion TEXT,
                scan_id TEXT,
                dispositivo_tipo TEXT,
                icono TEXT,
                categoria_nombre TEXT,
                raw_data_json TEXT,
                PRIMARY KEY (ip, user_id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                cve_id TEXT,
                user_id TEXT,
                descripcion TEXT,
                severidad TEXT,
                score REAL,
                ip TEXT,
                puerto INTEGER,
                servicio TEXT,
                version TEXT,
                fecha_deteccion TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT,
                user_id TEXT,
                status TEXT,
                devices_found INTEGER,
                total_targets INTEGER,
                vulnerabilidades_found INTEGER,
                timestamp TEXT,
                end_time TEXT,
                topology_json TEXT,
                logs_json TEXT,
                target_ip TEXT,
                network_name TEXT,
                PRIMARY KEY (scan_id, user_id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_devices (
                scan_id TEXT,
                ip TEXT,
                user_id TEXT,
                device_data_json TEXT,
                PRIMARY KEY (scan_id, ip, user_id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS offline_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_type TEXT,
                user_id TEXT,
                payload_json TEXT,
                timestamp TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cve_cache (
                keyword TEXT PRIMARY KEY,
                cves_json TEXT,
                cached_at TEXT
            )
        ''')

        # Migraciones automáticas seguras para bases de datos existentes
        migrations = [
            ("scans", "target_ip", "TEXT"),
            ("scans", "network_name", "TEXT"),
            ("devices", "dispositivo_tipo", "TEXT"),
            ("devices", "icono", "TEXT"),
            ("devices", "categoria_nombre", "TEXT"),
            ("devices", "raw_data_json", "TEXT"),
            ("devices", "medio_conexion", "TEXT"),
            ("devices", "medio_label", "TEXT"),
            ("devices", "medio_icono", "TEXT"),
        ]
        for table, col, col_type in migrations:
            try:
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
            except sqlite3.OperationalError:
                pass
        
        # Migración: poblar network_name en auditorías históricas huérfanas (solo si existen)
        try:
            orphan = cursor.execute(
                "SELECT 1 FROM scans WHERE (network_name IS NULL OR network_name = '' OR network_name = 'Red Local' OR network_name = 'auto') AND (target_ip = 'auto' OR target_ip IS NULL OR target_ip = '') LIMIT 1"
            ).fetchone()
            if orphan:
                from core.scanner import get_active_network_name
                cur_net = get_active_network_name()
                if cur_net and cur_net != "Red Local":
                    cursor.execute(
                        "UPDATE scans SET network_name = ? WHERE (network_name IS NULL OR network_name = '' OR network_name = 'Red Local' OR network_name = 'auto') AND (target_ip = 'auto' OR target_ip IS NULL OR target_ip = '')",
                        (cur_net,)
                    )
        except Exception:
            pass

        conn.commit()
        conn.close()
        print(f"[SQLite] Base de datos local inicializada en: {self.db_path}")

    def get_connection(self):
        """Retorna una conexión a la base de datos SQLite."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def execute_write(self, query, params=()):
        with self._lock:
            conn = self.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(query, params)
                conn.commit()
                return cursor.lastrowid
            finally:
                conn.close()

    def execute_read(self, query, params=()):
        with self._lock:
            conn = self.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(query, params)
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            finally:
                conn.close()
