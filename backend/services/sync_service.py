import time
import threading
from core.local_db import LocalDBManager

_sync_daemon_started = False
_sync_daemon_lock = threading.Lock()

def start_sync_daemon():
    """Lanza el hilo de sincronización en segundo plano."""
    global _sync_daemon_started
    with _sync_daemon_lock:
        if _sync_daemon_started:
            return
        _sync_daemon_started = True
        
    thread = threading.Thread(target=_run_sync_worker, daemon=True, name="SyncDaemon")
    thread.start()
    print("[SyncDaemon] Hilo de mantenimiento local iniciado correctamente.")

def _run_sync_worker():
    """
    Worker en segundo plano. En la arquitectura 100% local, los datos de escaneos
    se almacenan y consultan exclusivamente en SQLite local.
    """
    time.sleep(5)
    local_db = LocalDBManager()
    
    # Limpiar cola obsoleta de sincronizaciones previas para evitar acumulación
    try:
        local_db.execute_write("DELETE FROM offline_queue")
    except Exception:
        pass
        
    while True:
        # En modo local, la cola no se utiliza para escaneos.
        time.sleep(60)
