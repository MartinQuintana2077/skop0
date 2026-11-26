import os
import sys
import time
import threading

_lock = threading.Lock()
_active_ws_sessions = 0
_has_connected_once = False
_last_heartbeat_time = time.time()
_start_time = time.time()
_browser_launched_at = None
_watchdog_started = False


def mark_browser_launched():
    """Registra el momento en que se lanzó la ventana del navegador de SecScan."""
    global _browser_launched_at
    with _lock:
        _browser_launched_at = time.time()


def record_heartbeat():
    """Actualiza la marca de tiempo de actividad desde cualquier endpoint de heartbeat o WS."""
    global _last_heartbeat_time, _has_connected_once
    with _lock:
        _last_heartbeat_time = time.time()
        _has_connected_once = True


def ws_connected():
    """Registra una nueva sesión WebSocket activa."""
    global _active_ws_sessions, _has_connected_once, _last_heartbeat_time
    with _lock:
        _active_ws_sessions += 1
        _has_connected_once = True
        _last_heartbeat_time = time.time()


def ws_disconnected():
    """Registra la desconexión de una sesión WebSocket y programa verificación de cierre."""
    global _active_ws_sessions
    should_check = False
    with _lock:
        _active_ws_sessions = max(0, _active_ws_sessions - 1)
        if _active_ws_sessions == 0 and getattr(sys, "frozen", False):
            should_check = True
    if should_check:
        threading.Thread(target=_check_after_ws_drop, daemon=True, name="WsDropCheck").start()


def is_browser_profile_alive() -> bool:
    """Verifica si existe algún proceso msedge.exe / chrome.exe usando el perfil aislado de SecScan."""
    try:
        import psutil
        for proc in psutil.process_iter(["name", "cmdline"]):
            try:
                pname = (proc.info.get("name") or "").lower()
                if pname not in ("msedge.exe", "chrome.exe"):
                    continue
                cmdline = " ".join(proc.info.get("cmdline") or []).lower()
                if "browser_profile" in cmdline:
                    return True
            except Exception:
                continue
    except Exception:
        return True
    return False


def safe_cleanup_and_exit(code: int = 0):
    """Limpia puentes de subred, cierra procesos huérfanos del navegador de SecScan y finaliza."""
    try:
        from core.subnet_bridge import cleanup_all_bridges
        cleanup_all_bridges()
    except Exception:
        pass
    try:
        from core.updater import close_secscan_browser_windows
        close_secscan_browser_windows()
    except Exception:
        pass
    os._exit(code)


def _check_after_ws_drop():
    """
    Al cerrarse el último WebSocket, espera 3.5s (margen amplio para F5/Ctrl+R).
    Si no hubo reconexión ni nuevo heartbeat en ese lapso, finaliza SecScan.exe inmediatamente.
    """
    if not getattr(sys, "frozen", False):
        return
    time.sleep(3.5)
    with _lock:
        now = time.time()
        if _has_connected_once and _active_ws_sessions == 0 and (now - _last_heartbeat_time) >= 2.8:
            print("[Skop0] Ventana cerrada (sin WS ni heartbeat). Finalizando proceso...")
            safe_cleanup_and_exit(0)


def _watchdog_loop():
    """Vigilante permanente de respaldo (cubre cierres abruptos o cierres antes de cargar React)."""
    if not getattr(sys, "frozen", False):
        return
    while True:
        time.sleep(2.0)
        now = time.time()
        with _lock:
            ws_count = _active_ws_sessions
            connected = _has_connected_once
            last_hb = _last_heartbeat_time
            launched_at = _browser_launched_at

        # Caso 1: Ya hubo sesión activa, ahora no hay WS y pasaron > 5.5s sin heartbeat
        if connected and ws_count == 0 and (now - last_hb) > 5.5:
            print("[Skop0] Sesión finalizada por watchdog de heartbeat. Cerrando...")
            safe_cleanup_and_exit(0)

        # Caso 2: El usuario cerró la ventana antes de que React estableciera sesión
        if launched_at is not None and (now - launched_at) > 10.0 and ws_count == 0 and (now - last_hb) > 5.5:
            if not is_browser_profile_alive():
                time.sleep(1.5)
                with _lock:
                    if _active_ws_sessions == 0 and (time.time() - _last_heartbeat_time) > 5.5:
                        if not is_browser_profile_alive():
                            print("[Skop0] Navegador cerrado antes de conectar sesión. Finalizando...")
                            safe_cleanup_and_exit(0)


def start_lifecycle_watchdog():
    """Inicia el hilo vigilante de ciclo de vida en modo ejecutable (.exe)."""
    global _watchdog_started
    with _lock:
        if _watchdog_started:
            return
        _watchdog_started = True
    if getattr(sys, "frozen", False):
        threading.Thread(target=_watchdog_loop, daemon=True, name="LifecycleWatchdog").start()
