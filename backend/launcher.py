import os
import sys
import subprocess
import time
import socket
import webbrowser
import threading
import multiprocessing
import atexit

# Redirigir streams si corre sin consola (--noconsole en Windows) para evitar caídas
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w', encoding='utf-8')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w', encoding='utf-8')

# Silenciar 100% de consolas en subprocesos de Windows (incluye python-nmap, arp, ping, etc.)
if sys.platform == 'win32':
    _orig_popen = subprocess.Popen
    class _SilentPopen(_orig_popen):
        def __init__(self, *args, **kwargs):
            if 'creationflags' not in kwargs:
                kwargs['creationflags'] = 0x08000000
            else:
                kwargs['creationflags'] |= 0x08000000
            super().__init__(*args, **kwargs)
    subprocess.Popen = _SilentPopen

for nmap_dir in [r'C:\Program Files (x86)\Nmap', r'C:\Program Files\Nmap']:
    if os.path.exists(nmap_dir) and nmap_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = nmap_dir + os.pathsep + os.environ.get("PATH", "")


def is_server_running(host="127.0.0.1", port=8000, timeout=0.12) -> bool:
    """Verifica instantáneamente si ya hay una instancia de Skop0 escuchando en el puerto local."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.error, OSError):
        return False


def wait_for_server(host="127.0.0.1", port=8000, timeout=25):
    """Espera activamente a que el servidor Uvicorn esté escuchando en el puerto 8000."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        if is_server_running(host, port, timeout=0.06):
            return True
        time.sleep(0.025)
    return False


_WINDOW_TITLES = (
    "Skop0 | Monitoreo de Vulnerabilidades",
    "SecScan | Monitoreo de Vulnerabilidades",
)


def _find_app_hwnd(user32):
    for title in _WINDOW_TITLES:
        hwnd = user32.FindWindowW(None, title)
        if hwnd:
            return hwnd
    return 0


def _focus_existing_app_window() -> bool:
    """Si ya existe una ventana abierta de Skop0, la restaura y trae al frente."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        user32 = ctypes.windll.user32
        SW_MAXIMIZE = 3
        hwnd = _find_app_hwnd(user32)
        if hwnd and user32.IsWindowVisible(hwnd):
            user32.ShowWindow(hwnd, SW_MAXIMIZE)
            user32.SetForegroundWindow(hwnd)
            return True
    except Exception:
        pass
    return False


def _maximize_app_window():
    """Fuerza la ventana de Skop0 a pantalla completa / maximizada (SW_MAXIMIZE = 3) en Windows."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        user32 = ctypes.windll.user32
        SW_MAXIMIZE = 3

        for _ in range(35):
            hwnd = _find_app_hwnd(user32)
            if hwnd:
                user32.ShowWindow(hwnd, SW_MAXIMIZE)
                user32.SetForegroundWindow(hwnd)
                break
            time.sleep(0.15)
    except Exception:
        pass


def _reset_browser_zoom(profile_dir: str):
    """Restablece cualquier nivel de zoom guardado (ej. 50%) al 100% nativo antes de abrir la ventana."""
    try:
        import json
        prefs_path = os.path.join(profile_dir, "Default", "Preferences")
        if os.path.exists(prefs_path):
            with open(prefs_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            changed = False
            if isinstance(data.get("partition"), dict) and "per_host_zoom_levels" in data["partition"]:
                data["partition"]["per_host_zoom_levels"] = {}
                changed = True
            if "profile" in data and isinstance(data["profile"], dict) and "default_zoom_level" in data["profile"]:
                data["profile"]["default_zoom_level"] = {}
                changed = True
            if changed:
                with open(prefs_path, "w", encoding="utf-8") as f:
                    json.dump(data, f)
    except Exception:
        pass


def open_app_window(wait_server: bool = True, close_existing: bool = True):
    """
    Abre la ventana de la aplicación Skop0 en cuanto el servidor local esté listo:
    1. Prepara perfil, zoom y limpia ventanas huérfanas EN PARALELO mientras arranca Uvicorn.
    2. Espera activamente a que el socket 127.0.0.1:8000 responda para nunca
       mostrar pantallas de 'conexión rechazada'.
    3. Lanza Edge/Chrome inmediatamente maximizado al 100% de zoom.
    """
    target_url = "http://localhost:8000"

    # Preparar perfil y cerrar ventanas huérfanas EN PARALELO antes de esperar el socket
    if close_existing:
        try:
            from core.updater import close_secscan_browser_windows
            killed = close_secscan_browser_windows()
            if killed:
                time.sleep(0.15)
        except Exception:
            pass

    # Perfil de usuario aislado para Skop0 (conserva sesión/preferencias previas si ya existía perfil)
    legacy_profile = os.path.expandvars(r"%APPDATA%\SecScan\browser_profile")
    skop0_profile = os.path.expandvars(r"%APPDATA%\Skop0\browser_profile")
    profile_dir = legacy_profile if os.path.exists(legacy_profile) else skop0_profile
    try:
        os.makedirs(profile_dir, exist_ok=True)
    except Exception:
        pass

    _reset_browser_zoom(profile_dir)

    if wait_server:
        wait_for_server("127.0.0.1", 8000, timeout=25)

    # Parámetros de protección: sin DevTools, sin zoom pinch, sin procesos en 2º plano, maximizado
    browser_args = [
        f"--user-data-dir={profile_dir}",
        f"--app={target_url}",
        "--app-id=Skop0.Auditor",
        "--disable-dev-tools",
        "--disable-pinch",
        "--disable-background-mode",
        "--disable-features=Translate",
        "--disable-popup-blocking",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--start-maximized"
    ]

    edge_paths = [
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
    ]
    chrome_paths = [
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
    ]

    opened = False
    for browser_path in edge_paths + chrome_paths:
        if os.path.exists(browser_path):
            try:
                cmd = [browser_path] + browser_args
                _orig_popen(cmd)
                opened = True
                try:
                    from core.lifecycle import mark_browser_launched
                    mark_browser_launched()
                except Exception:
                    pass
                threading.Thread(target=_maximize_app_window, daemon=True).start()
                break
            except Exception:
                continue

    if not opened:
        webbrowser.open("http://localhost:8000")


def main():
    multiprocessing.freeze_support()

    # Instancia única inteligente: si Skop0 ya está corriendo en 127.0.0.1:8000,
    # enfocar su ventana o reabrirla inmediatamente en lugar de fallar en silencio.
    if is_server_running("127.0.0.1", 8000):
        if not _focus_existing_app_window():
            open_app_window(wait_server=False, close_existing=True)
            _maximize_app_window()
        return

    # Registrar limpieza preventiva al salir sin bloquear el arranque inicial
    def _register_exit_cleanup():
        try:
            from core.subnet_bridge import cleanup_all_bridges
            atexit.register(cleanup_all_bridges)
        except Exception:
            pass
    threading.Thread(target=_register_exit_cleanup, daemon=True).start()

    # Iniciar hilo de la ventana de aplicación
    threading.Thread(target=open_app_window, daemon=True).start()

    print("=" * 50)
    print("   SKOP0 - SERVIDOR Y APLICACION EN EJECUCION")
    print("   Acceso Local: http://127.0.0.1:8000")
    print("=" * 50)

    # Iniciar Uvicorn
    import uvicorn
    from app import app
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")


if __name__ == "__main__":
    main()
