import os
import re
import sys
import time
import json
import tempfile
import threading
import subprocess
import urllib.request
import urllib.error

def _load_app_version() -> str:
    candidates = [
        os.path.join(os.path.dirname(sys.executable), "app_version.txt"),
        os.path.join(os.path.dirname(sys.executable), "_internal", "app_version.txt"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app_version.txt"),
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    v = f.read().strip()
                    if v:
                        return v
            except Exception:
                pass
    return "1.3.0"


# Versión actual compilada de Skop0
APP_VERSION = _load_app_version()

# Repositorio oficial en GitHub donde se publican los Releases
GITHUB_REPO = "MartinQuintana2077/secscan"
GITHUB_API_LATEST = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
GITHUB_API_RELEASES = f"https://api.github.com/repos/{GITHUB_REPO}/releases"
GITHUB_RAW_VERSION = f"https://raw.githubusercontent.com/{GITHUB_REPO}/exe/version.json"

_update_state_lock = threading.Lock()
_update_state = {
    "status": "idle",        # idle | downloading | ready | installing | error
    "progress": 0,           # 0 - 100
    "downloaded_mb": 0.0,
    "total_mb": 0.0,
    "error": None,
    "installer_path": None,
    "latest_version": None,
}


def parse_version(v_str: str) -> tuple:
    """Convierte 'v1.2.3' o '1.2' en una tupla comparable (1, 2, 3)."""
    if not v_str:
        return (0, 0, 0)
    clean = re.sub(r"[^0-9.]", "", str(v_str).strip())
    parts = [int(p) for p in clean.split(".") if p.isdigit()]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def is_newer_version(remote_ver: str, current_ver: str = APP_VERSION) -> bool:
    """Retorna True si remote_ver es estrictamente mayor que current_ver."""
    return parse_version(remote_ver) > parse_version(current_ver)


def _fetch_json(url: str, timeout: int = 8) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"Skop0-Updater/{APP_VERSION}",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="ignore"))


def check_for_updates() -> dict:
    """
    Consulta Firebase Firestore (tiempo real) y GitHub Releases (con fallback a version.json)
    para verificar si existe una versión más reciente que APP_VERSION.
    """
    candidates = []

    # 1. Consultar Firebase Firestore (app_config/release_info) en tiempo real
    try:
        from core.firebase_client import FirebaseDB
        db = FirebaseDB().get_db()
        doc = db.collection("app_config").document("release_info").get()
        if doc.exists:
            fb_data = doc.to_dict() or {}
            fb_ver = str(fb_data.get("latest_version", "")).lstrip("vV")
            if fb_ver:
                dl_url = fb_data.get("download_url") or f"https://github.com/{GITHUB_REPO}/releases"
                has_exe = bool(fb_data.get("has_direct_exe")) or dl_url.lower().endswith(".exe")
                candidates.append({
                    "status": "ok",
                    "current_version": APP_VERSION,
                    "latest_version": fb_ver,
                    "update_available": is_newer_version(fb_ver, APP_VERSION),
                    "release_title": fb_data.get("release_title") or f"Skop0 v{fb_ver}",
                    "release_notes": fb_data.get("changelog") or fb_data.get("release_notes") or "Nueva actualización disponible.",
                    "published_at": fb_data.get("published_at"),
                    "download_url": dl_url,
                    "html_url": fb_data.get("html_url") or f"https://github.com/{GITHUB_REPO}/releases",
                    "asset_name": fb_data.get("asset_name") or f"Skop0_Setup_v{fb_ver}.exe",
                    "asset_size_mb": fb_data.get("size_mb", 0),
                    "has_direct_exe": has_exe,
                    "mandatory": bool(fb_data.get("mandatory", False)),
                })
    except Exception:
        pass

    release_data = None

    # 2. Intentar /releases/latest en GitHub API
    try:
        release_data = _fetch_json(GITHUB_API_LATEST, timeout=6)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            try:
                all_releases = _fetch_json(GITHUB_API_RELEASES, timeout=6)
                if isinstance(all_releases, list) and len(all_releases) > 0:
                    release_data = all_releases[0]
            except Exception:
                pass
    except Exception:
        pass

    # 3. Procesar respuesta de GitHub Releases si existe
    if release_data and isinstance(release_data, dict) and release_data.get("tag_name"):
        tag = release_data.get("tag_name", "").lstrip("vV")
        name = release_data.get("name") or f"Skop0 v{tag}"
        body = release_data.get("body") or "Mejoras de rendimiento y estabilidad."
        published_at = release_data.get("published_at")
        html_url = release_data.get("html_url") or f"https://github.com/{GITHUB_REPO}/releases"

        assets = release_data.get("assets") or []
        exe_asset = None
        for asset in assets:
            a_name = (asset.get("name") or "").lower()
            if a_name.endswith(".exe"):
                exe_asset = asset
                break

        download_url = exe_asset.get("browser_download_url") if exe_asset else html_url
        asset_name = exe_asset.get("name") if exe_asset else f"Skop0_Setup_v{tag}.exe"
        asset_size = exe_asset.get("size", 0) if exe_asset else 0
        has_direct_exe = bool(exe_asset and exe_asset.get("browser_download_url"))

        mandatory = any(
            kw in body.upper()
            for kw in ["[OBLIGATORIO]", "[MANDATORY]", "[CRITICO]", "[CRÍTICO]"]
        )

        candidates.append({
            "status": "ok",
            "current_version": APP_VERSION,
            "latest_version": tag,
            "update_available": is_newer_version(tag, APP_VERSION),
            "release_title": name,
            "release_notes": body,
            "published_at": published_at,
            "download_url": download_url,
            "html_url": html_url,
            "asset_name": asset_name,
            "asset_size_mb": round(asset_size / (1024 * 1024), 1) if asset_size else 0,
            "has_direct_exe": has_direct_exe,
            "mandatory": mandatory,
        })

    # 4. Fallback: consultar version.json en la rama del repositorio
    try:
        ver_json = _fetch_json(GITHUB_RAW_VERSION, timeout=5)
        if isinstance(ver_json, dict) and ver_json.get("latest_version"):
            tag = str(ver_json.get("latest_version")).lstrip("vV")
            dl_url = ver_json.get("download_url") or f"https://github.com/{GITHUB_REPO}/releases"
            notes = ver_json.get("changelog") or "Nueva actualización disponible."
            mandatory = bool(ver_json.get("mandatory", False))
            has_exe = dl_url.lower().endswith(".exe")

            candidates.append({
                "status": "ok",
                "current_version": APP_VERSION,
                "latest_version": tag,
                "update_available": is_newer_version(tag, APP_VERSION),
                "release_title": f"Skop0 v{tag}",
                "release_notes": notes,
                "published_at": ver_json.get("published_at"),
                "download_url": dl_url,
                "html_url": f"https://github.com/{GITHUB_REPO}/releases",
                "asset_name": f"Skop0_Setup_v{tag}.exe",
                "asset_size_mb": ver_json.get("size_mb", 0),
                "has_direct_exe": has_exe,
                "mandatory": mandatory,
            })
    except Exception:
        pass

    if candidates:
        # Elegir el candidato con la versión más alta; si hay empate, priorizar el que tenga .exe directo de GitHub
        candidates.sort(
            key=lambda c: (parse_version(c.get("latest_version", "0.0.0")), 1 if c.get("has_direct_exe") else 0),
            reverse=True,
        )
        return candidates[0]

    # Si aún no hay releases publicados en el repositorio, informar que está al día
    return {
        "status": "ok",
        "current_version": APP_VERSION,
        "latest_version": APP_VERSION,
        "update_available": False,
        "release_title": f"Skop0 v{APP_VERSION}",
        "release_notes": "Estás utilizando la versión más reciente disponible.",
        "published_at": None,
        "download_url": f"https://github.com/{GITHUB_REPO}/releases",
        "html_url": f"https://github.com/{GITHUB_REPO}/releases",
        "asset_name": None,
        "asset_size_mb": 0,
        "has_direct_exe": False,
        "mandatory": False,
    }


def get_update_progress() -> dict:
    with _update_state_lock:
        return dict(_update_state)


def _download_worker(download_url: str, asset_name: str, latest_version: str):
    update_dir = os.path.join(tempfile.gettempdir(), "Skop0_Updates")
    os.makedirs(update_dir, exist_ok=True)
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", asset_name or f"Skop0_Setup_v{latest_version}.exe")
    if not safe_name.lower().endswith(".exe"):
        safe_name += ".exe"
    dest_path = os.path.join(update_dir, safe_name)

    try:
        req = urllib.request.Request(
            download_url,
            headers={"User-Agent": f"Skop0-Updater/{APP_VERSION}"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            total_size = int(resp.headers.get("Content-Length", 0) or 0)
            total_mb = round(total_size / (1024 * 1024), 1) if total_size else 0.0

            with _update_state_lock:
                _update_state["total_mb"] = total_mb

            downloaded = 0
            chunk_size = 256 * 1024  # 256 KB
            with open(dest_path, "wb") as out_file:
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    out_file.write(chunk)
                    downloaded += len(chunk)
                    dl_mb = round(downloaded / (1024 * 1024), 1)
                    pct = int((downloaded / total_size) * 100) if total_size > 0 else 50
                    with _update_state_lock:
                        _update_state["downloaded_mb"] = dl_mb
                        _update_state["progress"] = min(99, pct)

        with _update_state_lock:
            _update_state["progress"] = 100
            _update_state["installer_path"] = dest_path
            _update_state["status"] = "ready"

    except Exception as e:
        # Fallback local de desarrollo: si el .exe aún no se ha adjuntado al Release de GitHub
        # pero existe en el Escritorio local, simular la descarga desde el instalador compilado
        desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")
        local_candidates = [
            os.path.join(desktop_dir, safe_name),
            os.path.join(desktop_dir, f"Skop0_Setup_v{latest_version}.exe"),
            os.path.join(desktop_dir, "Skop0_Setup_v1.3.0.exe"),
            os.path.join(desktop_dir, "Skop0_Setup_v1.3.exe"),
            os.path.join(desktop_dir, "Skop0_Setup_v1.2.exe"),
            os.path.join(desktop_dir, f"SecScan_Setup_v{latest_version}.exe"),
        ]
        local_found = next((p for p in local_candidates if os.path.exists(p)), None)
        if local_found:
            try:
                total_size = os.path.getsize(local_found)
                total_mb = round(total_size / (1024 * 1024), 1)
                with _update_state_lock:
                    _update_state["total_mb"] = total_mb
                downloaded = 0
                chunk_size = 2 * 1024 * 1024
                with open(local_found, "rb") as src_f, open(dest_path, "wb") as out_f:
                    while True:
                        chunk = src_f.read(chunk_size)
                        if not chunk:
                            break
                        out_f.write(chunk)
                        downloaded += len(chunk)
                        dl_mb = round(downloaded / (1024 * 1024), 1)
                        pct = int((downloaded / total_size) * 100) if total_size > 0 else 100
                        with _update_state_lock:
                            _update_state["downloaded_mb"] = dl_mb
                            _update_state["progress"] = min(99, pct)
                        time.sleep(0.04)
                with _update_state_lock:
                    _update_state["progress"] = 100
                    _update_state["installer_path"] = dest_path
                    _update_state["status"] = "ready"
                return
            except Exception:
                pass

        with _update_state_lock:
            _update_state["status"] = "error"
            _update_state["error"] = f"El archivo instalador aún no está adjunto en GitHub Releases ({str(e)})."


def start_update_download(download_url: str, asset_name: str = None, latest_version: str = "") -> dict:
    if not download_url:
        return {"status": "error", "message": "URL de descarga no válida."}

    with _update_state_lock:
        if _update_state["status"] == "downloading":
            return {"status": "downloading", "message": "La descarga ya está en progreso."}
        _update_state.update({
            "status": "downloading",
            "progress": 0,
            "downloaded_mb": 0.0,
            "total_mb": 0.0,
            "error": None,
            "installer_path": None,
            "latest_version": latest_version,
        })

    t = threading.Thread(
        target=_download_worker,
        args=(download_url, asset_name, latest_version),
        daemon=True,
    )
    t.start()
    return {"status": "downloading", "message": "Descarga iniciada."}


def close_secscan_browser_windows() -> int:
    """
    Cierra únicamente las ventanas de navegador (msedge.exe / chrome.exe) asociadas
    al perfil aislado de Skop0/SecScan (browser_profile) sin afectar el navegador
    personal del usuario ni procesos de sistema. Retorna el número de procesos cerrados.
    """
    killed = 0
    try:
        import psutil
        my_pid = os.getpid()
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                if proc.info.get("pid") == my_pid:
                    continue
                pname = (proc.info.get("name") or "").lower()
                if pname not in ("msedge.exe", "chrome.exe"):
                    continue
                cmdline = " ".join(proc.info.get("cmdline") or []).lower()
                if "browser_profile" in cmdline:
                    proc.kill()
                    killed += 1
            except Exception:
                pass
    except Exception:
        pass
    return killed


def resolve_installer_for_browser() -> dict:
    """
    Determina si la URL remota de GitHub Releases está activa (HTTP 200) o si
    debe entregarse el archivo .exe local directamente al navegador para evitar 404.
    """
    info = check_for_updates()
    dl_url = info.get("download_url") or ""
    latest_ver = info.get("latest_version") or APP_VERSION

    # 1. Comprobar si la URL remota existe realmente en GitHub (sin dar 404)
    if dl_url and dl_url.lower().endswith(".exe"):
        try:
            req = urllib.request.Request(
                dl_url,
                method="HEAD",
                headers={"User-Agent": f"Skop0-Updater/{APP_VERSION}"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status in (200, 301, 302):
                    return {"mode": "redirect", "url": dl_url}
        except Exception:
            pass

    # 2. Si aún no se ha subido el Release a GitHub, buscar el instalador local compilado
    update_dir = os.path.join(tempfile.gettempdir(), "Skop0_Updates")
    desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")
    repo_dist = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dist_installer"))

    local_candidates = [
        _update_state.get("installer_path"),
        os.path.join(update_dir, f"Skop0_Setup_v{latest_ver}.exe"),
        os.path.join(desktop_dir, f"Skop0_Setup_v{latest_ver}.exe"),
        os.path.join(desktop_dir, "Skop0_Setup_v1.3.0.exe"),
        os.path.join(desktop_dir, "Skop0_Setup_v1.3.exe"),
        os.path.join(repo_dist, f"Skop0_Setup_v{latest_ver}.exe"),
        os.path.join(repo_dist, "Skop0_Setup_v1.3.0.exe"),
        os.path.join(repo_dist, "Skop0_Setup_v1.3.exe"),
        os.path.join(repo_dist, "Skop0_Setup_v1.2.exe"),
    ]
    for path in local_candidates:
        if path and os.path.exists(path):
            return {
                "mode": "file",
                "path": path,
                "filename": os.path.basename(path),
            }

    return {"mode": "redirect", "url": f"https://github.com/{GITHUB_REPO}/releases"}


def trigger_installer_and_exit() -> dict:
    """
    Lanza el instalador descargado de forma desacoplada del árbol de procesos
    actual, cierra la ventana anterior de SecScan y termina el proceso para
    permitir el reemplazo limpio de binarios.
    """
    with _update_state_lock:
        installer_path = _update_state.get("installer_path")
        if not installer_path or not os.path.exists(installer_path):
            return {"status": "error", "message": "No se encontró el instalador descargado."}
        _update_state["status"] = "installing"

    def _launch_and_die():
        time.sleep(0.35)
        try:
            from core.subnet_bridge import unbind_subnet_bridge
            unbind_subnet_bridge()
        except Exception:
            pass

        if sys.platform == "win32":
            bat_path = os.path.join(tempfile.gettempdir(), "skop0_run_update.bat")
            with open(bat_path, "w", encoding="utf-8") as bf:
                bf.write("@echo off\n")
                bf.write("timeout /t 1 /nobreak >nul\n")
                bf.write(f'start "" "{installer_path}" /SILENT\n')
                bf.write('del "%~f0"\n')

            DETACHED_PROCESS = 0x00000008
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000
            flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB
            try:
                subprocess.Popen(
                    ["cmd.exe", "/c", bat_path],
                    creationflags=flags,
                    close_fds=True,
                )
            except Exception:
                os.startfile(installer_path)
        else:
            subprocess.Popen([installer_path])

        # Cerrar la ventana de navegador de la versión anterior para que no queden 2 abiertas
        close_secscan_browser_windows()
        time.sleep(0.25)
        os._exit(0)

    threading.Thread(target=_launch_and_die, daemon=True).start()
    return {"status": "installing", "message": "Ejecutando instalador y reiniciando Skop0..."}
