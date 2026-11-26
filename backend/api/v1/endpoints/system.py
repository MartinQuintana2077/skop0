from fastapi import APIRouter, Depends, Body
from fastapi.responses import FileResponse, RedirectResponse
from core.installer import install_nmap_silently
from core.updater import (
    APP_VERSION,
    check_for_updates,
    start_update_download,
    get_update_progress,
    trigger_installer_and_exit,
    resolve_installer_for_browser,
)
from services.scan_service import ScanService
from api.deps import get_current_user
import os
import time
import threading

router = APIRouter()
scan_service = ScanService()

_last_heartbeat = time.time()
_heartbeat_lock = threading.Lock()
_watchdog_started = False


@router.get("/health")
def health_check(user: dict = Depends(get_current_user)):
    from core.scanner import get_local_ip
    return {
        "status": "ok",
        "version": APP_VERSION,
        "nmap_installed": getattr(scan_service.scanner, "nmap_installed", False),
        "local_ip": get_local_ip(),
    }


@router.get("/version")
def get_version():
    return {"status": "ok", "version": APP_VERSION}


@router.api_route("/check-update", methods=["GET", "POST"])
def check_update_endpoint():
    return check_for_updates()


@router.post("/download-update")
def download_update_endpoint(payload: dict = Body(default={})):
    download_url = payload.get("download_url", "")
    asset_name = payload.get("asset_name", "")
    latest_version = payload.get("latest_version", "")
    return start_update_download(download_url, asset_name, latest_version)


@router.get("/update-progress")
def update_progress_endpoint():
    return get_update_progress()


@router.post("/apply-update")
def apply_update_endpoint():
    return trigger_installer_and_exit()


@router.get("/download-installer")
def download_installer_browser_endpoint():
    res = resolve_installer_for_browser()
    if res.get("mode") == "file" and res.get("path"):
        return FileResponse(
            path=res["path"],
            filename=res.get("filename") or "Skop0_Setup.exe",
            media_type="application/octet-stream",
        )
    return RedirectResponse(url=res.get("url") or "https://github.com/MartinQuintana2077/secscan/releases")


@router.post("/install-nmap")
def auto_install_nmap(user: dict = Depends(get_current_user)):
    success = install_nmap_silently()
    if success:
        if hasattr(scan_service.scanner, "reload_engine"):
            scan_service.scanner.reload_engine()
        return {"status": "ok", "mensaje": "Nmap instalado en sistema host."}
    return {"status": "error", "mensaje": "Falló la instalación desatendida."}


@router.api_route("/shutdown", methods=["GET", "POST"])
def client_shutdown():
    from core.lifecycle import safe_cleanup_and_exit
    def _kill_soon():
        time.sleep(0.2)
        safe_cleanup_and_exit(0)

    threading.Thread(target=_kill_soon, daemon=True).start()
    return {"status": "shutting_down"}


@router.api_route("/heartbeat", methods=["GET", "POST"])
def client_heartbeat():
    from core.lifecycle import record_heartbeat
    record_heartbeat()
    return {"status": "alive"}
