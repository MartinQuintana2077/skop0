import os
import sys
import time
import threading

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
if hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from api.v1.api import api_router

app = FastAPI(
    title="Skop0 API v1.3",
    description="Backend directo sin dependencias externas",
    version="1.3"
)

# Gestión de ciclo de vida unificada (WebSocket + Heartbeat + Watchdog)
from core.lifecycle import (
    record_heartbeat,
    ws_connected,
    ws_disconnected,
    safe_cleanup_and_exit as _safe_cleanup_and_exit,
    start_lifecycle_watchdog,
)


@app.websocket("/ws/session")
async def session_ws(websocket: WebSocket):
    await websocket.accept()
    ws_connected()
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                record_heartbeat()
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        ws_disconnected()


@app.api_route("/api/heartbeat", methods=["GET", "POST"])
def api_heartbeat():
    record_heartbeat()
    return {"status": "ok"}


@app.api_route("/api/shutdown", methods=["GET", "POST"])
def api_shutdown():
    """Apagado instantáneo solicitado al cerrar la ventana (X) o salir."""
    print("[Skop0] Cierre de ventana detectado (/api/shutdown). Terminando proceso inmediatamente...")
    def _instant_exit():
        time.sleep(0.1)
        _safe_cleanup_and_exit(0)
    threading.Thread(target=_instant_exit, daemon=True).start()
    return {"status": "ok", "message": "Skop0 finalizando..."}


app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8000", "http://127.0.0.1:8000"],
    allow_origin_regex=r"http://(localhost|127\.0\.0\.1)(:\d+)?",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir rutas de API
app.include_router(api_router, prefix="/api")

# Buscar carpeta de frontend compilado (dist)
dist_dirs = []
if getattr(sys, 'frozen', False):
    if hasattr(sys, '_MEIPASS'):
        dist_dirs.append(os.path.join(sys._MEIPASS, 'dist'))
        dist_dirs.append(os.path.join(sys._MEIPASS, 'frontend', 'dist'))
    base_dir = os.path.dirname(sys.executable)
    dist_dirs.append(os.path.join(base_dir, '_internal', 'dist'))
    dist_dirs.append(os.path.join(base_dir, '_internal', 'frontend', 'dist'))
    dist_dirs.append(os.path.join(base_dir, 'dist'))
    dist_dirs.append(os.path.join(base_dir, 'frontend', 'dist'))

current_dir = os.path.dirname(os.path.abspath(__file__))
dist_dirs.append(os.path.abspath(os.path.join(current_dir, '..', 'frontend', 'dist')))
dist_dirs.append(os.path.join(current_dir, 'dist'))
dist_dirs.append(os.path.join(os.getcwd(), 'frontend', 'dist'))
dist_dirs.append(os.path.join(os.getcwd(), 'dist'))

STATIC_DIR = None
for d in dist_dirs:
    if os.path.exists(d) and os.path.exists(os.path.join(d, "index.html")):
        STATIC_DIR = d
        print(f"[Skop0] Frontend estático encontrado en: {STATIC_DIR}")
        break

import mimetypes
mimetypes.init()
mimetypes.add_type("text/css", ".css")
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("image/svg+xml", ".svg")
mimetypes.add_type("font/woff2", ".woff2")
mimetypes.add_type("font/woff", ".woff")

admin_static_dir = os.path.abspath(os.path.join(current_dir, "..", "admin_portal", "static"))
if os.path.exists(admin_static_dir):
    app.mount("/admin-portal/static", StaticFiles(directory=admin_static_dir), name="admin_static")
    @app.get("/admin-portal")
    @app.get("/admin-portal/")
    def serve_admin_portal():
        return FileResponse(os.path.join(admin_static_dir, "index.html"))

if STATIC_DIR:
    assets_dir = os.path.join(STATIC_DIR, "assets")
    if os.path.exists(assets_dir):
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        target_file = os.path.join(STATIC_DIR, full_path)
        if full_path and os.path.isfile(target_file):
            ext = os.path.splitext(target_file)[1].lower()
            mime_map = {
                ".css": "text/css",
                ".js": "application/javascript",
                ".mjs": "application/javascript",
                ".json": "application/json",
                ".svg": "image/svg+xml",
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".ico": "image/x-icon",
                ".woff2": "font/woff2",
                ".woff": "font/woff",
                ".ttf": "font/ttf",
            }
            media_type = mime_map.get(ext) or mimetypes.guess_type(target_file)[0] or "application/octet-stream"
            return FileResponse(target_file, media_type=media_type)
        return FileResponse(
            os.path.join(STATIC_DIR, "index.html"), 
            media_type="text/html",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"}
        )
else:
    @app.get("/")
    def raiz():
        return {"mensaje": "Skop0 API está ONLINE (Modo solo Backend)."}

@app.on_event("startup")
def startup_event():
    start_lifecycle_watchdog()

    # Pre-calentar Firebase/gRPC en segundo plano mientras el navegador abre la UI
    from core.firebase_client import prewarm_firebase_async
    prewarm_firebase_async()

    def _bg_bootstrap():
        try:
            from core.subnet_bridge import cleanup_all_bridges
            cleanup_all_bridges()
        except Exception:
            pass
        try:
            from core.local_db import LocalDBManager
            LocalDBManager()
        except Exception:
            pass
        try:
            from services.db_service import DatabaseService
            DatabaseService().cleanup_dangling_scans()
        except Exception:
            pass
        try:
            from services.sync_service import start_sync_daemon
            start_sync_daemon()
        except Exception:
            pass
        try:
            from services.scan_service import start_passive_daemon
            start_passive_daemon()
        except Exception:
            pass

    threading.Thread(target=_bg_bootstrap, daemon=True, name="Skop0StartupBootstrap").start()
