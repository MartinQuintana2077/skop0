from fastapi import APIRouter
from api.v1.endpoints import scans, devices, system, wifi, backup, subscription, admin

api_router = APIRouter()

api_router.include_router(scans.router, tags=["scans"])
api_router.include_router(devices.router, tags=["devices"])
api_router.include_router(system.router, tags=["system"])
api_router.include_router(system.router, prefix="/system", tags=["system_prefixed"])
api_router.include_router(wifi.router, prefix="/wifi", tags=["wifi"])
api_router.include_router(backup.router, prefix="/backup", tags=["backup"])
api_router.include_router(backup.router, tags=["backup_direct"])
api_router.include_router(subscription.router, prefix="/subscription", tags=["subscription"])
api_router.include_router(subscription.router, prefix="/v1/subscription", tags=["subscription_v1"])
api_router.include_router(admin.router, prefix="/admin", tags=["admin"])
api_router.include_router(admin.router, prefix="/v1/admin", tags=["admin_v1"])
