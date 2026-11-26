from fastapi import APIRouter, Depends, HTTPException, Response, Query
from api.deps import get_current_user
from services.license_service import LicenseService

router = APIRouter()
license_service = LicenseService()

@router.get("/status")
def get_subscription_status(
    response: Response, 
    force: bool = Query(False),
    user: dict = Depends(get_current_user)
):
    """
    Devuelve el estado de suscripción y licencia del usuario autenticado.
    Agrega cabeceras no-cache para evitar que el navegador congele el estado.
    """
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    user_id = user.get("uid", "local_user")
    email = user.get("email", "")
    
    if force:
        license_service.clear_cache(user_id)
        
    status = license_service.get_user_license(user_id=user_id, email=email)
    return status

@router.post("/refresh")
def refresh_subscription_status(response: Response, user: dict = Depends(get_current_user)):
    """
    Invalida la caché en memoria y recarga el estado fresco de Firestore.
    """
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    user_id = user.get("uid", "local_user")
    email = user.get("email", "")
    
    license_service.clear_cache(user_id)
    status = license_service.get_user_license(user_id=user_id, email=email)
    return status
