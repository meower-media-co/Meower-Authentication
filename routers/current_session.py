from util.sessions import check_auth
from fastapi import APIRouter, Request, Depends


router = APIRouter(
    prefix="/session",
    tags=["Sessions"],
    dependencies=[Depends(check_auth)]
)


@router.get("/")
async def get_session(req:Request):
    """
    Get details about the current session.
    """

    return {
        "id": req.session.id,
        "user": req.session.user,
        "client": req.session.client,
        "expires": req.session.expires
    }


@router.delete("/")
async def revoke_session(req:Request):
    """
    Revoke current session.
    """

    req.session.revoke()
    return "OK"


@router.post("/refresh")
async def refresh_session(req:Request):
    """
    Refresh current session.
    """

    auth_token, main_token = req.session.refresh(req.client.info)
    return {
        "id": req.session.id,
        "auth_token": auth_token,
        "main_token": main_token
    }
