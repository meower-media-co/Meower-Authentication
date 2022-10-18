from util.database import db
from util.sessions import Session, check_auth, revoke_all_sessions
from fastapi import APIRouter, Request, Depends, HTTPException


router = APIRouter(
    prefix="/account/sessions",
    tags=["Account Settings"],
    dependencies=[Depends(check_auth)]
)


@router.get("/")
async def get_all_sessions(req:Request):
    """
    Get details about all sessions.
    """

    # Get all sessions from the database
    sessions = db.cur.execute("SELECT * FROM sessions WHERE user = ?", (req.user.id,)).fetchall()

    # Parse all sessions
    parsed_sessions = []
    for session_obj in sessions:
        parsed_sessions.append({
            "id": session_obj[0],
            "client": session_obj[3],
            "refreshed": session_obj[5]
        })

    # Return all sessions
    return parsed_sessions


@router.get("/{session_id}")
async def get_session(req:Request, session_id):
    """
    Get details about a specific session.
    """

    # Get session details
    session = Session(session_id)
    if (not session._valid) or (session.user != req.session.user.id):
        raise HTTPException(status_code = 400, detail = "Unknown session")
    
    # Return session data
    return {
        "id": session.id,
        "client": session.client,
        "refreshed": session.refreshed
    }


@router.delete("/{session_id}")
async def revoke_session(req:Request, session_id):
    """
    Revoke a specific session.
    """

    # Get session details
    session = Session(session_id)
    if (not session._valid) or (session.user != req.session.user.id):
        raise HTTPException(status_code = 400, detail = "Unknown session")
    
    # Revoke session
    session.revoke()

    return "OK"


@router.post("/revoke-all")
async def revoke_all(req:Request):
    """
    Revoke all sessions.
    """

    # Revoke all sessions
    revoke_all_sessions(req.session.user)

    return "OK"
