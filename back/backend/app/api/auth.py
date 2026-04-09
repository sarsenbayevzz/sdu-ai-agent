from fastapi import APIRouter, HTTPException, Header
from app.schemas.schemas import LoginRequest, LoginResponse
from app.agent.data_service import DataService
import jwt
import os
from datetime import datetime, timedelta
from typing import Optional

router = APIRouter()
SECRET_KEY = os.getenv("JWT_SECRET", "sdu-ai-agent-secret-change-in-production")
data_service = DataService()


def create_token(student_id: str, moodle_token: str = "") -> str:
    """JWT теперь содержит moodle_token студента."""
    payload = {
        "student_id": student_id,
        "moodle_token": moodle_token,
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def verify_token(token: str) -> dict:
    """Возвращает dict с student_id и moodle_token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return {
            "student_id": payload["student_id"],
            "moodle_token": payload.get("moodle_token", "")
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_student(authorization: Optional[str] = Header(None)) -> dict:
    """Dependency — достаёт студента из Authorization: Bearer <token>."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authorization header missing")
    token = authorization.split(" ", 1)[1]
    return verify_token(token)


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    student = await data_service.authenticate_student(
        request.student_id,
        request.password,
        portal_password=request.portal_password or "",
    )
    if not student:
        raise HTTPException(status_code=401, detail="Неверный студенческий ID или пароль.")

    moodle_token = student.get("moodle_token", "")
    jwt_token = create_token(request.student_id, moodle_token)

    return LoginResponse(
        success=True,
        student_id=student["student_id"],
        name=student["name"],
        firstname=student.get("firstname", ""),
        lastname=student.get("lastname", ""),
        fullname_native=student.get("fullname_native", ""),
        username=student.get("username", request.student_id),
        email=student.get("email", ""),
        avatar=student.get("avatar", ""),
        portal_photo_url=student.get("portal_photo_url", ""),
        program=student.get("program", ""),
        advisor=student.get("advisor", ""),
        birth_date=student.get("birth_date", ""),
        status=student.get("status", ""),
        grant_type=student.get("grant_type", ""),
        needs_portal_2fa=student.get("needs_portal_2fa", False),
        token=jwt_token,
        message=f"Добро пожаловать, {student['name']}!"
    )


@router.post("/verify")
async def verify(authorization: Optional[str] = Header(None)):
    data = get_current_student(authorization)
    return {"valid": True, "student_id": data["student_id"]}


@router.post("/portal-2fa")
async def portal_2fa(
    student_id: str,
    code: str,
    authorization: Optional[str] = Header(None),
):
    """Submit 2FA code for SDU portal and fetch profile."""
    from app.agent.data_service import PORTAL_SESSIONS
    portal = PORTAL_SESSIONS.get(student_id)
    if not portal:
        raise HTTPException(status_code=400, detail="No pending 2FA session. Please login again.")

    ok = await portal.verify_2fa(code)
    if not ok:
        raise HTTPException(status_code=401, detail="Неверный код верификации.")

    profile = await portal.get_profile()
    await portal.close()
    del PORTAL_SESSIONS[student_id]

    return {
        "success": True,
        "program": profile.get("program", "") if profile else "",
        "advisor": profile.get("advisor", "") if profile else "",
        "fullname_native": profile.get("fullname_native", "") if profile else "",
        "birth_date": profile.get("birth_date", "") if profile else "",
        "status": profile.get("status", "") if profile else "",
        "grant_type": profile.get("grant_type", "") if profile else "",
        "email": profile.get("email", "") if profile else "",
        "portal_photo_url": profile.get("photo_url", "") if profile else "",
    }
