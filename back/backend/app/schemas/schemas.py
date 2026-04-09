from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


# Auth schemas
class LoginRequest(BaseModel):
    student_id: str
    password: str  # Moodle password
    portal_password: Optional[str] = ""  # SDU Portal password (may differ)
    telegram_id: Optional[str] = None


class LoginResponse(BaseModel):
    success: bool
    student_id: str
    name: str
    firstname: Optional[str] = ""
    lastname: Optional[str] = ""
    fullname_native: Optional[str] = ""
    username: Optional[str] = ""
    email: Optional[str] = ""
    avatar: Optional[str] = ""
    portal_photo_url: Optional[str] = ""
    program: Optional[str] = ""
    advisor: Optional[str] = ""
    birth_date: Optional[str] = ""
    status: Optional[str] = ""
    grant_type: Optional[str] = ""
    needs_portal_2fa: Optional[bool] = False
    token: str
    message: str


# Chat schemas
class ChatRequest(BaseModel):
    message: str
    student_id: str
    telegram_id: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    tool_used: Optional[str] = None
    data: Optional[dict] = None


# Assignment schemas
class AssignmentSchema(BaseModel):
    id: int
    course_name: str
    course_code: str
    title: str
    deadline: datetime
    submitted: bool
    days_left: int

    class Config:
        from_attributes = True


class AssignmentsResponse(BaseModel):
    count: int
    assignments: List[AssignmentSchema]


# Schedule schemas
class ScheduleItemSchema(BaseModel):
    course_name: str
    course_code: str
    day: str
    start_time: str
    end_time: str
    room: str
    teacher: str
    class_type: str

    class Config:
        from_attributes = True


class NextClassResponse(BaseModel):
    course_name: str
    course_code: str
    start_time: str
    end_time: str
    room: str
    teacher: str
    day: str
    minutes_until: Optional[int] = None
    class_type: str


# Attendance schemas
class AttendanceItemSchema(BaseModel):
    course_name: str
    course_code: str
    attended: int
    total: int
    percentage: float
    status: str  # "ok", "warning", "critical"

    class Config:
        from_attributes = True


class AttendanceResponse(BaseModel):
    overall_percentage: float
    courses: List[AttendanceItemSchema]
    low_attendance_courses: List[AttendanceItemSchema]
