from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.api import chat, assignments, schedule, attendance, auth, profile
from app.models.database import create_tables


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_tables()
    yield


app = FastAPI(
    title="SDU AI Agent API",
    description="AI-powered academic assistant for SDU students",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(chat.router, prefix="/chat", tags=["Chat"])
app.include_router(assignments.router, prefix="/assignments", tags=["Assignments"])
app.include_router(schedule.router, prefix="/schedule", tags=["Schedule"])
app.include_router(attendance.router, prefix="/attendance", tags=["Attendance"])
app.include_router(profile.router, prefix="/profile", tags=["Profile"])


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "SDU AI Agent"}
