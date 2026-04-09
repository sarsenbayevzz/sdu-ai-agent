from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./sdu_agent.db"
)

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Student(Base):
    __tablename__ = "students"

    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(String, unique=True, index=True, nullable=False)
    telegram_id = Column(String, unique=True, index=True, nullable=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=True)
    program = Column(String, nullable=True)
    year = Column(Integer, nullable=True)
    moodle_token = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    enrollments = relationship("Enrollment", back_populates="student")
    chat_history = relationship("ChatHistory", back_populates="student")


class Course(Base):
    __tablename__ = "courses"

    id = Column(Integer, primary_key=True, index=True)
    course_code = Column(String, unique=True, index=True, nullable=False)
    course_name = Column(String, nullable=False)
    teacher = Column(String, nullable=True)
    credits = Column(Integer, default=3)
    moodle_course_id = Column(Integer, nullable=True)

    enrollments = relationship("Enrollment", back_populates="course")
    assignments = relationship("Assignment", back_populates="course")
    schedules = relationship("Schedule", back_populates="course")


class Enrollment(Base):
    __tablename__ = "enrollments"

    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey("students.id"))
    course_id = Column(Integer, ForeignKey("courses.id"))
    semester = Column(String, nullable=True)

    student = relationship("Student", back_populates="enrollments")
    course = relationship("Course", back_populates="enrollments")


class Assignment(Base):
    __tablename__ = "assignments"

    id = Column(Integer, primary_key=True, index=True)
    course_id = Column(Integer, ForeignKey("courses.id"))
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    deadline = Column(DateTime, nullable=False)
    submitted = Column(Boolean, default=False)
    grade = Column(Float, nullable=True)
    moodle_assign_id = Column(Integer, nullable=True)

    course = relationship("Course", back_populates="assignments")


class Schedule(Base):
    __tablename__ = "schedule"

    id = Column(Integer, primary_key=True, index=True)
    course_id = Column(Integer, ForeignKey("courses.id"))
    student_id = Column(Integer, ForeignKey("students.id"))
    day = Column(String, nullable=False)  # Monday, Tuesday, etc.
    start_time = Column(String, nullable=False)  # "14:00"
    end_time = Column(String, nullable=False)    # "15:30"
    room = Column(String, nullable=True)
    teacher = Column(String, nullable=True)
    class_type = Column(String, default="Lecture")  # Lecture, Lab, Seminar

    course = relationship("Course", back_populates="schedules")


class Attendance(Base):
    __tablename__ = "attendance"

    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey("students.id"))
    course_id = Column(Integer, ForeignKey("courses.id"))
    total_classes = Column(Integer, default=0)
    attended_classes = Column(Integer, default=0)
    percentage = Column(Float, default=0.0)
    last_updated = Column(DateTime, default=datetime.utcnow)


class ChatHistory(Base):
    __tablename__ = "chat_history"

    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey("students.id"))
    message = Column(Text, nullable=False)
    role = Column(String, nullable=False)  # "user" or "assistant"
    timestamp = Column(DateTime, default=datetime.utcnow)

    student = relationship("Student", back_populates="chat_history")


async def create_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
