"""
Data Service Layer
Set USE_MOCK_DATA=false and MOODLE_TOKEN=your_token in .env to use real Moodle data.
"""

import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging

from app.integrations.sdu_portal import (
    MOCK_SCHEDULE, MOCK_ASSIGNMENTS, MOCK_ATTENDANCE, MOCK_STUDENTS
)

logger = logging.getLogger(__name__)
USE_MOCK = os.getenv("USE_MOCK_DATA", "true").lower() == "true"
MOODLE_TOKEN = os.getenv("MOODLE_TOKEN", "")
MOODLE_URL = os.getenv("MOODLE_URL", "https://moodle.sdu.edu.kz")

DAY_ORDER = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

# Temporary storage for portal sessions awaiting 2FA
PORTAL_SESSIONS: dict = {}


class DataService:

    def __init__(self, moodle_token: str = "", portal_client=None):
        # Приоритет: токен переданный явно → токен из .env
        self.moodle_token = moodle_token or os.getenv("MOODLE_TOKEN", "")
        self._portal_client = portal_client  # logged-in SDUPortalClient if available
        self._schedule_cache: Optional[Dict] = None  # cached real schedule

    def _get_moodle_client(self):
        from app.integrations.moodle import MoodleClient
        return MoodleClient(self.moodle_token, MOODLE_URL)

    # ── AUTH ──────────────────────────────────────────────────────────

    async def authenticate_student(self, student_id: str, password: str, portal_password: str = "") -> Optional[Dict]:
        if USE_MOCK:
            student = MOCK_STUDENTS.get(student_id)
            if student and password == "password123":
                return student
            return None

        from app.integrations.moodle import get_moodle_token, MoodleClient
        token = await get_moodle_token(student_id, password)
        if not token:
            return None

        # Get basic info from Moodle
        try:
            client = MoodleClient(token, MOODLE_URL)
            info = await client.call("core_webservice_get_site_info")
            full_name = info.get("fullname", student_id)
            userid = info.get("userid")
            firstname = info.get("firstname", "")
            lastname = info.get("lastname", "")
            username = info.get("username", student_id)
            avatar = info.get("userpictureurl", "")
            lang = info.get("lang", "en")
        except Exception as e:
            logger.error(f"Moodle site_info error: {e}")
            full_name = student_id
            userid = None
            firstname = lastname = username = ""
            avatar = lang = ""

        result = {
            "student_id": student_id,
            "name": full_name,
            "firstname": firstname,
            "lastname": lastname,
            "username": username,
            "email": f"{username}@sdu.edu.kz",
            "avatar": avatar,
            "lang": lang,
            "program": "SDU Student",
            "advisor": "",
            "year": 1,
            "moodle_token": token,
            "moodle_userid": userid,
        }

        # Try to get richer profile from SDU portal if portal_password provided
        if portal_password:
            try:
                from app.integrations.sdu_portal import SDUPortalClient
                portal = SDUPortalClient(student_id, portal_password)
                status = await portal.login()
                if status == "needs_2fa":
                    # Store portal client in memory for 2FA verification
                    PORTAL_SESSIONS[student_id] = portal
                    result["needs_portal_2fa"] = True
                elif status == "ok":
                    profile = await portal.get_profile()
                    if profile:
                        result["program"] = profile.get("program", result["program"])
                        result["advisor"] = profile.get("advisor", "")
                        result["fullname_native"] = profile.get("fullname_native", "")
                        result["birth_date"] = profile.get("birth_date", "")
                        result["status"] = profile.get("status", "Studying")
                        result["grant_type"] = profile.get("grant_type", "")
                        result["email"] = profile.get("email", result["email"])
                        result["portal_photo_url"] = profile.get("photo_url", "")
                    # Keep portal client alive for schedule scraping
                    PORTAL_SESSIONS[student_id] = portal
            except Exception as e:
                logger.error(f"SDU portal profile error: {e}")

        return result

    # ── ASSIGNMENTS ───────────────────────────────────────────────────

    async def get_assignments(self, student_id: str, days: int = 30,
                               include_submitted: bool = False) -> Dict:
        if USE_MOCK:
            return self._mock_assignments(days, include_submitted)
        try:
            return await self._moodle_assignments(days, include_submitted)
        except Exception as e:
            logger.error(f"Moodle assignments error: {e}, falling back to mock")
            return self._mock_assignments(days, include_submitted)

    async def _moodle_assignments(self, days: int, include_submitted: bool) -> Dict:
        client = self._get_moodle_client()
        now = datetime.now()
        cutoff = now + timedelta(days=days)

        userid = await client.get_userid()
        courses_raw = await client.call("core_enrol_get_users_courses", {"userid": userid}) or []
        course_ids = [c["id"] for c in courses_raw]

        if not course_ids:
            return {"count": 0, "assignments": [], "days_range": days}

        params = {f"courseids[{i}]": cid for i, cid in enumerate(course_ids)}
        result = await client.call("mod_assign_get_assignments", params)
        assignments = []

        for course in result.get("courses", []):
            course_name = course.get("fullname", "")
            for assign in course.get("assignments", []):
                due_ts = assign.get("duedate", 0)
                if due_ts == 0:
                    continue
                deadline = datetime.fromtimestamp(due_ts)
                if deadline < now or deadline > cutoff:
                    continue

                submitted = False
                try:
                    r = await client.call("mod_assign_get_submission_status", {"assignid": assign["id"]})
                    sub = r.get("lastattempt", {}).get("submission", {})
                    submitted = sub.get("status") == "submitted"
                except Exception:
                    pass

                if submitted and not include_submitted:
                    continue

                days_left = (deadline - now).days
                assignments.append({
                    "course_name": course_name,
                    "course_code": str(course.get("id", "")),
                    "title": assign.get("name", "Assignment"),
                    "deadline": deadline.isoformat(),
                    "deadline_formatted": deadline.strftime("%b %d, %Y"),
                    "submitted": submitted,
                    "days_left": max(0, days_left),
                    "urgent": days_left <= 2,
                })

        assignments.sort(key=lambda x: x["deadline"])
        return {"count": len(assignments), "assignments": assignments, "days_range": days}

    def _mock_assignments(self, days: int, include_submitted: bool) -> Dict:
        now = datetime.now()
        cutoff = now + timedelta(days=days)
        result = []
        for a in MOCK_ASSIGNMENTS:
            deadline = now + timedelta(days=a["deadline_offset_days"])
            if deadline < now and not a["submitted"]:
                continue
            if deadline > cutoff:
                continue
            if a["submitted"] and not include_submitted:
                continue
            days_left = (deadline - now).days
            result.append({
                "course_name": a["course_name"],
                "course_code": a["course_code"],
                "title": a["title"],
                "deadline": deadline.isoformat(),
                "deadline_formatted": deadline.strftime("%b %d, %Y"),
                "submitted": a["submitted"],
                "days_left": max(0, days_left),
                "urgent": days_left <= 2,
            })
        result.sort(key=lambda x: x["deadline"])
        return {"count": len(result), "assignments": result, "days_range": days}

    # ── SCHEDULE (mock — SDU portal has no public API) ────────────────

    async def get_next_class(self, student_id: str) -> Dict:
        now = datetime.now()
        current_day = now.strftime("%A")
        current_time = now.strftime("%H:%M")
        current_day_idx = DAY_ORDER.index(current_day) if current_day in DAY_ORDER else 0

        real_schedule = await self._get_real_schedule()

        for day_offset in range(7):
            check_day = DAY_ORDER[(current_day_idx + day_offset) % 7]
            if real_schedule:
                day_classes = sorted(real_schedule.get(check_day, []), key=lambda x: x["start_time"])
            else:
                day_classes = sorted([s for s in MOCK_SCHEDULE if s["day"] == check_day], key=lambda x: x["start_time"])

            for cls in day_classes:
                if day_offset == 0 and cls["start_time"] <= current_time:
                    continue
                base = now + timedelta(days=day_offset)
                class_dt = base.replace(
                    hour=int(cls["start_time"].split(":")[0]),
                    minute=int(cls["start_time"].split(":")[1]), second=0
                )
                return {
                    "course_name": cls["course_name"], "course_code": cls["course_code"],
                    "day": check_day, "start_time": cls["start_time"], "end_time": cls["end_time"],
                    "room": cls["room"], "teacher": cls["teacher"], "class_type": cls["class_type"],
                    "minutes_until": int((class_dt - now).total_seconds() / 60),
                    "is_today": day_offset == 0, "is_tomorrow": day_offset == 1,
                }
        return {"message": "No upcoming classes found"}

    async def get_schedule_for_day(self, student_id: str, day: Optional[str] = None) -> Dict:
        now = datetime.now()
        if day is None:
            target_day, target_date = now.strftime("%A"), now.strftime("%Y-%m-%d")
        else:
            target_day, target_date = self._resolve_day(day, now)

        schedule = await self._get_real_schedule()
        if schedule:
            day_classes = sorted(schedule.get(target_day, []), key=lambda x: x["start_time"])
        else:
            day_classes = sorted([s for s in MOCK_SCHEDULE if s["day"] == target_day], key=lambda x: x["start_time"])
        return {"day": target_day, "date": target_date, "classes_count": len(day_classes),
                "classes": day_classes, "has_classes": len(day_classes) > 0}

    async def _get_real_schedule(self) -> Optional[Dict]:
        """Get schedule from portal if available, with caching."""
        if self._schedule_cache is not None:
            return self._schedule_cache
        if self._portal_client and self._portal_client._logged_in:
            try:
                self._schedule_cache = await self._portal_client.get_schedule()
                return self._schedule_cache
            except Exception as e:
                logger.error(f"Portal schedule error: {e}")
        return None

    def _resolve_day(self, day_input: str, now: datetime):
        for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%d.%m", "%d %B %Y"):
            try:
                if fmt == "%d.%m":
                    parsed = datetime.strptime(f"{day_input}.{now.year}", "%d.%m.%Y")
                else:
                    parsed = datetime.strptime(day_input, fmt)
                return parsed.strftime("%A"), parsed.strftime("%Y-%m-%d")
            except ValueError:
                continue
        ru_to_en = {
            "понедельник": "Monday", "вторник": "Tuesday", "среда": "Wednesday",
            "среду": "Wednesday", "четверг": "Thursday", "пятница": "Friday", "пятницу": "Friday",
        }
        day_name = ru_to_en.get(day_input.strip().lower(), day_input.capitalize())
        if day_name in DAY_ORDER:
            today_idx = DAY_ORDER.index(now.strftime("%A"))
            target_idx = DAY_ORDER.index(day_name)
            days_ahead = (target_idx - today_idx) % 7
            return day_name, (now + timedelta(days=days_ahead)).strftime("%Y-%m-%d")
        return now.strftime("%A"), now.strftime("%Y-%m-%d")

    async def get_full_schedule(self, student_id: str) -> Dict:
        real = await self._get_real_schedule()
        if real:
            weekly = {day: sorted(real.get(day, []), key=lambda x: x["start_time"]) for day in DAY_ORDER[:6]}
        else:
            weekly = {day: sorted([s for s in MOCK_SCHEDULE if s["day"] == day], key=lambda x: x["start_time"]) for day in DAY_ORDER[:5]}
        return {"schedule": weekly}

    # ── ATTENDANCE ────────────────────────────────────────────────────

    async def get_attendance(self, student_id: str, course_code: Optional[str] = None) -> Dict:
        if USE_MOCK:
            return self._mock_attendance(course_code)
        # Try portal first (more reliable than Moodle attendance plugin)
        if self._portal_client and self._portal_client._logged_in:
            try:
                result = await self._portal_client.get_attendance()
                if result and result.get("courses"):
                    return result
            except Exception as e:
                logger.error(f"Portal attendance error: {e}")
        # Fallback to Moodle
        try:
            result = await self._moodle_attendance(course_code)
            if not result["courses"]:
                return self._mock_attendance(course_code)
            return result
        except Exception as e:
            logger.error(f"Moodle attendance error: {e}, falling back to mock")
            return self._mock_attendance(course_code)

    async def _moodle_attendance(self, course_code: str = None) -> Dict:
        client = self._get_moodle_client()
        userid = await client.get_userid()
        courses_raw = await client.call("core_enrol_get_users_courses", {"userid": userid}) or []

        enriched = []
        for course in courses_raw:
            cid = course["id"]
            if course_code and str(cid) != str(course_code):
                continue
            try:
                att = await client.call("mod_attendance_get_user_data", {"courseid": cid, "userid": userid})
                sessions = att.get("attendances", [{}])[0] if att.get("attendances") else {}
                total = sessions.get("numsessions", 0)
                attended = sessions.get("numattended", 0)
                if total == 0:
                    continue
                pct = round(attended / total * 100, 1)
                status = "ok" if pct >= 75 else ("warning" if pct >= 50 else "critical")
                enriched.append({
                    "course_name": course["fullname"], "course_code": str(cid),
                    "attended": attended, "total": total, "percentage": pct,
                    "percentage_formatted": f"{pct}%", "status": status, "missed": total - attended,
                })
            except Exception:
                continue

        low = [a for a in enriched if a["percentage"] < 75]
        overall = sum(a["attended"] for a in enriched) / sum(a["total"] for a in enriched) * 100 if enriched else 0
        return {"overall_percentage": round(overall, 1), "courses": enriched,
                "low_attendance_courses": low, "has_issues": bool(low)}

    def _mock_attendance(self, course_code: str = None) -> Dict:
        attendance = MOCK_ATTENDANCE
        if course_code:
            attendance = [a for a in attendance if a["course_code"] == course_code]
        enriched = []
        for a in attendance:
            status = "ok" if a["percentage"] >= 75 else ("warning" if a["percentage"] >= 50 else "critical")
            enriched.append({**a, "status": status, "missed": a["total"] - a["attended"],
                              "percentage_formatted": f"{a['percentage']:.1f}%"})
        low = [a for a in enriched if a["percentage"] < 75]
        overall = sum(a["attended"] for a in enriched) / sum(a["total"] for a in enriched) * 100 if enriched else 0
        return {"overall_percentage": round(overall, 1), "courses": enriched,
                "low_attendance_courses": low, "has_issues": bool(low)}

    # ── CHAT HISTORY ──────────────────────────────────────────────────

    async def get_chat_history(self, student_id: str, limit: int = 10) -> List[Dict]:
        return []

    async def save_chat_message(self, student_id: str, role: str, message: str):
        pass
