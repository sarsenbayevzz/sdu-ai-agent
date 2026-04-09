"""
SDU Portal Integration (my.sdu.edu.kz)
Scrapes student profile data from the portal.
"""

import httpx
from bs4 import BeautifulSoup
from typing import Dict, List, Optional
import logging
import os

logger = logging.getLogger(__name__)
SDU_PORTAL_URL = os.getenv("SDU_PORTAL_URL", "https://my.sdu.edu.kz")


class SDUPortalClient:
    def __init__(self, student_id: str, password: str):
        self.student_id = student_id
        self.password = password
        self.client = httpx.AsyncClient(verify=False, 
            timeout=15.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SDU-AI-Agent/1.0)"}
        )
        self._logged_in = False

    async def login(self) -> str:
        """
        Login to my.sdu.edu.kz.
        First attempt may trigger 2FA — second attempt skips it.
        Returns: 'ok' | 'needs_2fa' | 'failed'
        """
        login_data = {
            "username": self.student_id,
            "password": self.password,
            "modstring": "",
            "LogIn": "+Log+in+",
        }
        headers = {"Referer": f"{SDU_PORTAL_URL}/index.php"}
        try:
            # First attempt — may get redirected to verification.php
            await self.client.post(f"{SDU_PORTAL_URL}/loginAuth.php", data=login_data, headers=headers)

            # Second attempt — portal usually skips 2FA for known IP
            resp = await self.client.post(f"{SDU_PORTAL_URL}/loginAuth.php", data=login_data, headers=headers)

            if "verification.php" in str(resp.url):
                return "needs_2fa"
            if self.client.cookies.get("PHPSESSID") or "logout.php" in resp.text:
                self._logged_in = True
                return "ok"
            logger.warning("SDU portal login failed")
            return "failed"
        except Exception as e:
            logger.error(f"SDU portal login error: {e}")
            return "failed"

    async def verify_2fa(self, code: str) -> bool:
        """Submit 2FA verification code."""
        try:
            resp = await self.client.post(
                f"{SDU_PORTAL_URL}/verification.php",
                data={
                    "username": self.student_id,
                    "password": self.password,
                    "code": code,
                    "LogIn": "",
                },
                headers={"Referer": f"{SDU_PORTAL_URL}/verification.php"}
            )
            if self.client.cookies.get("PHPSESSID") or "logout.php" in resp.text:
                self._logged_in = True
                return True
            return False
        except Exception as e:
            logger.error(f"SDU portal 2FA error: {e}")
            return False


    async def get_schedule(self, year: str = "2025", term: str = "2") -> Dict:
        """Scrape schedule via AJAX endpoint."""
        if not self._logged_in:
            return {}
        try:
            resp = await self.client.post(
                f"{SDU_PORTAL_URL}/index.php",
                data={
                    "mod": "schedule",
                    "ajx": "1",
                    "action": "showSchedule",
                    "year": year,
                    "term": term,
                    "type": "I",
                    "details": "0",
                },
                headers={"Referer": f"{SDU_PORTAL_URL}/index.php?mod=schedule"}
            )
            return self._parse_schedule(resp.text)
        except Exception as e:
            logger.error(f"SDU portal schedule error: {e}")
            return {}

    def _parse_schedule(self, html: str) -> Dict:
        """Parse schedule HTML into structured data."""
        soup = BeautifulSoup(html, "html.parser")
        table = soup.find("table", {"class": "clTbl"})
        if not table:
            return {}

        days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
        schedule = {day: [] for day in days}

        rows = table.find_all("tr")[1:]  # skip header row
        for row in rows:
            cells = row.find_all("td")
            if not cells:
                continue

            # First cell is time
            time_cell = cells[0]
            time_spans = time_cell.find_all("span")
            if len(time_spans) < 2:
                continue
            start_time = time_spans[0].get_text(strip=True)
            end_time = time_spans[1].get_text(strip=True)

            # Remaining cells are days (Mon-Sat)
            for i, day_cell in enumerate(cells[1:7]):
                if i >= len(days):
                    break
                link = day_cell.find("a")
                if not link:
                    continue

                course_code = link.get_text(strip=True)
                course_name = link.get("title", "").split("(")[0].strip()

                # Class type from span title (Theory/Practice)
                type_span = day_cell.find("span", {"title": True})
                class_type = "Lecture"
                if type_span:
                    t = type_span.get("title", "")
                    if "Practice" in t:
                        class_type = "Lab"
                    elif "Theory" in t:
                        class_type = "Lecture"

                # Teacher from img title
                teacher_img = day_cell.find("img", {"src": lambda s: s and "stud_icon" in s})
                teacher = teacher_img.get("title", "") if teacher_img else ""

                # Room from house img title
                room_img = day_cell.find("img", {"src": lambda s: s and "house.gif" in s})
                room = ""
                if room_img:
                    room_title = room_img.get("title", "")
                    # Extract short room code from last parenthesis e.g. "Main building: D214(L.T. C2)" -> "D214"
                    import re
                    match = re.search(r':\s*(\S+)\(', room_title)
                    if match:
                        room = match.group(1)

                schedule[days[i]].append({
                    "course_code": course_code,
                    "course_name": course_name,
                    "start_time": start_time,
                    "end_time": end_time,
                    "class_type": class_type,
                    "teacher": teacher,
                    "room": room,
                })

        return schedule


    async def get_attendance(self, year: str = "2025", term: str = "2") -> Dict:
        """Scrape attendance via AJAX endpoint."""
        if not self._logged_in:
            return {}
        try:
            resp = await self.client.post(
                f"{SDU_PORTAL_URL}/index.php",
                data={
                    "ajx": "1",
                    "mod": "ejurnal",
                    "action": "getCourses",
                    "ysem": f"{year}#{term}",
                    "stud_id": self.student_id,
                },
                headers={"Referer": f"{SDU_PORTAL_URL}/index.php?mod=ejurnal"}
            )
            return self._parse_attendance(resp.text, year, term)
        except Exception as e:
            logger.error(f"SDU portal attendance error: {e}")
            return {}

    def _parse_attendance(self, html: str, year: str = "2025", term: str = "2") -> Dict:
        """Parse attendance HTML into structured data."""
        soup = BeautifulSoup(html, "html.parser")
        table = soup.find("table", {"class": "clTbl"})
        if not table:
            return {}

        courses = []
        rows = table.find_all("tr")[1:]  # skip header

        for row in rows:
            cells = row.find_all("td")
            if len(cells) < 10:
                continue

            # Course code from link
            link = cells[1].find("a")
            if not link:
                continue
            course_code = link.get_text(strip=True)

            # Course name from label
            label = cells[2].find("label")
            course_name = label.get_text(strip=True) if label else cells[2].get_text(strip=True)

            # Hours, attended, absent, permitted
            try:
                total = int(cells[5].get_text(strip=True))
                attended = int(cells[6].get_text(strip=True))
                absent = int(cells[7].get_text(strip=True))
                permitted = int(cells[8].get_text(strip=True))
            except (ValueError, IndexError):
                continue

            # Absence percentage from title attribute
            absence_div = cells[9].find("div", {"title": True})
            absence_pct = 0.0
            if absence_div:
                try:
                    absence_pct = float(absence_div.get("title", "0").replace("%", ""))
                except ValueError:
                    pass

            attendance_pct = round(100 - absence_pct, 1)
            status = "ok" if absence_pct < 20 else "warning" if absence_pct < 30 else "critical"

            courses.append({
                "course_code": course_code,
                "course_name": course_name,
                "total": total,
                "attended": attended,
                "absent": absent,
                "permitted": permitted,
                "absence_percentage": absence_pct,
                "percentage": attendance_pct,
                "status": status,
            })

        if not courses:
            return {}

        overall_absence = sum(c["absent"] for c in courses) / sum(c["total"] for c in courses) * 100 if courses else 0
        overall_pct = round(100 - overall_absence, 1)

        return {
            "courses": courses,
            "overall_percentage": overall_pct,
            "term": f"{year}-{int(year)+1} term {term}",
        }

    async def get_profile(self) -> Optional[Dict]:
        """Scrape student profile from home page."""
        if not self._logged_in:
            return None
        try:
            resp = await self.client.get(f"{SDU_PORTAL_URL}/index.php")
            soup = BeautifulSoup(resp.text, "html.parser")

            # Photo URL
            photo_tag = soup.find("img", {"title": self.student_id})
            photo_url = ""
            if photo_tag and photo_tag.get("src"):
                src = photo_tag["src"]
                photo_url = f"{SDU_PORTAL_URL}/{src}" if not src.startswith("http") else src

            # Parse table rows with student info
            profile = {
                "student_id": self.student_id,
                "photo_url": photo_url,
            }

            rows = soup.select("table.clsTbl tr")
            field_map = {
                "Student №": "student_id",
                "Fullname": "fullname",
                "Fullname(native)": "fullname_native",
                "Birth date": "birth_date",
                "Program / Class": "program",
                "Advisor": "advisor",
                "Status": "status",
                "Grant type": "grant_type",
                "Email": "email",
                "Last login date": "last_login",
                "Registration date": "registration_date",
                "ENT exam score": "ent_score",
            }

            for row in rows:
                cells = row.find_all("td")
                if len(cells) >= 2:
                    label = cells[0].get_text(strip=True).rstrip(":")
                    # Remove balance label suffix like "Balance [ 2025 - 2 ]"
                    label = label.split("[")[0].strip()
                    value_tag = cells[1].find("b")
                    value = value_tag.get_text(strip=True) if value_tag else cells[1].get_text(strip=True)

                    for key, field in field_map.items():
                        if key in label:
                            profile[field] = value
                            break

            return profile

        except Exception as e:
            logger.error(f"SDU portal profile scrape error: {e}")
            return None

    async def close(self):
        await self.client.aclose()


# ── MOCK DATA ─────────────────────────────────────────────────────────────────

MOCK_STUDENTS = {
    "220103001": {
        "student_id": "220103001",
        "name": "Azhar Bekova",
        "firstname": "Azhar",
        "lastname": "Bekova",
        "username": "220103001",
        "email": "a.bekova@sdu.edu.kz",
        "avatar": "",
        "program": "Computer Science",
        "year": 3,
    }
}

MOCK_SCHEDULE = [
    {"course_code": "CS301", "course_name": "Data Structures", "day": "Monday", "start_time": "09:00", "end_time": "10:30", "room": "B404", "teacher": "Dr. Kim", "class_type": "Lecture"},
    {"course_code": "CS301", "course_name": "Data Structures", "day": "Wednesday", "start_time": "09:00", "end_time": "10:30", "room": "B404", "teacher": "Dr. Kim", "class_type": "Lecture"},
    {"course_code": "MATH201", "course_name": "Calculus II", "day": "Monday", "start_time": "11:00", "end_time": "12:30", "room": "A201", "teacher": "Prof. Seitkali", "class_type": "Lecture"},
    {"course_code": "MATH201", "course_name": "Calculus II", "day": "Thursday", "start_time": "11:00", "end_time": "12:30", "room": "A201", "teacher": "Prof. Seitkali", "class_type": "Lecture"},
    {"course_code": "PHY101", "course_name": "Physics", "day": "Tuesday", "start_time": "14:00", "end_time": "15:30", "room": "C310", "teacher": "Dr. Ivanov", "class_type": "Lecture"},
    {"course_code": "PHY101", "course_name": "Physics", "day": "Friday", "start_time": "14:00", "end_time": "15:30", "room": "Lab-2", "teacher": "Dr. Ivanov", "class_type": "Lab"},
    {"course_code": "CS310", "course_name": "Database Systems", "day": "Tuesday", "start_time": "09:00", "end_time": "10:30", "room": "B501", "teacher": "Dr. Akhmetov", "class_type": "Lecture"},
    {"course_code": "CS310", "course_name": "Database Systems", "day": "Thursday", "start_time": "14:00", "end_time": "15:30", "room": "Lab-1", "teacher": "Dr. Akhmetov", "class_type": "Lab"},
    {"course_code": "ENG201", "course_name": "Technical English", "day": "Wednesday", "start_time": "14:00", "end_time": "15:30", "room": "D102", "teacher": "Ms. Johnson", "class_type": "Seminar"},
    {"course_code": "ENG201", "course_name": "Technical English", "day": "Friday", "start_time": "09:00", "end_time": "10:30", "room": "D102", "teacher": "Ms. Johnson", "class_type": "Seminar"},
]

MOCK_ASSIGNMENTS = [
    {"course_code": "CS301", "course_name": "Data Structures", "title": "Heap Implementation", "deadline_offset_days": 5, "submitted": False},
    {"course_code": "MATH201", "course_name": "Calculus II", "title": "Problem Set 4", "deadline_offset_days": 6, "submitted": False},
    {"course_code": "PHY101", "course_name": "Physics", "title": "Lab Report #3", "deadline_offset_days": 7, "submitted": False},
    {"course_code": "CS310", "course_name": "Database Systems", "title": "ER Diagram Assignment", "deadline_offset_days": 14, "submitted": True},
    {"course_code": "ENG201", "course_name": "Technical English", "title": "Essay: AI in Society", "deadline_offset_days": 10, "submitted": False},
    {"course_code": "CS301", "course_name": "Data Structures", "title": "Binary Search Tree", "deadline_offset_days": -3, "submitted": True},
]

MOCK_ATTENDANCE = [
    {"course_code": "CS301", "course_name": "Data Structures", "attended": 12, "total": 14, "percentage": 85.7},
    {"course_code": "MATH201", "course_name": "Calculus II", "attended": 10, "total": 16, "percentage": 62.5},
    {"course_code": "PHY101", "course_name": "Physics", "attended": 8, "total": 13, "percentage": 61.5},
    {"course_code": "CS310", "course_name": "Database Systems", "attended": 13, "total": 14, "percentage": 92.8},
    {"course_code": "ENG201", "course_name": "Technical English", "attended": 11, "total": 12, "percentage": 91.7},
]
