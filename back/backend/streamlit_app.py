import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
import sys
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

import streamlit as st
from dotenv import load_dotenv


st.set_page_config(
    page_title="SDU AI Assistant",
    page_icon="🎓",
    layout="wide",
    initial_sidebar_state="collapsed",
)

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parents[1]


def load_local_env_files():
    for path in (BASE_DIR, PROJECT_ROOT / "back" / "docker", PROJECT_ROOT, Path.cwd()):
        env_file = path / ".env"
        if env_file.exists():
            load_dotenv(env_file, override=False)


def load_streamlit_secrets():
    """Expose Streamlit Cloud secrets as environment variables before app imports."""
    try:
        secrets = dict(st.secrets)
    except Exception:
        return

    for key, value in secrets.items():
        if isinstance(value, Mapping):
            for nested_key, nested_value in value.items():
                os.environ.setdefault(str(nested_key), str(nested_value))
        else:
            os.environ.setdefault(str(key), str(value))


load_local_env_files()
load_streamlit_secrets()

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.agent.agent import SDUAgent
from app.agent.data_service import DataService, PORTAL_SESSIONS


DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
DAY_LABELS = {
    "Monday": "Mon",
    "Tuesday": "Tue",
    "Wednesday": "Wed",
    "Thursday": "Thu",
    "Friday": "Fri",
    "Saturday": "Sat",
}
DAY_FULL = {
    "Monday": "Monday",
    "Tuesday": "Tuesday",
    "Wednesday": "Wednesday",
    "Thursday": "Thursday",
    "Friday": "Friday",
    "Saturday": "Saturday",
}

SESSION_QUERY_KEY = "sdu_session"
SESSION_SAFE_FIELDS = {
    "student_id",
    "name",
    "firstname",
    "lastname",
    "fullname_native",
    "username",
    "email",
    "avatar",
    "portal_photo_url",
    "program",
    "advisor",
    "birth_date",
    "status",
    "grant_type",
    "year",
}


def run_async(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        loop = st.session_state.get("_async_loop")
        if loop is None or loop.is_closed():
            loop = asyncio.new_event_loop()
            st.session_state["_async_loop"] = loop
        return loop.run_until_complete(coro)

    # Streamlit normally runs this script synchronously, but keep a fallback for
    # environments that already have a running loop. This path cannot reuse
    # portal clients created on the session loop, so app data calls should not
    # normally reach it.
    new_loop = asyncio.new_event_loop()
    try:
        return new_loop.run_until_complete(coro)
    finally:
        new_loop.close()


def session_secret() -> bytes:
    secret = (
        os.getenv("STREAMLIT_SESSION_SECRET")
        or os.getenv("JWT_SECRET")
        or os.getenv("GROQ_API_KEY")
        or "sdu-ai-agent-local-session"
    )
    return secret.encode("utf-8")


def sign_payload(payload: str) -> str:
    return hmac.new(session_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def encode_session(student: dict) -> str:
    safe_student = {key: value for key, value in student.items() if key in SESSION_SAFE_FIELDS and value}
    payload = json.dumps(safe_student, ensure_ascii=False, separators=(",", ":"))
    encoded = base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")
    return f"{encoded}.{sign_payload(encoded)}"


def decode_session(token: str) -> dict:
    if not token or "." not in token:
        return {}
    encoded, signature = token.rsplit(".", 1)
    if not hmac.compare_digest(sign_payload(encoded), signature):
        return {}
    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        data = json.loads(payload)
        if isinstance(data, dict) and data.get("student_id"):
            return data
    except Exception:
        return {}
    return {}


def persist_student_session(student: dict):
    st.query_params[SESSION_QUERY_KEY] = encode_session(student)


def clear_student_session():
    if SESSION_QUERY_KEY in st.query_params:
        del st.query_params[SESSION_QUERY_KEY]


def restore_student_session():
    if st.session_state.get("student"):
        return
    token = st.query_params.get(SESSION_QUERY_KEY, "")
    if isinstance(token, list):
        token = token[0] if token else ""
    student = decode_session(token)
    if student:
        st.session_state.student = student
        st.session_state.restored_session = True


def init_state():
    defaults = {
        "student": None,
        "chat_messages": [],
        "data_cache": {},
        "data_cache_loaded_at": "",
        "data_cache_error": "",
        "needs_2fa": False,
        "pending_student_id": "",
        "pending_moodle_password": "",
        "restored_session": False,
        "nav": "Chat",
        "last_error": "",
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)


def student_id() -> str:
    student = st.session_state.get("student") or {}
    return student.get("student_id", "220103001")


def moodle_token() -> str:
    student = st.session_state.get("student") or {}
    return student.get("moodle_token", "")


def data_service() -> DataService:
    return DataService(
        moodle_token=moodle_token(),
        portal_client=PORTAL_SESSIONS.get(student_id()),
    )


class CachedDataService:
    """Read-only DataService facade for chat, backed by Streamlit page cache."""

    def __init__(self, cache: dict):
        self.cache = cache

    async def get_assignments(self, student_id: str, days: int = 30, include_submitted: bool = False):
        cached = self.cache.get("assignments", {})
        assignments = [
            item for item in cached.get("assignments", [])
            if item.get("days_left", 999) <= days and (include_submitted or not item.get("submitted"))
        ]
        return {**cached, "assignments": assignments, "count": len(assignments), "days_range": days}

    async def get_next_class(self, student_id: str):
        return self.cache.get("next_class", {}) or {"message": "No upcoming classes found"}

    async def get_schedule_for_day(self, student_id: str, day: str | None = None):
        now = datetime.now()
        target_day = day or now.strftime("%A")
        if target_day == "tomorrow":
            target_day = DAYS[(DAYS.index(now.strftime("%A")) + 1) % len(DAYS)] if now.strftime("%A") in DAYS else "Monday"
        schedule = self.cache.get("schedule", {})
        classes = sorted(schedule.get(target_day, []), key=lambda x: x.get("start_time", ""))
        return {
            "day": target_day,
            "date": now.strftime("%Y-%m-%d"),
            "classes_count": len(classes),
            "classes": classes,
            "has_classes": bool(classes),
        }

    async def get_full_schedule(self, student_id: str):
        return {"schedule": self.cache.get("schedule", {})}

    async def get_attendance(self, student_id: str, course_code: str | None = None):
        data = self.cache.get("attendance", {})
        if not course_code:
            return data
        courses = [c for c in data.get("courses", []) if str(c.get("course_code")) == str(course_code)]
        return {**data, "courses": courses}


def clear_page_cache():
    st.session_state.data_cache = {}
    st.session_state.data_cache_loaded_at = ""
    st.session_state.data_cache_error = ""


def refresh_page_cache():
    """Load all slow page data once and reuse it while switching pages."""
    sid = student_id()
    ds = data_service()
    cache = {}

    try:
        schedule = run_async(ds.get_full_schedule(sid))
        cache["schedule"] = schedule.get("schedule", {})
        cache["next_class"] = run_async(ds.get_next_class(sid))
        cache["assignments"] = run_async(
            ds.get_assignments(
                sid,
                days=90,
                include_submitted=True,
            )
        )
        cache["attendance"] = run_async(ds.get_attendance(sid))
        st.session_state.data_cache = cache
        st.session_state.data_cache_loaded_at = datetime.now().strftime("%H:%M:%S")
        st.session_state.data_cache_error = ""
        return cache
    except Exception as exc:
        st.session_state.data_cache_error = str(exc)
        raise


def get_page_cache():
    if not st.session_state.data_cache:
        with st.spinner("Loading data from the portal..."):
            refresh_page_cache()
    return st.session_state.data_cache


def render_refresh_bar():
    loaded_at = st.session_state.get("data_cache_loaded_at")
    col1, col2 = st.columns([2, 1])
    with col1:
        if loaded_at:
            st.caption(f"Data loaded: {loaded_at}")
        else:
            st.caption("Data has not been loaded yet")
        if st.session_state.get("restored_session") and not PORTAL_SESSIONS.get(student_id()):
            st.caption("Account restored after refresh. Live portal data may require logging in again with the portal password.")
    with col2:
        if st.button("Refresh data", key="refresh_all_data"):
            with st.spinner("Refreshing all pages..."):
                refresh_page_cache()
            st.rerun()


def page_config():
    pass


def inject_css():
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&display=swap');

        :root {
            --bg: #0f1117;
            --bg-card: #181c27;
            --bg-elevated: #1e2333;
            --bg-input: #252b3b;
            --accent: #4f7cff;
            --green: #34d399;
            --yellow: #fbbf24;
            --red: #f87171;
            --text-primary: #eef0f8;
            --text-secondary: #9aa2b8;
            --text-muted: #626b80;
            --border: rgba(255,255,255,.08);
        }

        html, body, [data-testid="stAppViewContainer"] {
            background: var(--bg);
            color: var(--text-primary);
            font-family: 'DM Sans', sans-serif;
        }

        .main .block-container {
            width: calc(100vw - 64px);
            max-width: calc(100vw - 64px);
            padding: 2rem 2rem 7rem;
        }

        [data-testid="stHeader"], [data-testid="stToolbar"], #MainMenu, footer {
            display: none;
        }

        h1, h2, h3, p, label, span, div {
            font-family: 'DM Sans', sans-serif;
        }

        .app-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
            padding: 14px 0 12px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 14px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .logo {
            width: 44px;
            height: 44px;
            border-radius: 16px;
            background: linear-gradient(135deg, var(--accent), #7c3aed);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 23px;
            box-shadow: 0 0 24px rgba(79,124,255,.22);
        }

        .title {
            font-size: 20px;
            font-weight: 700;
            letter-spacing: 0;
            line-height: 1.1;
        }

        .subtitle {
            color: var(--text-secondary);
            font-size: 13px;
            margin-top: 3px;
        }

        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 16px;
            margin-bottom: 12px;
        }

        .metric-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 13px 12px;
            text-align: center;
        }

        .metric-value {
            font-size: 24px;
            font-weight: 700;
            line-height: 1;
        }

        .metric-label {
            color: var(--text-muted);
            font-size: 12px;
            margin-top: 6px;
        }

        .badge {
            display: inline-flex;
            align-items: center;
            padding: 3px 8px;
            border-radius: 7px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: .3px;
        }

        .badge-blue { background: rgba(79,124,255,.15); color: var(--accent); }
        .badge-green { background: rgba(52,211,153,.13); color: var(--green); }
        .badge-yellow { background: rgba(251,191,36,.13); color: var(--yellow); }
        .badge-red { background: rgba(248,113,113,.13); color: var(--red); }

        .class-card, .assignment-card, .attendance-card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 14px 16px;
            margin-bottom: 10px;
        }

        .muted { color: var(--text-muted); }
        .secondary { color: var(--text-secondary); }
        .accent { color: var(--accent); }
        .green { color: var(--green); }
        .yellow { color: var(--yellow); }
        .red { color: var(--red); }

        .info-row {
            display: flex;
            justify-content: space-between;
            gap: 16px;
            padding: 10px 0;
            border-bottom: 1px solid var(--border);
            font-size: 14px;
        }

        .info-row:last-child { border-bottom: 0; }
        .info-label { color: var(--text-secondary); }
        .info-value { color: var(--text-primary); font-weight: 600; text-align: right; }

        .stTextInput input, .stTextArea textarea, .stPassword input, .stSelectbox div[data-baseweb="select"] {
            background: var(--bg-input) !important;
            color: var(--text-primary) !important;
            border-color: var(--border) !important;
            border-radius: 10px !important;
        }

        .stButton > button {
            width: 100%;
            border-radius: 10px;
            border: 1px solid var(--border);
            background: var(--bg-elevated);
            color: var(--text-primary);
            font-weight: 600;
        }

        .stButton > button[kind="primary"] {
            background: var(--accent);
            border-color: var(--accent);
            color: white;
        }

        div[data-testid="stHorizontalBlock"] {
            gap: .7rem;
        }

        .chat-bubble {
            padding: 11px 14px;
            border-radius: 18px;
            margin: 6px 0 12px;
            max-width: 86%;
            line-height: 1.55;
            white-space: pre-wrap;
            word-break: break-word;
        }

        .chat-user {
            margin-left: auto;
            border-bottom-right-radius: 5px;
            background: var(--accent);
            color: white;
        }

        .chat-assistant {
            margin-right: auto;
            border-bottom-left-radius: 5px;
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            color: var(--text-primary);
        }

        .chat-meta {
            margin: -8px 0 12px 42px;
            color: var(--text-muted);
            font-size: 11px;
        }

        .bottom-nav {
            position: fixed;
            left: 50%;
            bottom: 16px;
            transform: translateX(-50%);
            width: min(1320px, calc(100% - 48px));
            background: rgba(24,28,39,.96);
            border: 1px solid var(--border);
            border-radius: 18px;
            padding: 8px;
            backdrop-filter: blur(14px);
            z-index: 999;
            box-shadow: 0 8px 30px rgba(0,0,0,.32);
        }

        .stRadio [role="radiogroup"] {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: 6px;
        }

        .stRadio label {
            background: var(--bg-elevated);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 8px 6px;
            justify-content: center;
            min-height: 42px;
        }

        .stRadio label p {
            font-size: 13px;
            font-weight: 600;
        }

        [data-testid="stCaptionContainer"], .stMarkdown, .stAlert, .stToggle, .stSlider, .stTextInput label, .stSelectbox label {
            font-size: 14px;
        }

        [data-testid="stChatInput"] {
            width: min(1320px, calc(100% - 48px));
            left: 50%;
            transform: translateX(-50%);
        }

        [data-testid="stChatInput"] textarea {
            font-size: 14px !important;
        }

        @media (max-width: 520px) {
            .main .block-container { width: 100%; max-width: 100%; padding-left: 1rem; padding-right: 1rem; }
            .title { font-size: 18px; }
            .stRadio [role="radiogroup"] { grid-template-columns: repeat(5, minmax(0, 1fr)); }
            .stRadio label p { font-size: 11px; }
            .bottom-nav { width: calc(100% - 18px); }
            .chat-bubble { max-width: 94%; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def header(title: str, subtitle: str = ""):
    student = st.session_state.get("student") or {}
    name = student.get("name", "")
    st.markdown(
        f"""
        <div class="app-header">
            <div class="brand">
                <div class="logo">🎓</div>
                <div>
                    <div class="title">{title}</div>
                    <div class="subtitle">{subtitle or name or "SDU AI Assistant"}</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def metric_card(label: str, value: Any, color_class: str = "accent"):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-value {color_class}">{value}</div>
            <div class="metric-label">{label}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def badge(text: str, kind: str = "blue") -> str:
    return f'<span class="badge badge-{kind}">{text}</span>'


def render_login():
    header("SDU AI Assistant", "Sign in with your student account")
    st.markdown(
        """
        <div class="card" style="text-align:center;">
            <div style="font-size:44px;margin-bottom:8px;">🎓</div>
            <div style="font-size:18px;font-weight:700;">SDU Academic Assistant</div>
            <div class="secondary" style="font-size:13px;margin-top:5px;">
                Schedule, assignments, attendance, and AI chat in one Streamlit app.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not st.session_state.needs_2fa:
        with st.form("login_form"):
            sid = st.text_input("Student ID", placeholder="")
            password = st.text_input("Moodle password", type="password")
            portal_password = st.text_input(
                "Portal password",
                type="password",
                placeholder="",
            )
            submitted = st.form_submit_button("Sign in", type="primary")

        if submitted:
            if not sid or not password:
                st.error("Enter your student ID and Moodle password.")
                return

            with st.spinner("Checking account..."):
                student = run_async(
                    DataService().authenticate_student(
                        sid.strip(),
                        password,
                        portal_password=portal_password,
                    )
                )

            if not student:
                st.error("Invalid student ID or password.")
                return

            st.session_state.student = {
                **student,
                "student_id": student.get("student_id", sid.strip()),
            }
            st.session_state.restored_session = False
            persist_student_session(st.session_state.student)
            st.session_state.pending_student_id = sid.strip()
            st.session_state.pending_moodle_password = password

            if student.get("needs_portal_2fa"):
                clear_page_cache()
                st.session_state.needs_2fa = True
                st.rerun()

            seed_chat()
            with st.spinner("Loading page data..."):
                refresh_page_cache()
            st.rerun()

    else:
        st.info("SDU Portal requested verification. Check your email or SMS.")
        with st.form("two_fa_form"):
            code = st.text_input("Verification code", placeholder="123456")
            col1, col2 = st.columns(2)
            verify = col1.form_submit_button("Verify", type="primary")
            back = col2.form_submit_button("Back")

        if back:
            st.session_state.needs_2fa = False
            st.rerun()

        if verify:
            if not code:
                st.error("Enter the verification code.")
                return

            portal = PORTAL_SESSIONS.get(st.session_state.pending_student_id)
            if not portal:
                st.error("2FA session not found. Try signing in again.")
                st.session_state.needs_2fa = False
                return

            with st.spinner("Checking code..."):
                ok = run_async(portal.verify_2fa(code))
                if ok:
                    profile = run_async(portal.get_profile()) or {}
                    current = st.session_state.student or {}
                    st.session_state.student = {
                        **current,
                        "program": profile.get("program", current.get("program", "")),
                        "advisor": profile.get("advisor", current.get("advisor", "")),
                        "fullname_native": profile.get("fullname_native", current.get("fullname_native", "")),
                        "birth_date": profile.get("birth_date", current.get("birth_date", "")),
                        "status": profile.get("status", current.get("status", "")),
                        "grant_type": profile.get("grant_type", current.get("grant_type", "")),
                        "email": profile.get("email", current.get("email", "")),
                        "portal_photo_url": profile.get("photo_url", current.get("portal_photo_url", "")),
                        "portal_photo_data_uri": profile.get("photo_data_uri", current.get("portal_photo_data_uri", "")),
                    }
                    st.session_state.restored_session = False
                    persist_student_session(st.session_state.student)
                    st.session_state.needs_2fa = False
                    seed_chat()
                    with st.spinner("Loading data from the portal..."):
                        refresh_page_cache()
                    st.rerun()
                else:
                    st.error("Invalid verification code.")


def seed_chat():
    if st.session_state.chat_messages:
        return
    student = st.session_state.get("student") or {}
    first_name = (student.get("name") or "").split(" ")[0]
    greeting = (
        f"Hi{', ' + first_name if first_name else ''}!\n\n"
        "I can help you quickly understand your studies: schedule, next class, deadlines, assignments, and attendance. "
        "I use the already loaded cache, so switching pages and chatting should not parse the portal again."
    )
    st.session_state.chat_messages = [{"role": "assistant", "text": greeting}]


def nav():
    labels = {
        "Chat": "Chat",
        "Schedule": "Schedule",
        "Assignments": "Assignments",
        "Attendance": "Attendance",
        "Profile": "Profile",
    }
    st.markdown('<div class="bottom-nav">', unsafe_allow_html=True)
    selected = st.radio(
        "Navigation",
        options=list(labels.keys()),
        format_func=labels.get,
        key="nav",
        label_visibility="collapsed",
        horizontal=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)
    return selected


def render_chat():
    header("SDU AI Assistant", "online")
    seed_chat()

    suggestions = [
        "What is my next class?",
        "What is urgent to submit?",
        "My schedule for today",
        "Any attendance risks?",
        "Show my weekly schedule",
        "Which assignments are due this week?",
    ]

    cache = get_page_cache()
    attendance_source = cache.get("attendance", {}).get("source", "unknown")
    total_assignments = len(cache.get("assignments", {}).get("assignments", []))
    st.markdown(
        f"""
        <div class="card" style="padding:12px 14px;">
            <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;">
                <div>
                    <div style="font-size:13px;font-weight:700;">Chat context is ready</div>
                    <div class="secondary" style="font-size:12px;margin-top:3px;">
                        Cached assignments: {total_assignments} · attendance: {attendance_source}
                    </div>
                </div>
                <div>{badge("cache", "green")}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_clear, col_hint = st.columns([1, 2])
    if col_clear.button("Clear chat"):
        st.session_state.chat_messages = []
        seed_chat()
        st.rerun()
    col_hint.caption("Suggestions below use loaded data without parsing the portal again.")

    cols = st.columns(2)
    for index, text in enumerate(suggestions):
        if cols[index % 2].button(text, key=f"suggestion_{index}"):
            send_message(text)
            st.rerun()

    for message in st.session_state.chat_messages:
        cls = "chat-user" if message["role"] == "user" else "chat-assistant"
        st.markdown(
            f'<div class="chat-bubble {cls}">{html.escape(message["text"])}</div>',
            unsafe_allow_html=True,
        )
        if message.get("tool_used"):
            st.markdown(
                f'<div class="chat-meta">tool: {html.escape(message["tool_used"])}</div>',
                unsafe_allow_html=True,
            )

    prompt = st.chat_input("Ask a question...")
    if prompt:
        send_message(prompt)
        st.rerun()


def send_message(text: str):
    st.session_state.chat_messages.append({"role": "user", "text": text})
    ds = CachedDataService(get_page_cache())
    agent = SDUAgent(ds)
    history = [
        {"role": m["role"], "message": m["text"]}
        for m in st.session_state.chat_messages
        if m["role"] in {"user", "assistant"}
    ][-8:]

    try:
        with st.spinner("Thinking..."):
            result = run_async(agent.process_message(text, student_id(), history))
        st.session_state.chat_messages.append(
            {
                "role": "assistant",
                "text": result.get("response") or "Could not get an answer.",
                "tool_used": result.get("tool_used"),
            }
        )
    except Exception as exc:
        st.session_state.chat_messages.append(
            {
                "role": "assistant",
                "text": f"AI service error: {exc}",
            }
        )


def render_schedule():
    today = datetime.now().strftime("%A")
    header(
        "Schedule",
        datetime.now().strftime("%d.%m.%Y"),
    )
    cache = get_page_cache()
    schedule_data = cache.get("schedule", {})
    next_class = cache.get("next_class", {})

    if next_class.get("course_name"):
        label = "Next class" if next_class.get("is_today") else "Upcoming class"
        st.markdown(
            f"""
            <div class="card" style="border-color:rgba(79,124,255,.38);">
                {badge(label, "blue")}
                <div style="font-size:17px;font-weight:700;margin-top:10px;">{next_class["course_name"]}</div>
                <div class="secondary" style="margin-top:6px;font-size:13px;">
                    {next_class["start_time"]}-{next_class["end_time"]} · {next_class.get("room", "")} · {next_class.get("teacher", "")}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    default_day = today if today in DAYS else "Monday"
    active_day = st.radio(
        "Weekday",
        DAYS,
        format_func=lambda day: f"{DAY_LABELS.get(day, day)} · {len(schedule_data.get(day, []))}",
        index=DAYS.index(default_day),
        horizontal=True,
    )
    classes = schedule_data.get(active_day, [])

    st.markdown(
        f'<div class="subtitle" style="margin:14px 0 8px;">{DAY_FULL.get(active_day, active_day)}</div>',
        unsafe_allow_html=True,
    )
    if not classes:
        st.markdown(
            '<div class="card" style="text-align:center;padding:38px 20px;"><div style="font-size:34px;">🎉</div><div class="secondary" style="margin-top:8px;">No classes today.</div></div>',
            unsafe_allow_html=True,
        )
        return

    for cls in classes:
        kind = {
            "Lecture": ("Lecture", "blue"),
            "Lab": ("Lab", "green"),
            "Seminar": ("Seminar", "yellow"),
        }.get(cls.get("class_type", "Lecture"), (cls.get("class_type", "Class"), "blue"))
        st.markdown(
            f"""
            <div class="class-card">
                <div style="display:flex;justify-content:space-between;gap:12px;">
                    <div>
                        <div class="accent" style="font-size:13px;font-weight:700;">{cls.get("start_time")} - {cls.get("end_time")}</div>
                        <div style="font-size:16px;font-weight:700;margin-top:5px;">{cls.get("course_name")}</div>
                    </div>
                    <div>{badge(kind[0], kind[1])}</div>
                </div>
                <div class="secondary" style="font-size:13px;margin-top:9px;">
                    📍 {cls.get("room", "")} &nbsp;&nbsp; 👤 {cls.get("teacher", "")}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_assignments():
    header("Assignments", "Upcoming deadlines")
    include_submitted = st.toggle("Show submitted assignments", value=False)
    days = st.slider("Period", min_value=7, max_value=90, value=30, step=7)

    cached = get_page_cache().get("assignments", {})
    cached_assignments = cached.get("assignments", [])
    assignments = [
        item for item in cached_assignments
        if item.get("days_left", 999) <= days and (include_submitted or not item.get("submitted"))
    ]
    data = {
        **cached,
        "assignments": assignments,
        "count": len(assignments),
        "days_range": days,
    }

    pending = [a for a in assignments if not a.get("submitted")]
    urgent = [a for a in pending if a.get("days_left", 99) <= 2]

    cols = st.columns(3)
    with cols[0]:
        metric_card("Total", len(assignments), "accent")
    with cols[1]:
        metric_card("Pending", len(pending), "yellow")
    with cols[2]:
        metric_card("Urgent", len(urgent), "red" if urgent else "green")

    if not assignments:
        st.markdown(
            '<div class="card" style="text-align:center;padding:38px 20px;"><div style="font-size:34px;">✅</div><div class="secondary" style="margin-top:8px;">No assignments.</div></div>',
            unsafe_allow_html=True,
        )
        return

    for item in assignments:
        submitted = item.get("submitted")
        days_left = item.get("days_left", 0)
        if submitted:
            status = badge("Submitted", "green")
            border = "var(--border)"
        elif days_left == 0:
            status = badge("Today", "red")
            border = "rgba(248,113,113,.35)"
        elif days_left <= 2:
            status = badge(f"In {days_left} days", "red")
            border = "rgba(248,113,113,.35)"
        elif days_left <= 5:
            status = badge(f"In {days_left} days", "yellow")
            border = "rgba(251,191,36,.30)"
        else:
            status = badge(f"In {days_left} days", "blue")
            border = "var(--border)"

        opacity = ".62" if submitted else "1"
        st.markdown(
            f"""
            <div class="assignment-card" style="border-color:{border};opacity:{opacity};">
                <div style="display:flex;justify-content:space-between;gap:12px;">
                    <div>
                        <div style="font-size:16px;font-weight:700;">{item.get("title", "Assignment")}</div>
                        <div class="accent" style="font-size:13px;margin-top:4px;">{item.get("course_name", "")}</div>
                    </div>
                    <div>{status}</div>
                </div>
                <div class="muted" style="font-size:13px;margin-top:10px;">📅 {item.get("deadline_formatted", "")}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_attendance():
    header("Attendance", "Current semester")
    data = get_page_cache().get("attendance", {})

    source = data.get("source", "unknown")
    source_labels = {
        "portal": ("SDU Portal", "green"),
        "moodle": ("Moodle", "blue"),
        "mock": ("Mock data", "yellow"),
    }
    source_label, source_kind = source_labels.get(source, ("Unknown source", "yellow"))
    st.markdown(
        f'<div style="margin:-4px 0 18px;">{badge(f"Source: {source_label}", source_kind)}</div>',
        unsafe_allow_html=True,
    )
    if source != "portal":
        if not PORTAL_SESSIONS.get(student_id()):
            st.info("To load attendance from SDU Portal, sign out and sign in again with the portal password.")
        else:
            st.info("Portal did not return attendance data, so the app used fallback data.")

    overall = data.get("overall_percentage", 0)
    status_class = "green" if overall >= 75 else "yellow" if overall >= 50 else "red"
    cols = st.columns([1, 2])
    with cols[0]:
        st.markdown(
            f"""
                <div class="metric-card">
                    <div class="metric-value {status_class}">{overall:.1f}%</div>
                    <div class="metric-label">Overall</div>
                </div>
            """,
            unsafe_allow_html=True,
        )
    with cols[1]:
        if data.get("has_issues"):
            st.warning(f"The SDU minimum attendance is 75%. Low attendance in {len(data.get('low_attendance_courses', []))} course(s).")
        else:
            st.success("Everything looks good.")

    courses = sorted(data.get("courses", []), key=lambda c: c.get("percentage", 0))
    if not courses:
        st.markdown('<div class="card secondary">No attendance data.</div>', unsafe_allow_html=True)
        return

    for course in courses:
        pct = course.get("percentage", 0)
        kind = "green" if pct >= 75 else "yellow" if pct >= 50 else "red"
        label = "Good" if pct >= 75 else "Warning" if pct >= 50 else "Critical"
        st.markdown(
            f"""
            <div class="attendance-card" style="border-color:{'var(--border)' if kind == 'green' else 'rgba(251,191,36,.32)' if kind == 'yellow' else 'rgba(248,113,113,.35)'};">
                <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;">
                    <div>
                        <div style="font-size:16px;font-weight:700;">{course.get("course_name", "")}</div>
                        <div class="secondary" style="font-size:13px;margin-top:5px;">{course.get("attended", 0)}/{course.get("total", 0)} classes · missed {course.get("missed", 0)}</div>
                    </div>
                    <div style="text-align:right;">
                        <div class="{kind}" style="font-size:22px;font-weight:700;line-height:1;">{pct:.1f}%</div>
                        <div style="margin-top:6px;">{badge(label, kind)}</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.progress(min(max(pct / 100, 0), 1))


def info_row(label: str, value: Any) -> str:
    if not value:
        return ""
    return f'<div class="info-row"><div class="info-label">{label}</div><div class="info-value">{value}</div></div>'


def render_profile():
    header("Profile", "Student information")
    student = st.session_state.get("student") or {}
    name = student.get("name") or "Student"
    initials = "".join(part[:1] for part in name.split()[:2]).upper() or "?"
    embedded_photo = student.get("portal_photo_data_uri") or ""
    external_photo = student.get("portal_photo_url") or student.get("avatar") or ""
    photo = embedded_photo or external_photo
    photo_status = "embedded" if embedded_photo else "link found" if external_photo else "not found"

    avatar = (
        f'<img src="{photo}" style="width:128px;height:128px;border-radius:50%;object-fit:cover;border:3px solid rgba(79,124,255,.38);">'
        if photo
        else f'<div class="logo" style="width:96px;height:96px;border-radius:50%;font-size:32px;font-weight:700;color:white;">{initials}</div>'
    )

    st.markdown(
        f"""
        <div class="card" style="text-align:center;">
            <div style="display:flex;justify-content:center;">{avatar}</div>
            <div style="font-size:20px;font-weight:700;margin-top:14px;">{name}</div>
            <div class="secondary" style="font-size:13px;margin-top:4px;">{student.get("fullname_native", "")}</div>
            <div style="margin-top:10px;">{badge(student.get("status") or "Studying", "green")}</div>
        </div>
        <div class="card">
            {info_row("Student ID", student.get("student_id"))}
            {info_row("Program", student.get("program"))}
            {info_row("Advisor", student.get("advisor"))}
            {info_row("Email", student.get("email"))}
            {info_row("Birth date", student.get("birth_date"))}
            {info_row("Grant", student.get("grant_type"))}
            {info_row("Photo", photo_status)}
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("Sign out"):
        for key in ["student", "chat_messages", "needs_2fa", "pending_student_id", "pending_moodle_password"]:
            st.session_state[key] = None if key == "student" else "" if key.startswith("pending") else False if key == "needs_2fa" else []
        st.session_state.restored_session = False
        clear_page_cache()
        clear_student_session()
        st.rerun()


def main():
    page_config()
    inject_css()
    init_state()
    restore_student_session()

    if not st.session_state.student:
        render_login()
        return

    selected = nav()
    render_refresh_bar()
    if selected == "Chat":
        render_chat()
    elif selected == "Schedule":
        render_schedule()
    elif selected == "Assignments":
        render_assignments()
    elif selected == "Attendance":
        render_attendance()
    elif selected == "Profile":
        render_profile()


if __name__ == "__main__":
    main()
