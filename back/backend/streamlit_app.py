import asyncio
import html
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
    layout="centered",
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
    "Monday": "Пн",
    "Tuesday": "Вт",
    "Wednesday": "Ср",
    "Thursday": "Чт",
    "Friday": "Пт",
    "Saturday": "Сб",
}
DAY_FULL = {
    "Monday": "Понедельник",
    "Tuesday": "Вторник",
    "Wednesday": "Среда",
    "Thursday": "Четверг",
    "Friday": "Пятница",
    "Saturday": "Суббота",
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
        with st.spinner("Загружаем данные с портала..."):
            refresh_page_cache()
    return st.session_state.data_cache


def render_refresh_bar():
    loaded_at = st.session_state.get("data_cache_loaded_at")
    col1, col2 = st.columns([2, 1])
    with col1:
        if loaded_at:
            st.caption(f"Данные загружены: {loaded_at}")
        else:
            st.caption("Данные ещё не загружены")
    with col2:
        if st.button("Обновить данные", key="refresh_all_data"):
            with st.spinner("Обновляем все страницы..."):
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
            max-width: 760px;
            padding: 1.2rem 1rem 5rem;
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
            letter-spacing: -.2px;
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
            width: min(720px, calc(100% - 24px));
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

        @media (max-width: 520px) {
            .main .block-container { padding-left: .85rem; padding-right: .85rem; }
            .title { font-size: 18px; }
            .stRadio [role="radiogroup"] { grid-template-columns: repeat(5, minmax(0, 1fr)); }
            .stRadio label p { font-size: 11px; }
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
    header("SDU AI Assistant", "Войди через свой студенческий аккаунт")
    st.markdown(
        """
        <div class="card" style="text-align:center;">
            <div style="font-size:44px;margin-bottom:8px;">🎓</div>
            <div style="font-size:18px;font-weight:700;">Академический помощник SDU</div>
            <div class="secondary" style="font-size:13px;margin-top:5px;">
                Расписание, задания, посещаемость и AI-чат в одном Streamlit приложении.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not st.session_state.needs_2fa:
        with st.form("login_form"):
            sid = st.text_input("Студенческий ID", placeholder="230103237")
            password = st.text_input("Пароль Moodle", type="password")
            portal_password = st.text_input(
                "Пароль Портала",
                type="password",
                placeholder="Необязательно, нужен для фото/программы/портала",
            )
            submitted = st.form_submit_button("Войти", type="primary")

        if submitted:
            if not sid or not password:
                st.error("Введите студенческий ID и пароль Moodle.")
                return

            with st.spinner("Проверяем аккаунт..."):
                student = run_async(
                    DataService().authenticate_student(
                        sid.strip(),
                        password,
                        portal_password=portal_password,
                    )
                )

            if not student:
                st.error("Неверный студенческий ID или пароль.")
                return

            st.session_state.student = {
                **student,
                "student_id": student.get("student_id", sid.strip()),
            }
            st.session_state.pending_student_id = sid.strip()
            st.session_state.pending_moodle_password = password

            if student.get("needs_portal_2fa"):
                clear_page_cache()
                st.session_state.needs_2fa = True
                st.rerun()

            seed_chat()
            with st.spinner("Загружаем данные для страниц..."):
                refresh_page_cache()
            st.rerun()

    else:
        st.info("Портал SDU запросил подтверждение. Проверь email или SMS.")
        with st.form("two_fa_form"):
            code = st.text_input("Код верификации", placeholder="123456")
            col1, col2 = st.columns(2)
            verify = col1.form_submit_button("Подтвердить", type="primary")
            back = col2.form_submit_button("Назад")

        if back:
            st.session_state.needs_2fa = False
            st.rerun()

        if verify:
            if not code:
                st.error("Введите код верификации.")
                return

            portal = PORTAL_SESSIONS.get(st.session_state.pending_student_id)
            if not portal:
                st.error("Сессия 2FA не найдена. Попробуйте войти заново.")
                st.session_state.needs_2fa = False
                return

            with st.spinner("Проверяем код..."):
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
                    st.session_state.needs_2fa = False
                    seed_chat()
                    with st.spinner("Загружаем данные с портала..."):
                        refresh_page_cache()
                    st.rerun()
                else:
                    st.error("Неверный код верификации.")


def seed_chat():
    if st.session_state.chat_messages:
        return
    student = st.session_state.get("student") or {}
    first_name = (student.get("name") or "").split(" ")[0]
    greeting = (
        f"Привет{', ' + first_name if first_name else ''}!\n\n"
        "Я помогу быстро разобраться с учёбой: расписание, следующая пара, дедлайны, задания и посещаемость. "
        "Данные беру из уже загруженного кэша, поэтому переключение страниц и чат не должны заново парсить портал."
    )
    st.session_state.chat_messages = [{"role": "assistant", "text": greeting}]


def nav():
    labels = {
        "Chat": "Чат",
        "Schedule": "Расписание",
        "Assignments": "Задания",
        "Attendance": "Посещаемость",
        "Profile": "Профиль",
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
    header("SDU AI Assistant", "онлайн")
    seed_chat()

    suggestions = [
        "Какая следующая пара?",
        "Что срочно сдать?",
        "Моё расписание сегодня",
        "Какие риски по посещаемости?",
        "Покажи расписание на неделю",
        "Какие задания на этой неделе?",
    ]

    cache = get_page_cache()
    attendance_source = cache.get("attendance", {}).get("source", "unknown")
    total_assignments = len(cache.get("assignments", {}).get("assignments", []))
    st.markdown(
        f"""
        <div class="card" style="padding:12px 14px;">
            <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;">
                <div>
                    <div style="font-size:13px;font-weight:700;">Контекст чата готов</div>
                    <div class="secondary" style="font-size:12px;margin-top:3px;">
                        Заданий в кэше: {total_assignments} · посещаемость: {attendance_source}
                    </div>
                </div>
                <div>{badge("cache", "green")}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_clear, col_hint = st.columns([1, 2])
    if col_clear.button("Очистить чат"):
        st.session_state.chat_messages = []
        seed_chat()
        st.rerun()
    col_hint.caption("Подсказки ниже отвечают по загруженным данным без повторного парсинга.")

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

    prompt = st.chat_input("Напиши вопрос...")
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
        with st.spinner("Думаю..."):
            result = run_async(agent.process_message(text, student_id(), history))
        st.session_state.chat_messages.append(
            {
                "role": "assistant",
                "text": result.get("response") or "Не удалось получить ответ.",
                "tool_used": result.get("tool_used"),
            }
        )
    except Exception as exc:
        st.session_state.chat_messages.append(
            {
                "role": "assistant",
                "text": f"Ошибка AI-сервиса: {exc}",
            }
        )


def render_schedule():
    today = datetime.now().strftime("%A")
    header(
        "Расписание",
        datetime.now().strftime("%d.%m.%Y"),
    )
    cache = get_page_cache()
    schedule_data = cache.get("schedule", {})
    next_class = cache.get("next_class", {})

    if next_class.get("course_name"):
        label = "Следующая пара" if next_class.get("is_today") else "Ближайшая пара"
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
        "День недели",
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
            '<div class="card" style="text-align:center;padding:38px 20px;"><div style="font-size:34px;">🎉</div><div class="secondary" style="margin-top:8px;">Пар нет — выходной!</div></div>',
            unsafe_allow_html=True,
        )
        return

    for cls in classes:
        kind = {
            "Lecture": ("Лекция", "blue"),
            "Lab": ("Лаб", "green"),
            "Seminar": ("Семинар", "yellow"),
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
    header("Задания", "Ближайшие дедлайны")
    include_submitted = st.toggle("Показывать сданные задания", value=False)
    days = st.slider("Период", min_value=7, max_value=90, value=30, step=7)

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
        metric_card("Всего", len(assignments), "accent")
    with cols[1]:
        metric_card("Не сдано", len(pending), "yellow")
    with cols[2]:
        metric_card("Срочно", len(urgent), "red" if urgent else "green")

    if not assignments:
        st.markdown(
            '<div class="card" style="text-align:center;padding:38px 20px;"><div style="font-size:34px;">✅</div><div class="secondary" style="margin-top:8px;">Заданий нет.</div></div>',
            unsafe_allow_html=True,
        )
        return

    for item in assignments:
        submitted = item.get("submitted")
        days_left = item.get("days_left", 0)
        if submitted:
            status = badge("Сдано", "green")
            border = "var(--border)"
        elif days_left == 0:
            status = badge("Сегодня", "red")
            border = "rgba(248,113,113,.35)"
        elif days_left <= 2:
            status = badge(f"Через {days_left} дн.", "red")
            border = "rgba(248,113,113,.35)"
        elif days_left <= 5:
            status = badge(f"Через {days_left} дн.", "yellow")
            border = "rgba(251,191,36,.30)"
        else:
            status = badge(f"Через {days_left} дн.", "blue")
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
    header("Посещаемость", "Текущий семестр")
    data = get_page_cache().get("attendance", {})

    source = data.get("source", "unknown")
    source_labels = {
        "portal": ("SDU Portal", "green"),
        "moodle": ("Moodle", "blue"),
        "mock": ("Mock data", "yellow"),
    }
    source_label, source_kind = source_labels.get(source, ("Unknown source", "yellow"))
    st.markdown(
        f'<div style="margin:-4px 0 12px;">{badge(f"Источник: {source_label}", source_kind)}</div>',
        unsafe_allow_html=True,
    )
    if source != "portal":
        if not PORTAL_SESSIONS.get(student_id()):
            st.info("Чтобы брать посещаемость с SDU Portal, выйдите и войдите заново, указав пароль Портала.")
        else:
            st.info("Portal не вернул данные посещаемости, поэтому приложение использовало fallback.")

    overall = data.get("overall_percentage", 0)
    status_class = "green" if overall >= 75 else "yellow" if overall >= 50 else "red"
    cols = st.columns([1, 2])
    with cols[0]:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-value {status_class}">{overall:.1f}%</div>
                <div class="metric-label">Общая</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with cols[1]:
        if data.get("has_issues"):
            st.warning(f"Минимальная посещаемость в SDU — 75%. Низкая посещаемость в {len(data.get('low_attendance_courses', []))} курс(ах).")
        else:
            st.success("Всё в порядке.")

    courses = sorted(data.get("courses", []), key=lambda c: c.get("percentage", 0))
    if not courses:
        st.markdown('<div class="card secondary">Нет данных по посещаемости.</div>', unsafe_allow_html=True)
        return

    for course in courses:
        pct = course.get("percentage", 0)
        kind = "green" if pct >= 75 else "yellow" if pct >= 50 else "red"
        label = "Хорошо" if pct >= 75 else "Внимание" if pct >= 50 else "Критично"
        st.markdown(
            f"""
            <div class="attendance-card" style="border-color:{'var(--border)' if kind == 'green' else 'rgba(251,191,36,.32)' if kind == 'yellow' else 'rgba(248,113,113,.35)'};">
                <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;">
                    <div>
                        <div style="font-size:16px;font-weight:700;">{course.get("course_name", "")}</div>
                        <div class="secondary" style="font-size:13px;margin-top:5px;">{course.get("attended", 0)}/{course.get("total", 0)} занятий · пропущено {course.get("missed", 0)}</div>
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
    header("Профиль", "Информация о студенте")
    student = st.session_state.get("student") or {}
    name = student.get("name") or "Student"
    initials = "".join(part[:1] for part in name.split()[:2]).upper() or "?"
    embedded_photo = student.get("portal_photo_data_uri") or ""
    external_photo = student.get("portal_photo_url") or student.get("avatar") or ""
    photo = embedded_photo or external_photo
    photo_status = "встроено" if embedded_photo else "ссылка найдена" if external_photo else "не найдено"

    avatar = (
        f'<img src="{photo}" style="width:96px;height:96px;border-radius:50%;object-fit:cover;border:3px solid rgba(79,124,255,.38);">'
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
            {info_row("Программа", student.get("program"))}
            {info_row("Advisor", student.get("advisor"))}
            {info_row("Email", student.get("email"))}
            {info_row("Дата рождения", student.get("birth_date"))}
            {info_row("Грант", student.get("grant_type"))}
            {info_row("Фото", photo_status)}
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("Выйти из аккаунта"):
        for key in ["student", "chat_messages", "needs_2fa", "pending_student_id", "pending_moodle_password"]:
            st.session_state[key] = None if key == "student" else "" if key.startswith("pending") else False if key == "needs_2fa" else []
        clear_page_cache()
        st.rerun()


def main():
    page_config()
    inject_css()
    init_state()

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
