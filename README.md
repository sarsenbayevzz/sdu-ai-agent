# SDU AI Agent

An AI-powered academic assistant for students at Suleyman Demirel University (SDU), Kazakhstan.

---

## Problem Statement

SDU students face fragmented access to academic resources — Moodle notifications, advisor FAQs, library services, and homework help are spread across different platforms. There is no unified intelligent assistant that understands the SDU academic context and can support students in real time.

---

## Features

- **Homework Checker** — Upload assignments and receive AI feedback
- **Lecture Transcription** — Convert lecture audio to searchable text
- **News Feed** — Aggregated SDU academic news and announcements
- **Advisor FAQ** — Instant answers to common advising questions
- **Student Advising** — Personalized course and schedule guidance
- **Library Automation** — Book search and reservation via chat
- **Socratic Learning** — Guided problem-solving without giving direct answers
- **Email via Chat** — Send emails to university staff directly from the interface

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| App | Streamlit (Python) |
| Backend logic | FastAPI-compatible Python services |
| LLM | Groq API (LLaMA 3) |
| Legacy frontend | React.js |
| Styling | CSS |
| API Docs | Swagger UI if running the FastAPI entry point |

---

## Project Structure

```
sdu-ai-agent/
├── back/
│   ├── backend/
│   │   ├── streamlit_app.py  # Streamlit application
│   │   └── app/              # Agent, data, API, integrations
│   └── docker/
│       └── docker-compose.yml
├── front/                    # Legacy React/Vite frontend
├── README.md
├── .gitignore
└── LICENSE
```

---

## Installation

### Prerequisites

- Python 3.10+
- Node.js 18+
- Groq API key

### Streamlit App

```bash
cd back/backend
pip install -r requirements.txt
streamlit run streamlit_app.py
```

The app will be available at `http://localhost:8501`.

For Streamlit Cloud, do not commit `.env`. Add these in **Manage app -> Settings -> Secrets**:

```toml
GROQ_API_KEY = "your_groq_key"
GROQ_MODEL = "llama-3.3-70b-versatile"
MOODLE_URL = "https://moodle.sdu.edu.kz"
SDU_PORTAL_URL = "https://my.sdu.edu.kz"
USE_MOCK_DATA = "false"
```

Mock login:

```text
student_id: 220103001
password: password123
```

The React/Vite frontend and FastAPI app are still in the repository as legacy/separate entry points.

---

## Usage

1. Open the app in your browser
2. Type your question or select a feature from the sidebar
3. The agent responds using the Groq LLM with SDU-specific context

---

## Authors

Developed as a course project at SDU, Kazakhstan.
