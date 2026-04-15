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
| Backend | FastAPI (Python) |
| LLM | Groq API (LLaMA 3) |
| Frontend | React.js |
| Styling | CSS |
| API Docs | Swagger UI (auto-generated) |

---

## Project Structure

```
sdu-ai-agent/
├── src/
│   ├── backend/          # FastAPI application
│   └── frontend/         # React application
├── docs/                 # Architecture diagrams, API docs
├── tests/                # Unit and integration tests
├── assets/               # Images, icons, static files
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

### Backend

```bash
cd src/backend
pip install -r requirements.txt
cp .env.example .env   # add your GROQ_API_KEY
uvicorn main:app --reload --port 8000
```

### Frontend

```bash
cd src/frontend
npm install
npm run dev
```

The app will be available at `http://localhost:3000`.

---

## Usage

1. Open the app in your browser
2. Type your question or select a feature from the sidebar
3. The agent responds using the Groq LLM with SDU-specific context

---

## Authors

Developed as a course project at SDU, Kazakhstan.
