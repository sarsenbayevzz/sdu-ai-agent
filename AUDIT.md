# AUDIT.md — SDU AI Agent Repository

## 230103180
## 230103237
## 230103362

## Score: 9 / 10

---

## Evaluation

### README Quality — 2/2
A full `README.md` is present at the root with project title, problem statement, features, installation steps, usage instructions, and technology stack. A collaborator can understand and run the project without any additional guidance.

### Folder Structure — 2/2
The repository follows the required structure: `src/backend` (FastAPI), `src/frontend` (React), `docs/`, `tests/`, and `assets/`. Separation of concerns is clear and consistent with workshop standards.

### File Naming Consistency — 2/2
File names follow Python and JavaScript conventions throughout. Folder names are descriptive and use standard naming. No inconsistencies in casing or separators were observed.

### Presence of Essential Files — 2/2
- `.gitignore` present
- `LICENSE` present (MIT)
- `requirements.txt` present inside `src/backend`
- `package.json` present inside `src/frontend`
- `README.md` present at root

### Commit History Quality — 1/2
Commit history has been improved with separate, meaningful commits per change (refactor, docs, chore). However, the overall number of commits is still low and there is no branching strategy visible. A more incremental development history would reflect better engineering practice.

---

## Summary

The project has a solid technical foundation — FastAPI backend with Groq LLM integration, React frontend, and a well-scoped feature set covering eight academic assistant functions. The repository now meets all structural and documentation requirements. The one remaining weakness is a shallow commit history. Adding tests to the `tests/` folder would bring the score to a full 10/10.
