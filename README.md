# Zero-Trust Campus Club Vault

An AI-powered, zero-trust access control platform for campus club collaboration. Securely share credentials (API keys, tokens, secrets) with team members through time-bound, risk-assessed access workflows.

> **"Never trust, always verify."**

---

## Features

- **AI Risk Scoring** — Every access request is analyzed by Google Gemini 2.0 Flash (with rule-based fallback), scoring risk 1–100 across dimensions like time, IP, device, frequency, account age, and denial history.
- **Time-Bound Access Tokens** — Approved requests grant scoped JWTs valid for 1–120 minutes. Tokens auto-expire and can be manually terminated or extended by the host.
- **Encrypted Credentials Vault** — Project secrets are stored with Fernet symmetric encryption. Members can only view decrypted values while holding an active token.
- **Misuse Detection** — Automatic account freezing when suspicious patterns are detected (high request frequency, repeated denials). Hosts can manually unfreeze users.
- **Role-Based Access Control** — Two roles: **User** (requests access) and **Host** (creates projects, approves/denies/terminates access, manages credentials).
- **Full Audit Trail** — Every action (login, request, approval, credential view, freeze) is logged with timestamp, IP, and user identity.
- **Platform Chatbot** — Rule-based + optional Gemini-powered chatbot to help users navigate the platform.
- **Group & Membership System** — Approved users are added as project members; hosts manage project membership.
- **Extension Workflow** — Users can request time extensions; hosts approve them, generating a new token with an extended expiry.

---

## Tech Stack

| Layer           | Technology                                                |
| --------------- | --------------------------------------------------------- |
| **Backend**     | Python, FastAPI, Uvicorn                                  |
| **Database**    | SQLite via SQLAlchemy ORM                                 |
| **Auth**        | JWT (python-jose), bcrypt (passlib)                       |
| **Encryption**  | Fernet (cryptography library)                             |
| **AI**          | Google Gemini 2.0 Flash API (risk scoring + chatbot)      |
| **Frontend**    | Vanilla HTML/CSS/JS, Font Awesome, Inter font             |
| **Validation**  | Pydantic v2                                               |

---

## Project Structure

```
zero-trust-vault/
├── run.py                  # Server entry point
├── requirements.txt        # Python dependencies
├── backend/
│   ├── main.py             # FastAPI app & all API routes
│   ├── auth.py             # JWT auth, password hashing, user verification
│   ├── models.py           # SQLAlchemy ORM models (7 tables)
│   ├── database.py         # Database engine & session setup
│   ├── risk_engine.py      # AI risk analysis (Gemini + fallback)
│   ├── token_manager.py    # Scoped token creation, encryption utilities
│   └── chatbot.py          # Platform chatbot (rule-based + Gemini)
└── frontend/
    ├── index.html           # Landing page
    ├── dashboard.html       # User dashboard
    ├── host.html            # Host management panel
    ├── app.js               # Frontend logic
    ├── styles.css           # Styling
    ├── animations.css       # CSS animations
    └── theme.js             # Dark/light theme toggle
```

---

## Getting Started

### Prerequisites

- Python 3.9+
- (Optional) A [Google Gemini API key](https://ai.google.dev/) for AI risk scoring and chatbot features

### Installation

```bash
# Clone the repository
git clone https://github.com/vikasgupta20/ClubVault.git
cd ClubVault/zero-trust-vault

# Install dependencies
pip install -r requirements.txt
```

### Environment Variables (Optional)

| Variable          | Description                              | Default              |
| ----------------- | ---------------------------------------- | -------------------- |
| `GEMINI_API_KEY`  | Enables AI risk scoring & chatbot        | Falls back to rules  |
| `JWT_SECRET_KEY`  | Secret key for JWT signing               | Dev default          |
| `FERNET_KEY`      | Encryption key for credentials vault     | Auto-generated       |

### Run the Server

```bash
python run.py
```

The server starts on **http://localhost:8000** with hot-reload enabled.

---

## API Endpoints

### Authentication
| Method | Endpoint               | Description              |
| ------ | ---------------------- | ------------------------ |
| POST   | `/api/auth/register`   | Register a new user      |
| POST   | `/api/auth/login`      | Login & get JWT          |
| GET    | `/api/auth/me`         | Get current user profile |

### Projects
| Method | Endpoint               | Description                    |
| ------ | ---------------------- | ------------------------------ |
| POST   | `/api/projects`        | Create a new project           |
| GET    | `/api/projects`        | List all projects              |
| GET    | `/api/projects/{id}`   | Get project details & members  |
| GET    | `/api/my-projects`     | List your hosted projects      |

### Access Requests
| Method | Endpoint                                  | Description                     |
| ------ | ----------------------------------------- | ------------------------------- |
| POST   | `/api/access-requests`                    | Submit an access request        |
| GET    | `/api/access-requests/pending`            | View pending requests (host)    |
| GET    | `/api/access-requests/all`                | View all requests (host)        |
| GET    | `/api/access-requests/my`                 | View your requests              |
| POST   | `/api/access-requests/decide`             | Approve/deny/terminate (host)   |
| POST   | `/api/access-requests/extend`             | Extend a token (host)           |
| POST   | `/api/access-requests/request-extension`  | Request an extension (user)     |

### Credentials Vault
| Method | Endpoint                        | Description                        |
| ------ | ------------------------------- | ---------------------------------- |
| POST   | `/api/credentials`              | Add encrypted credential (host)    |
| GET    | `/api/credentials/{project_id}` | View credentials (active token)    |
| DELETE | `/api/credentials/{id}`         | Delete credential (host)           |

### Other
| Method | Endpoint                          | Description                    |
| ------ | --------------------------------- | ------------------------------ |
| POST   | `/api/chatbot`                    | Platform navigation chatbot    |
| GET    | `/api/stats`                      | Dashboard statistics           |
| GET    | `/api/activity-logs/{project_id}` | Project audit log (host)       |
| POST   | `/api/users/unfreeze/{user_id}`   | Unfreeze a user (host)         |

---

## Security Highlights

1. **Zero-trust architecture** — every endpoint re-validates JWT and checks user status
2. **Bcrypt password hashing** — passwords never stored in plaintext
3. **Scoped, time-capped JWTs** — project access tokens are separate from login tokens and expire in ≤2 hours
4. **Fernet-encrypted credential storage** — secrets encrypted at rest, decryption gated by active token
5. **AI-powered risk analysis** — contextual signals fed to Gemini with deterministic fallback
6. **Automatic misuse detection & account freezing** — based on request frequency and denial patterns
7. **Full audit logging** — every action recorded with IP address and timestamp
8. **Input validation** — Pydantic schemas with field-level constraints and sanitization

---

## License

This project was built for the AMD Hackathon.
