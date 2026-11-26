# DataLineage AI
### SQL Lineage, Impact Analysis & Data Governance Platform

DataLineage AI is a Python-based application that analyzes SQL queries to identify table dependencies and column-level data lineage. It helps developers and data teams understand how data moves through SQL transformations and assess the potential impact of schema changes.

SQL statements are parsed for analysis and are never executed against a database.

## Features

- **SQL analysis:** Upload SQL files and analyze SQL dependencies.
- **Table lineage:** Identify relationships and dependencies between tables.
- **Column lineage:** Trace source columns to their corresponding output columns.
- **Schema impact analysis:** Assess potential effects of schema changes.
- **Multi-file analysis:** Analyze SQL files and ZIP uploads.
- **Visual lineage:** Explore data relationships through the web interface.
- **Analysis history:** Save and review previous analysis runs.
- **HTML reports:** Generate downloadable analysis reports.
- **GitHub integration:** Review SQL changes in pull requests.
- **Authentication:** Account registration, login, email verification and password recovery.
- **Organization support:** Workspaces, membership roles and organization-scoped data.
- **Governance capabilities:** Audit records, approvals, access controls and metadata integrations.

Some integrations require external services and additional configuration.

## Technology Stack

| Area | Technologies |
|---|---|
| Backend | Python, FastAPI |
| SQL parsing | SQLGlot |
| Graph processing | NetworkX |
| Frontend | HTML, CSS, JavaScript |
| Data storage | SQLite, optional PostgreSQL adapters |
| Authentication and security | Session-based authentication, cryptography |
| Testing | Pytest, HTTPX |
| API | REST, FastAPI |

## Project Structure

```text
DataLineage_AI/
├── backend/
│   ├── app/                 # Application and API source
│   ├── tests/               # Automated tests
│   ├── sample_sql/          # Example SQL inputs
│   └── requirements.txt     # Python dependencies
├── frontend/
│   ├── index.html
│   └── enterprise_intelligence.html
├── scripts/                 # Backup, migration and validation tools
├── docs/                    # Technical documentation
├── .github/
│   └── workflows/           # GitHub Actions workflow
├── .env.example
├── .gitignore
├── setup-local.ps1
├── smoke_test.py
└── README.md
```

## Getting Started

### Requirements

- Python 3.12 recommended
- pip
- Windows, Linux or macOS

### 1. Clone the repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
cd DataLineage_AI_GitHub_Upload
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with your actual GitHub repository URL.

### 2. Create a virtual environment

From the repository root:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure local authentication

Return to the repository root:

```powershell
cd ..
.\setup-local.ps1
```

This creates a local `backend/.env` file with generated development credentials. Keep this file private and never commit it.

### 5. Start the application

```powershell
cd backend
python -m uvicorn app.main:app --reload
```

Open:

- Application: http://127.0.0.1:8000
- API documentation: http://127.0.0.1:8000/docs
- Readiness endpoint: http://127.0.0.1:8000/health/ready

The exact available routes depend on the application configuration.

## Running Tests

From the `backend` directory:

```powershell
python -m pytest tests -q
```

The test suite covers API functionality, SQL analysis, authentication, integrations, security and governance features.

**Current validation note:** The latest recorded full test run completed with 381 passing tests and 9 failures. The remaining failures include authentication/rate-limit behaviour, lineage expectations, schema comparison and a Windows SQLite recovery file-lock issue. These are not being represented as passing tests.

## Documentation

Additional technical documentation is available in the `docs/` directory:

- [API Examples](docs/API_EXAMPLES.md)
- [Architecture Overview](docs/architecture/SAAS_ARCHITECTURE.md)
- [Deployment Guide](docs/deployment/DEPLOYMENT.md)
- [GitHub Integration](docs/integrations/GITHUB_INTEGRATION.md)
- [Security Review](docs/security/SECURITY_REVIEW_M35.md)
- [Benchmark Results](docs/BENCHMARKS.md)
- [Tenant Isolation Testing](docs/TENANT_ISOLATION_TESTING.md)
- [Email Configuration](docs/setup/EMAIL_SETUP.md)

## Security Notes

- Never commit `.env` files, passwords, tokens, private keys or database files.
- Use `.env.example` as a configuration reference.
- Configure strong, unique secrets for any shared deployment.
- Review authentication, authorization, database backups and external integrations before deployment.
- SQL analysis parses statements; it does not execute uploaded SQL.

## Deployment Status

This repository contains development and pilot-oriented deployment components. It should not be considered production-certified.

Before using it in a production environment, perform a security review, validate tenant isolation, configure durable storage and backups, and test recovery procedures.

## Project Purpose

This project demonstrates practical software engineering across backend API development, SQL parsing, graph-based lineage analysis, frontend integration, authentication, automated testing and data governance.

---
**DataLineage AI** | Built with Python, FastAPI and SQLGlot.
