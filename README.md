# 🔐 TrustVault — Secure Document Management System

TrustVault is a secure document management web application that helps users upload, organize, search, and share documents with controlled access permissions.

## 🌐 Live Website

**Live Demo:** https://trustvault-app.onrender.com

## 🚀 Features

- User registration and login
- Role-based access control
- Administrator, document owner, and viewer roles
- Secure document upload and validation
- Document search and management
- Read and edit permissions for named users
- Grant and revoke document access
- Administrator dashboard
- Audit logs for system and document activity
- Responsive user interface with interactive elements

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Python | Application logic |
| Flask | Web framework |
| HTML5 | Page structure |
| CSS3 | Styling and responsive design |
| JavaScript | Interactive UI |
| Supabase | Backend services |
| GitHub | Version control |
| Render | Web hosting |

## 👥 User Roles

### Administrator
- Access the administrator dashboard.
- Review system-wide audit logs.
- Monitor document and permission activity.
- Access administrative functions.

### Document Owner
- Upload and manage documents.
- Search for documents.
- Grant and revoke access to other users.

### Viewer
- Access documents shared with them according to their permissions.
- Cannot access administrator-only pages.

## 🔒 Security

TrustVault is designed to provide:
- Role-based authorization
- Document-level permission checks
- File-upload validation
- Activity logging
- Restricted administrator access

Never publish passwords, secret keys, or private user documents in the public repository.

## ⚙️ Backend Configuration

TrustVault uses Supabase for the backend services configured in the application.

Environment variables may include:

- `SUPABASE_URL`
- `SUPABASE_ANON_KEY`
- `SECRET_KEY`

Configure the variables required by your actual implementation in your local environment or Render dashboard. Never commit production credentials to GitHub.

## 💻 Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/Pavansai-5756/TrustVault.git
cd TrustVault
```

### 2. Create a virtual environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure environment variables

Set the environment variables required by your application.

### 5. Start the application

```bash
python app.py
```

Open http://127.0.0.1:5000 in your browser.

## ☁️ Deployment

TrustVault is deployed on Render.

**Live URL:** https://trustvault-app.onrender.com

The application can be configured to deploy from GitHub when new commits are pushed.

## 🧪 Testing

Run the automated tests, if included in the repository:

```bash
python -m pytest -q
```

Before submission, verify registration, login, document permissions, file uploads, access revocation, audit logging, and administrator-only access.

## 🎯 Project Objective

The objective of TrustVault is to provide a centralized and secure platform for document management with controlled sharing, role-based permissions, and activity monitoring.

## 👨‍💻 Developer

**Pavan Sai Tanniru**

- GitHub: https://github.com/Pavansai-5756
- Live Website: https://trustvault-app.onrender.com
