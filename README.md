# 🛡️ TrustVault — Secure Document Management System

TrustVault is a web-based document management application designed to help users securely organize, upload, and manage their important documents in one place. It provides account-based access so users can manage their own documents and keep their files separate from those of other users.

## 🚀 Live Demo

**Live Website:** https://trustvault-app.onrender.com

## 📌 Project Overview

Managing important documents can be difficult when files are scattered across different locations. TrustVault aims to simplify document management by providing a centralized platform where users can create an account, sign in, upload documents, and manage their personal files.

The application uses a Flask backend and a PostgreSQL database to support user accounts and document-related data.

## ✨ Features

- 🔐 **User Authentication** — Register and sign in to your account.
- 👤 **Account-Based Access** — Keep document management associated with individual user accounts.
- 📁 **Document Management** — Upload and manage important documents.
- 🗄️ **PostgreSQL Database** — Store application data using PostgreSQL.
- 📋 **Activity Logging** — Record relevant user activities for auditing.
- 🎨 **Modern User Interface** — Dark green design with a clean, responsive layout.
- ☁️ **Cloud Deployment** — Access the application through its deployed website.

## 🛠️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend programming |
| Flask | Web application framework |
| Flask-Login | User authentication and session management |
| Flask-SQLAlchemy | Database integration |
| Flask-WTF | Form handling and CSRF protection |
| PostgreSQL | Relational database |
| Supabase | Hosted PostgreSQL database |
| HTML5 | Web page structure |
| CSS3 | Styling and responsive design |
| Jinja2 | Dynamic HTML templates |
| Gunicorn | Production WSGI server |
| Render | Application hosting |

## 🏗️ Application Architecture

The application follows a simple web architecture:

1. **Frontend:** HTML and CSS provide the user interface.
2. **Backend:** Flask handles requests, authentication, and application logic.
3. **Database:** PostgreSQL stores user, document, and activity-log records.
4. **Hosting:** Render runs the deployed Flask application.

## 📂 Project Structure

```text
TrustVault/
│
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/             # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   └── ...
│
├── static/                # CSS, JavaScript, and static assets
│
└── README.md              # Project documentation
```

*Update the folder and file names above if your actual repository structure is different.*

## ⚙️ Installation and Setup

Follow these steps to run TrustVault locally.

### 1. Clone the repository

```bash
git clone https://github.com/Pavansai-5756/TrustVault.git
```

### 2. Open the project folder

```bash
cd TrustVault
```

### 3. Create a virtual environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Configure environment variables

Set the required environment variables before starting the application.

| Variable | Description |
|---|---|
| `SECRET_KEY` | Secret key used by Flask |
| `DATABASE_URL` | PostgreSQL database connection string |
| `COOKIE_SECURE` | Set to `1` when using HTTPS and secure cookies |

**Security note:** Keep your database credentials and secret keys private. Do not commit them to GitHub.

### 6. Run the application

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

*Make sure your application supports running with `python app.py`; otherwise, use the development command configured in your project.*

## ☁️ Deployment

TrustVault is deployed using Render and uses Supabase for its PostgreSQL database.

General deployment steps:

1. Push your project code to a public or appropriately accessible GitHub repository.
2. Create a web service on Render and connect the repository.
3. Install dependencies using `requirements.txt`.
4. Configure the required environment variables in Render.
5. Use the production start command:

   ```bash
   gunicorn app:app
   ```

6. Deploy the application and test registration, login, and document-management functionality.

## 🔒 Security Considerations

TrustVault includes several security-related measures:

- Password hashing rather than storing plain-text passwords.
- CSRF protection for form submissions.
- Login-protected application routes.
- HTTP-only session cookies.
- Account-based document management.
- Activity logging for relevant application events.

**Important:** These features do not automatically guarantee complete security. Production use should also include appropriate file validation, authorization checks, secure database configuration, and testing to prevent unauthorized document access.

## 🎯 Project Objective

The main objective of TrustVault is to develop a user-friendly document management system that combines authentication, database integration, and a modern web interface to help users manage their important files in one place.

## 🔮 Future Enhancements

- Two-factor authentication.
- Document search and filtering.
- File preview and download controls.
- Improved audit-log dashboard.
- Password reset and email verification.
- Enhanced access controls and security monitoring.
- Document encryption and secure file storage.

## 👨‍💻 Developer

**Pavan Sai Tanniru**

GitHub: [Pavansai-5756](https://github.com/Pavansai-5756)

Project Repository: [TrustVault](https://github.com/Pavansai-5756/TrustVault)

---

⭐ If you find this project useful, consider giving the repository a star!
