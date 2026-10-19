import os
import secrets
import magic
from pathlib import Path

from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    send_from_directory,
    abort,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


app = Flask(__name__, instance_relative_config=True)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError(
        "Set the SECRET_KEY environment variable before starting the app."
    )

app.config["SECRET_KEY"] = secret_key
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + str(Path(app.instance_path) / "trustvault.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE") == "1"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

# Email settings are configured through environment variables.
app.config["MAIL_SERVER"] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.environ.get("MAIL_PORT", "587"))
app.config["MAIL_USE_TLS"] = os.environ.get("MAIL_USE_TLS", "1") == "1"
app.config["MAIL_USE_SSL"] = os.environ.get("MAIL_USE_SSL", "0") == "1"
app.config["MAIL_USERNAME"] = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_DEFAULT_SENDER") or app.config["MAIL_USERNAME"]

Path(app.instance_path).mkdir(parents=True, exist_ok=True)

UPLOAD_FOLDER = Path(app.instance_path) / "documents"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg"}

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
mail = Mail(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"


def get_reset_serializer():
    # The salt separates password-reset tokens from other signed values.
    return URLSafeTimedSerializer(
        app.config["SECRET_KEY"],
        salt="trustvault-password-reset",
    )


# -------------------- DATABASE MODELS --------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    # Incremented after a successful reset to invalidate previously issued links.
    reset_token_version = db.Column(db.Integer, nullable=False, default=0)

    documents = db.relationship(
        "Document",
        backref="owner",
        lazy=True,
        cascade="all, delete-orphan",
    )


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)
    storage_name = db.Column(db.String(100), unique=True, nullable=False)
    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False,
        index=True,
    )
    uploaded_at = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.current_timestamp(),
    )


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=True,
        index=True,
    )
    event_type = db.Column(db.String(50), nullable=False, index=True)
    document_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        server_default=db.func.current_timestamp(),
        index=True,
    )


# -------------------- LOGIN CONFIGURATION --------------------

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


# -------------------- AUDIT HELPER --------------------

def record_audit(event_type, details="", document_id=None, user_id=None):
    """Record security events without storing passwords or file contents."""
    try:
        if user_id is None and current_user.is_authenticated:
            user_id = current_user.id

        entry = AuditLog(
            user_id=user_id,
            event_type=event_type,
            document_id=document_id,
            details=details[:255],
        )
        db.session.add(entry)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Could not write audit event")


# -------------------- FILE VALIDATION --------------------

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def allowed_file_content(file, extension):
    """Check whether the detected MIME type matches the extension."""
    allowed_mime_types = {
        "pdf": {"application/pdf"},
        "txt": {"text/plain"},
        "png": {"image/png"},
        "jpg": {"image/jpeg"},
        "jpeg": {"image/jpeg"},
    }

    file_header = file.stream.read(8192)
    file.stream.seek(0)

    if not file_header:
        return False

    try:
        detected_type = magic.from_buffer(file_header, mime=True)
    except Exception:
        return False

    return detected_type in allowed_mime_types.get(extension, set())


# -------------------- HOME --------------------

@app.route("/")
def home():
    return render_template("base.html")


# -------------------- REGISTRATION --------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or len(name) > 100 or len(email) > 254:
            flash("Please enter a valid name and email.", "error")
            return render_template("register.html")

        if len(password) < 12:
            flash("Your password must contain at least 12 characters.", "error")
            return render_template("register.html")

        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
            return render_template("register.html")

        user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
        )
        db.session.add(user)

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("Could not create the account. Please try again.", "error")
            return render_template("register.html")

        record_audit("REGISTER_SUCCESS", "Account created", user_id=user.id)
        login_user(user)
        return redirect(url_for("dashboard"))

    return render_template("register.html")


# -------------------- LOGIN --------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            record_audit("LOGIN_SUCCESS", "User signed in", user_id=user.id)
            login_user(user)
            return redirect(url_for("dashboard"))

        record_audit("LOGIN_FAILURE", "Invalid login credentials")
        flash("Invalid email or password.", "error")

    return render_template("login.html")


# -------------------- PASSWORD RECOVERY --------------------

@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()

        # Do not reveal whether an email address has an account.
        flash(
            "If an account exists for that email, a password reset link will be sent.",
            "info",
        )

        if user:
            try:
                token = get_reset_serializer().dumps(
                    {
                        "email": user.email,
                        "version": user.reset_token_version,
                    }
                )
                reset_url = url_for(
                    "reset_password",
                    token=token,
                    _external=True,
                )
                message = Message(
                    subject="TrustVault Password Reset",
                    recipients=[user.email],
                    body=(
                        "We received a request to reset your TrustVault password.\n\n"
                        f"Use this link to choose a new password:\n{reset_url}\n\n"
                        "This link expires in 15 minutes. If you did not request "
                        "this, you can ignore this email."
                    ),
                )
                mail.send(message)
                record_audit(
                    "PASSWORD_RESET_REQUEST",
                    "Password reset email sent",
                    user_id=user.id,
                )
            except Exception:
                app.logger.exception("Password reset email could not be sent")
                # Keep the same public response if mail delivery fails.

        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        payload = get_reset_serializer().loads(token, max_age=900)  # 15 minutes
    except SignatureExpired:
        flash("This reset link has expired. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("This reset link is invalid. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))

    if not isinstance(payload, dict):
        flash("This reset link is invalid. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))

    email = payload.get("email")
    version = payload.get("version")
    user = User.query.filter_by(email=email).first() if isinstance(email, str) else None
    if (
        user is None
        or not isinstance(version, int)
        or isinstance(version, bool)
        or version != user.reset_token_version
    ):
        flash("This reset link is invalid. Please request a new one.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 12:
            flash("Your password must contain at least 12 characters.", "error")
            return render_template("reset_password.html")

        if password != confirm_password:
            flash("The passwords do not match.", "error")
            return render_template("reset_password.html")

        user.password_hash = generate_password_hash(password)
        user.reset_token_version += 1

        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception("Password reset failed")
            flash("Could not reset your password. Please try again.", "error")
            return render_template("reset_password.html")

        record_audit(
            "PASSWORD_RESET_SUCCESS",
            "Password reset completed",
            user_id=user.id,
        )
        flash("Your password has been reset. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")


# -------------------- DASHBOARD --------------------

@app.route("/dashboard")
@login_required
def dashboard():
    documents = (
        Document.query
        .filter_by(owner_id=current_user.id)
        .order_by(Document.uploaded_at.desc())
        .all()
    )
    return render_template("dashboard.html", documents=documents)


# -------------------- DOCUMENT UPLOAD --------------------

@app.route("/upload", methods=["POST"])
@login_required
def upload_document():
    file = request.files.get("document")

    if not file or not file.filename:
        flash("Choose a file to upload.", "error")
        return redirect(url_for("dashboard"))

    original_name = secure_filename(file.filename)
    if not original_name or not allowed_file(original_name):
        flash("Allowed file types: PDF, TXT, PNG, JPG, JPEG.", "error")
        return redirect(url_for("dashboard"))

    extension = original_name.rsplit(".", 1)[1].lower()
    if not allowed_file_content(file, extension):
        flash("The file content does not match an allowed file type.", "error")
        return redirect(url_for("dashboard"))

    storage_name = secrets.token_hex(24) + "." + extension
    destination = UPLOAD_FOLDER / storage_name

    try:
        file.save(destination)
        document = Document(
            original_name=original_name,
            storage_name=storage_name,
            owner_id=current_user.id,
        )
        db.session.add(document)
        db.session.commit()
    except Exception:
        db.session.rollback()
        destination.unlink(missing_ok=True)
        app.logger.exception("Document upload failed")
        flash("Upload failed. Please try again.", "error")
        return redirect(url_for("dashboard"))

    record_audit("DOCUMENT_UPLOAD", "Document uploaded", document_id=document.id)
    flash("Document uploaded successfully.", "success")
    return redirect(url_for("dashboard"))


# -------------------- DOCUMENT DOWNLOAD --------------------

@app.route("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    document = db.session.get(Document, document_id)

    if document is None or document.owner_id != current_user.id:
        record_audit(
            "DOCUMENT_ACCESS_DENIED",
            "Download denied by ownership check",
            document_id=document_id,
        )
        abort(404)

    record_audit(
        "DOCUMENT_DOWNLOAD",
        "Document downloaded by owner",
        document_id=document.id,
    )
    return send_from_directory(
        UPLOAD_FOLDER,
        document.storage_name,
        as_attachment=True,
        download_name=document.original_name,
    )


# -------------------- AUDIT TRAIL --------------------

@app.route("/audit")
@login_required
def audit():
    logs = (
        AuditLog.query
        .filter_by(user_id=current_user.id)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(100)
        .all()
    )
    return render_template("audit.html", logs=logs)


# -------------------- LOGOUT --------------------

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    record_audit("LOGOUT", "User signed out")
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# -------------------- ERROR HANDLERS --------------------

@app.errorhandler(413)
def file_too_large(error):
    if current_user.is_authenticated:
        flash("File is too large. The maximum upload size is 5 MB.", "error")
        return redirect(url_for("dashboard"))
    return "File too large. Maximum upload size is 5 MB.", 413


# -------------------- DATABASE INITIALIZATION --------------------
# Keep this initialization so the tables are created when Gunicorn imports app.
# For production, use persistent database storage and migrations.

with app.app_context():
    db.create_all()

    # Lightweight SQLite migration for existing TrustVault databases.
    # New databases already have this column from db.create_all().
    inspector = db.inspect(db.engine)
    user_columns = {column["name"] for column in inspector.get_columns("user")}
    if "reset_token_version" not in user_columns:
        with db.engine.begin() as connection:
            connection.exec_driver_sql(
                "ALTER TABLE user ADD COLUMN reset_token_version INTEGER NOT NULL DEFAULT 0"
            )


if __name__ == "__main__":
    app.run(debug=True)
