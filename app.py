
import os
import secrets
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

Path(app.instance_path).mkdir(parents=True, exist_ok=True)

UPLOAD_FOLDER = Path(app.instance_path) / "documents"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "txt", "png", "jpg", "jpeg"}

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    documents = db.relationship(
        "Document", backref="owner", lazy=True,
        cascade="all, delete-orphan"
    )


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)
    storage_name = db.Column(db.String(100), unique=True, nullable=False)
    owner_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False, index=True
    )
    uploaded_at = db.Column(
        db.DateTime, nullable=False,
        server_default=db.func.current_timestamp()
    )


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/")
def home():
    return render_template("base.html")


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
        db.session.commit()

        login_user(user)
        flash("Account created successfully.", "success")
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    documents = (
        Document.query.filter_by(owner_id=current_user.id)
        .order_by(Document.uploaded_at.desc())
        .all()
    )
    return render_template("dashboard.html", documents=documents)


@app.route("/upload", methods=["POST"])
@login_required
def upload_document():
    file = request.files.get("document")

    if not file or not file.filename:
        flash("Choose a file to upload.", "error")
        return redirect(url_for("dashboard"))

    safe_original_name = secure_filename(file.filename)

    if not safe_original_name or not allowed_file(safe_original_name):
        flash("Allowed file types: PDF, TXT, PNG, JPG, JPEG.", "error")
        return redirect(url_for("dashboard"))

    # MAX_CONTENT_LENGTH limits the entire request to 5 MB.
    storage_name = secrets.token_hex(24) + "." + safe_original_name.rsplit(".", 1)[1].lower()
    destination = UPLOAD_FOLDER / storage_name

    try:
        file.save(destination)

        document = Document(
            original_name=safe_original_name,
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

    flash("Document uploaded successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    document = db.session.get(Document, document_id)

    # Check ownership on the server for every download request.
    if document is None or document.owner_id != current_user.id:
        abort(404)

    return send_from_directory(
        UPLOAD_FOLDER,
        document.storage_name,
        as_attachment=True,
        download_name=document.original_name,
    )


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


@app.errorhandler(413)
def file_too_large(error):
    flash("File is too large. The maximum upload size is 5 MB.", "error")
    return redirect(url_for("dashboard"))


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)
