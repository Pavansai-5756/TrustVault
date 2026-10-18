
import io
import pytest

from app import app, db, User, Document, UPLOAD_FOLDER
from werkzeug.security import generate_password_hash


@pytest.fixture
def client(tmp_path):
    database_path = tmp_path / "test.db"
    upload_path = tmp_path / "uploads"
    upload_path.mkdir()

    app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{database_path.as_posix()}",
        SECRET_KEY="test-only-secret-key",
    )

    # Redirect file storage to a temporary directory for tests.
    import app as app_module
    original_upload_folder = app_module.UPLOAD_FOLDER
    app_module.UPLOAD_FOLDER = upload_path

    with app.app_context():
        db.drop_all()
        db.create_all()

        yield app.test_client()

        db.session.remove()
        db.drop_all()

    app_module.UPLOAD_FOLDER = original_upload_folder


def create_user(name, email, password):
    user = User(
        name=name,
        email=email,
        password_hash=generate_password_hash(password),
    )
    db.session.add(user)
    db.session.commit()
    return user


def login(client, email, password):
    return client.post(
        "/login",
        data={"email": email, "password": password},
        follow_redirects=False,
    )


def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.location


def test_upload_requires_login(client):
    response = client.post("/upload")
    assert response.status_code == 302
    assert "/login" in response.location


def test_other_user_cannot_download_document(client):
    with app.app_context():
        owner = create_user(
            "Owner", "owner@example.com", "owner-password-123"
        )
        other = create_user(
            "Other", "other@example.com", "other-password-123"
        )

        stored_name = "random-test-file.pdf"
        (UPLOAD_FOLDER / stored_name).write_bytes(b"test PDF content")

        document = Document(
            original_name="private.pdf",
            storage_name=stored_name,
            owner_id=owner.id,
        )
        db.session.add(document)
        db.session.commit()
        document_id = document.id

    login(client, "other@example.com", "other-password-123")
    response = client.get(f"/documents/{document_id}/download")

    assert response.status_code == 404


def test_unsupported_upload_is_rejected(client):
    with app.app_context():
        create_user("Tester", "tester@example.com", "tester-password-123")

    login(client, "tester@example.com", "tester-password-123")

    response = client.post(
        "/upload",
        data={"document": (io.BytesIO(b"not allowed"), "malware.exe")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"Allowed file types" in response.data


def test_audit_page_requires_login(client):
    response = client.get("/audit")
    assert response.status_code == 302
    assert "/login" in response.location


def test_failed_login_records_audit_event(client):
    from app import AuditLog

    response = client.post(
        "/login",
        data={
            "email": "unknown@example.com",
            "password": "incorrect-password",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200

    with app.app_context():
        event = AuditLog.query.filter_by(
            event_type="LOGIN_FAILURE"
        ).first()

        assert event is not None
        assert event.details == "Invalid login credentials"


def test_csrf_protection_rejects_post_without_token(client):
    app.config["WTF_CSRF_ENABLED"] = True

    try:
        response = client.post(
            "/login",
            data={
                "email": "unknown@example.com",
                "password": "incorrect-password",
            },
        )

        assert response.status_code == 400
    finally:
        app.config["WTF_CSRF_ENABLED"] = False
