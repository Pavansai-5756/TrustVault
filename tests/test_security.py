import io

import pytest
from werkzeug.security import check_password_hash, generate_password_hash

from app import app, db, User, Document, AuditLog, get_reset_serializer


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
        MAIL_SUPPRESS_SEND=True,
    )

    import app as app_module
    original_upload_folder = app_module.UPLOAD_FOLDER
    app_module.UPLOAD_FOLDER = upload_path

    with app.app_context():
        db.drop_all()
        db.create_all()

    try:
        yield app.test_client()
    finally:
        with app.app_context():
            db.session.remove()
            db.drop_all()
        app_module.UPLOAD_FOLDER = original_upload_folder


def create_user(name, email, password):
    user = User(
        name=name,
        email=email.lower(),
        password_hash=generate_password_hash(password),
    )
    db.session.add(user)
    db.session.commit()
    return user


def make_reset_token(user):
    """Create a token using the current TrustVault reset-token format."""
    return get_reset_serializer().dumps(
        {"email": user.email, "version": user.reset_token_version}
    )


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
    response = client.post("/upload", data={})
    assert response.status_code == 302
    assert "/login" in response.location


def test_other_user_cannot_download_document(client):
    import app as app_module
    with app.app_context():
        owner = create_user("Owner", "owner@example.com", "owner-password-123")
        create_user("Other", "other@example.com", "other-password-123")
        stored_name = "private-document.txt"
        document = Document(
            original_name="private.txt",
            storage_name=stored_name,
            owner_id=owner.id,
        )
        db.session.add(document)
        db.session.commit()
        document_id = document.id
        (app_module.UPLOAD_FOLDER / stored_name).write_text(
            "private content", encoding="utf-8"
        )

    login(client, "other@example.com", "other-password-123")
    response = client.get(f"/documents/{document_id}/download")
    assert response.status_code == 404


def test_unsupported_upload_is_rejected(client):
    with app.app_context():
        create_user("Uploader", "uploader@example.com", "uploader-password-123")
    login(client, "uploader@example.com", "uploader-password-123")
    response = client.post(
        "/upload",
        data={"document": (io.BytesIO(b"hello"), "malware.exe")},
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
    with app.app_context():
        create_user("Login Tester", "login@example.com", "correct-password-123")
    response = login(client, "login@example.com", "wrong-password-123")
    assert response.status_code == 200
    with app.app_context():
        assert AuditLog.query.filter_by(event_type="LOGIN_FAILURE").first() is not None


def test_csrf_protection_rejects_post_without_token(client):
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        response = client.post(
            "/login", data={"email": "nobody@example.com", "password": "wrong"}
        )
        assert response.status_code == 400
    finally:
        app.config["WTF_CSRF_ENABLED"] = False


def test_fake_pdf_content_is_rejected(client):
    with app.app_context():
        create_user("PDF Tester", "pdf@example.com", "pdf-password-123")
    login(client, "pdf@example.com", "pdf-password-123")
    response = client.post(
        "/upload",
        data={"document": (io.BytesIO(b"this is not a real PDF"), "fake.pdf")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"file content does not match" in response.data.lower()


def test_forgot_password_does_not_reveal_unknown_email(client):
    response = client.post(
        "/forgot-password", data={"email": "unknown@example.com"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"If an account exists for that email" in response.data


def test_reset_password_rejects_invalid_token(client):
    response = client.get("/reset-password/not-a-valid-token")
    assert response.status_code == 302
    assert "/forgot-password" in response.location


def test_reset_password_rejects_short_password(client):
    with app.app_context():
        user = create_user(
            "Reset Tester", "reset-short@example.com", "original-password-123"
        )
        token = make_reset_token(user)
    response = client.post(
        f"/reset-password/{token}",
        data={"password": "short", "confirm_password": "short"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"at least 12 characters" in response.data


def test_reset_password_changes_password(client):
    with app.app_context():
        user = create_user("Reset Tester", "reset@example.com", "original-password-123")
        token = make_reset_token(user)
        user_id = user.id
    response = client.post(
        f"/reset-password/{token}",
        data={
            "password": "new-secure-password-456",
            "confirm_password": "new-secure-password-456",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "/login" in response.location
    with app.app_context():
        updated_user = db.session.get(User, user_id)
        assert updated_user is not None
        assert check_password_hash(updated_user.password_hash, "new-secure-password-456")
        assert updated_user.reset_token_version == 1


def test_reset_link_cannot_be_reused_after_password_change(client):
    with app.app_context():
        user = create_user("Reuse Tester", "reuse@example.com", "original-password-123")
        token = make_reset_token(user)
    first_response = client.post(
        f"/reset-password/{token}",
        data={
            "password": "first-new-password-123",
            "confirm_password": "first-new-password-123",
        },
        follow_redirects=False,
    )
    assert first_response.status_code == 302
    assert "/login" in first_response.location

    second_response = client.post(
        f"/reset-password/{token}",
        data={
            "password": "second-new-password-456",
            "confirm_password": "second-new-password-456",
        },
        follow_redirects=False,
    )
    assert second_response.status_code == 302
    assert "/forgot-password" in second_response.location
    with app.app_context():
        user = User.query.filter_by(email="reuse@example.com").first()
        assert check_password_hash(user.password_hash, "first-new-password-123")
        assert not check_password_hash(user.password_hash, "second-new-password-456")
