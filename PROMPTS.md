# TrustVault — AI Prompt and Development Log

This log records AI assistance used while developing TrustVault. Entries should reflect actual interactions and work completed.

## Entry 1 — 2026-10-18

**Topic:** Initial application setup

**Prompt:** Help me set up a Flask web application for secure document sharing.

**AI output:** Guidance for organizing the application and configuring Flask.

**What was wrong or needed checking:** The generated code needed to be checked against the actual project structure and installed packages.

**What I did instead:** I integrated and tested the application in my local development environment.

**Commit link:** Local commit `0063784` — Create initial TrustVault web application. Add the repository URL and full commit link after publishing the repository.

## Entry 2 — 2026-10-18

**Topic:** Authentication and password security

**Prompt:** Help implement secure user registration and login in Flask.

**AI output:** Guidance on authentication, password hashing, and login validation.

**What was wrong or needed checking:** Authentication needed tests to verify that protected pages require login and passwords are not stored as plain text.

**What I did instead:** I tested the authentication flow and committed the implementation.

**Commit link:** Local commit `9a84a68` — Implement secure user authentication.

## Entry 3 — 2026-10-18

**Topic:** Document access control

**Prompt:** Help secure document uploads and ensure users cannot download documents belonging to other users.

**AI output:** Guidance on upload validation, safe filenames, and ownership checks.

**What was wrong or needed checking:** File extensions alone cannot establish that uploaded content is safe. Download authorization must also be checked on the server.

**What I did instead:** I added upload and ownership checks and tested unauthorized downloads.

**Commit link:** Local commit `d0d64db` — Add secure document upload and ownership checks.

## Entry 4 — 2026-10-18

**Topic:** Security audit trail

**Prompt:** Help add an audit trail for authentication and document-related events.

**AI output:** Guidance for recording security events and displaying audit records.

**What was wrong or needed checking:** Audit records must not expose another user's records or store sensitive information unnecessarily.

**What I did instead:** I added audit logging and checked that the audit page requires authentication and displays the current user's records.

**Commit link:** Local commit `4debd1f` — Add security audit trail.

## Entry 5 — 2026-10-18

**Topic:** Security configuration and testing

**Prompt:** Help review the application's security configuration and write tests for important security controls.

**AI output:** Guidance on session cookies, CSRF protection, and security tests.

**What was wrong or needed checking:** Security controls needed automated tests rather than relying only on manual checks.

**What I did instead:** I improved the configuration and ran the test suite.

**Commit link:** Local commit `88cd185` — Improve security configuration and tests.

## Entry 6 — 2026-10-18

**Topic:** Uploaded file content validation

**Prompt:** Help reject uploaded files whose detected content does not match their allowed file extension.

**AI output:** Guidance on inspecting file content and checking detected MIME types.

**What was wrong or needed checking:** MIME detection is not a complete security check and can vary by file type.

**What I did instead:** I implemented content-type validation and added a test that rejects fake PDF content.

**Commit link:** Local commit `986a3f6` — Validate uploaded file content.

## Accuracy note

These entries are a draft based on the development history. Replace any prompt or description that does not match the original interaction or actual implementation. Record future AI-assisted work honestly, including the generated output, problems found, your own changes, and the relevant commit.