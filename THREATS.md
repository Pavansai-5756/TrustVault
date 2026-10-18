# TrustVault — Security Threats and Mitigations

## 1. Purpose

TrustVault is a secure document-sharing application. This document identifies potential security threats and the measures implemented to reduce them.

## 2. Threats and Mitigations

### Threat 1: Unauthorized Access

**Risk:** An unauthenticated user may attempt to access protected pages or documents.

**Mitigation:** Require users to log in before accessing protected routes. Test that unauthenticated requests are rejected.

### Threat 2: Unauthorized Document Download

**Risk:** A user may try to download another user's private document.

**Mitigation:** Check document ownership on every download request. Return a not-found response when the document does not exist or does not belong to the requesting user.

### Threat 3: Password Exposure

**Risk:** Storing passwords as plain text could expose user credentials if the database is compromised.

**Mitigation:** Store password hashes using Flask's password-hashing functions. Never store plain-text passwords.

### Threat 4: Cross-Site Request Forgery (CSRF)

**Risk:** An attacker may attempt to make a logged-in user's browser submit an unwanted request.

**Mitigation:** Enable CSRF protection for forms and test that POST requests without a valid CSRF token are rejected.

### Threat 5: Malicious File Uploads

**Risk:** An attacker may upload an unsupported file or disguise a file using an allowed extension.

**Mitigation:** Restrict file extensions, limit upload size, inspect file content, generate unique storage names, and reject content that does not match the expected file type.

**Limitation:** File-type detection is not a guarantee that a file is harmless. Further validation and malware scanning may be needed.

### Threat 6: Filename Attacks

**Risk:** A crafted filename may attempt to escape the intended storage directory or overwrite another file.

**Mitigation:** Sanitize filenames and use randomly generated storage names rather than trusting user-provided names.

### Threat 7: Session and Secret Exposure

**Risk:** Weak application secrets or insecure session-cookie settings may compromise user sessions.

**Mitigation:** Load the Flask secret key from an environment variable. Use HttpOnly and SameSite cookie settings. Enable Secure cookies when deploying over HTTPS.

### Threat 8: Missing Security Audit Records

**Risk:** Suspicious activity or document access may be difficult to investigate if events are not recorded.

**Mitigation:** Record relevant events such as successful and failed logins, uploads, downloads, denied document access, and logout.

### Threat 9: Audit Log Privacy

**Risk:** Users may gain access to another user's audit records.

**Mitigation:** Restrict the audit page to authenticated users and display only the current user's audit records.

## 3. Testing

The security test suite checks authentication requirements, document ownership, unsupported uploads, failed-login audit events, CSRF protection, and rejection of fake PDF content.

Run the tests with:

```powershell
python -m pytest -v
```

## 4. Remaining Risks

- File content detection does not replace malware scanning.
- Rate limiting and protection against repeated login attempts may require additional implementation.
- Production deployment must use HTTPS and securely configured environment variables.
- Audit logs should be protected against unauthorized modification and should avoid storing passwords, secrets, or unnecessary personal data.

## 5. Scope

These mitigations reduce identified risks but do not guarantee complete security. Additional review and testing are required before production use.