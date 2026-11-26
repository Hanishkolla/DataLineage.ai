# Security Review Checklist

This is a review aid, not a penetration-test report or security certification.

- Authentication is enabled and production secrets are unique, strong and private.
- Production configuration fails closed when required security settings are missing.
- Session cookies use Secure and HttpOnly attributes and an appropriate SameSite policy.
- Password reset and verification tokens are single-use, time-limited and stored safely.
- Rate limits cover authentication and sensitive actions.
- Tenant identity is derived from authenticated server-side context, not trusted from client input.
- Every object read/write checks tenant ownership and role permission.
- GitHub webhook signatures and CI bearer tokens are validated.
- Uploads enforce file type, size and content handling limits.
- SQL parsing/analysis does not execute user-submitted SQL against production databases.
- Logs redact passwords, cookies, access tokens, API keys and payment secrets.
- CORS allows only explicitly approved origins.
- Security headers are present on normal and error responses.
- Dependencies are reviewed and pinned according to release policy.
- Backups are encrypted, access-controlled and restore-tested.
- Admin access, audit records and incident response are reviewed.

Record each item as PASS / FAIL / NOT TESTED with evidence before production use.
