# M41 API examples

Create a key (authenticated organization owner/admin session):
```json
{"label":"analytics-reader","role":"viewer","expires_at":"2027-01-01T00:00:00Z"}
```

List keys:
```http
GET /api/v1/enterprise/security/api-keys
```

List audit events:
```http
GET /api/v1/enterprise/security/audit?limit=100
```

Security posture:
```http
GET /api/v1/enterprise/security/posture
```

The create response includes plaintext API key material once. Store it securely; list operations never return it.
