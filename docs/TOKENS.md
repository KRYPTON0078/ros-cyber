# REST Auth Tokens

Use the ingestion API to request a JWT:

```
POST http://localhost:8000/v1/auth/token
{
  "username": "operator",
  "password": "operator123!"
}
```

Paste the token into the dashboard session box to unlock role-based actions.
