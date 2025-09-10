# Persistent Session Cookie Keys

To avoid invalidating user sessions on server restarts, configure secure cookie keys in `configs/config.json`.

Example snippet:

```
{
  "session": {
    "auth_key": "change-this-to-a-long-random-string",
    "enc_key":  "change-this-to-a-long-random-string"
  }
}
```

Notes:

- If keys are missing, the server generates random keys at startup and logs a warning. In that case, sessions created will stop working after a restart. Set the values above in production.
- Environment variables `SESSION_AUTH_KEY` and `SESSION_ENC_KEY` are also supported as a fallback.

