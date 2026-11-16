# IT ELKHAWGA Relay (MVP)

Managed HTTPS relay: Admin and Client Agents connect outbound (no port forwarding). Deploy behind TLS (Fly.io, Render, Azure Container Apps, VPS+Caddy/Nginx).

## Environment
- `PORT` default `8787`
- `ADMIN_KEY` **required** (long random secret for admin API)
- `DATA_DIR` default `./data` (SQLite)
- `CORS_ORIGIN` optional

## Protocol v1
- `POST /api/v1/enroll` `Authorization: Bearer <pairing_token>` body `{hostname, app_version, device_id?, os}` => `{ok, device_id, device_token, poll_seconds}`
- `POST /api/v1/device/poll` `Authorization: Bearer <device_token>` body `{hostname, blocked, mode, policy_version, app_version, ack_command_id?, command_result?}` => `{ok, command:{id,type}|null, policy|null, poll_seconds}`
- `GET /api/v1/admin/devices` admin
- `POST /api/v1/admin/devices/:id/command` admin `{command:"block"|"unblock"}`
- `GET/PUT /api/v1/admin/policy` admin
- `POST /api/v1/admin/pairing-tokens` admin `{label?, expires_minutes?}`

## Security
TLS required in production. Pairing tokens are one-time; device tokens are per-device. Add rate limiting at proxy for production.
