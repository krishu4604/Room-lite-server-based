# Room Lite Remote — control server

Backend-only deployment package for the hybrid Room Lite app. Android sources,
SDK binaries, APKs, account exports, private keys and credentials are excluded.
Account creation is not included.

This server owns subscriptions, encrypted account assignments, room gateway
sessions, chat, seats, KTV queue controls and bounded Auto Chat jobs. Android
retains its RTC/microphone/music engine. Client-side media checks do not make a
modified client unbypassable.

## Deploy on Render

Create a **new Web Service** from this repository; keep the existing service and
database unchanged. Use Docker, repository root, Dockerfile ./Dockerfile and no
Docker command override. The render.yaml Blueprint is an alternative.

Set privately in Render Environment:

| Variable | Required value |
|---|---|
| MONGODB_URI | Fresh authorized Atlas SRV connection URI |
| MONGODB_DATABASE | roomlite_remote |
| ROOMLITE_MASTER_SECRET | Stable strong random secret, at least 32 characters |
| ROOMLITE_ADMIN_PASSWORD | New private password, at least 16 characters |

Give the Atlas database user readWrite access to roomlite_remote. Allow the
service's outbound IP ranges in Atlas Network Access. Do not expose the database
to all IP addresses simply to bypass a connection error.

Back up the master secret privately; changing it prevents decryption of existing
stored signing/account material. Never commit .env files or credentials.

The Docker entry point is python -m licensing.remote_bootstrap. It starts one
Gunicorn worker with eight threads and binds the platform-provided PORT. Do not
substitute the legacy licensing.bootstrap entry point or add replicas: live
session/admission state is process-owned.

After deployment:

1. Check https://YOUR-SERVICE.onrender.com/health.
2. Open the main URL and sign in as owner using ROOMLITE_ADMIN_PASSWORD.
3. Upload authorized existing account groups and assign them to device activation
   IDs after the matching configured Android app is built.
4. Configure the app with this deployment's HTTPS origin, subscription verification
   public key and independently verified primary/backup TLS SPKI pins.

The verification public key is not the HTTPS certificate key. Do not invent a
backup pin. The local unconfigured APK will not connect until rebuilt correctly.
No production account data or Android signing key belongs in this repository.

## Railway

Deploy this repository using its Dockerfile. Set the same private environment
variables, allow the service's outbound network access in Atlas, generate its
public HTTPS domain, and run exactly one replica. railway.json supplies the
health check and restart policy. Verify the chosen hosting plan's pricing before
deployment; no free or continuous-uptime guarantee is implied.

## Runtime limits

- Four manual sessions per device; four manual sessions globally in this build.
- Four Auto Chat panels per device; account groups support 1–64 accounts.
- Shared global socket admission cap: 32, configurable via
  ROOMLITE_REMOTE_MAX_CONNECTIONS (1–128).
- Explicit run duration: 60–3600 seconds.
- KTV includes three previously captured song choices, not live catalog search.
- No automatic reconnect/replay after a process restart or uncertain message.
- Audio publishing authorization requires fresh upstream seat/singer confirmation
  and expires after at most five seconds in the normal Android client.

These are safety limits, not load-tested concurrency guarantees. Free services
can sleep or restart. Atlas persists account/subscription records, not sockets.

Offline verification before publishing: 57 backend tests, 43 remote/KTV/security
and source-boundary tests, plus five host Java media test programs passed in the
development project. Test fixtures are not needed at runtime and are excluded.
No live room/audio/KTV, production load or phone acceptance test is claimed.

## Safe Atlas startup diagnostics

Startup failures now include a fixed stage and category, for example:

    Atlas initialization failed [stage=PING; category=AUTHENTICATION_FAILED].

Stages: CLIENT_SETUP (URI/options/SRV setup), PING (reachability and database
authentication), STORE_SETUP (indexes and encrypted application material).

Categories distinguish URI_INVALID, DNS_LOOKUP_FAILED, TLS_FAILED,
CONFIGURATION_OR_DNS, SERVER_SELECTION_TIMEOUT, NETWORK_TIMEOUT,
CONNECTION_FAILED, AUTHENTICATION_FAILED, DATABASE_PERMISSION_DENIED,
ATLAS_REQUEST_REJECTED, INDEX_OR_DATA_CONFLICT, INDEX_CONFIGURATION_CONFLICT,
DATABASE_OPERATION_FAILED, KEY_UNLOCK_FAILED, CLIENT_TYPE_ERROR and
INITIALIZATION_ERROR.

Only allowlisted text is emitted. No URI, username, password, host, driver
message/details or key material is included. A timeout alone does not prove an
allowlist error; Atlas request-rejection code 8000 alone does not identify the
cause. TLS validation and fail-closed startup remain enabled. Restore the matching
master secret/database backup on KEY_UNLOCK_FAILED; do not delete keys or rotate
the master secret as a troubleshooting shortcut.
