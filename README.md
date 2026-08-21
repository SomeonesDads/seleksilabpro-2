# Auth Provider Platform - Tugas 2 Seleksi LabPro (semoga masuk)

- Nama: Natanael I. Manurung
- NIM: 13524021

## Ringkasan Komponen

| Komponen             | Tanggung jawab                                                                 | Penyimpanan                                      |
| -------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------ |
| Auth Provider Server | Login, central session, OAuth2, token, UserInfo, policy, admin API, revocation | PostgreSQL primary                               |
| Control Panel        | UI HTML admin dan HTTP proxy ke`/admin/*`                                      | Tidak memiliki database atau local session store |
| Sync Worker          | Publish outbox, consume event, retry delivery, DLQ, back-channel logout        | PostgreSQL primary dan RabbitMQ                  |
| App A                | Relying application dengan local session dan profile cache                     | PostgreSQL App A                                 |
| App B                | Relying application dengan local session dan profile cache                     | PostgreSQL App B                                 |
| RabbitMQ             | Message broker event revocation                                                | Queue durable dan native DLQ                     |

## Arsitektur dan Alur

```mermaid
sequenceDiagram
    autonumber
    actor User as User Browser
    participant App as Relying Application (App A / App B)
    participant Auth as Auth Provider Server
    participant DB as PostgreSQL Database

    User->>App: 1. Access Protected Page
    App-->>User: 2. Redirect to Auth Provider `GET /authorize`<br/>(client_id, redirect_uri, scope=userinfo, state, code_challenge, code_challenge_method=S256)

    User->>Auth: 3. `GET /authorize` with PKCE parameters
    Auth->>Auth: Check for active `sso_session` cookie

    alt SSO Session Not Present / Invalid
        Auth-->>User: 4. Redirect to `GET /login?return_to=...`
        User->>Auth: 5. Submit Login Form `POST /login`<br/>(email, password)
        Auth->>DB: 6. Lookup user & verify bcrypt password hash

        alt MFA / TOTP Enabled
            Auth-->>User: 7. Prompt MFA Form `POST /login/mfa`
            User->>Auth: 8. Submit TOTP Code `POST /login/mfa`
            Auth->>DB: 9. Verify encrypted TOTP secret & counter
        end

        Auth->>DB: 10. Create Central SSO Session (`sso_session` token)
        Auth-->>User: 11. Set `sso_session` HTTP-only Cookie & Redirect back to `/authorize`
    end

    User->>Auth: 12. `GET /authorize` (with active `sso_session` cookie)
    Auth->>DB: 13. Validate Client ID, Active Application, Redirect URI equality & Group Policy
    Auth->>DB: 14. Generate & store Authorization Code (short-lived, S256 challenge bound)
    Auth-->>User: 15. Redirect to Relying App `redirect_uri?code={code}&state={state}`
```

### Control Panel

1. Browser membuka Control Panel.
2. `POST /login` pada Control Panel meneruskan credential ke Auth Provider.
3. Auth Provider membuat central session dan mengembalikan cookie `sso_session`.
4. Control Panel meneruskan cookie tersebut pada request `/admin/*`.
5. Middleware Auth Provider melakukan Authentication dan Authorization:
   central session harus aktif, belum expired, belum revoked, user aktif, dan
   user tergabung dalam group `administrators`.
6. Control Panel hanya merender response HTML. Query database tetap berada di
   Auth Provider Server.

### Login App A dan App B

1. Aplikasi membuat `state` dan PKCE `code_verifier` secara server-side.
2. Browser diarahkan ke Auth Provider `/authorize`.
3. Auth Provider memeriksa central session. Jika belum ada, user login melalui
   `/login`.
4. Auth Provider mengevaluasi user status, application status, redirect URI
   exact-match, dan group policy.
5. Auth Provider mengirim authorization code satu kali ke callback aplikasi.
6. Backend aplikasi menukar code ke `/token` melalui back-channel dengan
   client credential dan PKCE verifier.
7. Backend aplikasi mengambil profile melalui `/userinfo`.
8. Aplikasi menyimpan profile cache dan membuat local session sendiri.
9. App A memakai cookie `appa_session`; App B memakai cookie `appb_session`.

### Logout dan Revocation

1. SSO logout mencabut central session secara synchronous.
2. Pencabutan session dan pembuatan event `SessionRevoked` dilakukan dalam satu
   transaksi database.
3. Sync Worker membaca event outbox yang belum dipublish.
4. Worker mengirim event ke App A dan App B melalui `POST /internal/logout`.
5. Aplikasi memvalidasi `X-Internal-Auth`, mencatat `eventId`, lalu mencabut
   local session secara idempotent.
6. Logout lokal App A atau App B hanya mencabut session aplikasi tersebut.
7. Kehilangan policy untuk satu aplikasi menghasilkan event
   `AccessPolicyChanged` tanpa mencabut central session atau aplikasi lain.

## Cara Menjalankan Sistem

### Prasyarat

- Docker Desktop dengan Docker Compose.
- Go 1.25 untuk menjalankan seed dan test dari host.
- OpenSSL atau generator random lain untuk membuat secret.
- Browser modern.

### 1. Siapkan file environment

Compose membaca file `.env`, bukan `.env.example`. Jalankan dari root repository
di PowerShell:

```powershell
Copy-Item .env.example .env
Copy-Item auth-provider/server/.env.example auth-provider/server/.env
Copy-Item auth-provider/control-panel/.env.example auth-provider/control-panel/.env
Copy-Item auth-provider/sync-worker/.env.example auth-provider/sync-worker/.env
Copy-Item applications/app-a/.env.example applications/app-a/.env
Copy-Item applications/app-b/.env.example applications/app-b/.env
```

File `.env` berisi credential lokal dan tidak boleh di-commit.

### 2. Isi konfigurasi dan secret

Generate dua key:

```powershell
openssl rand -base64 32
```

Masukkan output pertama sebagai `JWT_SIGNING_KEY` dan output kedua sebagai
`MFA_ENCRYPTION_KEY` pada `auth-provider/server/.env`. Nilai
`MFA_ENCRYPTION_KEY` harus berupa base64 yang jika didecode menghasilkan 32
bytes.

Isi enam secret seed berikut pada `auth-provider/server/.env`:

| Variabel                         | Kegunaan                    |
| -------------------------------- | --------------------------- |
| `SEED_ADMIN_PASSWORD`            | Password`admin@example.com` |
| `SEED_DEMO_PASSWORD`             | Password`demo@example.com`  |
| `SEED_APP_A_CLIENT_SECRET`       | Client secret App A         |
| `SEED_APP_B_CLIENT_SECRET`       | Client secret App B         |
| `SEED_APP_A_INTERNAL_AUTH_TOKEN` | Token delivery ke App A     |
| `SEED_APP_B_INTERNAL_AUTH_TOKEN` | Token delivery ke App B     |

Nilai berikut harus sama di file aplikasi masing-masing:

| File                      | Variabel                                   |
| ------------------------- | ------------------------------------------ |
| `applications/app-a/.env` | `APP_CLIENT_SECRET`, `INTERNAL_AUTH_TOKEN` |
| `applications/app-b/.env` | `APP_CLIENT_SECRET`, `INTERNAL_AUTH_TOKEN` |

Isi `APP_TARGETS_JSON` pada `auth-provider/sync-worker/.env`. Gunakan application
ID tetap berikut dan token yang sama dengan konfigurasi App A/App B:

```text
APP_TARGETS_JSON=[{"name":"App A","applicationId":"00000000-0000-0000-0000-0000000000a1","logoutNotifyURL":"http://app-a:5010/internal/logout","internalAuthToken":"APP_A_INTERNAL_TOKEN"},{"name":"App B","applicationId":"00000000-0000-0000-0000-0000000000b2","logoutNotifyURL":"http://app-b:5020/internal/logout","internalAuthToken":"APP_B_INTERNAL_TOKEN"}]
```

Ganti `APP_A_INTERNAL_TOKEN` dan `APP_B_INTERNAL_TOKEN` dengan secret asli.
Jangan menambahkan whitespace atau secret lain ke repository.

### 3. Gunakan URL browser Compose

File environment contoh memakai `localhost` untuk URL yang dibuka browser dan
hostname Docker (`auth-server`, `app-a`, `app-b`) hanya untuk komunikasi internal.
Tidak perlu mengubah file hosts.

## Untuk step 4-5 ada shortcut `powershell python startup.py --up` (cuman di windows)

### 4. Start seluruh stack

```powershell
docker compose up --build
```

### 5. Jalankan seed

Buka terminal lagi .

Karena `go run` tidak membaca file `.env` secara otomatis, jadi harus set environment variable.

Ganti semua placeholder dengan nilai yang sama seperti konfigurasi service:

```powershell
$env:DATABASE_URL = "postgres://authprovider:authprovider@localhost:5433/authprovider?sslmode=disable"
$env:SEED_ADMIN_PASSWORD = "<admin-password>"
$env:SEED_DEMO_PASSWORD = "<demo-password>"
$env:SEED_APP_A_CLIENT_SECRET = "<app-a-client-secret>"
$env:SEED_APP_B_CLIENT_SECRET = "<app-b-client-secret>"
$env:SEED_APP_A_INTERNAL_AUTH_TOKEN = "<app-a-internal-token>"
$env:SEED_APP_B_INTERNAL_AUTH_TOKEN = "<app-b-internal-token>"

Push-Location auth-provider/server
go run ./cmd/seed
Pop-Location
```

Seed feeding data berikut:

- user admin `admin@example.com`;
- user demo `demo@example.com`;
- group `administrators`, `app-a-users`, dan `app-b-users`;
- aplikasi App A dan App B;
- redirect URI, policy, dan membership.

Seed boleh dijalankan ulang tanpa membuat duplicate data.

### 6. Login untuk demo

1. Buka Control Panel: `http://localhost:5002/login`.
2. Login sebagai `admin@example.com` untuk mengelola user, group, aplikasi, dan
   policy.
3. Buka App A: `http://localhost:5010`.
4. Buka App B: `http://localhost:5020`.
5. Login sebagai `demo@example.com` menggunakan password seed.
6. App A dan App B membuat local session yang berbeda, tetapi menggunakan
   central session Auth Provider yang sama.

## URL Komponen

| Komponen              | URL atau alamat                                                                                             |
| --------------------- | ----------------------------------------------------------------------------------------------------------- |
| Auth Provider Server  | `http://localhost:5001`                                                                                     |
| Control Panel         | `http://localhost:5002`                                                                                     |
| App A                 | `http://localhost:5010`                                                                                     |
| App B                 | `http://localhost:5020`                                                                                     |
| Auth Provider metrics | `http://localhost:5001/metrics`                                                                             |
| Sync Worker metrics   | `http://sync-worker:9091/metrics` dari network Compose; port tidak dipublish ke host (inaccessible harusny) |
| RabbitMQ management   | `http://localhost:15672`                                                                                    |
| RabbitMQ AMQP         | `localhost:5672`                                                                                            |
| PostgreSQL primary    | `localhost:5433`                                                                                            |
| PostgreSQL App A      | `localhost:5434`                                                                                            |
| PostgreSQL App B      | `localhost:5435`                                                                                            |

## Keputusan Teknis

### Access token: JWT HS256

Access token menggunakan JWT dengan algoritma HS256. JWT diterbitkan oleh Auth
Provider dengan claim berikut:

```json
{
  "iss": "auth-provider",
  "sub": "user-uuid",
  "aud": "application-uuid",
  "iat": 1720000000,
  "exp": 1720000900,
  "jti": "unique-token-id",
  "sid": "sso-session-uuid",
  "scope": "userinfo"
}
```

Alasan pemilihan:

- format standar dan interoperable;
- validasi signature dapat dilakukan tanpa menyimpan signed token;
- audience mengikat token ke aplikasi tujuan;
- access token berumur pendek, default 15 menit;
- cocok untuk beberapa relying application.

Konsekuensi dan mitigasi:

- JWT yang bocor secara teori tetap berlaku sampai `exp`;
- Auth Provider menyimpan metadata `jti` di database untuk active/revocation
  lookup pada `/userinfo`;
- `/userinfo` memvalidasi signature, issuer, audience, expiry, `jti`, metadata
  token, central session, dan user status;
- setiap application memakai client authentication dan audience sendiri;
- signing key wajib berada di environment atau secret manager dan tidak boleh
  masuk repository;
- HS256 berarti service yang memiliki shared signing key juga memiliki kemampuan
  membuat signature. Deployment lebih besar dapat mengganti ke algoritma
  asymmetric.

### Message broker: RabbitMQ

RabbitMQ dipilih karena mendukung durable queue, persistent message, manual ACK,
publisher confirm, retry melalui worker, dan native dead-letter exchange.

Topology yang digunakan:

| Resource          | Nilai                                                      |
| ----------------- | ---------------------------------------------------------- |
| Exchange          | `auth.events` dengan tipe `topic`                          |
| Main queue        | `sync-worker.main`                                         |
| Dead-letter queue | `sync-worker.dlq`                                          |
| Routing key       | `SessionRevoked`, `PasswordChanged`, `AccessPolicyChanged` |

Auth Provider menulis state change dan outbox event dalam satu transaksi.
Publisher pada Sync Worker hanya menandai `published_at` setelah broker
memberikan confirmation. Worker mengirim delivery per aplikasi secara terpisah,
menggunakan retry dan exponential backoff. Kegagalan permanen dikirim ke DLQ.

### Autentikasi service-to-service `/internal/logout`

Sync Worker mengirim header berikut ke App A atau App B:

```http
X-Internal-Auth: <token-per-aplikasi>
```

Setiap aplikasi menyimpan tokennya melalui `INTERNAL_AUTH_TOKEN`. Worker
menyimpan pasangan URL dan token melalui `APP_TARGETS_JSON`. Token tidak
disimpan di primary database. App memvalidasi token sebelum memproses event.

Event diproses idempotent berdasarkan `eventId`, sehingga redelivery tidak
mencabut session berulang kali.

### Soft-delete dan hard-delete

- User memakai logical status `active` atau `inactive`, bukan hard-delete pada
  lifecycle admin. Menonaktifkan user mencabut central session aktif dan
  membuat event revocation.
- Application memiliki status `active` atau `inactive` pada modelnya. Status
  inactive mencegah authorization dan token exchange baru.
- Central session dan access-token metadata dipertahankan dengan status atau
  `revoked_at` untuk audit dan revocation lookup, bukan langsung dihapus.
- Membership group, application policy, dan redirect URI dihapus secara hard
  ketika admin memilih remove.
- Foreign key child rows memakai `ON DELETE CASCADE` jika data induk dihapus;
  audit dan outbox references memakai `SET NULL` jika diperlukan agar riwayat
  tetap tersimpan.

## Technology Stack

| Teknologi                                             | Versi atau konfigurasi                        |
| ----------------------------------------------------- | --------------------------------------------- |
| Go service modules                                    | `1.25.0`                                      |
| Go shared module directive                            | `1.22`                                        |
| PostgreSQL                                            | `16-alpine`                                   |
| RabbitMQ                                              | `3.13-management-alpine`                      |
| GORM                                                  | `v1.31.2`                                     |
| GORM PostgreSQL driver                                | `v1.6.2`                                      |
| pgx                                                   | `v5`                                          |
| golang-migrate                                        | `v4.18.3`                                     |
| JWT                                                   | `github.com/golang-jwt/jwt/v5 v5.3.1`         |
| RabbitMQ Go client                                    | `github.com/rabbitmq/amqp091-go v1.10.0`      |
| TOTP                                                  | `github.com/pquerna/otp v1.4.0`               |
| Prometheus client                                     | `github.com/prometheus/client_golang v1.23.0` |
| Password hashing                                      | `golang.org/x/crypto/bcrypt`                  |
| Runtime image Auth Provider/Control Panel/Sync Worker | `alpine:3.20`                                 |
| Runtime image App A/App B                             | `golang:1.25`                                 |

## Daftar Endpoint

### Auth Provider Server

Semua endpoint `/admin/*` membutuhkan `sso_session` yang valid dan user dalam
group `administrators`.

| Method | Path                                              | Kegunaan                                              |
| ------ | ------------------------------------------------- | ----------------------------------------------------- |
| GET    | `/login`                                          | Form login dan login intent                           |
| POST   | `/login`                                          | Verifikasi email/password dan membuat central session |
| POST   | `/login/mfa`                                      | Verifikasi TOTP dan menyelesaikan central session     |
| GET    | `/mfa/enroll`                                     | Halaman enrollment TOTP                               |
| POST   | `/mfa/enroll`                                     | Membuat pending TOTP enrollment                       |
| POST   | `/mfa/enroll/confirm`                             | Mengaktifkan TOTP setelah kode valid                  |
| GET    | `/authorize`                                      | OAuth2 Authorization Code + S256 PKCE                 |
| POST   | `/token`                                          | Menukar authorization code menjadi access token       |
| GET    | `/userinfo`                                       | Mengambil profile user dengan Bearer token            |
| POST   | `/logout`                                         | SSO logout dan revocation central session             |
| GET    | `/admin/users`                                    | List user                                             |
| POST   | `/admin/users`                                    | Membuat user                                          |
| GET    | `/admin/users/{id}`                               | Melihat user                                          |
| PATCH  | `/admin/users/{id}`                               | Memperbarui user atau password                        |
| PATCH  | `/admin/users/{id}/status`                        | Mengaktifkan atau menonaktifkan user                  |
| GET    | `/admin/groups`                                   | List group                                            |
| POST   | `/admin/groups`                                   | Membuat group                                         |
| POST   | `/admin/groups/{id}/members`                      | Menambahkan user ke group                             |
| DELETE | `/admin/groups/{id}/members/{userId}`             | Menghapus user dari group                             |
| GET    | `/admin/applications`                             | List application                                      |
| POST   | `/admin/applications`                             | Mendaftarkan application dan redirect URI             |
| POST   | `/admin/applications/{id}/redirect-uris`          | Menambahkan redirect URI                              |
| POST   | `/admin/applications/{id}/policies`               | Menambahkan allow policy group                        |
| DELETE | `/admin/applications/{id}/policies?group_id={id}` | Menghapus policy group                                |
| GET    | `/admin/overview/{userId}`                        | Melihat user, group, application, dan policy          |
| GET    | `/health`                                         | Health check database                                 |
| GET    | `/health/live`                                    | Liveness probe                                        |
| GET    | `/health/ready`                                   | Readiness probe database dan RabbitMQ                 |
| GET    | `/metrics`                                        | Prometheus metrics server                             |

### Control Panel

Control Panel tidak memiliki database. Endpoint berikut merender HTML atau
mem-proxy request ke Auth Provider Server.

| Method   | Path                            | Kegunaan                                 |
| -------- | ------------------------------- | ---------------------------------------- |
| GET      | `/login`                        | Form login admin                         |
| POST     | `/login`                        | Proxy login ke Auth Provider             |
| POST     | `/login/mfa`                    | Proxy verifikasi MFA                     |
| GET/POST | `/logout`                       | Proxy SSO logout dan membersihkan cookie |
| GET      | `/`                             | Dashboard                                |
| GET      | `/users`                        | Daftar dan create user                   |
| GET      | `/users/{id}`                   | User overview                            |
| POST     | `/users`                        | Proxy create user                        |
| POST     | `/users/status`                 | Proxy activate/deactivate user           |
| GET      | `/groups`                       | Daftar dan create group                  |
| POST     | `/groups`                       | Proxy create group                       |
| POST     | `/groups/members`               | Proxy add group member                   |
| POST     | `/groups/members/delete`        | Proxy remove group member                |
| GET      | `/applications`                 | Daftar dan register application          |
| POST     | `/applications`                 | Proxy register application               |
| POST     | `/applications/redirect`        | Proxy add redirect URI                   |
| POST     | `/applications/policies`        | Proxy add policy                         |
| POST     | `/applications/policies/delete` | Proxy remove policy                      |
| GET      | `/health`                       | Health check panel                       |

### App A dan App B

Kedua aplikasi memiliki endpoint yang sama. Cookie dan database berbeda.

| Method | Path               | Kegunaan                                                            |
| ------ | ------------------ | ------------------------------------------------------------------- |
| GET    | `/`                | Dashboard, profile cache, local session, activity, processed events |
| GET    | `/login`           | Memulai OAuth2 Authorization Code + PKCE                            |
| GET    | `/auth/callback`   | Validasi state, token exchange, UserInfo, local session             |
| POST   | `/logout`          | Local logout aplikasi terkait                                       |
| POST   | `/internal/logout` | Back-channel revocation dari Sync Worker                            |
| GET    | `/health`          | Health check aplikasi                                               |

### Sync Worker

| Method | Path                    | Kegunaan                                                  |
| ------ | ----------------------- | --------------------------------------------------------- |
| GET    | `/metrics` pada `:9091` | Worker delivery, retry, DLQ, database, dan broker metrics |

Sync Worker juga menjalankan consumer RabbitMQ dan outbox publisher. Tidak ada
endpoint browser lain pada worker.

## Bonus

| Bonus                       | Implementasi                                                                                                                                                                                                                                         |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B01 MFA                     | TOTP enrollment dan login MFA. Secret dienkripsi AES-GCM, pending state memiliki expiry dan attempt limit, central session baru dibuat setelah kode valid.                                                                                           |
| B02 Observability (Partial) | Prometheus metrics pada Auth Provider`/metrics` dan Sync Worker `:9091/metrics`, termasuk request, error, duration, auth failure, outbox depth, delivery, retry, permanent failure, DLQ, database, dan broker health. Dashboard visual gak sempat... |
| B03 Liveness dan Readiness  | `/health/live` tidak bergantung dependency. `/health/ready` memeriksa PostgreSQL dan RabbitMQ serta mengembalikan `503` jika salah satu down.                                                                                                        |
| B04 Graceful Shutdown       | HTTP intake, RabbitMQ consumer, publisher, delivery goroutine, metrics server, database, dan broker ditutup dengan deadline`SHUTDOWN_TIMEOUT`; delivery yang belum selesai dibiarkan untuk redelivery.                                               |

## Verifikasi

Validasi Compose dari root repository:

```powershell
docker compose config
docker compose build
docker compose ps
```

Jalankan test dari setiap module secara terpisah:

| Module               | Directory                     |
| -------------------- | ----------------------------- |
| Shared               | `shared`                      |
| Auth Provider Server | `auth-provider/server`        |
| Control Panel        | `auth-provider/control-panel` |
| Sync Worker          | `auth-provider/sync-worker`   |
| App A                | `applications/app-a`          |
| App B                | `applications/app-b`          |

Perintah pada setiap directory:

```powershell
go test ./...
go vet ./...
```

Test integrasi yang memakai database atau broker membutuhkan PostgreSQL dan
RabbitMQ disposable. Untuk integration test persistence Sync Worker, set
`TEST_DATABASE_URL` sesuai instruksi test sebelum menjalankan test terkait.

## Screenshots

### 01. Control Panel Login

![Control Panel login](docs/screenshots/01-control-panel-login.png)

### 02. Control Panel Dashboard

![Control Panel dashboard](docs/screenshots/02-control-panel-dashboard.png)

### 03. Users & Groups Management

![Users and Groups](docs/screenshots/03-control-panel-users-groups.png)

### 04. Application Registration & Client Secret

![Application secret provisioning](docs/screenshots/04-control-panel-application-secret.png)

### 05. App A Dashboard After OAuth Login

![App A dashboard](docs/screenshots/05-app-a-dashboard.png)

### 06. App B Dashboard (SSO Session Reuse)

![App B dashboard](docs/screenshots/06-app-b-dashboard.png)

### 07. MFA Enrollment

![MFA enrollment](docs/screenshots/07-mfa-enrollment.png)

### 08. SSO Revocation

![SSO revocation](docs/screenshots/08-sso-revocation.png)

### 09. Health & Metrics

![Health and metrics](docs/screenshots/09-health-metrics.png)

![Health and metrics](docs/screenshots/09-health-metrics2.png)
