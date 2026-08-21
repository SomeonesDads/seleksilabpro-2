# seleksilabpro-2

## Identitas

Nama dan NIM: isi sesuai identitas anggota kelompok.

## Keputusan teknis: JWT access token

Proyek ini menggunakan JSON Web Token (JWT) sebagai access token (`TOKEN_STRATEGY=jwt`). JWT dipilih karena sistem memiliki satu Auth Provider dan lebih dari satu relying application, yaitu App A dan App B. Token yang diterbitkan oleh Auth Provider dapat diverifikasi oleh layanan yang membutuhkan autentikasi tanpa harus melakukan query ke database Auth Provider untuk setiap request.

JWT paling sesuai untuk proyek ini karena:

- **Verifikasi efisien dan stateless.** Setelah tanda tangan token diverifikasi, aplikasi dapat membaca identitas pengguna, penerbit, audience, dan masa berlaku langsung dari token. Hal ini mengurangi beban database pusat dan menghindari ketergantungan jaringan antara setiap relying application dan Auth Provider.
- **Mendukung horizontal scaling.** Instance App A, App B, dan instance tambahan di masa depan dapat memvalidasi token dengan konfigurasi kunci yang sama atau dengan public key yang sama, tanpa membutuhkan session store bersama.
- **Claims membawa konteks autentikasi.** Token dapat memuat `sub` untuk user ID, `aud` untuk application ID, `iss` untuk Auth Provider, `iat`, `exp`, `jti`, serta scope atau role yang diperlukan. Dengan demikian, setiap aplikasi dapat memastikan token memang diterbitkan untuk dirinya sendiri.
- **Interoperabel.** JWT adalah format standar yang tersedia di library Go dan platform lain. App A dan App B tidak perlu memahami struktur database internal Auth Provider untuk memvalidasi access token.
- **Cocok untuk access token berumur pendek.** Konfigurasi `ACCESS_TOKEN_TTL` membatasi dampak jika token bocor. SSO session tetap dikelola dan dapat dicabut di Auth Provider, sedangkan access token dibuat berumur pendek agar kebutuhan revocation real-time berkurang.

### Konsekuensi dan mitigasi

JWT bukan pilihan yang unggul untuk semua kebutuhan. Token yang sudah diterbitkan tetap valid sampai `exp`, kecuali setiap resource server melakukan introspection atau menerapkan denylist `jti`. Karena itu, implementasi proyek ini harus:

1. menggunakan access token berumur pendek;
2. memeriksa `exp`, `nbf` bila digunakan, `iss`, dan `aud` pada setiap validasi;
3. menggunakan `jti` unik untuk setiap token;
4. tidak memasukkan password, client secret, session token, atau data sensitif ke dalam claims;
5. memvalidasi bahwa `aud` sama dengan application ID pemanggil sehingga token App A tidak dapat digunakan untuk App B;
6. menggunakan HTTPS agar token tidak dapat disadap;
7. menyimpan signing key hanya melalui environment variable atau secret manager;
8. menyiapkan rotasi signing key. Untuk deployment multi-service, asymmetric signing seperti RS256 atau EdDSA lebih aman karena aplikasi hanya menerima public key dan tidak memiliki kemampuan menerbitkan token baru.

Logout dan perubahan policy tetap dicatat sebagai event transactional outbox dan dikirim ke relying applications melalui Sync Worker. Dengan TTL access token yang pendek, propagasi logout membatasi sesi aplikasi yang tersisa tanpa memerlukan query database pada setiap request.

Sync Worker membaca event outbox yang belum dipublikasikan dari database, menerbitkannya ke RabbitMQ dengan routing key `SessionRevoked`, `PasswordChanged`, atau `AccessPolicyChanged`, lalu mengirim payload ke endpoint `logout_notification_url` aplikasi. Pengiriman internal memakai header `X-Internal-Auth`; token per aplikasi hanya dikonfigurasi melalui `APP_TARGETS_JSON` pada Sync Worker dan tidak disimpan di database. `APP_TARGETS_JSON` wajib memuat setiap aplikasi aktif sebelum worker mulai mengonsumsi pesan.

Integration test persistence: set `TEST_DATABASE_URL` to disposable PostgreSQL, then run `go test ./internal/store -run TestStorePostgresIntegration` from `auth-provider/sync-worker`.

### Perbandingan dengan opaque token

Opaque token lebih mudah dicabut secara real-time karena setiap validasi dapat melakukan lookup ke database. Namun, pendekatan tersebut menambah latency dan beban database pada setiap request ke App A atau App B, serta membuat semua aplikasi bergantung pada ketersediaan Auth Provider. JWT mengurangi ketergantungan tersebut dengan tradeoff bahwa revocation tidak langsung terlihat sampai token kedaluwarsa atau resource server melakukan pemeriksaan tambahan.

### Kontrak access token

Auth Provider menerbitkan access token dengan algoritma **HS256** menggunakan `JWT_SIGNING_KEY`. Validator wajib menolak algoritma lain, termasuk token yang mencoba mengganti algoritma menjadi `none` atau algoritma HMAC lain. `JWT_ISSUER` default ke `auth-provider`, dan dapat dikonfigurasi melalui environment.

Setiap token memiliki format claims berikut:

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

`aud` selalu merupakan UUID aplikasi tujuan. `exp` memakai `ACCESS_TOKEN_TTL`, dengan default 15 menit. `jti` dibuat unik untuk setiap token. `iss`, `aud`, tanda tangan, dan `exp` wajib valid saat token divalidasi. Claims tidak boleh memuat password, client secret, raw session token, signing key, atau data sensitif pengguna.

## Cara menjalankan sistem

Compose reads service `.env` files, not `.env.example` files. Copy examples
before starting; the copied files are gitignored.

PowerShell:

```powershell
Copy-Item .env.example .env
Copy-Item auth-provider/server/.env.example auth-provider/server/.env
Copy-Item auth-provider/control-panel/.env.example auth-provider/control-panel/.env
Copy-Item auth-provider/sync-worker/.env.example auth-provider/sync-worker/.env
Copy-Item applications/app-a/.env.example applications/app-a/.env
Copy-Item applications/app-b/.env.example applications/app-b/.env
```

POSIX shell:

```sh
cp .env.example .env
cp auth-provider/server/.env.example auth-provider/server/.env
cp auth-provider/control-panel/.env.example auth-provider/control-panel/.env
cp auth-provider/sync-worker/.env.example auth-provider/sync-worker/.env
cp applications/app-a/.env.example applications/app-a/.env
cp applications/app-b/.env.example applications/app-b/.env
```

Set `JWT_SIGNING_KEY` and `MFA_ENCRYPTION_KEY` in the server file. Generate
both with `openssl rand -base64 32`; the MFA value must decode to 32 bytes.
Set non-empty App A and App B client secrets and internal auth tokens in both
the application files and the matching `SEED_*` variables in the server file.
Set `APP_TARGETS_JSON` in the worker file with the fixed application IDs from
the example and the same internal tokens.

Start the stack:

```sh
docker compose up --build
```

Seed after PostgreSQL is ready. Run from `auth-provider/server` with the six
`SEED_*` variables exported and `DATABASE_URL` pointed at host port `5433`:

```sh
go run ./cmd/seed
```

The seed command is idempotent. It prints provisioning credentials once; the
database stores only password and client-secret hashes.

Component URLs:

| Component | URL |
|---|---|
| Auth Provider | http://localhost:5001 |
| Control Panel | http://localhost:5002 |
| App A | http://localhost:5010 |
| App B | http://localhost:5020 |
| RabbitMQ management | http://localhost:15672 |

Verification commands:

```sh
docker compose config
```

Run the following from each module directory (`shared`, `auth-provider/server`,
`auth-provider/control-panel`, `auth-provider/sync-worker`, `applications/app-a`,
and `applications/app-b`):

```sh
go test ./...
go vet ./...
```

## Arsitektur dan alur

Dokumentasi arsitektur dan alur OAuth/OIDC proyek.

## Technology stack

Daftar teknologi beserta versinya.

## Endpoint

Daftar endpoint yang dibuat.

## Bonus

Bonus yang dikerjakan, bila ada.

## Screenshot

Tambahkan screenshot sistem di sini.
