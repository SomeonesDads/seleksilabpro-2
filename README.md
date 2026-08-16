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

Dokumentasi langkah `docker compose up`, migration, seed, dan URL tiap komponen.

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
