# Chat Random Number

Full-stack prototype chat app dengan:
- registrasi email + OTP Gmail
- nomor random 7 digit untuk tiap user
- kontak berdasarkan nomor
- chat real-time dengan Socket.IO
- SQLite untuk database lokal

## Install
```bash
npm install
```

## Setup `.env`
Copy `.env.example` menjadi `.env`, lalu isi:
- `GMAIL_USER`
- `GMAIL_APP_PASSWORD`

> Pakai Gmail App Password, bukan password akun biasa.

## Run
```bash
npm start
```

Buka:
```text
http://localhost:3000
```

## API utama
- `POST /api/auth/request-otp`
- `POST /api/auth/verify-otp`
- `GET /api/me`
- `GET /api/contacts`
- `POST /api/contacts/add`
- `GET /api/chats/:number`
- `POST /api/chats/send`

## Catatan
- Kalau env Gmail belum diisi, OTP tetap jalan mode demo dan code akan tampil di response.
- Chat real-time jalan lewat Socket.IO setelah login.
