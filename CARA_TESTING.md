# 🧪 Cara Testing WAF - Quick Guide

## 🚀 Langkah Cepat

### 1. Start Sistem
```bash
.\START.bat
```

Atau manual:
- MySQL & Redis: `docker-compose up -d mysql redis`
- AI Service: `cd backend/ai-service && python -m uvicorn ai:app --host 0.0.0.0 --port 5000`
- Backend: `cd backend && go run .`
- Frontend: `cd frontend && npm run dev`

### 2. Login ke Dashboard
- URL: http://localhost:3000
- Username: `admin`
- Password: `admin123`

---

## 🖥️ Testing via Frontend (Paling Mudah!)

### Cara 1: Tombol WAF TEST
1. Login ke dashboard
2. Scroll ke bagian **AI Commands**
3. Klik tombol **"WAF TEST"**
4. Lihat hasil di AI Console

### Cara 2: Ketik di AI Console
1. Login ke dashboard
2. Di AI Console, ketik: `WAF_TEST`
3. Tekan Enter
4. Lihat hasil testing otomatis

**Test yang dijalankan:**
- ✅ SQL Injection
- ✅ XSS Attack
- ✅ Path Traversal
- ✅ File Upload

---

## 💻 Testing via Command Line

### Cara 1: Script Otomatis
```bash
.\TEST_WAF.bat
```

### Cara 2: Manual Testing
Lihat file `TESTING_WAF.md` untuk command lengkap.

**Contoh cepat:**
```bash
# SQL Injection
curl -X POST http://localhost:8080/api/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"username\": \"admin' OR '1'='1\", \"password\": \"test\"}"

# XSS
curl "http://localhost:8080/api/data?q=<script>alert('XSS')</script>"

# Path Traversal
curl "http://localhost:8080/admin/../etc/passwd"
```

---

## ✅ Verifikasi Hasil

### 1. Dashboard
- Buka http://localhost:3000
- Lihat **Security Statistics**:
  - Total Threats Detected
  - Blocked Requests
  - Active Threat Actors
- Lihat **Attack Logs** untuk detail

### 2. Backend Logs
Lihat terminal backend, cari:
- `🛡️ WAF BLOCKED: SQL Injection detected`
- `🚫 IP Blocked: 127.0.0.1`
- `⚠️ Rate limit exceeded`

### 3. API Stats
```bash
# Get statistics (perlu login token)
curl http://localhost:8080/api/quantum/stats \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## 📊 Expected Results

| Test | Expected Status | Artinya |
|------|----------------|---------|
| SQL Injection | `403` | ✅ **BLOCKED** - WAF bekerja! |
| XSS | `403` | ✅ **BLOCKED** - WAF bekerja! |
| Path Traversal | `403` | ✅ **BLOCKED** - WAF bekerja! |
| Rate Limiting | `429` | ✅ **BLOCKED** - Rate limit bekerja! |

**Jika dapat `403` = WAF bekerja dengan baik! ✅**

---

## 🎯 Tips

1. **Test via Frontend** = Paling mudah, hasil langsung terlihat
2. **Test via Script** = Untuk testing otomatis berulang
3. **Test Manual** = Untuk testing spesifik/custom

---

## 📚 Dokumentasi Lengkap

Lihat `TESTING_WAF.md` untuk:
- Semua jenis serangan yang bisa di-test
- Command lengkap untuk setiap test
- Advanced testing
- Troubleshooting

---

**Selamat Testing! 🛡️**



