# 🧪 Panduan Testing WAF - Zein Security

## 📋 Daftar Isi

1. [Persiapan](#persiapan)
2. [Cara Start Sistem](#cara-start-sistem)
3. [Testing via Frontend UI](#testing-via-frontend-ui)
4. [Testing via Command Line](#testing-via-command-line)
5. [Jenis Serangan untuk Diuji](#jenis-serangan-untuk-diuji)
6. [Verifikasi Hasil](#verifikasi-hasil)

---

## 🚀 Persiapan

### 1. Pastikan Semua Service Berjalan

Jalankan `START.bat` untuk memulai semua service:

```bash
.\START.bat
```

Atau start manual:

- **MySQL & Redis**: `docker-compose up -d mysql redis`
- **AI Service**: `cd backend/ai-service && python -m uvicorn ai:app --host 0.0.0.0 --port 5000`
- **Backend**: `cd backend && go run .`
- **Frontend**: `cd frontend && npm run dev`

### 2. Verifikasi Service Berjalan

Buka browser dan cek:

- ✅ Frontend: http://localhost:3000
- ✅ Backend: http://localhost:8080/health
- ✅ AI Service: http://localhost:5000/health

### 3. Login ke Dashboard

1. Buka http://localhost:3000
2. Login dengan:
   - Username: `admin`
   - Password: `admin123`

---

## 🖥️ Testing via Frontend UI

### 1. Test WAF Protection (Built-in)

Di dashboard, ada fitur **"Test WAF Protection"** yang akan otomatis test:

- SQL Injection
- XSS Attack
- Path Traversal
- File Upload

**Cara pakai:**

1. Login ke dashboard
2. Cari tombol/command "Test WAF Protection" di AI Console
3. Klik dan lihat hasilnya

### 2. Monitor Real-time

Dashboard menampilkan:

- **Security Statistics**: Total threats, blocked requests
- **Attack Logs**: Real-time log serangan
- **Threat Actors**: IP yang terdeteksi mencurigakan
- **WAF Config**: Konfigurasi protection level

---

## 💻 Testing via Command Line

### 1. SQL Injection Test

```bash
# Test 1: Basic SQL Injection
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR '\''1'\''='\''1", "password": "test"}'

# Test 2: UNION-based SQL Injection
curl "http://localhost:8080/api/data?q=1' UNION SELECT * FROM users--"

# Test 3: Time-based SQL Injection
curl "http://localhost:8080/api/data?id=1' AND SLEEP(5)--"
```

**Expected Result**: Status `403 Forbidden` atau `400 Bad Request`

### 2. XSS (Cross-Site Scripting) Test

```bash
# Test 1: Basic XSS
curl "http://localhost:8080/api/data?q=<script>alert('XSS')</script>"

# Test 2: XSS dengan encoding
curl "http://localhost:8080/api/data?q=%3Cscript%3Ealert('XSS')%3C/script%3E"

# Test 3: XSS di POST body
curl -X POST http://localhost:8080/api/data \
  -H "Content-Type: application/json" \
  -d '{"comment": "<img src=x onerror=alert(1)>"}'
```

**Expected Result**: Status `403 Forbidden`

### 3. Path Traversal Test

```bash
# Test 1: Basic Path Traversal
curl "http://localhost:8080/admin/../etc/passwd"
curl "http://localhost:8080/api/../../etc/passwd"

# Test 2: Encoded Path Traversal
curl "http://localhost:8080/api/..%2F..%2Fetc%2Fpasswd"
curl "http://localhost:8080/api/..%5C..%5Cwindows%5Csystem32"
```

**Expected Result**: Status `403 Forbidden`

### 4. Command Injection Test

```bash
# Test 1: Basic Command Injection
curl "http://localhost:8080/api/exec?cmd=ls; cat /etc/passwd"

# Test 2: Command Injection dengan pipe
curl "http://localhost:8080/api/exec?cmd=whoami | cat"

# Test 3: Command Injection dengan backtick
curl "http://localhost:8080/api/exec?cmd=\`id\`"
```

**Expected Result**: Status `403 Forbidden`

### 5. Rate Limiting Test

```bash
# Test: Kirim banyak request dalam waktu singkat
for i in {1..150}; do
  curl -s http://localhost:8080/api/quantum/stats \
    -H "Authorization: Bearer YOUR_TOKEN" \
    -o /dev/null -w "%{http_code}\n"
  sleep 0.1
done
```

**Expected Result**: Setelah ~100 request, status `429 Too Many Requests`

### 6. DDoS Simulation Test

```bash
# Test: Burst request (simulasi DDoS)
for i in {1..1000}; do
  curl -s http://localhost:8080/api/data &
done
wait
```

**Expected Result**: IP akan di-block otomatis setelah threshold

### 7. Bot Detection Test

```bash
# Test: Request tanpa User-Agent (bot-like)
curl -H "User-Agent: " http://localhost:8080/api/data

# Test: Request dengan bot User-Agent
curl -H "User-Agent: Googlebot" http://localhost:8080/api/data
curl -H "User-Agent: curl/7.68.0" http://localhost:8080/api/data
```

**Expected Result**: Status `403 Forbidden` atau header `X-Bot-Detected: true`

### 8. XXE (XML External Entity) Test

```bash
# Test: XXE Attack
curl -X POST http://localhost:8080/api/upload \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>'
```

**Expected Result**: Status `403 Forbidden`

### 9. Insecure Deserialization Test

```bash
# Test: Malicious serialized data
curl -X POST http://localhost:8080/api/data \
  -H "Content-Type: application/json" \
  -d '{"data": "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"evil\";}"}'
```

**Expected Result**: Status `403 Forbidden`

---

## 🎯 Jenis Serangan untuk Diuji

### OWASP Top 10 (2021)

| #   | Kategori             | Test Case                | Command                                     |
| --- | -------------------- | ------------------------ | ------------------------------------------- |
| A01 | **Injection**        | SQL Injection            | `admin' OR '1'='1`                          |
| A01 | **Injection**        | Command Injection        | `; cat /etc/passwd`                         |
| A02 | **Broken Auth**      | Brute Force              | Multiple login attempts                     |
| A03 | **Sensitive Data**   | Exposed credentials      | Check response headers                      |
| A04 | **XXE**              | XML External Entity      | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| A05 | **Broken Access**    | Path Traversal           | `../../etc/passwd`                          |
| A06 | **Misconfiguration** | Default credentials      | Try `admin/admin`                           |
| A07 | **XSS**              | Cross-Site Scripting     | `<script>alert(1)</script>`                 |
| A08 | **Deserialization**  | Insecure deserialization | Malicious serialized data                   |
| A09 | **Known Vuln**       | Old dependencies         | Check versions                              |
| A10 | **Logging**          | Insufficient logging     | Check logs after attack                     |

---

## ✅ Verifikasi Hasil

### 1. Cek Log Backend

Lihat terminal backend untuk melihat:

- `🛡️ WAF BLOCKED: SQL Injection detected`
- `🚫 IP Blocked: 127.0.0.1`
- `⚠️ Rate limit exceeded`

### 2. Cek Dashboard

1. Buka http://localhost:3000
2. Lihat **Security Statistics**:
   - Total Threats Detected
   - Blocked Requests
   - Active Threat Actors
3. Lihat **Attack Logs**:
   - Real-time log serangan
   - IP address attacker
   - Jenis serangan
   - Threat score

### 3. Cek API Stats

```bash
# Get security statistics
curl http://localhost:8080/api/quantum/stats \
  -H "Authorization: Bearer YOUR_TOKEN"

# Get attack logs
curl http://localhost:8080/api/quantum/logs \
  -H "Authorization: Bearer YOUR_TOKEN"

# Get blocked IPs
curl http://localhost:8080/api/admin/ip-blocks \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 4. Cek Metrics

```bash
# Prometheus metrics
curl http://localhost:8080/metrics
```

Cari metrics:

- `zein_requests_blocked` - Total request yang di-block
- `zein_threats_detected` - Total threat yang terdeteksi
- `zein_response_time_seconds` - Response time

---

## 🔧 Advanced Testing

### 1. Test Threat Intelligence

```bash
# Test dengan IP yang mencurigakan
curl -H "X-Forwarded-For: 1.2.3.4" http://localhost:8080/api/data
```

### 2. Test Behavioral Analysis

```bash
# Test dengan pola request yang aneh
# Request cepat dari IP yang sama
for i in {1..50}; do
  curl http://localhost:8080/api/data?page=$i
  sleep 0.01
done
```

### 3. Test CDN Caching

```bash
# Request pertama (miss)
curl http://localhost:8080/api/data

# Request kedua (hit)
curl http://localhost:8080/api/data
```

### 4. Test Zero Trust

```bash
# Test tanpa authentication
curl http://localhost:8080/api/admin/users

# Test dengan invalid token
curl -H "Authorization: Bearer invalid_token" \
  http://localhost:8080/api/admin/users
```

---

## 📊 Expected Results Summary

| Test Type         | Expected Status            | Expected Behavior                  |
| ----------------- | -------------------------- | ---------------------------------- |
| SQL Injection     | `403`                      | Blocked, logged, IP may be blocked |
| XSS               | `403`                      | Blocked, logged                    |
| Path Traversal    | `403`                      | Blocked, logged                    |
| Command Injection | `403`                      | Blocked, logged                    |
| Rate Limiting     | `429`                      | After threshold, IP may be blocked |
| DDoS              | `503` or `403`             | IP blocked automatically           |
| Bot Detection     | `403` or `200` with header | Header `X-Bot-Detected: true`      |
| XXE               | `403`                      | Blocked, logged                    |
| Deserialization   | `403`                      | Blocked, logged                    |

---

## 🐛 Troubleshooting

### WAF tidak memblokir serangan?

1. **Cek Protection Level**:

   ```bash
   curl http://localhost:8080/api/quantum/config \
     -H "Authorization: Bearer YOUR_TOKEN"
   ```

   Pastikan `protection_level` adalah `high` atau `paranoid`

2. **Cek WAF Enabled**:
   Pastikan WAF enabled di config

3. **Cek Logs**:
   Lihat terminal backend untuk error messages

### IP tidak ter-block?

1. **Cek Threat Score Threshold**:

   - Low: 0.9
   - Medium: 0.7
   - High: 0.5
   - Paranoid: 0.3

2. **Cek Auto-blocking**:
   Pastikan auto-blocking enabled di config

### Rate limiting tidak bekerja?

1. **Cek Rate Limit Config**:

   ```json
   {
     "rate_limit_requests": 100,
     "rate_limit_window": "1m"
   }
   ```

2. **Cek Redis**:
   Pastikan Redis berjalan (`docker-compose ps`)

---

## 📝 Test Script Otomatis

Buat file `test_waf.sh` (untuk Linux/Mac) atau `test_waf.bat` (untuk Windows):

```bash
#!/bin/bash
# test_waf.sh

echo "🧪 Testing WAF Protection..."

# Test SQL Injection
echo "Test 1: SQL Injection"
curl -s -o /dev/null -w "Status: %{http_code}\n" \
  -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin'\'' OR '\''1'\''='\''1", "password": "test"}'

# Test XSS
echo "Test 2: XSS"
curl -s -o /dev/null -w "Status: %{http_code}\n" \
  "http://localhost:8080/api/data?q=<script>alert(1)</script>"

# Test Path Traversal
echo "Test 3: Path Traversal"
curl -s -o /dev/null -w "Status: %{http_code}\n" \
  "http://localhost:8080/admin/../etc/passwd"

echo "✅ Testing complete!"
```

---

## 🎓 Tips Testing

1. **Test secara bertahap**: Mulai dari serangan sederhana, lalu ke yang lebih kompleks
2. **Monitor logs**: Selalu perhatikan log backend saat testing
3. **Test berbagai protection level**: Coba `low`, `medium`, `high`, `paranoid`
4. **Test kombinasi serangan**: Gabungkan beberapa serangan sekaligus
5. **Test edge cases**: Coba dengan encoding, obfuscation, dll

---

**Selamat Testing! 🛡️**

Jika ada pertanyaan atau masalah, cek dokumentasi atau log backend.


