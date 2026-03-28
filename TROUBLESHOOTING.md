# 🔧 Troubleshooting Guide

## ❌ START.bat Error - Web Tidak Berjalan

### Solusi 1: Gunakan npm run dev (Recommended)

Cara paling mudah dan reliable:

```bash
npm run dev
```

Atau double-click file: **START_SIMPLE.bat**

### Solusi 2: Perbaiki START.bat

Jika START.bat error, coba langkah berikut:

1. **Pastikan semua prerequisites terinstall:**
   ```bash
   node --version
   go version
   python --version
   docker --version
   ```

2. **Install dependencies terlebih dahulu:**
   ```bash
   npm run install:all
   ```

3. **Jalankan services secara manual:**

   **Terminal 1 - Database:**
   ```bash
   docker-compose up -d postgres redis
   ```

   **Terminal 2 - AI Service:**
   ```bash
   cd backend/ai-service
   python -m uvicorn ai:app --host 0.0.0.0 --port 5000 --reload
   ```

   **Terminal 3 - Backend:**
   ```bash
   cd backend
   go run main.go
   ```

   **Terminal 4 - Frontend:**
   ```bash
   cd frontend
   npm run dev
   ```

---

## 🔍 Masalah Umum

### 1. Error: "Python not found"

**Solusi:**
- Pastikan Python terinstall
- Cek apakah `python` atau `python3` ada di PATH
- Coba jalankan: `python --version` atau `python3 --version`

**Windows:**
- Install Python dari python.org
- Pastikan "Add Python to PATH" dicentang saat install

### 2. Error: "Go not found"

**Solusi:**
- Install Go dari golang.org/dl
- Pastikan Go ada di PATH
- Restart terminal setelah install

### 3. Error: "Docker not found"

**Solusi:**
- Install Docker Desktop untuk Windows
- Pastikan Docker Desktop sudah running
- Atau install PostgreSQL dan Redis secara lokal

### 4. Error: "Port already in use"

**Solusi Windows:**
```powershell
# Cek port yang digunakan
netstat -ano | findstr :3000
netstat -ano | findstr :5000
netstat -ano | findstr :8080

# Kill process (ganti PID dengan nomor yang muncul)
taskkill /PID <PID> /F
```

**Solusi Linux/Mac:**
```bash
# Cek port yang digunakan
lsof -i :3000
lsof -i :5000
lsof -i :8080

# Kill process
kill -9 <PID>
```

### 5. Error: "Cannot find module" atau "node_modules not found"

**Solusi:**
```bash
# Install dependencies
npm run install:all

# Atau manual:
npm install
cd frontend && npm install
cd ../backend/ai-service && pip install -r requirements.txt
```

### 6. Error: "Database connection failed"

**Solusi:**
```bash
# Pastikan Docker running
docker ps

# Start database services
docker-compose up -d postgres redis

# Tunggu 5-10 detik, lalu coba lagi
```

### 7. Error: "Frontend tidak bisa akses Backend"

**Solusi:**
- Pastikan Backend berjalan di port 8080
- Cek file `frontend/src/App.js` atau komponen yang menggunakan API
- Pastikan URL API benar: `http://localhost:8080`

### 8. Error: "AI Service tidak bisa diakses"

**Solusi:**
- Pastikan Python dependencies terinstall:
  ```bash
  cd backend/ai-service
  pip install -r requirements.txt
  ```
- Cek apakah AI Service berjalan di port 5000
- Test: `curl http://localhost:5000/health`

---

## ✅ Checklist Sebelum Menjalankan

- [ ] Node.js terinstall (v16+)
- [ ] Go terinstall (v1.19+)
- [ ] Python terinstall (v3.8+)
- [ ] Docker Desktop running (Windows/Mac)
- [ ] Dependencies sudah diinstall (`npm run install:all`)
- [ ] Port 3000, 5000, 8080 tidak digunakan aplikasi lain
- [ ] Firewall tidak memblokir port tersebut

---

## 🚀 Cara Terbaik untuk Menjalankan

### Opsi 1: npm run dev (Paling Recommended)

```bash
npm run dev
```

**Keuntungan:**
- ✅ Otomatis cek prerequisites
- ✅ Otomatis install dependencies jika perlu
- ✅ Error handling yang baik
- ✅ Logging yang jelas
- ✅ Graceful shutdown

### Opsi 2: START_SIMPLE.bat

Double-click file `START_SIMPLE.bat`

**Keuntungan:**
- ✅ Sederhana
- ✅ Menggunakan npm run dev di belakang layar

### Opsi 3: Manual (Untuk Debugging)

Jalankan setiap service di terminal terpisah untuk melihat error dengan jelas.

---

## 📞 Masih Error?

1. **Cek log error** di terminal
2. **Pastikan semua prerequisites terinstall**
3. **Coba restart Docker Desktop** (jika Windows/Mac)
4. **Coba restart terminal/command prompt**
5. **Cek apakah ada antivirus/firewall yang memblokir**

---

## 🔄 Reset Semuanya

Jika masih error, coba reset:

```bash
# Stop semua services
docker-compose down

# Clean up
npm run clean

# Install ulang dependencies
npm run install:all

# Jalankan lagi
npm run dev
```

---

**Selamat mencoba! 🛡️**







