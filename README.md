![JScanner](https://github.com/enamnyatigakali/JScanner/blob/main/JScanner%20.png?raw=true)

# JScanner

`JScanner` *security auditing tool* yang dibuat dengan Python, yang dirancang untuk melakukan scanning pada file JavaScript (baik lokal maupun langsung dari URL) guna mendeteksi kebocoran data sensitif. Tools ini akan melakukan deteksi pada *hardcoded* API Keys, Token, Kredensial, serta informasi lingkungan kerja (*environment*) internal yang tidak sengaja terekspos ke publik.

Selain proses deteksi `JScanner`, Tools ini dapat menghasilkan laporan akhir dalam format `.txt` berbahasa Indonesia yang **ramah pengguna dan mudah dipahami oleh orang awam** (staf non-IT, manajemen, atau klien).

---

##  Fitur Utama (Features)

- **Pemindaian Berbasis Pattern :** Menggunakan Regex yang dioptimalkan untuk mendeteksi:
  - Kunci API (Google, Firebase, Stripe, dll).
  - Token Akses (JWT, Bearer Token, Slack Token, dll).
  - Kredensial AWS (Access Key ID & Secret Key).
  - Kata sandi yang tertulis langsung (*hardcoded password*).
  - Kunci privat (*Private Key Block*).
- **Deteksi Lingkungan Kerja (Environment Detection):** Mengidentifikasi konfigurasi dan tautan URL yang merujuk pada lingkungan internal seperti:
  - **Development / Local** (`localhost`, `dev.example.com`)
  - **Staging** (`stg`, `staging`)
  - **Pre-Production / UAT** (`preprod`, `uat`)
  - **Production** (`prod`)
- **Analisis String :** Menemukan kunci rahasia yang tidak memiliki nama variabel jelas dengan cara mengukur tingkat acak pada penggunaan string panjang.
- **Laporan yang Friendly :** Menghasilkan laporan `.txt` otomatis yang menjelaskan apa arti temuan tersebut, tingkat bahayanya, serta rekomendasi tindakan pemulihan tanpa jargon teknis yang rumit.
- **Dukungan Multi-Sumber:** Dapat memindai file JavaScript lokal maupun mengunduh langsung dari URL HTTPS secara aman.

---

## Installasi

### Requirement
Pastikan sudah menginstal **Python 3.x** di komputer Anda. `JScanner` dibuat menggunakan pustaka bawaan Python (*standard library*), sehingga **tidak memerlukan instalasi modul tambahan (no external dependencies)**.

### Step 
1. Unduh atau salin skrip `js_scanner.py` ke komputer Anda.
2. Buka Terminal (macOS/Linux) atau Command Prompt (Windows).
3. Verifikasi instalasi Python dan jalankan `js_scanner.py` dengan perintah:

```bash
python3 js_scanner.py --help
```
### Opsi Perintah

| Opsi  | Keterangan |
| --- | :-----: |
| -h.  |Menampilkan menu bantuan dan panduan parameter.    |
| -o   |Menentukan nama file laporan output (Default: laporan_keamanan.txt).|

---
### Penggunaan
Basic
```bash
python3 js_scanner.py <filepath_atau_url> [opsi]
```
Contoh Scan via URL
```bash
python3 js_scanner.py https://example.com/assets/index-123456.js -o laporan_example.com.txt
```
Contoh Scan via local file
```bash
python3 js_scanner.py index-123456.js -o laporan_example.com.txt
```
---
### Lisensi

Proyek ini dilisensikan di bawah MIT License 

