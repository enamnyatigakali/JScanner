#!/usr/bin/env python3
import argparse
import math
import re
import sys
import urllib.request
import urllib.error
from collections import Counter
from datetime import datetime


BANNER = r"""
      _  _____                                      
     | |/ ____|                                     
     | | (___   ___ __ _ _ __  _ __   ___ _ __      
 _   | |\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|     
| |__| |____) | (_| (_| | | | | | | |  __/ |        
 \____/|_____/ \___\__,_|_| |_|_| |_|\___|_|  v1.0  
                                                    
     [ JS Secret & Credential Scanner for Humans ]
     [ By : EnamnyaTigaKali ]
"""


PATTERNS = {
    "Kunci API Umum (API Key)": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-z0-9_\-]{16,64}['\"]",
    "Kunci Rahasia (Secret Key)": r"(?i)(secret|secret[_-]?key)\s*[:=]\s*['\"][a-zA-Z0-9_\-\/\+=]{8,64}['\"]",
    "Token Akses (Access Token)": r"(?i)(token|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.\/\+=]{8,128}['\"]",
    "Kata Sandi di dalam Kode (Hardcoded Password)": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,64}['\"]",
    "Token Bearer": r"(?i)bearer\s+[a-zA-Z0-9_\-\.=]{10,}",
    "Token JWT (JSON Web Token)": r"eyJ[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+",
    "AWS Access Key ID (Amazon)": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase Config Key": r"(?i)(apiKey|authDomain|databaseURL|projectId)\s*[:=]\s*['\"][^'\"]+['\"]",
    "Kunci Privat (Private Key Block)": r"-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----",
    "Alamat Web dengan Username/Password": r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]+:[^/\s:@]+@[^\s'\"]+",
    "Konfigurasi Lingkungan (Environment Variable)": r"(?i)(env|environment|mode|targetEnv)\s*[:=]\s*['\"](dev|develop|development|staging|stg|preprod|pre-prod|uat|prod|production)['\"]",
    "Link Lingkungan Development (Dev/Local)": r"(?i)https?://[a-zA-Z0-9_\-\.]*(dev|localhost|127\.0\.0\.1|local)[a-zA-Z0-9_\-\.]*\.[a-zA-Z]{2,}",
    "Link Lingkungan Staging (Stg)": r"(?i)https?://[a-zA-Z0-9_\-\.]*(staging|stg|stage)[a-zA-Z0-9_\-\.]*\.[a-zA-Z]{2,}",
    "Link Lingkungan Pre-Production (Preprod/UAT)": r"(?i)https?://[a-zA-Z0-9_\-\.]*(preprod|pre-prod|uat)[a-zA-Z0-9_\-\.]*\.[a-zA-Z]{2,}",
    "Link Lingkungan Production (Prod)": r"(?i)https?://[a-zA-Z0-9_\-\.]*(prod|api|portal|m|www)[a-zA-Z0-9_\-\.]*\.[a-zA-Z]{2,}",
}

COMPILED_PATTERNS = {name: re.compile(pat) for name, pat in PATTERNS.items()}
STRING_LITERAL_RE = re.compile(r"""['"]([A-Za-z0-9_\-+/=]{20,200})['"]""")

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def looks_like_hash_or_asset(s: str) -> bool:
    if re.fullmatch(r"[0-9a-f]{16,64}", s, re.IGNORECASE):
        return True
    if re.fullmatch(r"[A-Za-z0-9_\-]+\.(js|css|png|svg|jpg|woff2?|map)", s):
        return True
    return False

def fetch_content(source: str) -> str:
    if source.startswith("http://") or source.startswith("https://"):
        req = urllib.request.Request(
            source,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
            return raw.decode("utf-8", errors="replace")
        except Exception as e:
            print(f"[ERROR] Gagal mengunduh URL: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            with open(source, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except FileNotFoundError:
            print(f"[ERROR] File tidak ditemukan: {source}", file=sys.stderr)
            sys.exit(1)


def generate_layman_report(filepath: str, source: str, pattern_findings, entropy_findings):
    waktu_scan = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("========================================================================\n")
        f.write(BANNER)
        f.write("========================================================================\n")
        f.write("          LAPORAN PEMERIKSAAN FILE JAVASCRIPT \n")
        f.write("========================================================================\n\n")
        
        f.write(f"Tanggal Pemeriksaan : {waktu_scan}\n")
        f.write(f"Sumber File         : {source}\n")
        f.write("Tujuan              : Mencari apakah ada data sensitif (seperti secret key,\n")
        f.write("                      token, atau credential) yang tidak sengaja tertinggal\n")
        f.write("                      di dalam kode aplikasi web.\n\n")
        
        f.write("------------------------------------------------------------------------\n")
        f.write("1. RINGKASAN TEMUAN\n")
        f.write("------------------------------------------------------------------------\n")
        total_pola = len(pattern_findings)
        total_acak = len(entropy_findings)
        
        f.write(f"- Menemukan {total_pola} teks yang cocok dengan pola Kunci/Token sensitif.\n")
        f.write(f"- Menemukan {total_acak} teks acak panjang yang suspicious (potensi secret key).\n\n")
        
        if total_pola == 0 and total_acak == 0:
            f.write("KESIMPULAN SEMENTARA: AMAN\n")
            f.write("Tidak ditemukan tanda-tanda kebocoran data sensitif yang jelas pada file ini.\n\n")
        else:
            f.write("KESIMPULAN SEMENTARA: \n")
            f.write("Ditemukan beberapa data yang menyerupai kunci akses/kredensial. Direkomendasikan\n")
            f.write("untuk melakukan verifikasi manual guna memastikan informasi tersebut bukan data sensitif.\n\n")
            
        
        f.write("------------------------------------------------------------------------\n")
        f.write("2. RINCIAN TEMUAN BERDASARKAN POLA KATA KUNCI\n")
        f.write("------------------------------------------------------------------------\n")
        if not pattern_findings:
            f.write("-> Tidak ditemukan pola kata informasi sensitif yang terdeteksi.\n\n")
        else:
            f.write("Berikut adalah informasi sensitif yang berhasil dideteksi:\n\n")
            for i, item in enumerate(pattern_findings, 1):
                f.write(f"Temuan #{i}:\n")
                f.write(f"  - Jenis Kategori : {item['type']}\n")
                f.write(f"  - Potongan Teks  : {item['match']}\n")
                f.write(f"  - Konteks Kode   : ... {item['context']} ...\n")
                f.write("  - Impact         : Jika ini adalah informasi sensitif / disclosure,\n")
                f.write("                     pihak luar dapat menggunakan informasi ini untuk mengakses\n")
                f.write("                     layanan internal perusahaan secara ilegal.\n\n")

        
        f.write("------------------------------------------------------------------------\n")
        f.write("3. RINCIAN TEKS ACAK YANG SUSPICIOUS\n")
        f.write("------------------------------------------------------------------------\n")
        f.write("Sistem mendeteksi teks acak yang sangat panjang. secret key komputer\n")
        f.write("biasanya berupa karakter acak (seperti sandi rumit). Namun, bagian ini juga\n")
        f.write("bisa berisi teks biasa dari sistem (False Positive).\n\n")
        
        if not entropy_findings:
            f.write("-> Tidak ditemukan teks acak berisiko tinggi.\n\n")
        else:
            for i, item in enumerate(entropy_findings, 1):
                f.write(f"Kandidat #{i}:\n")
                f.write(f"  - Karakter Acak  : {item['string'][:80]}...\n")
                f.write(f"  - Panjang Teks   : {item['length']} karakter\n")
                f.write(f"  - Tingkat Keacakan: {item['entropy']} (Skala 1-8, semakin tinggi semakin dicurigai)\n\n")

       
        f.write("------------------------------------------------------------------------\n")
        f.write("4. APA YANG HARUS DILAKUKAN SEKARANG? (LANGKAH REKOMENDASI)\n")
        f.write("------------------------------------------------------------------------\n")
        f.write("1. Tanyakan kepada Pengembang (Developer):\n")
        f.write("   Tunjukkan potongan teks di atas kepada tim IT/Developer Anda. Tanyakan:\n")
        f.write("   'Apakah kunci/token ini aktif dan digunakan untuk sistem penting kita?'\n\n")
        f.write("2. Lakukan Penonaktifan (Revoke Key):\n")
        f.write("   Jika tim pengembang (Developer) mengonfirmasi bahwa itu adalah secret key/token yang aktif,\n")
        f.write("   segera disable key tersebut di panel admin (misal AWS, Google, Firebase)\n")
        f.write("   dan buat kunci baru yang disimpan dengan aman di sisi server (bukan di JavaScript browser).\n\n")
        f.write("3. Bersihkan Riwayat Kode:\n")
        f.write("   Pastikan file JavaScript yang bocor ini dihapus dari server publik dan diganti\n")
        f.write("   dengan versi baru yang sudah bersih.\n\n")
        f.write("------------------------------------------------------------------------\n")
        f.write("                      --- AKHIR DARI LAPORAN ---\n")
        f.write("========================================================================\n")


def main():
    print("\033[94m" + BANNER + "\033[0m")
    parser = argparse.ArgumentParser(
        description="Scan file JavaScript untuk mendeteksi credential dengan laporan ramah pengguna."
    )
    parser.add_argument("source", help="URL file JS atau path file lokal")
    parser.add_argument("-o", "--output", default="laporan_keamanan.txt", 
                        help="Nama file laporan output .txt (default: laporan_keamanan.txt)")
    args = parser.parse_args()

    print(f"[*] Membaca data dari: {args.source}")
    content = fetch_content(args.source)
    print(f"[*] Berhasil membaca {len(content):,} karakter.")

    pattern_findings = []
    for name, regex in COMPILED_PATTERNS.items():
        for match in regex.finditer(content):
            start = max(0, match.start() - 30)
            end = min(len(content), match.end() + 30)
            snippet = content[start:end].replace("\n", " ")
            pattern_findings.append({
                "type": name,
                "match": match.group(0)[:100],
                "context": snippet,
            })

    
    entropy_findings = []
    seen = set()
    for m in STRING_LITERAL_RE.finditer(content):
        s = m.group(1)
        if s in seen or len(s) < 24 or looks_like_hash_or_asset(s):
            continue
        ent = shannon_entropy(s)
        if ent >= 3.8:  
            seen.add(s)
            entropy_findings.append({"string": s, "entropy": round(ent, 2), "length": len(s)})
    
    entropy_findings.sort(key=lambda x: x["entropy"], reverse=True)
    top_entropy = entropy_findings[:15]  

    
    generate_layman_report(args.output, args.source, pattern_findings, top_entropy)
    
    print("\n" + "="*50)
    print(" Scanning SELESAI!")
    print("="*50)
    print(f"Laporan hasil scanning  telah disimpan ke file: \033[92m{args.output}\033[0m")
    print("file tersebut dapat dibuka dengan Notepad atau Text Editor lainnya.")
    print("="*50)

if __name__ == "__main__":
    main()
