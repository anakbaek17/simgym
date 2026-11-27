"""
isi_data.py - Isi data asli FIT HUB GYM (paket, trainer, alat gym) ke database.db.

CARA PAKAI
  1. Edit 3 daftar di bawah (PAKET, TRAINER, ALAT) sesuai data gym Anda.
  2. Cek dulu tanpa mengubah apa pun:   python isi_data.py --cek
  3. Jalankan sungguhan:                python isi_data.py

Aman dijalankan berulang kali. Data member, pembayaran, dan check-in TIDAK dihapus.
Sebelum mengubah, database otomatis dicadangkan ke database_backup_<waktu>.db
"""
import secrets
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

from werkzeug.security import generate_password_hash

# =====================================================================
# 1) PAKET MEMBERSHIP  ->  (nama paket, durasi dalam bulan, harga Rp, status)
#    status: 'Aktif' (tampil & bisa dibeli) atau 'Nonaktif' (disembunyikan)
#    Jika nama paket sudah ada, harga/durasi/status-nya diperbarui.
# =====================================================================
PAKET = [
    ('Paket Biru', 1, 250000, 'Aktif'),
    ('Standard',   3, 400000, 'Aktif'),
    ('Premium',    6, 600000, 'Aktif'),
]
# True  = paket yang TIDAK ada di daftar di atas otomatis di-Nonaktif-kan
#         (tidak dihapus, karena riwayat pembayaran lama masih memakainya).
NONAKTIFKAN_PAKET_LAIN = False

# =====================================================================
# 2) TRAINER  ->  (kode, nama, email, nomor HP)
#    - kode 'TRN001' (dst.) = UBAH data trainer yang sudah ada.
#    - kode ''              = TAMBAH trainer baru (password acak dibuat & ditampilkan sekali).
# =====================================================================
TRAINER = [
    ('TRN001', 'Rian Fitness', 'rian@gym.com', '081234567802'),
    # ('', 'Nama Trainer Baru', 'email@gym.com', '08xxxxxxxxxx'),
]

# =====================================================================
# 3) ALAT GYM  ->  (nama alat, kategori, status)
#    status harus salah satu: 'Tersedia', 'Perbaikan', 'Rusak'
# =====================================================================
ALAT = [
    ('Treadmill Pro X', 'Cardio', 'Tersedia'),
    ('Olympic Barbell', 'Beban',  'Tersedia'),
]
# True = alat yang TIDAK ada di daftar di atas dihapus dari database.
HAPUS_ALAT_LAIN = False
# =====================================================================

DB_PATH = Path(__file__).resolve().parent / 'database.db'
STATUS_ALAT = ('Tersedia', 'Perbaikan', 'Rusak')
STATUS_PAKET = ('Aktif', 'Nonaktif')
TERLARANG = set('<>"\'&`\\')  # karakter yang tidak boleh ada di teks (dashboard menampilkan teks apa adanya)


def bersih(teks, label, maks=60):
    teks = ' '.join(str(teks).split())
    if not teks or len(teks) > maks or any(c in TERLARANG or ord(c) < 32 for c in teks):
        raise ValueError(f"{label} '{teks}' tidak valid (wajib diisi, maks {maks} karakter, tanpa < > \" ' & ` \\).")
    return teks


def validasi():
    paket, trainer, alat = [], [], []
    for n, d, h, st in PAKET:
        n = bersih(n, 'Nama paket')
        if int(d) < 1:
            raise ValueError(f"Durasi paket '{n}' minimal 1 bulan.")
        if float(h) <= 0:
            raise ValueError(f"Harga paket '{n}' harus lebih dari 0.")
        if st not in STATUS_PAKET:
            raise ValueError(f"Status paket '{n}' harus 'Aktif' atau 'Nonaktif'.")
        paket.append((n, int(d), float(h), st))
    for kode, n, email, hp in TRAINER:
        n = bersih(n, 'Nama trainer')
        email = bersih(email, 'Email trainer', 100).lower()
        if '@' not in email:
            raise ValueError(f"Email trainer '{email}' tidak valid.")
        hp = bersih(hp, 'Nomor HP trainer', 20)
        trainer.append((str(kode).strip().upper(), n, email, hp))
    for n, k, st in ALAT:
        n, k = bersih(n, 'Nama alat', 80), bersih(k, 'Kategori alat', 40)
        if st not in STATUS_ALAT:
            raise ValueError(f"Status alat '{n}' harus salah satu dari: {', '.join(STATUS_ALAT)}.")
        alat.append((n, k, st))
    return paket, trainer, alat


def main():
    hanya_cek = '--cek' in sys.argv
    try:
        paket, trainer, alat = validasi()
    except (ValueError, TypeError) as e:
        print(f"[ERROR] {e}\nTidak ada yang diubah.")
        sys.exit(1)

    if not DB_PATH.is_file():
        print("[ERROR] database.db belum ada. Jalankan dulu: python app.py (lalu hentikan dengan Ctrl+C).")
        sys.exit(1)

    if not hanya_cek:
        cadangan = DB_PATH.with_name(f"database_backup_{datetime.now():%Y%m%d_%H%M%S}.db")
        shutil.copy2(DB_PATH, cadangan)
        print(f"Cadangan database: {cadangan.name}")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    password_baru = []

    # ---- Paket ----
    print("\n== PAKET ==")
    for n, d, h, st in paket:
        row = cur.execute("SELECT id, duration_months, price, status FROM membership_packages WHERE LOWER(package_name) = ?",
                          (n.lower(),)).fetchone()
        if row:
            if (row[1], row[2], row[3]) != (d, h, st):
                cur.execute("UPDATE membership_packages SET package_name=?, duration_months=?, price=?, status=? WHERE id=?",
                            (n, d, h, st, row[0]))
                print(f"  ~ diperbarui : {n} ({d} bln, Rp{h:,.0f}, {st})")
            else:
                print(f"  = sama       : {n}")
        else:
            cur.execute("INSERT INTO membership_packages (package_name, duration_months, price, status) VALUES (?, ?, ?, ?)",
                        (n, d, h, st))
            print(f"  + ditambah   : {n} ({d} bln, Rp{h:,.0f}, {st})")
    if NONAKTIFKAN_PAKET_LAIN:
        namas = [p[0].lower() for p in paket]
        for pid, pn in cur.execute("SELECT id, package_name FROM membership_packages WHERE status='Aktif'").fetchall():
            if pn.lower() not in namas:
                cur.execute("UPDATE membership_packages SET status='Nonaktif' WHERE id=?", (pid,))
                print(f"  - dinonaktifkan: {pn}")

    # ---- Trainer ----
    print("\n== TRAINER ==")
    for kode, n, email, hp in trainer:
        row = None
        if kode:
            row = cur.execute("SELECT id, unique_code FROM users WHERE role='trainer' AND UPPER(unique_code)=?", (kode,)).fetchone()
            if not row:
                print(f"  ! dilewati   : kode {kode} tidak ditemukan (kosongkan kode untuk menambah trainer baru)")
                continue
        else:
            row = cur.execute("SELECT id, unique_code FROM users WHERE role='trainer' AND LOWER(email)=?", (email,)).fetchone()
        try:
            if row:
                lama = cur.execute("SELECT name, email, phone FROM users WHERE id=?", (row[0],)).fetchone()
                if (lama[0], (lama[1] or '').lower(), lama[2]) == (n, email, hp):
                    print(f"  = sama       : {row[1]} - {n}")
                else:
                    cur.execute("UPDATE users SET name=?, email=?, phone=? WHERE id=?", (n, email, hp, row[0]))
                    print(f"  ~ diperbarui : {row[1]} - {n}")
            else:
                maks = cur.execute("SELECT MAX(CAST(SUBSTR(unique_code, 4) AS INTEGER)) FROM users WHERE unique_code LIKE 'TRN%'").fetchone()[0] or 0
                kode_baru = f"TRN{maks + 1:03d}"
                pw = secrets.token_urlsafe(9)
                cur.execute("INSERT INTO users (unique_code, name, email, password, role, phone) VALUES (?, ?, ?, ?, 'trainer', ?)",
                            (kode_baru, n, email, generate_password_hash(pw), hp))
                password_baru.append((kode_baru, n, pw))
                print(f"  + ditambah   : {kode_baru} - {n}")
        except sqlite3.IntegrityError:
            print(f"  ! dilewati   : email {email} sudah dipakai akun lain")

    # ---- Alat ----
    print("\n== ALAT GYM ==")
    for n, k, st in alat:
        row = cur.execute("SELECT id, category, status FROM equipment WHERE LOWER(equipment_name)=?", (n.lower(),)).fetchone()
        if row:
            if (row[1], row[2]) != (k, st):
                cur.execute("UPDATE equipment SET equipment_name=?, category=?, status=? WHERE id=?", (n, k, st, row[0]))
                print(f"  ~ diperbarui : {n} ({k}, {st})")
            else:
                print(f"  = sama       : {n}")
        else:
            cur.execute("INSERT INTO equipment (equipment_name, category, status) VALUES (?, ?, ?)", (n, k, st))
            print(f"  + ditambah   : {n} ({k}, {st})")
    if HAPUS_ALAT_LAIN:
        namas = [a[0].lower() for a in alat]
        for eid, en in cur.execute("SELECT id, equipment_name FROM equipment").fetchall():
            if en.lower() not in namas:
                cur.execute("DELETE FROM equipment WHERE id=?", (eid,))
                print(f"  - dihapus    : {en}")

    if hanya_cek:
        conn.rollback()
        print("\n[MODE CEK] Tidak ada perubahan yang disimpan. Jalankan tanpa --cek untuk menyimpan.")
    else:
        conn.commit()
        print("\nSelesai. Data tersimpan di database.db.")
        if password_baru:
            print("\n" + "=" * 60)
            print("PASSWORD TRAINER BARU (tampil sekali, berikan ke yang bersangkutan):")
            for kode, n, pw in password_baru:
                print(f"  {kode}  {n:<25} {pw}")
            print("Mereka bisa menggantinya sendiri di menu 'Akun Saya'.")
            print("=" * 60)
    conn.close()


if __name__ == '__main__':
    main()
