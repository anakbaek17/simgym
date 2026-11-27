# FIT HUB GYM

Aplikasi web manajemen gym berbasis Flask + SQLite.
Halaman publik (paket, trainer, fasilitas, cara bergabung) bisa dibuka tanpa login.
Owner, Admin, Trainer, dan Member login lewat `/login` untuk masuk ke `/dashboard`.

## Struktur folder

```
FitHubGym/
├── app.py                  # seluruh aplikasi
├── requirements.txt        # dependensi (Flask)
├── README.md
├── .gitignore
├── static/
│   └── images/
│       ├── hero.jpg        # foto gym untuk halaman utama (opsional, disarankan)
│       ├── login-bg.png    # background halaman login (opsional)
│       ├── bg-<role>-<menu>.jpg  # background dashboard per menu (opsional, lihat bagian Gambar)
│       └── qris_dana.png   # foto QRIS asli untuk pembayaran (WAJIB jika pakai QRIS)
├── database.db             # dibuat otomatis saat pertama jalan
└── payment_proofs/         # dibuat otomatis saat ada bukti bayar pertama
```

## Cara menjalankan (Windows)

1. Pastikan Python 3.10+ sudah terpasang.
2. Buka terminal di folder proyek, lalu (opsional tapi disarankan) buat virtual environment:
   ```
   python -m venv venv
   venv\Scripts\activate
   ```
3. Pasang dependensi:
   ```
   pip install -r requirements.txt
   ```
4. Jalankan:
   ```
   python app.py
   ```
5. Buka http://localhost:8080/

Dari HP/perangkat lain di jaringan yang sama, buka `http://<IP-komputer>:8080/`
(contoh: `http://192.168.100.71:8080/`).

## Gambar

- **Foto halaman utama:** simpan foto gym sendiri sebagai `static/images/hero.jpg`
  (juga bisa `.png` / `.webp`). Otomatis dipakai tanpa ubah kode.
  Pilih foto portrait atau mendekati persegi, gelap dan kontras, di bawah 300 KB.
- **Jika belum ada foto lokal**, web memakai foto cadangan dari internet
  (butuh koneksi di perangkat pengunjung).
- **Background dashboard (semua role):** setiap menu di dashboard Member, Trainer, Admin, dan Owner punya foto latar.
  Default-nya foto dari internet (sama seperti dashboard member sebelumnya). Untuk memakai foto sendiri, simpan di
  `static/images/` dengan nama `bg-<role>-<menu>.jpg` (juga `.png` / `.webp`), contoh `bg-admin-manage_payments.jpg`,
  atau `bg-<role>.jpg` untuk satu foto yang dipakai semua menu role itu. Role: `member`, `trainer`, `admin`, `owner`.
- **QRIS:** foto QRIS asli sudah tersimpan di `static/images/qris_dana.png` dan tampil di checkout
  Paket Membership (member). Untuk mengganti, timpa file itu dengan nama yang sama.
- **Font halaman visitor** (Big Shoulders Display & Figtree) dimuat dari Google Fonts. Tanpa internet,
  halaman tetap tampil dengan font cadangan (Impact / sistem).

## Pendaftaran member (tanpa WhatsApp)

- Tombol **Daftar** di halaman utama membuka `/daftar`, alurnya mirip pendaftaran Google:
  1. **Data akun**: nama, email, nomor HP, password (email dicek langsung apakah sudah terdaftar).
  2. **Pilih paket** (bisa langsung dari tombol "Ambil paket ini").
  3. **Pembayaran**: scan QRIS (atau transfer GoPay/DANA), lalu unggah bukti.
- Setelah dikirim, pendaftar langsung masuk ke area member. Membership baru aktif setelah admin
  memverifikasi pembayaran di **Kelola Pembayaran** (sampai itu, status tetap *Belum Aktif*).
- Akun baru otomatis berkode `MEM###`, tersimpan dengan password ter-hash, dan dibatasi 10 percobaan daftar per jam per IP.

## Dashboard member

Dashboard Utama menampilkan grafik yang mengikuti paket aktif member:

- **Masa aktif**: grafik donat sisa hari vs hari terpakai, dihitung dari durasi paket.
- **Kehadiran check-in**: grafik batang. Paket 1 bulan = 4 minggu terakhir; paket 3/6 bulan = per bulan sesuai durasi paket.
- Member yang belum punya paket aktif melihat ajakan memilih paket (grafik muncul setelah pembayaran diverifikasi).

Riwayat pembayaran member ada di menu **Paket Membership** (di bawah daftar paket); menu Pembayaran yang terpisah sudah dihapus.
Profil, ganti nama, dan ganti password ada di **Akun Saya**.

## Grafik per role

- **Member**: donat masa aktif + batang kehadiran check-in.
- **Trainer**: donat status program latihan (selesai vs belum) + batang jumlah program per member.
- **Admin**: batang check-in 7 hari terakhir, donat status pembayaran (Lunas/Pending/Ditolak), donat kondisi alat gym.
- **Owner**: batang tren pendapatan bulanan.

Semua grafik berupa SVG murni (tanpa library/CDN) dan dihitung dari database.

## Notifikasi

Ikon lonceng di pojok kanan atas semua dashboard. Notifikasi muncul sebagai toast saat ada yang baru
(dicek otomatis tiap 12 detik) dan tersimpan di tabel `notifications`.

- **Admin**: pendaftar baru, pembayaran baru dari member.
- **Member**: bukti bayar diterima, pembayaran terverifikasi/ditolak, program latihan baru, target diperbarui.
- **Trainer**: member baru yang sudah aktif.
- **Owner**: pembayaran lunas.

## Fitur publik

- Paket membership, trainer, fasilitas, dan cara bergabung (data dari SQLite).
- Tombol WhatsApp **081574783604** tinggal sebagai jalur "Tanya admin"; ubah nomornya lewat variabel `phone`
  di fungsi `public_home()` pada `app.py`.

## Akun & password

- Saat database **pertama kali dibuat**, aplikasi membuat 4 akun awal (`OWN001` Owner, `ADM001` Admin,
  `TRN001` Trainer, `MEM001` Member) dengan **password acak**. Password ditampilkan **sekali** di terminal
  saat `python app.py` pertama kali dijalankan. Catat, lalu ganti sesuai kebutuhan.
- Semua password disimpan dalam bentuk **hash** (bukan teks polos).
- Login dibatasi: setelah 5x salah untuk satu akun (atau 20x salah dari satu IP), login diblokir 5 menit.
  Catatan percobaan gagal disimpan di `database.db` (tabel `login_attempts`), jadi blokir tetap berlaku
  walau server di-restart.
- Password akun baru (member/trainer) minimal 8 karakter.

### Ganti nama & password sendiri

Semua role (Owner, Admin, Trainer, Member) bisa membuka menu **🔐 Akun Saya** di sidebar
(member juga melihat ringkasan **Profil Member** di halaman yang sama). Di sana pengguna bisa:

- mengubah nama tampilan (2-60 karakter, tanpa karakter `< > " ' & \` `),
- mengganti password: wajib mengisi password saat ini, password baru minimal 8 karakter,
  dan harus berbeda dari yang lama. Salah memasukkan password saat ini 5x akan diblokir 5 menit.

### Reset password lewat terminal

Untuk lupa password atau bantuan admin/owner: (bisa untuk semua akun, termasuk jika lupa password):

```
python app.py reset-password OWN001
```

Ganti `OWN001` dengan kode akun yang dimaksud.

## Check-in QR Code aman & Laporan Kunjungan

**Cara kerja**

1. Member membuka **Check-in QR Code**. QR dibuat di server sendiri (tanpa situs luar) dan berisi token
   bertanda tangan yang **kedaluwarsa dalam 90 detik**; halaman memperbaruinya otomatis.
2. **Admin** memindai QR itu di menu **Scan Check-in** (kamera, scanner USB, atau tempel manual) atau dengan
   kamera HP biasa lalu membuka tautannya sambil login admin. Hanya admin yang bisa memproses check-in.
3. Check-in **ditolak** jika QR palsu/diubah, QR kedaluwarsa, atau membership tidak aktif (sisa hari 0).
   Member yang sudah check-in tidak bisa check-in lagi selama 2 jam (`CHECKIN_COOLDOWN_MINUTES` di `app.py`).
4. Member menerima notifikasi tiap check-in berhasil, jadi pemakaian QR oleh orang lain cepat ketahuan.

**Laporan Kunjungan** (menu admin dan owner): filter tanggal/member/status, total kunjungan, member berbeda,
rata-rata per hari, jam paling ramai, member paling rajin, grafik, daftar kunjungan, unduh CSV, dan cetak/PDF.
Angka "Check-in Hari Ini" di dashboard admin/owner hanya menghitung check-in yang berhasil.

**Catatan pemasangan**

- Jalankan `pip install -r requirements.txt` sekali (menambah pustaka `segno` untuk membuat QR).
- Tetap memakai `database.db` yang sama. Saat `python app.py` dijalankan, hanya ditambahkan 2 kolom pada tabel
  `checkins` (`scanned_by`, `note`). Data member, trainer, dan password tidak diubah.
- **Kamera scan:** saat `python app.py` dijalankan, aplikasi sekarang membuka dua alamat: `http://<IP>:8080`
  (biasa) dan `https://<IP>:8443` (HTTPS, sertifikat dibuat otomatis di `cert.pem`/`key.pem`). Kamera browser
  hanya bisa dipakai lewat HTTPS, jadi **admin membuka `https://<IP>:8443`**. Saat browser memperingatkan
  sertifikat, klik *Advanced* lalu *Lanjutkan* (cukup sekali; aman karena hanya di jaringan gym sendiri).
  Pemindai memakai `BarcodeDetector` bila ada, dan pustaka `jsQR` (`static/js/jsQR.js`) sebagai cadangan,
  jadi jalan di Chrome, Edge, Firefox, dan Safari.
- Admin tidak perlu mengetik alamat HTTPS: di `http://<IP>:8080` cukup klik **Aktifkan Kamera**, halaman otomatis
  pindah ke `https://<IP>:8443` (login tetap berlaku) dan kamera langsung menyala.
- Alternatif tanpa kamera browser: kamera bawaan HP, scanner USB, atau kolom ketik manual.

## Update dari versi lama

1. Cadangkan `app.py` lama, lalu ganti dengan yang baru.
2. **Jangan hapus** `database.db`, `static/`, dan `payment_proofs/` milik proyek yang sedang dipakai.
3. Jalankan `python app.py`. Password lama di database otomatis diubah menjadi hash
   (akun tetap bisa login dengan password lamanya).
4. Jika terminal menampilkan `[PERINGATAN]` karena ada akun masih memakai `password123`,
   segera ganti dengan `python app.py reset-password <KODE>`.
5. Refresh browser dengan Ctrl+F5.

## Sebelum dipakai sungguhan

- Ganti semua password yang masih bawaan lama (lihat peringatan di terminal saat aplikasi dijalankan).
- Jangan upload/bagikan `database.db`, `.gym_secret_key`, dan `payment_proofs/`.
- `app.run(host='0.0.0.0')` cocok untuk testing di jaringan lokal. Untuk publik, jalankan
  dengan server produksi (waitress/gunicorn) di belakang HTTPS.
- Backup `database.db` dan `payment_proofs/` secara rutin.
