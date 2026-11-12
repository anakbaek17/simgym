from flask import Flask, request, redirect, url_for, session, render_template, send_from_directory, abort, jsonify
import sqlite3
from presentation import fragment
import os
import secrets
from pathlib import Path
from datetime import datetime, timedelta
import html
import re
from urllib.parse import urlparse, parse_qs, quote
import sys
import time
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# Kunci sesi lokal yang stabil, tetapi tidak ditulis langsung di kode sumber.
BASE_DIR = Path(__file__).resolve().parent
SECRET_FILE = BASE_DIR / '.gym_secret_key'
if not SECRET_FILE.exists():
    SECRET_FILE.write_text(secrets.token_urlsafe(48), encoding='utf-8')
app.secret_key = os.environ.get('GYM_SECRET_KEY') or SECRET_FILE.read_text(encoding='utf-8').strip()
DB_PATH = str(BASE_DIR / 'database.db')
PROOF_DIR = BASE_DIR / 'payment_proofs'  # Bukti pembayaran bersifat privat, bukan di /static.
app.config['MAX_CONTENT_LENGTH'] = 6 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# ---- Keamanan login: hash password + pembatasan percobaan login ----
MIN_PASSWORD_LEN = 8
LOGIN_MAX_FAILS = 5          # maksimal salah per kombinasi IP + akun
LOGIN_IP_MAX_FAILS = 20      # maksimal salah per IP (semua akun)
LOGIN_WINDOW_SECONDS = 300   # jendela hitung & lama blokir (5 menit)
_DUMMY_HASH = generate_password_hash('dummy-password-untuk-menyamakan-waktu')


def is_password_hashed(value):
    return isinstance(value, str) and value.startswith(('scrypt:', 'pbkdf2:'))


def _attempts_conn():
    """Koneksi ke tabel percobaan gagal (disimpan di database.db agar tidak hilang saat restart)."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute('CREATE TABLE IF NOT EXISTS login_attempts (key TEXT NOT NULL, ts REAL NOT NULL)')
    conn.execute('CREATE INDEX IF NOT EXISTS idx_login_attempts_key ON login_attempts(key, ts)')
    return conn


def _keys(ip, login_input):
    return ((f"{ip}|{login_input}", LOGIN_MAX_FAILS), (f"{ip}", LOGIN_IP_MAX_FAILS))


def login_lock_seconds(ip, login_input):
    """Sisa detik blokir (0 jika boleh mencoba)."""
    now = time.time()
    since = now - LOGIN_WINDOW_SECONDS
    locks = []
    conn = _attempts_conn()
    try:
        conn.execute('DELETE FROM login_attempts WHERE ts < ?', (since,))
        conn.commit()
        for key, limit in _keys(ip, login_input):
            rows = conn.execute('SELECT ts FROM login_attempts WHERE key = ? AND ts >= ? ORDER BY ts',
                                (key, since)).fetchall()
            if len(rows) >= limit:
                locks.append(int(LOGIN_WINDOW_SECONDS - (now - rows[0][0])) + 1)
    finally:
        conn.close()
    return max(locks) if locks else 0


def record_login_fail(ip, login_input):
    now = time.time()
    conn = _attempts_conn()
    try:
        conn.executemany('INSERT INTO login_attempts (key, ts) VALUES (?, ?)',
                         [(key, now) for key, _ in _keys(ip, login_input)])
        conn.commit()
    finally:
        conn.close()


def clear_login_fails(ip, login_input):
    conn = _attempts_conn()
    try:
        conn.execute('DELETE FROM login_attempts WHERE key = ?', (f"{ip}|{login_input}",))
        conn.commit()
    finally:
        conn.close()



# Foto cadangan (gym gelap) dipakai otomatis jika file lokal belum ada di static/images.
FALLBACK_IMAGES = {
    'hero': 'https://images.unsplash.com/photo-1534438327276-14e5300c3a48?auto=format&fit=crop&w=1200&q=80',
    'login': 'https://images.unsplash.com/photo-1517836357463-d25dfeac3438?auto=format&fit=crop&w=1920&q=80',
}


def site_image(filenames, fallback_key):
    """Pakai gambar lokal pertama yang ada di static/images; jika tidak ada, pakai foto cadangan."""
    for name in filenames:
        if (Path(app.static_folder) / 'images' / name).is_file():
            return url_for('static', filename=f'images/{name}')
    return FALLBACK_IMAGES[fallback_key]


@app.context_processor
def inject_site_images():
    return {
        # Taruh foto gym sendiri di static/images/hero.jpg (atau login-bg.png) agar otomatis dipakai.
        'hero_img': site_image(['hero.jpg', 'hero.png', 'hero.webp', 'login-bg.png'], 'hero'),
        'login_bg_img': site_image(['login-bg.png'], 'login'),
    }


def csrf_valid():
    """Periksa CSRF token pada aksi pembayaran baru."""
    submitted = request.form.get('csrf_token', '')
    expected = session.get('payment_csrf', '')
    return bool(submitted and expected and secrets.compare_digest(submitted, expected))


def image_type(data):
    """Menerima bukti PNG/JPEG/WebP saja, diverifikasi dari signature berkas."""
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if data.startswith(b'\xff\xd8\xff'):
        return 'jpg'
    if data.startswith(b'RIFF') and data[8:12] == b'WEBP':
        return 'webp'
    return None


YOUTUBE_ID = re.compile(r'^[A-Za-z0-9_-]{11}$')


def safe(value):
    """Escape teks untuk HTML dan netralkan kurung kurawal agar tidak dieksekusi sebagai template Jinja."""
    text = '' if value is None else str(value)
    return html.escape(text).replace('{', '&#123;').replace('}', '&#125;')


def _now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def rupiah(value):
    return 'Rp ' + f'{float(value):,.0f}'.replace(',', '.')


def notify_user(conn, user_id, title, message='', link=None):
    """Simpan satu notifikasi untuk satu pengguna (dipakai di dalam transaksi pemanggil)."""
    conn.execute("INSERT INTO notifications (user_id, title, message, link, created_at, is_read) VALUES (?, ?, ?, ?, ?, 0)",
                 (user_id, str(title)[:120], str(message or '')[:300], link, _now()))


def notify_role(conn, role, title, message='', link=None):
    """Kirim notifikasi ke semua akun dengan role tertentu (status baca dicatat per akun)."""
    for row in conn.execute("SELECT id FROM users WHERE role = ?", (role,)).fetchall():
        notify_user(conn, row[0], title, message, link)


_RATE = {}


def rate_ok(bucket, key, limit, window):
    """Pembatas sederhana di memori: maksimal `limit` kejadian per `window` detik."""
    now = time.time()
    hits = [t for t in _RATE.get((bucket, key), []) if now - t < window]
    if len(hits) >= limit:
        _RATE[(bucket, key)] = hits
        return False
    hits.append(now)
    _RATE[(bucket, key)] = hits
    return True


def csrf_header_valid():
    submitted = request.headers.get('X-CSRF-Token', '')
    expected = session.get('payment_csrf', '')
    return bool(submitted and expected and secrets.compare_digest(submitted, expected))


def fmt_num(value):
    try:
        return f'{float(value):g}'
    except (TypeError, ValueError):
        return '-'


def attr_num(value):
    return '' if value is None else fmt_num(value)


def progress_pct(start, current, target):
    """Persentase menuju target (berlaku untuk menurunkan maupun menaikkan angka)."""
    try:
        start, current, target = float(start), float(current), float(target)
    except (TypeError, ValueError):
        return None
    if start == target:
        return None
    return max(0, min(100, round((start - current) / (start - target) * 100)))


def target_card(label, unit, start, current, target):
    pct = progress_pct(start, current, target)
    bar = fragment('components/target-progress-bar', pct=pct) if pct is not None else ''
    pct_txt = f' · tercapai {pct}%' if pct is not None else ''
    return (fragment('components/target-card',
        label=label,
        start=fmt_num(start),
        target=fmt_num(target),
        unit=unit,
        current=fmt_num(current),
        unit_6=unit,
        pct_txt=pct_txt,
        bar=bar,
    ))


def normalize_video_url(raw):
    """Kembalikan (url, error). URL kosong dibolehkan (video opsional)."""
    raw = (raw or '').strip()
    if not raw:
        return '', None
    if len(raw) > 500:
        return None, 'Link video terlalu panjang (maksimum 500 karakter).'
    if re.search(r'[\s{}<>"\'`\\]', raw):
        return None, 'Link video mengandung karakter yang tidak diizinkan.'
    try:
        parsed = urlparse(raw)
    except ValueError:
        return None, 'Link video tidak valid.'
    if parsed.scheme not in ('http', 'https') or not parsed.netloc:
        return None, 'Link video harus diawali http:// atau https://'
    return raw, None


def video_html(url):
    """Pemutar video untuk dashboard member: YouTube di-embed, file mp4/webm diputar langsung."""
    if not url:
        return fragment('components/video-empty')
    parsed = urlparse(url)
    host = (parsed.hostname or '').lower()
    if host.startswith('www.'):
        host = host[4:]
    video_id = None
    if host in ('youtube.com', 'm.youtube.com'):
        if parsed.path == '/watch':
            video_id = parse_qs(parsed.query).get('v', [''])[0]
        else:
            match = re.match(r'^/(?:embed|shorts|live)/([A-Za-z0-9_-]{11})', parsed.path)
            video_id = match.group(1) if match else None
    elif host == 'youtu.be':
        video_id = parsed.path.lstrip('/')[:11]
    if video_id and YOUTUBE_ID.match(video_id):
        return (fragment('components/video-youtube', video_id=video_id))
    if parsed.path.lower().endswith(('.mp4', '.webm', '.ogg')):
        return fragment('components/video-player', url=safe(url))
    return (fragment('components/video-link', url=safe(url)))


# =========================================================
# ⚠️ ISIKAN NOMOR GOPAY & NAMA ASLI KAMU DI SINI:
GOPAY_NUMBER = "083857533722"  # Ganti dengan Nomor HP GoPay Kamu
GOPAY_NAME = "NAUFAL HANIF JABRAN SUKMA"     # Nama Akun GoPay Kamu
# =========================================================

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            unique_code TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            phone TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS membership_packages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            duration_months INTEGER NOT NULL,
            price REAL NOT NULL,
            status TEXT DEFAULT 'Aktif'
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS member_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            package_id INTEGER,
            remaining_days INTEGER DEFAULT 30,
            status_paket TEXT DEFAULT 'Paket Premium',
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS checkins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            checkin_time TEXT NOT NULL,
            status TEXT DEFAULT 'Berhasil',
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS workouts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trainer_id INTEGER,
            member_id INTEGER,
            exercise_name TEXT NOT NULL,
            sets INTEGER,
            reps INTEGER,
            weight_kg REAL,
            schedule_date TEXT,
            schedule_time TEXT,
            status TEXT DEFAULT 'Belum',
            FOREIGN KEY(member_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS member_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER,
            target_weight REAL,
            target_body_fat REAL,
            notes TEXT,
            FOREIGN KEY(member_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS member_progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER,
            weight REAL,
            body_fat REAL,
            stomach_circumference REAL,
            recorded_date TEXT DEFAULT CURRENT_DATE,
            FOREIGN KEY(member_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS equipment (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            equipment_name TEXT NOT NULL,
            category TEXT NOT NULL,
            status TEXT DEFAULT 'Tersedia'
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER,
            package_id INTEGER,
            amount REAL,
            payment_date TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            FOREIGN KEY(member_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # Migrasi aman: tambah kolom ke database.db lama TANPA menghapus transaksi.
    cursor.execute("PRAGMA table_info(payments)")
    existing_payment_columns = {row[1] for row in cursor.fetchall()}
    payment_migrations = {
        'payment_method': 'TEXT',
        'proof_filename': 'TEXT',
        'verified_at': 'TEXT',
        'verified_by': 'INTEGER',
        'rejection_reason': 'TEXT'
    }
    for column, sql_type in payment_migrations.items():
        if column not in existing_payment_columns:
            cursor.execute(f'ALTER TABLE payments ADD COLUMN {column} {sql_type}')
    conn.commit()

    # Migrasi aman: kolom baru untuk target (berat/body fat awal) dan video program latihan.
    extra_migrations = {
        'member_targets': {'start_weight': 'REAL', 'start_body_fat': 'REAL', 'trainer_id': 'INTEGER', 'updated_at': 'TEXT'},
        'workouts': {'video_url': 'TEXT'},
    }
    for table_name, columns in extra_migrations.items():
        cursor.execute(f"PRAGMA table_info({table_name})")
        existing_columns = {row[1] for row in cursor.fetchall()}
        for column, sql_type in columns.items():
            if column not in existing_columns:
                cursor.execute(f'ALTER TABLE {table_name} ADD COLUMN {column} {sql_type}')
    conn.commit()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT,
            link TEXT,
            created_at TEXT NOT NULL,
            is_read INTEGER DEFAULT 0
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id, is_read, id)')
    cursor.execute("PRAGMA table_info(users)")
    user_cols = {row[1] for row in cursor.fetchall()}
    for column in ('registered_at', 'signup_source'):
        if column not in user_cols:
            cursor.execute(f'ALTER TABLE users ADD COLUMN {column} TEXT')
    conn.commit()

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        seed_users = [
            ('OWN001', 'Budi Santoso', 'budi@gym.com', 'owner', '081234567800'),
            ('ADM001', 'Siti Aminah', 'siti@gym.com', 'admin', '081234567801'),
            ('TRN001', 'Rian Fitness', 'rian@gym.com', 'trainer', '081234567802'),
            ('MEM001', 'Andi Pratama', 'andi@gym.com', 'member', '081234567803'),
        ]
        first_run_passwords = {}
        for code, uname, email, role, phone in seed_users:
            plain = secrets.token_urlsafe(9)  # password acak, unik per akun
            first_run_passwords[code] = plain
            cursor.execute("INSERT INTO users (unique_code, name, email, password, role, phone) VALUES (?, ?, ?, ?, ?, ?)",
                           (code, uname, email, generate_password_hash(plain), role, phone))
        cursor.executemany("INSERT INTO membership_packages (package_name, duration_months, price, status) VALUES (?, ?, ?, ?)", [
            ('Paket Biru', 1, 250000, 'Aktif'),
            ('Standard', 3, 400000, 'Aktif'),
            ('Premium', 6, 600000, 'Aktif')
        ])
        cursor.execute("INSERT INTO member_profiles (user_id, package_id, remaining_days, status_paket) VALUES (4, 3, 45, 'Paket Premium')")
        cursor.execute("INSERT INTO member_progress (member_id, weight, body_fat, stomach_circumference, recorded_date) VALUES (4, 70.5, 18.2, 82.0, '2026-10-10')")
        cursor.execute("INSERT INTO workouts (trainer_id, member_id, exercise_name, sets, reps, weight_kg, schedule_date, schedule_time, status) VALUES (3, 4, 'Bench Press', 4, 10, 60.0, '2026-10-21', '16:00', 'Belum')")
        cursor.execute("INSERT INTO equipment (equipment_name, category, status) VALUES ('Treadmill Pro X', 'Cardio', 'Tersedia'), ('Olympic Barbell', 'Beban', 'Tersedia')")
        cursor.execute("INSERT INTO payments (member_id, package_id, amount, payment_date, status) VALUES (4, 3, 600000, '2026-10-20 20:00:00', 'Lunas')")
        conn.commit()
        print("\n" + "=" * 60)
        print("AKUN AWAL DIBUAT. Catat password ini, hanya tampil sekali:")
        for code, plain in first_run_passwords.items():
            print(f"  {code:<8} {plain}")
        print("=" * 60 + "\n")

    # Migrasi: ubah password lama (teks polos) menjadi hash. Aman dijalankan berulang.
    migrated = 0
    for uid, pw in cursor.execute("SELECT id, password FROM users").fetchall():
        if not is_password_hashed(pw):
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (generate_password_hash(pw), uid))
            migrated += 1
    if migrated:
        conn.commit()
        print(f"[KEAMANAN] {migrated} password lama berhasil di-hash.")

    # Peringatan jika masih ada akun yang memakai password bawaan lama.
    weak = [r[0] for r in cursor.execute("SELECT unique_code, password FROM users").fetchall()
            if check_password_hash(r[1], 'password123')]
    if weak:
        print("[PERINGATAN] Akun ini masih memakai password lama 'password123': " + ", ".join(weak))
        print("             Ganti dengan: python app.py reset-password <KODE>")

    conn.close()


EMAIL_RE = re.compile(r"^[^\s@<>\"'&`\\]+@[^\s@<>\"'&`\\]+\.[^\s@<>\"'&`\\]+$")
PHONE_RE = re.compile(r'^\+?[0-9]{9,15}$')


def active_packages():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT id, package_name, duration_months, price FROM membership_packages WHERE status = 'Aktif' ORDER BY duration_months, price").fetchall()
    conn.close()
    per_month = [r['price'] / max(r['duration_months'], 1) for r in rows]
    best = per_month.index(min(per_month)) if len(rows) > 1 else -1
    return [{
        'id': r['id'], 'name': r['package_name'], 'months': r['duration_months'], 'price': r['price'],
        'price_fmt': f"{r['price']:,.0f}".replace(',', '.'),
        'per_month_fmt': f"{per_month[i]:,.0f}".replace(',', '.'),
        'best': i == best,
    } for i, r in enumerate(rows)]


def render_register(error=None, start_step=1, vals=None, preselect=None, status=200):
    if 'payment_csrf' not in session:
        session['payment_csrf'] = secrets.token_urlsafe(32)
    page = render_template(
        'register.html', error=error, start_step=start_step,
        vals=vals or {'name': '', 'email': '', 'phone': ''},
        packages=active_packages(), preselect=preselect,
        gopay_number=GOPAY_NUMBER, gopay_name=GOPAY_NAME, csrf_token=session['payment_csrf'])
    return page, status


@app.route('/daftar', methods=['GET', 'POST'])
def register():
    """Pendaftaran member mandiri: data akun, pilih paket, bayar, lalu langsung masuk ke area member."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'GET':
        try:
            pre = int(request.args.get('paket', ''))
        except ValueError:
            pre = None
        return render_register(preselect=pre)

    ip = request.remote_addr or '-'
    if not rate_ok('reg', ip, 10, 3600):
        return render_register(error='Terlalu banyak percobaan pendaftaran. Coba lagi sekitar satu jam lagi.', status=429)
    if not csrf_valid():
        return render_register(error='Form kedaluwarsa. Isi ulang lalu kirim lagi.', status=400)

    name = ' '.join(request.form.get('name', '').split())
    email = request.form.get('email', '').strip().lower()
    phone = re.sub(r'[\s-]', '', request.form.get('phone', ''))
    password = request.form.get('password', '').strip()
    confirm = request.form.get('confirm', '').strip()
    vals = {'name': name, 'email': email, 'phone': phone}
    try:
        pre = int(request.form.get('package_id', ''))
    except ValueError:
        pre = None

    def fail(msg, step):
        return render_register(error=msg, start_step=step, vals=vals, preselect=pre, status=400)

    if not (2 <= len(name) <= 60) or any(ch in NAME_FORBIDDEN or ord(ch) < 32 for ch in name):
        return fail('Nama harus 2-60 karakter dan tidak boleh mengandung < > " \' & ` atau garis miring terbalik.', 1)
    if len(email) > 100 or not EMAIL_RE.match(email):
        return fail('Masukkan alamat email yang valid.', 1)
    if not PHONE_RE.match(phone):
        return fail('Nomor HP harus 9-15 angka.', 1)
    if len(password) < MIN_PASSWORD_LEN or len(password) > 128:
        return fail(f'Password minimal {MIN_PASSWORD_LEN} karakter.', 1)
    if password != confirm:
        return fail('Password dan konfirmasi tidak sama.', 1)

    package = next((p for p in active_packages() if p['id'] == pre), None)
    if package is None:
        return fail('Pilih salah satu paket yang tersedia.', 2)
    method = request.form.get('payment_method', '')
    if method not in ('qris', 'gopay_direct'):
        return fail('Pilih metode pembayaran.', 3)
    proof = request.files.get('payment_proof')
    if proof is None or not proof.filename:
        return fail('Unggah bukti pembayaran dulu.', 3)
    proof_data = proof.read(5 * 1024 * 1024 + 1)
    if len(proof_data) > 5 * 1024 * 1024:
        return fail('Bukti melebihi 5 MB.', 3)
    extension = image_type(proof_data)
    if extension is None:
        return fail('Bukti harus berupa JPG, PNG, atau WebP yang valid.', 3)

    PROOF_DIR.mkdir(parents=True, exist_ok=True)
    filename = secrets.token_hex(24) + '.' + extension
    proof_path = PROOF_DIR / filename
    proof_path.write_bytes(proof_data)

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute('BEGIN IMMEDIATE')
        if conn.execute("SELECT 1 FROM users WHERE LOWER(email) = ?", (email,)).fetchone():
            conn.rollback()
            proof_path.unlink(missing_ok=True)
            return fail('Email ini sudah terdaftar. Silakan masuk, atau pakai email lain.', 1)
        last = conn.execute("SELECT MAX(CAST(SUBSTR(unique_code, 4) AS INTEGER)) FROM users WHERE unique_code LIKE 'MEM%'").fetchone()[0] or 0
        code = f'MEM{last + 1:03d}'
        now_text = _now()
        cur = conn.execute("INSERT INTO users (unique_code, name, email, password, role, phone, registered_at, signup_source) VALUES (?, ?, ?, ?, 'member', ?, ?, 'mandiri')",
                           (code, name, email, generate_password_hash(password), phone, now_text))
        user_id = cur.lastrowid
        conn.execute("INSERT INTO member_profiles (user_id, package_id, remaining_days, status_paket) VALUES (?, NULL, 0, 'Belum Aktif')", (user_id,))
        conn.execute("""INSERT INTO payments (member_id, package_id, amount, payment_date, status, payment_method, proof_filename)
                        VALUES (?, ?, ?, ?, 'Pending', ?, ?)""",
                     (user_id, package['id'], package['price'], now_text, method, filename))
        notify_role(conn, 'admin', f'Pendaftar baru: {name}',
                    f"{code} memilih {package['name']} ({rupiah(package['price'])}) dan sudah mengirim bukti bayar. Menunggu verifikasi.",
                    '/dashboard?menu=manage_payments')
        notify_user(conn, user_id, 'Selamat datang di FIT HUB GYM',
                    'Bukti pembayaranmu sudah kami terima. Membership aktif setelah admin memverifikasi.',
                    '/dashboard?menu=packages#riwayat-pembayaran')
        conn.commit()
    except Exception:
        conn.rollback()
        proof_path.unlink(missing_ok=True)
        raise
    finally:
        conn.close()

    session.clear()
    session['user_id'] = user_id
    session['name'] = name
    session['role'] = 'member'
    session['unique_code'] = code
    return redirect(url_for('dashboard'))


@app.route('/daftar/cek-email')
def register_check_email():
    if not rate_ok('mail', request.remote_addr or '-', 60, 300):
        return jsonify(ok=False, msg='Terlalu banyak pengecekan. Coba lagi sebentar.'), 429
    email = request.args.get('e', '').strip().lower()[:100]
    if not EMAIL_RE.match(email):
        return jsonify(ok=False, msg='Masukkan alamat email yang valid.')
    with sqlite3.connect(DB_PATH) as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE LOWER(email) = ?", (email,)).fetchone()
    return jsonify(ok=not exists, msg='Email ini sudah terdaftar. Coba masuk.' if exists else '')


@app.route('/notifications')
def notifications_feed():
    if 'user_id' not in session:
        return jsonify(error='login'), 401
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT id, title, message, link, created_at, is_read FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 30",
                        (session['user_id'],)).fetchall()
    unread = conn.execute("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0", (session['user_id'],)).fetchone()[0]
    conn.close()
    resp = jsonify(unread=unread, items=[dict(r) for r in rows])
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/notifications/read', methods=['POST'])
def notifications_read():
    if 'user_id' not in session:
        return jsonify(error='login'), 401
    if not csrf_header_valid():
        return jsonify(error='csrf'), 400
    with sqlite3.connect(DB_PATH) as conn:
        if request.form.get('all'):
            conn.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (session['user_id'],))
        else:
            try:
                nid = int(request.form.get('id', ''))
            except ValueError:
                return jsonify(error='id'), 400
            conn.execute("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?", (nid, session['user_id']))
    return jsonify(ok=True)


@app.route('/qris_image')
def serve_qris():
    # Gunakan QRIS asli dari foto yang diunggah pemilik gym.
    # Jangan membuat QR palsu / QR berisi teks transfer saat file hilang.
    return send_from_directory(os.path.join(app.static_folder, 'images'), 'qris_dana.png')

@app.route('/payment_proof/<int:payment_id>')
def view_payment_proof(payment_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute('SELECT member_id, proof_filename FROM payments WHERE id=?', (payment_id,)).fetchone()
    if not row or not row[1]:
        abort(404)
    if session.get('role') not in ('admin', 'owner') and session.get('user_id') != row[0]:
        abort(403)
    # Nama file hanya berasal dari server (token acak); tidak pernah dari nama upload user.
    return send_from_directory(str(PROOF_DIR), row[1], as_attachment=False)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        login_input = request.form.get('login_input', '').strip().lower()[:100]
        password = request.form.get('password', '').strip()
        ip = request.remote_addr or '-'

        wait = login_lock_seconds(ip, login_input)
        if wait:
            minutes = max(1, (wait + 59) // 60)
            return render_template('login.html', error=f'Terlalu banyak percobaan gagal. Coba lagi sekitar {minutes} menit.'), 429

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE LOWER(unique_code) = ? OR LOWER(name) = ? OR LOWER(email) = ?",
                       (login_input, login_input, login_input))
        candidates = cursor.fetchall()
        conn.close()

        user = None
        for row in candidates:
            if is_password_hashed(row['password']) and check_password_hash(row['password'], password):
                user = row
                break
        if not candidates:
            check_password_hash(_DUMMY_HASH, password)  # samakan waktu respons

        if user and user['role'] in ('owner', 'admin', 'trainer', 'member'):
            clear_login_fails(ip, login_input)
            session.clear()
            session['user_id'] = user['id']
            session['name'] = user['name']
            session['role'] = user['role']
            session['unique_code'] = user['unique_code']
            return redirect(url_for('dashboard'))

        record_login_fail(ip, login_input)
        error = 'Akun atau password salah.'
        return render_template('login.html', error=error), 401
    return render_template('login.html', error=error)

@app.route('/qr_checkin/<unique_code>')
def qr_checkin(unique_code):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE unique_code = ?", (unique_code,))
    user = cursor.fetchone()
    
    if user:
        current_wib_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO checkins (user_id, checkin_time, status) VALUES (?, ?, 'Berhasil')", 
                       (user['id'], current_wib_time))
        conn.commit()
        conn.close()
        return render_template('checkin.html', user=user, time_now=current_wib_time)
    
    conn.close()
    return fragment('components/checkin-invalid'), 400

@app.route('/')
def public_home():
    """Halaman publik tanpa akun dan tanpa akses data pribadi."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    data = {}
    # Visitor hanya menerima informasi umum gym (tanpa data pribadi member/pembayaran).
    cursor.execute("SELECT id, package_name, duration_months, price FROM membership_packages WHERE status = 'Aktif' ORDER BY duration_months, price")
    data['packages'] = cursor.fetchall()
    cursor.execute("SELECT name FROM users WHERE role = 'trainer' ORDER BY name")
    data['trainers'] = cursor.fetchall()
    cursor.execute("SELECT equipment_name, category, status FROM equipment ORDER BY category, equipment_name")
    data['equipment'] = cursor.fetchall()
    conn.close()
    # Nomor WhatsApp pendaftaran publik (081574783604 -> format internasional 6281574783604).
    # Tidak bergantung pada nomor admin yang tersimpan di database.
    phone = '6281574783604'

    def wa_link(text):
        return f'https://wa.me/{phone}?text={quote(text)}' if phone else ''

    packages = data['packages']
    per_month = [p['price'] / max(p['duration_months'], 1) for p in packages]
    best_idx = per_month.index(min(per_month)) if len(packages) > 1 else -1
    package_cards = [{
        'id': p['id'],
        'name': p['package_name'],
        'months': p['duration_months'],
        'price_fmt': f"{p['price']:,.0f}".replace(',', '.'),
        'per_month_fmt': f"{per_month[i]:,.0f}".replace(',', '.'),
        'best': i == best_idx,
        'wa': wa_link(f"Halo admin FIT HUB GYM, saya tertarik mengambil {p['package_name']}. Mohon info pendaftarannya."),
    } for i, p in enumerate(packages)]
    trainer_cards = [{'name': t['name'], 'initial': (t['name'] or '?').strip()[:1].upper()} for t in data['trainers']]
    groups = {}
    for e in data['equipment']:
        groups.setdefault(e['category'], []).append({'name': e['equipment_name'], 'status': e['status']})
    equipment_groups = [{'name': k, 'rows': v} for k, v in groups.items()]
    return render_template(
        'home.html',
        name='Pengunjung', packages=package_cards, trainers=trainer_cards,
        equipment=data['equipment'], equipment_groups=equipment_groups,
        available_count=sum(1 for e in data['equipment'] if e['status'] == 'Tersedia'),
        wa_general=wa_link(f"Halo admin FIT HUB GYM, saya tertarik menjadi member. Mohon info pendaftarannya."))



NAME_FORBIDDEN = set('<>"\'&`\\')


def account_form_html(csrf_token, current_name, msg=None):
    """Form ganti nama & password milik pengguna yang sedang login."""
    notice = ''
    if msg:
        kind, text = msg
        color, bg = ('#86efac', 'rgba(34,197,94,.15)') if kind == 'ok' else ('#fca5a5', 'rgba(239,68,68,.15)')
        notice = (fragment('components/account-notice', bg=bg, color=color, color_3=color, text=html.escape(text)))
    return fragment('components/account-form',
        notice=notice,
        csrf_token=csrf_token,
        current_name=html.escape(current_name, quote=True),
        min_password_len=MIN_PASSWORD_LEN,
        min_password_len_5=MIN_PASSWORD_LEN,
    )


# ---------------------------------------------------------------------------
# Background per role & menu (semua role mengikuti pola dashboard member)
# ---------------------------------------------------------------------------
_U = 'https://images.unsplash.com/photo-{}?auto=format&fit=crop&w=1920&q=80'
_BG_GYM = _U.format('1534438327276-14e5300c3a48')
_BG_FLOOR = _U.format('1540497077202-7c8a3999166f')
_BG_CARDIO = _U.format('1517838277536-f5f99be501cd')
_BG_WEIGHTS = _U.format('1517963879433-6ad2b056d712')
_BG_TRAIN = _U.format('1517836357463-d25dfeac3438')
_BG_CALM = _U.format('1499750310107-5fef28a66643')

DASHBOARD_BACKGROUNDS = {
    'member': {
        'dashboard': _BG_GYM, 'packages': _BG_FLOOR, 'checkin': _BG_CARDIO,
        'workouts': _BG_WEIGHTS, 'progress': _BG_TRAIN, 'profile': _BG_CALM,
        'account': _BG_CALM,
    },
    'trainer': {
        'dashboard': _BG_WEIGHTS, 'assign_workout': _BG_TRAIN, 'set_target': _BG_CARDIO,
        'monitor_progress': _BG_GYM, 'account': _BG_CALM,
    },
    'admin': {
        'dashboard': _BG_GYM, 'manage_members': _BG_TRAIN, 'manage_packages': _BG_FLOOR,
        'manage_equipment': _BG_WEIGHTS, 'manage_payments': _BG_CALM,
        'manage_trainers': _BG_CARDIO, 'account': _BG_CALM,
    },
    'owner': {
        'dashboard': _BG_GYM, 'account': _BG_CALM,
    },
}


def dashboard_bg(role, menu):
    """Foto latar untuk role+menu. Foto sendiri di static/images dipakai lebih dulu:
    bg-<role>-<menu>.jpg  ->  bg-<role>.jpg  (juga .png / .webp)."""
    safe_menu = re.sub(r'[^a-z_]', '', str(menu))
    names = []
    for stem in (f'bg-{role}-{safe_menu}', f'bg-{role}'):
        names += [f'{stem}.jpg', f'{stem}.png', f'{stem}.webp']
    for name in names:
        if (Path(app.static_folder) / 'images' / name).is_file():
            return url_for('static', filename=f'images/{name}')
    per_role = DASHBOARD_BACKGROUNDS.get(role, DASHBOARD_BACKGROUNDS['member'])
    return per_role.get(menu, per_role['dashboard'])


# ---------------------------------------------------------------------------
# Grafik dashboard member (SVG murni, tanpa library/CDN)
# ---------------------------------------------------------------------------
_BULAN = ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Agu', 'Sep', 'Okt', 'Nov', 'Des']


def _donut_svg(remaining, total):
    import math
    r = 70
    circ = 2 * math.pi * r
    frac = 0 if total <= 0 else max(0.0, min(1.0, remaining / total))
    return (
        fragment('components/donut-chart',
            remaining=remaining,
            total=total,
            r=r,
            r_4=r,
            value=format(circ * frac, '.2f'),
            circ=format(circ, '.2f'),
            remaining_7=remaining,
        )
    )


def _bars_svg(labels, values, aria='Grafik jumlah check-in'):
    w, h = 460, 230
    left, right, top, bottom = 34, 10, 22, 36
    plot_w, plot_h = w - left - right, h - top - bottom
    peak = max(values + [4])
    step = max(1, -(-peak // 4))          # pembulatan ke atas
    top_val = step * 4
    out = [fragment('components/bar-chart-open', w=w, h=h, aria=html.escape(aria))]
    for i in range(5):
        y = top + plot_h - plot_h * i / 4
        out.append(fragment('components/bar-chart-gridline',
            left=left,
            y=format(y, '.1f'),
            value=w - right,
            y_4=format(y, '.1f'),
        ))
        out.append(fragment('components/bar-chart-tick',
            value=left - 6,
            value_2=format(y + 4, '.1f'),
            value_3=step * i,
        ))
    slot = plot_w / max(1, len(values))
    bar_w = min(46, slot * 0.55)
    for i, (lab, val) in enumerate(zip(labels, values)):
        x = left + slot * i + (slot - bar_w) / 2
        bh = plot_h * val / top_val
        y = top + plot_h - bh
        out.append(fragment('components/bar-chart-column',
            x=format(x, '.1f'),
            y=format(y, '.1f'),
            bar_w=format(bar_w, '.1f'),
            bh=format(max(bh, 0), '.1f'),
        ))
        out.append(fragment('components/bar-chart-value',
            value=format(x + bar_w / 2, '.1f'),
            value_2=format(y - 6, '.1f'),
            val=val,
        ))
        out.append(fragment('components/bar-chart-label',
            value=format(x + bar_w / 2, '.1f'),
            value_2=h - 14,
            lab=html.escape(lab),
        ))
    out.append(fragment('components/bar-chart-close'))
    return ''.join(out)


def _donut_multi_svg(parts, center_value, center_label, aria='Grafik donat'):
    """Donat beberapa segmen. parts = [(label, nilai, warna), ...]."""
    import math
    r = 70
    circ = 2 * math.pi * r
    total = sum(v for _, v, _ in parts)
    out = [fragment('components/donut-multi-open', aria=html.escape(aria)),
           fragment('components/donut-multi-track', r=r)]
    cum = 0.0
    if total > 0:
        for _, v, color in parts:
            if v <= 0:
                continue
            seg = circ * v / total
            out.append(fragment('components/donut-multi-segment',
                r=r,
                color=color,
                seg=format(seg, '.2f'),
                value=format(circ - seg, '.2f'),
                value_5=format(-cum, '.2f'),
            ))
            cum += seg
    out.append(fragment('components/donut-multi-value', center_value=html.escape(str(center_value))))
    out.append(fragment('components/donut-multi-label', center_label=html.escape(center_label)))
    out.append(fragment('components/donut-multi-close'))
    return ''.join(out)


def _legend_html(parts):
    return ''.join(
        fragment('components/chart-legend-item', color=color, label=html.escape(label), value=value) for label, value, color in parts)


def _donut_panel(title, subtitle, parts, center_value, center_label, empty_text):
    if sum(v for _, v, _ in parts) <= 0:
        body = fragment('components/donut-panel-empty', empty_text=html.escape(empty_text))
    else:
        body = (fragment('components/donut-panel-content',
            parts=_donut_multi_svg(parts, center_value, center_label, title),
            parts_2=_legend_html(parts),
        ))
    return (fragment('components/donut-panel', title=title, subtitle=subtitle, body=body))


def _bars_panel(title, subtitle, labels, values, empty_text):
    if sum(values) <= 0:
        body = fragment('components/bar-panel-empty', empty_text=html.escape(empty_text))
    else:
        body = _bars_svg(labels, values, title)
    return (fragment('components/bar-panel', title=title, subtitle=subtitle, body=body))


def _chart_grid(*panels):
    return (fragment('components/chart-grid-open')
            + ''.join(panels) + fragment('components/chart-grid-close'))


def trainer_charts(workouts, members):
    """Grafik dashboard trainer: penyelesaian program & beban program per member."""
    done = sum(1 for w in workouts if w['status'] == 'Selesai')
    todo = len(workouts) - done
    pct = round(done * 100 / len(workouts)) if workouts else 0
    per_member = {}
    for w in workouts:
        per_member[w['member_name']] = per_member.get(w['member_name'], 0) + 1
    top = sorted(per_member.items(), key=lambda kv: (-kv[1], kv[0]))[:6]
    labels = [(n if len(n) <= 9 else n[:8] + '…') for n, _ in top]
    return _chart_grid(
        _donut_panel('✅ Status Program Latihan', f'{len(workouts)} program dikirim ke {len(members)} member.',
                     [('Selesai', done, '#10b981'), ('Belum selesai', todo, '#f5b000')],
                     f'{pct}%', 'selesai', 'Belum ada program latihan yang dikirim.'),
        _bars_panel('🏋️ Program per Member', 'Jumlah program latihan per member (maks. 6 teratas).',
                    labels, [v for _, v in top], 'Belum ada program latihan yang dikirim.'))


def admin_charts(payments, equipment, checkin_by_day):
    """Grafik dashboard admin: check-in 7 hari, status pembayaran, kondisi alat."""
    today = datetime.now().date()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    labels = [f'{d:%d/%m}' for d in days]
    values = [int(checkin_by_day.get(d.isoformat(), 0)) for d in days]

    cnt = {'Lunas': 0, 'Pending': 0, 'Ditolak': 0}
    for p in payments:
        if p['status'] in cnt:
            cnt[p['status']] += 1
    pay_parts = [('Lunas', cnt['Lunas'], '#10b981'), ('Pending', cnt['Pending'], '#f59e0b'), ('Ditolak', cnt['Ditolak'], '#ef4444')]

    ok = sum(1 for e in equipment if e['status'] == 'Tersedia')
    fix = sum(1 for e in equipment if e['status'] == 'Perbaikan')
    other = len(equipment) - ok - fix
    eq_parts = [('Tersedia', ok, '#10b981'), ('Perbaikan', fix, '#f59e0b'), ('Lainnya', other, '#ef4444')]
    pct = round(ok * 100 / len(equipment)) if equipment else 0

    return _chart_grid(
        _bars_panel('🏃 Check-in 7 Hari Terakhir', f'Total {sum(values)} check-in berhasil dalam seminggu.',
                    labels, values, 'Belum ada check-in dalam 7 hari terakhir.'),
        _donut_panel('💰 Status Pembayaran', 'Perbandingan seluruh transaksi member.',
                     pay_parts, len(payments), 'transaksi', 'Belum ada transaksi pembayaran.'),
        _donut_panel('⚙️ Kondisi Alat Gym', f'{len(equipment)} alat terdata di inventaris.',
                     eq_parts, f'{pct}%', 'layak pakai', 'Belum ada data alat gym.'))


def member_package_charts(profile, package, checkins):
    """Grafik di dashboard member, mengikuti paket yang sedang aktif."""
    remaining = int(profile['remaining_days'] or 0) if profile else 0
    if not package or remaining <= 0:
        return (fragment('components/member-charts-empty'))

    months = int(package['duration_months'] or 1)
    total = max(months * 30, remaining)      # perpanjangan menumpuk, jadi total tidak boleh < sisa
    used = total - remaining
    pkg_name = html.escape(str(package['package_name']))

    today = datetime.now().date()
    days = []
    for c in checkins:
        if c['status'] != 'Berhasil':
            continue
        try:
            days.append(datetime.strptime(str(c['checkin_time'])[:10], '%Y-%m-%d').date())
        except ValueError:
            continue

    if months <= 1:                          # paket 1 bulan: 4 minggu terakhir
        labels, values = [], []
        for i in range(3, -1, -1):
            end = today - timedelta(days=7 * i)
            start = end - timedelta(days=6)
            labels.append(f'{start:%d/%m}-{end:%d/%m}')
            values.append(sum(1 for d in days if start <= d <= end))
        scope = '4 minggu terakhir'
    else:                                    # paket 3/6 bulan: per bulan sesuai durasi paket (maks. 6)
        n = min(months, 6)
        keys = []
        y, m = today.year, today.month
        for _ in range(n):
            keys.append((y, m))
            m -= 1
            if m == 0:
                y, m = y - 1, 12
        keys.reverse()
        labels = [_BULAN[k[1] - 1] + (f" {str(k[0])[2:]}" if k[0] != today.year else '') for k in keys]
        values = [sum(1 for d in days if (d.year, d.month) == k) for k in keys]
        scope = f'{n} bulan terakhir'

    total_ci = sum(values)
    return fragment('components/member-charts',
        pkg_name=pkg_name,
        months=months,
        value=months * 30,
        remaining=_donut_svg(remaining, total),
        remaining_5=remaining,
        used=used,
        scope=scope,
        total_ci=total_ci,
        labels=_bars_svg(labels, values),
    )

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or session.get('role') not in ('owner', 'admin', 'trainer', 'member'):
        return redirect(url_for('login'))
    
    menu = request.args.get('menu', 'dashboard')
    if menu == 'profile' and session.get('role') == 'member':   # menu Pembayaran sudah digabung ke Paket Membership
        return redirect(url_for('dashboard', menu='packages') + '#riwayat-pembayaran')
    search_query = request.args.get('q', '').strip().lower()
    role = session['role']
    user_id = session['user_id']
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    data = {}
    bg_url = None
    csrf_token = session.setdefault('payment_csrf', secrets.token_urlsafe(32))

    bg_url = dashboard_bg(role, menu)

    if role == 'member':
        cursor.execute("SELECT * FROM member_profiles WHERE user_id = ?", (user_id,))
        data['profile'] = cursor.fetchone()
        cursor.execute("SELECT unique_code, name, email, phone FROM users WHERE id = ?", (user_id,))
        data['user'] = cursor.fetchone()
        data['active_package'] = None
        if data['profile'] and data['profile']['package_id']:
            cursor.execute("SELECT * FROM membership_packages WHERE id = ?", (data['profile']['package_id'],))
            data['active_package'] = cursor.fetchone()
        cursor.execute("SELECT * FROM checkins WHERE user_id = ? ORDER BY id DESC", (user_id,))
        data['checkins'] = cursor.fetchall()
        cursor.execute("SELECT * FROM workouts WHERE member_id = ?", (user_id,))
        data['workouts'] = cursor.fetchall()
        cursor.execute("SELECT * FROM member_progress WHERE member_id = ? ORDER BY recorded_date DESC", (user_id,))
        data['progress'] = cursor.fetchall()
        cursor.execute("SELECT * FROM member_targets WHERE member_id = ? ORDER BY id DESC LIMIT 1", (user_id,))
        data['target'] = cursor.fetchone()
        cursor.execute("SELECT payments.*, membership_packages.package_name FROM payments JOIN membership_packages ON payments.package_id = membership_packages.id WHERE member_id = ? ORDER BY payments.id DESC", (user_id,))
        data['payments'] = cursor.fetchall()
        cursor.execute("SELECT * FROM membership_packages")
        data['packages'] = cursor.fetchall()

    elif role == 'trainer':
        cursor.execute("""SELECT u.*,
                                 (SELECT weight FROM member_progress p WHERE p.member_id = u.id
                                  ORDER BY recorded_date DESC, id DESC LIMIT 1) AS last_weight,
                                 (SELECT body_fat FROM member_progress p WHERE p.member_id = u.id
                                  ORDER BY recorded_date DESC, id DESC LIMIT 1) AS last_body_fat
                          FROM users u WHERE u.role = 'member'""")
        data['members'] = cursor.fetchall()
        cursor.execute("""SELECT t.*, u.name AS member_name, u.unique_code
                          FROM member_targets t JOIN users u ON t.member_id = u.id
                          ORDER BY t.id DESC""")
        data['targets'] = cursor.fetchall()
        cursor.execute("SELECT workouts.*, users.name as member_name FROM workouts JOIN users ON workouts.member_id = users.id ORDER BY schedule_date DESC")
        data['workouts'] = cursor.fetchall()

    elif role == 'admin':
        if search_query:
            cursor.execute("SELECT * FROM users WHERE role = 'member' AND (name LIKE ? OR unique_code LIKE ? OR email LIKE ?)", 
                           (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'))
        else:
            cursor.execute("SELECT * FROM users WHERE role = 'member'")
        data['members'] = cursor.fetchall()
        cursor.execute("SELECT * FROM users WHERE role = 'trainer'")
        data['trainers'] = cursor.fetchall()
        cursor.execute("SELECT * FROM membership_packages")
        data['packages'] = cursor.fetchall()
        cursor.execute("SELECT * FROM equipment")
        data['equipment'] = cursor.fetchall()
        cursor.execute("""SELECT payments.*, users.name,
                                  membership_packages.package_name
                           FROM payments JOIN users ON payments.member_id = users.id
                           LEFT JOIN membership_packages ON payments.package_id = membership_packages.id
                           ORDER BY CASE WHEN payments.status='Pending' THEN 0 ELSE 1 END,
                                    payments.id DESC""")
        data['payments'] = cursor.fetchall()
        cursor.execute("SELECT COUNT(*) FROM users WHERE role='member'")
        data['total_members'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM checkins")
        data['total_checkins'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM payments WHERE status = 'Pending'")
        data['pending_payments'] = cursor.fetchone()[0]
        since = (datetime.now().date() - timedelta(days=6)).isoformat()
        cursor.execute("SELECT substr(checkin_time, 1, 10) AS d, COUNT(*) AS n FROM checkins "
                       "WHERE status = 'Berhasil' AND substr(checkin_time, 1, 10) >= ? GROUP BY d", (since,))
        data['checkin_by_day'] = {r['d']: r['n'] for r in cursor.fetchall()}
        cursor.execute("SELECT COUNT(*) FROM checkins WHERE checkin_time LIKE ?", (datetime.now().strftime('%Y-%m-%d') + '%',))
        data['checkins_today'] = cursor.fetchone()[0]
        cursor.execute('''SELECT u.unique_code, u.name, u.phone, u.registered_at,
                                 (SELECT mp.package_name FROM payments p JOIN membership_packages mp ON p.package_id = mp.id
                                  WHERE p.member_id = u.id ORDER BY p.id DESC LIMIT 1) AS package_name,
                                 (SELECT p.status FROM payments p WHERE p.member_id = u.id ORDER BY p.id DESC LIMIT 1) AS pay_status
                          FROM users u WHERE u.signup_source = 'mandiri' ORDER BY u.id DESC LIMIT 8''')
        data['new_signups'] = cursor.fetchall()

    elif role == 'owner':
        # 1. Total Revenue
        cursor.execute("SELECT SUM(amount) FROM payments WHERE status='Lunas'")
        total_rev = cursor.fetchone()[0]
        data['total_revenue'] = total_rev if total_rev is not None else 0

        # 2. Total Active Members (remaining_days > 0)
        cursor.execute("SELECT COUNT(*) FROM member_profiles WHERE remaining_days > 0")
        data['total_active_members'] = cursor.fetchone()[0]

        # 3. Check-ins Today
        today_str = datetime.now().strftime('%Y-%m-%d')
        cursor.execute("SELECT COUNT(*) FROM checkins WHERE checkin_time LIKE ?", (f"{today_str}%",))
        data['checkins_today'] = cursor.fetchone()[0]

        # 4. Total Members registered
        cursor.execute("SELECT COUNT(*) FROM users WHERE role='member'")
        data['total_members'] = cursor.fetchone()[0]

        # 5. Memberships Expiring Soon (remaining_days <= 7 and > 0)
        cursor.execute("SELECT COUNT(*) FROM member_profiles WHERE remaining_days <= 7 AND remaining_days > 0")
        data['expiring_soon'] = cursor.fetchone()[0]

        # 6. Total Successful Transactions
        cursor.execute("SELECT COUNT(*) FROM payments WHERE status='Lunas'")
        data['successful_transactions'] = cursor.fetchone()[0]

        # 7. Total Checkins
        cursor.execute("SELECT COUNT(*) FROM checkins")
        data['total_checkins'] = cursor.fetchone()[0]

        # 8. Recent Transactions (Limit 5)
        cursor.execute('''
            SELECT payments.*, users.name as member_name, membership_packages.package_name 
            FROM payments 
            JOIN users ON payments.member_id = users.id 
            LEFT JOIN membership_packages ON payments.package_id = membership_packages.id 
            WHERE payments.status='Lunas' 
            ORDER BY payments.id DESC LIMIT 5
        ''')
        data['recent_payments'] = cursor.fetchall()

        # 9. Recent Check-ins (Limit 5)
        cursor.execute('''
            SELECT checkins.*, users.name as member_name, users.unique_code 
            FROM checkins 
            JOIN users ON checkins.user_id = users.id 
            ORDER BY checkins.id DESC LIMIT 5
        ''')
        data['recent_checkins'] = cursor.fetchall()

        # 10. Monthly revenue aggregation for chart
        cursor.execute("SELECT payment_date, amount FROM payments WHERE status='Lunas'")
        all_payments = cursor.fetchall()
        monthly_rev = {}
        for p in all_payments:
            p_date = p['payment_date']
            if p_date and len(p_date) >= 7:
                month_key = p_date[:7]
                monthly_rev[month_key] = monthly_rev.get(month_key, 0) + p['amount']
        data['monthly_revenue'] = monthly_rev

    conn.close()

    body_content = ""
    
    if menu == 'account':
        profile_box = ''
        if role == 'member' and data.get('user'):
            u, pf, pk = data['user'], data['profile'], data['active_package']
            pf_days = int(pf['remaining_days'] or 0) if pf else 0
            pf_status = html.escape(str(pf['status_paket'])) if pf else 'Belum Aktif'
            pk_name = html.escape(str(pk['package_name'])) if pk else '-'
            profile_box = fragment('dashboard/profile-box',
                u_unique_code=html.escape(str(u['unique_code'])),
                u_name=html.escape(str(u['name'])),
                value=html.escape(str(u['email'] or '-')),
                value_4=html.escape(str(u['phone'] or '-')),
                pk_name=pk_name,
                pf_status=pf_status,
                pf_days=pf_days,
            )
        body_content = fragment('dashboard/account',
            value=html.escape(session.get('unique_code', '')),
            profile_box=profile_box,
            csrf_token=account_form_html(csrf_token, session.get('name', ''), session.pop('account_msg', None)),
        )
    elif role == 'member':
        if menu == 'dashboard':
            p = data['profile'] or {'remaining_days': 0, 'status_paket': 'Belum Aktif'}
            pend = [x for x in data['payments'] if x['status'] == 'Pending']
            pending_banner = ''
            if pend:
                pending_banner = (fragment('dashboard/pending-banner', package_name=safe(pend[0]['package_name'])))
            body_content = fragment('dashboard/member-overview',
                session_name=session['name'],
                pending_banner=pending_banner,
                p_remaining_days=p['remaining_days'],
                p_status_paket=p['status_paket'],
                data_profile=member_package_charts(data['profile'], data['active_package'], data['checkins']),
            )
        elif menu == 'packages':
            pay_rows = "".join([fragment('dashboard/member-payment-row',
                p_id=p['id'],
                p_package_name=safe(p['package_name']),
                p_amount=format(p['amount'], ',.0f'),
                p_payment_date=safe(p['payment_date']),
                value='badge-success' if p['status'] == 'Lunas' else 'badge-danger' if p['status'] == 'Ditolak' else 'badge-warning',
                p_status=safe(p['status']),
            ) for p in data['payments']])
            if not pay_rows:
                pay_rows = fragment('dashboard/member-payments-empty')
            rows = "".join([fragment('dashboard/member-package-row',
                pkg_package_name=pkg['package_name'],
                pkg_duration_months=pkg['duration_months'],
                value=pkg['duration_months'] * 30,
                pkg_price=format(pkg['price'], ',.0f'),
                pkg_id=pkg['id'],
                pkg_package_name_6=html.escape(str(pkg['package_name']), quote=True),
                pkg_price_7=pkg['price'],
                pkg_duration_months_8=pkg['duration_months'],
            ) for pkg in data['packages']])
            body_content = fragment('dashboard/member-packages',
                rows=rows,
                pay_rows=pay_rows,
                csrf_token=csrf_token,
                gopay_number=GOPAY_NUMBER,
                gopay_name=GOPAY_NAME,
            )
        elif menu == 'checkin':
            rows = "".join([fragment('dashboard/member-checkin-row', c_checkin_time=c['checkin_time'], c_status=c['status']) for c in data['checkins']])
            qr_valid_url = f"{request.host_url}qr_checkin/{session['unique_code']}"
            
            body_content = fragment('dashboard/member-checkin',
                qr_valid_url=qr_valid_url,
                session_unique_code=session['unique_code'],
                rows=rows,
            )
        elif menu == 'workouts':
            rows = "".join([fragment('dashboard/member-workout-row',
                w_exercise_name=safe(w['exercise_name']),
                w_sets=w['sets'],
                w_reps=w['reps'],
                w_weight_kg=w['weight_kg'],
                w_schedule_date=safe(w['schedule_date']),
                w_schedule_time=safe(w['schedule_time']),
                w_video_url=video_html(w['video_url']),
                value='badge-success' if w['status'] == 'Selesai' else 'badge-warning',
                w_status=safe(w['status']),
            ) for w in data['workouts']])
            if not rows:
                rows = fragment('dashboard/member-workouts-empty')
            body_content = fragment('dashboard/member-workouts', rows=rows)
        elif menu == 'progress':
            rows = "".join([fragment('dashboard/member-progress-row',
                pr_recorded_date=pr['recorded_date'],
                pr_weight=pr['weight'],
                pr_body_fat=pr['body_fat'],
                pr_stomach_circumference=pr['stomach_circumference'],
            ) for pr in data['progress']])
            t = data['target']
            last = data['progress'][0] if data['progress'] else None
            if t:
                target_section = fragment('dashboard/member-target-heading') \
                    + target_card('Berat Badan', 'kg', t['start_weight'], last['weight'] if last else None, t['target_weight']) \
                    + target_card('Body Fat', '%', t['start_body_fat'], last['body_fat'] if last else None, t['target_body_fat']) \
                    + fragment('dashboard/member-target-end')
                if t['notes']:
                    target_section += fragment('dashboard/member-target-note', t_notes=safe(t['notes']))
            else:
                target_section = fragment('dashboard/member-target-empty')
            body_content = fragment('dashboard/member-progress', target_section=target_section, rows=rows)

    elif role == 'trainer':
        if menu == 'dashboard':
            body_content = fragment('dashboard/trainer-overview',
                session_name=session['name'],
                data_members=len(data['members']),
                data_workouts=len(data['workouts']),
                value=data['members'][0]['name'] if data['members'] else '-',
                data_workouts_5=trainer_charts(data['workouts'], data['members']),
            )
        elif menu == 'assign_workout':
            options = "".join([fragment('dashboard/trainer-workout-member-option',
                m_id=m['id'],
                m_name=safe(m['name']),
                m_unique_code=safe(m['unique_code']),
            ) for m in data['members']])
            sent_rows = "".join([fragment('dashboard/trainer-assigned-workout-row',
                w_member_name=safe(w['member_name']),
                w_exercise_name=safe(w['exercise_name']),
                w_sets=w['sets'],
                w_reps=w['reps'],
                w_schedule_date=safe(w['schedule_date']),
                w_schedule_time=safe(w['schedule_time']),
                value='🎬 Ada video' if w['video_url'] else '—',
            ) for w in data['workouts']])
            if not sent_rows:
                sent_rows = fragment('dashboard/trainer-assigned-workouts-empty')
            body_content = fragment('dashboard/trainer-assign-workout',
                csrf_token=csrf_token,
                options=options,
                sent_rows=sent_rows,
            )
        elif menu == 'set_target':
            tmap = {t['member_id']: t for t in data['targets']}
            mmap = {m['id']: m for m in data['members']}
            opt_list = []
            for m in data['members']:
                tg = tmap.get(m['id'])
                opt_list.append(
                    fragment('dashboard/trainer-target-member-option',
                        m_id=m['id'],
                        m_last_weight=attr_num(m['last_weight']),
                        m_last_body_fat=attr_num(m['last_body_fat']),
                        value=attr_num(tg['start_weight']) if tg else '',
                        value_5=attr_num(tg['target_weight']) if tg else '',
                        value_6=attr_num(tg['start_body_fat']) if tg else '',
                        value_7=attr_num(tg['target_body_fat']) if tg else '',
                        value_8=safe(tg['notes']) if tg else '',
                        m_name=safe(m['name']),
                        m_unique_code=safe(m['unique_code']),
                    ))
            options = "".join(opt_list)
            trows = ""
            for t in data['targets']:
                m = mmap.get(t['member_id'])
                cur_w = m['last_weight'] if m else None
                cur_bf = m['last_body_fat'] if m else None
                pw = progress_pct(t['start_weight'], cur_w, t['target_weight'])
                pbf = progress_pct(t['start_body_fat'], cur_bf, t['target_body_fat'])
                trows += (fragment('dashboard/trainer-target-row',
                    t_member_name=safe(t['member_name']),
                    t_unique_code=safe(t['unique_code']),
                    t_start_weight=fmt_num(t['start_weight']),
                    t_target_weight=fmt_num(t['target_weight']),
                    cur_w=fmt_num(cur_w),
                    value=' · ' + str(pw) + '%' if pw is not None else '',
                    t_start_body_fat=fmt_num(t['start_body_fat']),
                    t_target_body_fat=fmt_num(t['target_body_fat']),
                    cur_bf=fmt_num(cur_bf),
                    value_10=' · ' + str(pbf) + '%' if pbf is not None else '',
                    value_11=safe(t['notes'] or '-'),
                ))
            if not trows:
                trows = fragment('dashboard/trainer-targets-empty')
            body_content = fragment('dashboard/trainer-set-target',
                csrf_token=csrf_token,
                options=options,
                trows=trows,
            )
        elif menu == 'monitor_progress':
            rows = ""
            for w in data['workouts']:
                dt_obj = datetime.strptime(w['schedule_date'], '%Y-%m-%d') if w['schedule_date'] else datetime.now()
                day_name = ['Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu', 'Minggu'][dt_obj.weekday()]
                month_name = ['Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember'][dt_obj.month - 1]
                rows += fragment('dashboard/trainer-progress-row',
                    w_member_name=w['member_name'],
                    w_exercise_name=w['exercise_name'],
                    w_sets=w['sets'],
                    w_reps=w['reps'],
                    value=dt_obj.day,
                    month_name=month_name,
                    value_7=dt_obj.year,
                    day_name=day_name,
                    w_schedule_time=w['schedule_time'],
                    value_10='badge-success' if w['status'] == 'Selesai' else 'badge-warning',
                    w_status=w['status'],
                )
            body_content = fragment('dashboard/trainer-progress', rows=rows)

    elif role == 'admin':
        if menu == 'dashboard':
            signup_rows = "".join([
                fragment('dashboard/admin-signup-row',
                    s_unique_code=safe(s['unique_code']),
                    s_name=safe(s['name']),
                    value=safe(s['phone'] or '-'),
                    value_4=safe(s['package_name'] or '-'),
                    value_5=safe((s['registered_at'] or '-')[:16]),
                    value_6='badge-success' if s['pay_status'] == 'Lunas' else 'badge-danger' if s['pay_status'] == 'Ditolak' else 'badge-warning',
                    value_7=safe(s['pay_status'] or '-'),
                )
                for s in data['new_signups']]) or fragment('dashboard/admin-signups-empty')
            body_content = fragment('dashboard/admin-overview',
                data_total_members=data['total_members'],
                data_checkins_today=data['checkins_today'],
                value=round(sum((1 for e in data['equipment'] if e['status'] == 'Tersedia')) * 100 / len(data['equipment'])) if data['equipment'] else 0,
                data_pending_payments=data['pending_payments'],
                data_payments=admin_charts(data['payments'], data['equipment'], data['checkin_by_day']),
                signup_rows=signup_rows,
            )
        elif menu == 'manage_members':
            rows = "".join([fragment('dashboard/admin-member-row',
                m_unique_code=m['unique_code'],
                m_name=m['name'],
                m_email=m['email'],
                value=m['phone'] or '-',
                m_id=m['id'],
            ) for m in data['members']])
            body_content = fragment('dashboard/admin-members', search_query=search_query, rows=rows)
        elif menu == 'manage_trainers':
            rows = "".join([fragment('dashboard/admin-trainer-row',
                t_unique_code=t['unique_code'],
                t_name=t['name'],
                t_email=t['email'],
                value=t['phone'] or '-',
                t_id=t['id'],
            ) for t in data['trainers']])
            body_content = fragment('dashboard/admin-trainers', rows=rows)
        elif menu == 'manage_packages':
            rows = "".join([fragment('dashboard/admin-package-row',
                p_package_name=p['package_name'],
                p_duration_months=p['duration_months'],
                p_price=format(p['price'], ',.0f'),
                p_status=p['status'],
            ) for p in data['packages']])
            body_content = fragment('dashboard/admin-packages', rows=rows)
        elif menu == 'manage_equipment':
            rows = "".join([fragment('dashboard/admin-equipment-row',
                eq_equipment_name=eq['equipment_name'],
                eq_category=eq['category'],
                value='badge-success' if eq['status'] == 'Tersedia' else 'badge-warning' if eq['status'] == 'Perbaikan' else 'badge-danger',
                eq_status=eq['status'],
            ) for eq in data['equipment']])
            body_content = fragment('dashboard/admin-equipment', rows=rows)
        elif menu == 'manage_payments':
            rows = ""
            for p in data['payments']:
                status = p['status']
                badge_class = 'badge-success' if status == 'Lunas' else ('badge-danger' if status == 'Ditolak' else 'badge-warning')
                method = {'qris': 'QRIS', 'gopay_direct': 'Transfer'}.get(p['payment_method'], '—')
                proof = (fragment('dashboard/admin-payment-proof-link', p_id=p['id'])
                         if p['proof_filename'] else '—')
                if status == 'Pending':
                    action_buttons = fragment('dashboard/admin-payment-actions',
                        csrf_token=csrf_token,
                        p_id=p['id'],
                        csrf_token_3=csrf_token,
                        p_id_4=p['id'],
                    )
                else:
                    action_buttons = 'Sudah diproses'
                rows += fragment('dashboard/admin-payment-row',
                    p_id=p['id'],
                    p_name=p['name'],
                    value=p['package_name'] or '-',
                    p_amount=format(p['amount'], ',.0f'),
                    method=method,
                    p_payment_date=p['payment_date'],
                    proof=proof,
                    badge_class=badge_class,
                    status=status,
                    action_buttons=action_buttons,
                )
            if not rows:
                rows = fragment('dashboard/admin-payments-empty')
            body_content = fragment('dashboard/admin-payments', rows=rows)

    elif role == 'owner':
        formatted_revenue = f"Rp {data['total_revenue']:,.0f}"
        
        # Render SVG chart dynamically
        months_data = data['monthly_revenue']
        sorted_months = sorted(months_data.keys())[-6:]
        chart_height = 200
        bar_width = 45
        gap = 35
        start_x = 45
        
        if not sorted_months:
            chart_content = fragment('dashboard/owner-revenue-empty')
        else:
            max_val = max(months_data.values()) if months_data and max(months_data.values()) > 0 else 1000000
            svg_items = []
            for i, m in enumerate(sorted_months):
                val = months_data[m]
                bar_h = int((val / max_val) * 120) if max_val > 0 else 10
                x = start_x + (i * (bar_width + gap))
                y = chart_height - bar_h - 35
                try:
                    dt_parsed = datetime.strptime(m, '%Y-%m')
                    m_label = dt_parsed.strftime('%b %Y')
                except:
                    m_label = m
                
                svg_items.append(fragment('dashboard/owner-revenue-bar',
                    x=x,
                    y=y,
                    bar_width=bar_width,
                    bar_h=bar_h,
                    m_label=m_label,
                    val=format(val, ',.0f'),
                    value=x + bar_width / 2,
                    value_8=chart_height - 12,
                    m_label_9=m_label,
                    value_10=x + bar_width / 2,
                    value_11=y - 8,
                    value_12=format(val / 1000, ',.0f'),
                ))
            chart_content = fragment('dashboard/owner-revenue-chart',
                chart_height=chart_height,
                value=chart_height - 30,
                value_3=chart_height - 30,
                svg_items=''.join(svg_items),
            )

        pay_rows = ""
        if data['recent_payments']:
            for p in data['recent_payments']:
                pay_rows += fragment('dashboard/owner-payment-row',
                    p_member_name=p['member_name'],
                    value=p['package_name'] or 'Membership',
                    p_payment_date=p['payment_date'],
                    p_amount=format(p['amount'], ',.0f'),
                    p_status=p['status'],
                )
        else:
            pay_rows = fragment('dashboard/owner-payments-empty')

        checkin_rows = ""
        if data['recent_checkins']:
            for c in data['recent_checkins']:
                checkin_rows += fragment('dashboard/owner-checkin-row',
                    c_member_name=c['member_name'],
                    c_unique_code=c['unique_code'],
                    c_checkin_time=c['checkin_time'],
                    c_status=c['status'],
                )
        else:
            checkin_rows = fragment('dashboard/owner-checkins-empty')

        alert_box = ""
        if data['expiring_soon'] > 0:
            alert_box += fragment('dashboard/alert-box', data_expiring_soon=data['expiring_soon'])

        body_content = fragment('dashboard/owner-overview',
            session_name=session['name'],
            alert_box=alert_box,
            formatted_revenue=formatted_revenue,
            data_total_active_members=data['total_active_members'],
            data_checkins_today=data['checkins_today'],
            data_total_members=data['total_members'],
            data_expiring_soon=data['expiring_soon'],
            data_successful_transactions=data['successful_transactions'],
            chart_content=chart_content,
            value=format(int(data['total_revenue'] / data['successful_transactions']) if data['successful_transactions'] > 0 else 0, ',.0f'),
            data_total_checkins=data['total_checkins'],
            pay_rows=pay_rows,
            checkin_rows=checkin_rows,
            value_14=datetime.now().strftime('%B %Y'),
            data_total_members_15=data['total_members'],
            formatted_revenue_16=formatted_revenue,
            data_total_checkins_17=data['total_checkins'],
        )

    return render_template('dashboard.html', body_content=body_content, role=role, menu=menu, bg_url=bg_url, csrf_token=csrf_token)

@app.route('/action', methods=['POST'])
def action():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') == 'visitor':
        abort(403, description='Akun visitor hanya dapat melihat data.')

    action_type = request.form.get('action_type')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if action_type == 'update_account':
        def back(kind, text):
            conn.close()
            session['account_msg'] = (kind, text)
            return redirect(url_for('dashboard', menu='account'))

        if not csrf_valid():
            conn.close()
            abort(400, description='Form kedaluwarsa. Muat ulang halaman dan coba lagi.')

        uid = session['user_id']
        new_name = ' '.join(request.form.get('name', '').split())
        current_pw = request.form.get('current_password', '').strip()
        new_pw = request.form.get('new_password', '').strip()
        confirm_pw = request.form.get('confirm_password', '').strip()

        if not (2 <= len(new_name) <= 60) or any(ch in NAME_FORBIDDEN or ord(ch) < 32 for ch in new_name):
            return back('err', 'Nama harus 2-60 karakter dan tidak boleh mengandung < > " \' & ` atau \\.')

        row = cursor.execute('SELECT password FROM users WHERE id = ?', (uid,)).fetchone()
        if not row:
            conn.close()
            session.clear()
            return redirect(url_for('login'))

        changing_pw = bool(new_pw or confirm_pw or current_pw)
        if changing_pw:
            ip = request.remote_addr or '-'
            limit_key = f'ganti-password:{uid}'
            wait = login_lock_seconds(ip, limit_key)
            if wait:
                return back('err', f'Terlalu banyak percobaan gagal. Coba lagi sekitar {max(1, (wait + 59) // 60)} menit.')
            if not (is_password_hashed(row[0]) and check_password_hash(row[0], current_pw)):
                record_login_fail(ip, limit_key)
                return back('err', 'Password saat ini salah. Tidak ada perubahan yang disimpan.')
            if len(new_pw) < MIN_PASSWORD_LEN:
                return back('err', f'Password baru minimal {MIN_PASSWORD_LEN} karakter.')
            if new_pw != confirm_pw:
                return back('err', 'Konfirmasi password baru tidak sama.')
            if new_pw == current_pw:
                return back('err', 'Password baru harus berbeda dari password saat ini.')
            clear_login_fails(ip, limit_key)
            cursor.execute('UPDATE users SET password = ? WHERE id = ?', (generate_password_hash(new_pw), uid))

        cursor.execute('UPDATE users SET name = ? WHERE id = ?', (new_name, uid))
        conn.commit()
        session['name'] = new_name
        if changing_pw:
            session['payment_csrf'] = secrets.token_urlsafe(32)  # putar token CSRF setelah ganti password
        return back('ok', 'Password dan nama berhasil diperbarui.' if changing_pw else 'Nama berhasil diperbarui.')

    if action_type == 'process_payment':
        if session.get('role') != 'member':
            conn.close()
            abort(403, description='Hanya member dapat membuat pembayaran.')
        if not csrf_valid():
            conn.close()
            abort(400, description='Form kedaluwarsa. Muat ulang halaman dan coba lagi.')
        try:
            package_id = int(request.form.get('package_id', ''))
        except ValueError:
            conn.close()
            abort(400, description='Paket tidak valid.')
        method = request.form.get('payment_method', '')
        if method not in ('qris', 'gopay_direct'):
            conn.close()
            abort(400, description='Metode pembayaran tidak valid.')

        # Jangan percaya amount/duration_months dari browser: ambil dari database.
        cursor.execute("SELECT id, package_name, duration_months, price FROM membership_packages WHERE id=? AND status='Aktif'", (package_id,))
        package = cursor.fetchone()
        if package is None:
            conn.close()
            abort(400, description='Paket tidak tersedia.')

        proof = request.files.get('payment_proof')
        if proof is None or not proof.filename:
            conn.close()
            abort(400, description='Bukti transfer harus diunggah.')
        proof_data = proof.read(5 * 1024 * 1024 + 1)
        if len(proof_data) > 5 * 1024 * 1024:
            conn.close()
            abort(413, description='Bukti melebihi 5 MB.')
        extension = image_type(proof_data)
        if extension is None:
            conn.close()
            abort(400, description='Bukti harus berupa JPG, PNG, atau WebP yang valid.')
        PROOF_DIR.mkdir(parents=True, exist_ok=True)
        filename = secrets.token_hex(24) + '.' + extension
        proof_path = PROOF_DIR / filename
        proof_path.write_bytes(proof_data)
        try:
            wib_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute("""INSERT INTO payments
                    (member_id, package_id, amount, payment_date, status, payment_method, proof_filename)
                    VALUES (?, ?, ?, ?, 'Pending', ?, ?)""",
                    (session['user_id'], package_id, package[3], wib_time, method, filename))
            notify_role(conn, 'admin', f"Pembayaran baru dari {session['name']}",
                        f"{package[1]} ({rupiah(package[3])}). Bukti menunggu verifikasi.", '/dashboard?menu=manage_payments')
            notify_user(conn, session['user_id'], 'Bukti pembayaran diterima',
                        f"Pembayaran {package[1]} sedang diverifikasi admin.", '/dashboard?menu=packages#riwayat-pembayaran')
            conn.commit()
        except Exception:
            proof_path.unlink(missing_ok=True)
            raise
        finally:
            conn.close()
        # Membership TIDAK berubah saat member mengunggah bukti.
        return redirect(url_for('dashboard', menu='packages') + '#riwayat-pembayaran')

    elif action_type in ('verify_payment', 'reject_payment'):
        if session.get('role') != 'admin':
            conn.close()
            abort(403, description='Hanya admin dapat memverifikasi pembayaran.')
        if not csrf_valid():
            conn.close()
            abort(400, description='Token verifikasi tidak valid. Refresh dashboard.')
        try:
            payment_id = int(request.form.get('payment_id', ''))
        except ValueError:
            conn.close()
            abort(400, description='ID transaksi tidak valid.')
        try:
            # Satu transaksi hanya diproses sekali, termasuk jika admin klik dua kali.
            conn.execute('BEGIN IMMEDIATE')
            cursor.execute("""SELECT payments.id, payments.status, payments.member_id,
                                     payments.package_id, payments.proof_filename,
                                     membership_packages.duration_months, membership_packages.package_name
                              FROM payments JOIN membership_packages
                              ON payments.package_id = membership_packages.id
                              WHERE payments.id = ?""", (payment_id,))
            p = cursor.fetchone()
            if p is None or p[1] != 'Pending':
                conn.rollback()
                abort(409, description='Transaksi sudah diproses atau tidak ditemukan.')
            if action_type == 'verify_payment' and not p[4]:
                conn.rollback()
                abort(400, description='Transaksi belum memiliki bukti pembayaran.')
            new_status = 'Lunas' if action_type == 'verify_payment' else 'Ditolak'
            cursor.execute("""UPDATE payments SET status=?, verified_at=?, verified_by=?
                              WHERE id=? AND status='Pending'""",
                           (new_status, datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            session['user_id'], payment_id))
            if cursor.rowcount != 1:
                conn.rollback()
                abort(409, description='Status transaksi telah berubah.')

            if new_status == 'Lunas':
                additional_days = int(p[5]) * 30  # Tahap 2 nanti memakai tanggal kedaluwarsa asli.
                pkg_name = p[6]
                status_name = pkg_name if pkg_name.lower().startswith('paket ') else f'Paket {pkg_name}'
                cursor.execute('SELECT id, remaining_days FROM member_profiles WHERE user_id=?', (p[2],))
                profile = cursor.fetchone()
                was_inactive = (not profile) or (profile[1] or 0) <= 0
                if profile:
                    cursor.execute("""UPDATE member_profiles
                            SET remaining_days=MAX(0, COALESCE(remaining_days, 0)) + ?,
                                package_id=?, status_paket=?
                            WHERE user_id=?""", (additional_days, p[3], status_name, p[2]))
                else:
                    cursor.execute("""INSERT INTO member_profiles
                            (user_id, package_id, remaining_days, status_paket)
                            VALUES (?, ?, ?, ?)""", (p[2], p[3], additional_days, status_name))
            mem = cursor.execute('SELECT name FROM users WHERE id=?', (p[2],)).fetchone()
            mname = mem[0] if mem else 'Member'
            if new_status == 'Lunas':
                notify_user(conn, p[2], 'Pembayaran terverifikasi', f"{p[6]} sudah aktif. Selamat berlatih!", '/dashboard?menu=dashboard')
                notify_role(conn, 'owner', 'Pembayaran lunas', f"{mname} - {p[6]}", '/dashboard?menu=dashboard')
                if was_inactive:
                    notify_role(conn, 'trainer', 'Member baru aktif', f"{mname} baru bergabung ({p[6]}). Buat program dan target latihannya.", '/dashboard?menu=set_target')
            else:
                notify_user(conn, p[2], 'Pembayaran ditolak', f"Pembayaran {p[6]} belum bisa diverifikasi. Hubungi admin atau kirim bukti yang benar.", '/dashboard?menu=packages')
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        return redirect(url_for('dashboard', menu='manage_payments'))

    elif action_type == 'add_user':
        if session.get('role') != 'admin':
            conn.close()
            abort(403)
        role = request.form.get('role')
        name = request.form.get('name').strip()
        email = request.form.get('email').strip()
        phone = request.form.get('phone', '').strip()
        password = (request.form.get('password') or '').strip()
        
        prefix = 'MEM' if role == 'member' else 'TRN'
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = ?", (role,))
        count = cursor.fetchone()[0] + 1
        unique_code = f"{prefix}{count:03d}"

        if role not in ('member', 'trainer') or len(password) < MIN_PASSWORD_LEN:
            conn.close()
            abort(400, description=f'Password minimal {MIN_PASSWORD_LEN} karakter.')
        try:
            cursor.execute("INSERT INTO users (unique_code, name, email, password, role, phone) VALUES (?, ?, ?, ?, ?, ?)",
                           (unique_code, name, email, generate_password_hash(password), role, phone))
            new_user_id = cursor.lastrowid
            
            if role == 'member':
                cursor.execute("INSERT INTO member_profiles (user_id, package_id, remaining_days, status_paket) VALUES (?, NULL, 0, 'Belum Aktif')", (new_user_id,))
            conn.commit()
        except sqlite3.IntegrityError:
            pass

    elif action_type == 'delete_user':
        if session.get('role') != 'admin':
            conn.close()
            abort(403)
        u_id = request.form.get('id')
        cursor.execute("DELETE FROM users WHERE id = ?", (u_id,))
        conn.commit()

    elif action_type == 'add_workout':
        if session.get('role') != 'trainer':
            conn.close()
            abort(403)
        if not csrf_valid():
            conn.close()
            abort(400, description='Form kedaluwarsa. Muat ulang halaman dan coba lagi.')
        try:
            member_id = int(request.form['member_id'])
            sets = int(request.form['sets'])
            reps = int(request.form['reps'])
            weight_kg = float(request.form['weight_kg'])
            exercise_name = request.form['exercise_name'].strip()[:100]
            schedule_date = request.form['schedule_date']
            schedule_time = request.form['schedule_time']
            datetime.strptime(schedule_date, '%Y-%m-%d')
            datetime.strptime(schedule_time, '%H:%M')
        except (KeyError, ValueError):
            conn.close()
            abort(400, description='Data program latihan tidak valid.')
        if not exercise_name or sets < 1 or reps < 1 or not (0 <= weight_kg <= 1000):
            conn.close()
            abort(400, description='Data program latihan tidak valid.')
        video_url, video_error = normalize_video_url(request.form.get('video_url'))
        if video_error:
            conn.close()
            abort(400, description=video_error)
        cursor.execute("SELECT 1 FROM users WHERE id = ? AND role = 'member'", (member_id,))
        if cursor.fetchone() is None:
            conn.close()
            abort(400, description='Member tidak ditemukan.')
        cursor.execute("INSERT INTO workouts (trainer_id, member_id, exercise_name, sets, reps, weight_kg, schedule_date, schedule_time, status, video_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Belum', ?)",
                       (session['user_id'], member_id, exercise_name, sets, reps, weight_kg, schedule_date, schedule_time, video_url or None))
        notify_user(conn, member_id, 'Program latihan baru', f"{exercise_name} dijadwalkan {schedule_date} pukul {schedule_time}.", '/dashboard?menu=workouts')
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard', menu='assign_workout'))

    elif action_type == 'set_target':
        if session.get('role') != 'trainer':
            conn.close()
            abort(403)
        if not csrf_valid():
            conn.close()
            abort(400, description='Form kedaluwarsa. Muat ulang halaman dan coba lagi.')
        try:
            member_id = int(request.form['member_id'])
            start_weight = float(request.form['start_weight'])
            target_weight = float(request.form['target_weight'])
            start_body_fat = float(request.form['start_body_fat'])
            target_body_fat = float(request.form['target_body_fat'])
        except (KeyError, ValueError):
            conn.close()
            abort(400, description='Berat badan dan body fat harus berupa angka.')
        weights_ok = all(20 <= v <= 300 for v in (start_weight, target_weight))
        fats_ok = all(2 <= v <= 60 for v in (start_body_fat, target_body_fat))
        if not (weights_ok and fats_ok):
            conn.close()
            abort(400, description='Berat badan harus 20-300 kg dan body fat 2-60%.')
        notes = (request.form.get('notes') or '').strip()[:500]
        cursor.execute("SELECT 1 FROM users WHERE id = ? AND role = 'member'", (member_id,))
        if cursor.fetchone() is None:
            conn.close()
            abort(400, description='Member tidak ditemukan.')
        now_text = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute("SELECT id FROM member_targets WHERE member_id = ? ORDER BY id DESC LIMIT 1", (member_id,))
        existing = cursor.fetchone()
        if existing:
            cursor.execute("""UPDATE member_targets
                              SET start_weight=?, target_weight=?, start_body_fat=?, target_body_fat=?,
                                  notes=?, trainer_id=?, updated_at=?
                              WHERE id=?""",
                           (start_weight, target_weight, start_body_fat, target_body_fat,
                            notes, session['user_id'], now_text, existing[0]))
        else:
            cursor.execute("""INSERT INTO member_targets
                              (member_id, start_weight, target_weight, start_body_fat, target_body_fat, notes, trainer_id, updated_at)
                              VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                           (member_id, start_weight, target_weight, start_body_fat, target_body_fat,
                            notes, session['user_id'], now_text))
        notify_user(conn, member_id, 'Target latihan diperbarui', 'Trainer memperbarui target berat badan dan body fat kamu.', '/dashboard?menu=progress')
        conn.commit()
        conn.close()
        return redirect(url_for('dashboard', menu='set_target'))

    elif action_type == 'add_equipment':
        if session.get('role') != 'admin':
            conn.close()
            abort(403)
        cursor.execute("INSERT INTO equipment (equipment_name, category, status) VALUES (?, ?, ?)",
                       (request.form['equipment_name'], request.form['category'], request.form['status']))
        conn.commit()

    conn.close()
    return redirect(url_for('dashboard', menu=request.args.get('menu', 'manage_members')))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('public_home'))

def reset_password_cli(code):
    """Ganti password lewat terminal: python app.py reset-password OWN001"""
    import getpass
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute("SELECT id, name FROM users WHERE LOWER(unique_code) = ?", (code.lower(),)).fetchone()
    if not row:
        print(f"Akun dengan kode '{code}' tidak ditemukan.")
        conn.close()
        return
    new_pw = getpass.getpass(f"Password baru untuk {row[1]} ({code}): ").strip()
    if len(new_pw) < MIN_PASSWORD_LEN:
        print(f"Password minimal {MIN_PASSWORD_LEN} karakter. Tidak ada perubahan.")
        conn.close()
        return
    if new_pw != getpass.getpass("Ulangi password baru: ").strip():
        print("Password tidak sama. Tidak ada perubahan.")
        conn.close()
        return
    conn.execute("UPDATE users SET password = ? WHERE id = ?", (generate_password_hash(new_pw), row[0]))
    conn.commit()
    conn.close()
    print("Password berhasil diganti.")


if __name__ == '__main__':
    init_db()
    if len(sys.argv) >= 3 and sys.argv[1] == 'reset-password':
        reset_password_cli(sys.argv[2])
        sys.exit(0)
    app.run(debug=False, host='0.0.0.0', port=8080)
