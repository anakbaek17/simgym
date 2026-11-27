from flask import Flask, request, redirect, url_for, session, render_template_string, send_from_directory, abort, jsonify, make_response
import sqlite3
import os
import secrets
from pathlib import Path
from datetime import datetime, timedelta, timezone
import html
import re
from urllib.parse import urlparse, parse_qs, quote
import sys
import time
import hmac
import hashlib
import csv
import io
from werkzeug.security import generate_password_hash, check_password_hash
try:
    import segno          # pembuat QR lokal (pip install -r requirements.txt)
except ImportError:
    segno = None

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


# ---------------------------------------------------------------------------
# Check-in QR Code aman
#  - QR member berisi token bertanda tangan (HMAC) yang kedaluwarsa dalam 90 detik,
#    bukan lagi kode member statis yang bisa ditebak/dibagikan.
#  - Yang boleh memindai hanya admin yang sedang login (bukan sembarang orang).
#  - Check-in ditolak bila membership tidak aktif, dan dibatasi 1x per 2 jam per member.
#  - Semua tersimpan di tabel `checkins` yang sudah ada (tanpa database baru).
# ---------------------------------------------------------------------------
QR_TOKEN_TTL = 90                 # detik; QR di layar member diperbarui otomatis sebelum habis
CHECKIN_COOLDOWN_MINUTES = 120    # harus >= QR_TOKEN_TTL agar token tidak bisa dipakai ulang
_QR_KEY = hmac.new(app.secret_key.encode('utf-8'), b'fithub-gym-qr-checkin-v1', hashlib.sha256).digest()
_QR_TOKEN_RE = re.compile(r'(\d{1,9})\.(\d{9,11})\.([0-9a-f]{8})\.([0-9a-f]{32})')
_NOW_FMT = '%Y-%m-%d %H:%M:%S'


def make_qr_token(user_id):
    body = f"{int(user_id)}.{int(time.time())}.{secrets.token_hex(4)}"
    sig = hmac.new(_QR_KEY, body.encode('ascii'), hashlib.sha256).hexdigest()[:32]
    return f"{body}.{sig}"


def read_qr_token(raw):
    """Kembalikan (user_id, masalah). masalah: None | 'invalid' | 'expired'.
    `raw` boleh token saja atau URL lengkap hasil scan."""
    m = _QR_TOKEN_RE.search(str(raw or '')[:400])
    if not m:
        return None, 'invalid'
    uid, ts, nonce, sig = m.groups()
    body = f"{uid}.{ts}.{nonce}"
    good = hmac.new(_QR_KEY, body.encode('ascii'), hashlib.sha256).hexdigest()[:32]
    if not hmac.compare_digest(sig, good):
        return None, 'invalid'
    age = time.time() - int(ts)
    if age < -30:
        return None, 'invalid'
    if age > QR_TOKEN_TTL:
        return int(uid), 'expired'
    return int(uid), None


def qr_svg(text):
    """Gambar QR dibuat di server sendiri (tanpa situs pihak ketiga)."""
    if segno is None:
        return None
    return segno.make(text, error='m').svg_inline(scale=1, border=2, dark='#000000', light='#ffffff')


def member_is_active(cursor, user_id):
    row = cursor.execute("SELECT remaining_days FROM member_profiles WHERE user_id = ? ORDER BY id DESC LIMIT 1",
                         (user_id,)).fetchone()
    return bool(row and (row[0] or 0) > 0)


def process_checkin(raw_token, staff_id):
    """Validasi token lalu catat check-in. Atomik, supaya dua pemindaian bersamaan tidak tercatat ganda."""
    uid, problem = read_qr_token(raw_token)
    if problem == 'invalid':
        return {'ok': False, 'code': 'invalid', 'title': 'QR TIDAK VALID',
                'message': 'QR ini bukan QR check-in FIT HUB GYM yang sah. Minta member membuka halaman Check-in QR Code miliknya.'}
    conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('BEGIN IMMEDIATE')
        user = conn.execute("SELECT id, unique_code, name, role FROM users WHERE id = ?", (uid,)).fetchone()
        if not user or user['role'] != 'member':
            conn.execute('ROLLBACK')
            return {'ok': False, 'code': 'invalid', 'title': 'QR TIDAK VALID',
                    'message': 'Akun member tidak ditemukan.'}
        prof = conn.execute("""SELECT mp.remaining_days, pk.package_name FROM member_profiles mp
                               LEFT JOIN membership_packages pk ON pk.id = mp.package_id
                               WHERE mp.user_id = ? ORDER BY mp.id DESC LIMIT 1""", (uid,)).fetchone()
        days = int(prof['remaining_days'] or 0) if prof else 0
        info = {'name': user['name'], 'member_code': user['unique_code'],
                'package': (prof['package_name'] if prof and prof['package_name'] else '-'), 'days': days}
        now_dt = datetime.now()
        now = now_dt.strftime(_NOW_FMT)
        info['time'] = now

        def deny(code, title, note, message):
            conn.execute("INSERT INTO checkins (user_id, checkin_time, status, scanned_by, note) VALUES (?, ?, 'Ditolak', ?, ?)",
                         (uid, now, staff_id, note))
            conn.execute('COMMIT')
            return dict(info, ok=False, code=code, title=title, message=message)

        if problem == 'expired':
            return deny('expired', 'QR KEDALUWARSA', 'QR kedaluwarsa',
                        'QR sudah lewat batas waktu (QR berganti tiap beberapa detik). Minta member menunggu QR baru di layarnya lalu pindai lagi.')
        if days <= 0:
            return deny('denied', 'MEMBERSHIP TIDAK AKTIF', 'Membership tidak aktif',
                        'Masa aktif membership sudah habis atau pembayaran belum diverifikasi. Arahkan member ke Paket Membership.')
        last = conn.execute("SELECT checkin_time FROM checkins WHERE user_id = ? AND status = 'Berhasil' ORDER BY id DESC LIMIT 1",
                            (uid,)).fetchone()
        if last:
            try:
                last_dt = datetime.strptime(str(last['checkin_time'])[:19], _NOW_FMT)
            except ValueError:
                last_dt = None
            if last_dt and now_dt - last_dt < timedelta(minutes=CHECKIN_COOLDOWN_MINUTES):
                conn.execute('ROLLBACK')
                return dict(info, ok=False, code='duplicate', title='SUDAH CHECK-IN',
                            message=f"Member ini sudah check-in pukul {str(last['checkin_time'])[11:16]}. Check-in ulang baru bisa setelah {CHECKIN_COOLDOWN_MINUTES // 60} jam.")
        conn.execute("INSERT INTO checkins (user_id, checkin_time, status, scanned_by, note) VALUES (?, ?, 'Berhasil', ?, 'QR')",
                     (uid, now, staff_id))
        notify_user(conn, uid, 'Check-in berhasil', f'Anda masuk gym pukul {now[11:16]}. Bukan Anda? Segera hubungi admin.',
                    '/dashboard?menu=checkin')
        conn.execute('COMMIT')
        return dict(info, ok=True, code='ok', title='CHECK-IN BERHASIL',
                    message='Akses member telah diverifikasi.')
    except Exception:
        try:
            conn.execute('ROLLBACK')
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


def recent_scans(limit=8):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""SELECT c.checkin_time, c.status, c.note, u.name, u.unique_code
                               FROM checkins c JOIN users u ON u.id = c.user_id
                               ORDER BY c.id DESC LIMIT ?""", (limit,)).fetchall()
    return [dict(r) for r in rows]


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
    bar = f'<div class="target-bar"><div style="width:{pct}%"></div></div>' if pct is not None else ''
    pct_txt = f' · tercapai {pct}%' if pct is not None else ''
    return (f'<div class="card"><h3>{label}</h3>'
            f'<div class="value" style="font-size:20px;">{fmt_num(start)} → {fmt_num(target)} {unit}</div>'
            f'<p style="margin-top:6px;">Saat ini: {fmt_num(current)} {unit}{pct_txt}</p>{bar}</div>')


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
        return "<span style='color:var(--text-muted);'>Belum ada video</span>"
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
        return (f'<div class="video-wrap"><iframe src="https://www.youtube-nocookie.com/embed/{video_id}" '
                'title="Video panduan latihan" loading="lazy" allowfullscreen '
                'referrerpolicy="strict-origin-when-cross-origin" '
                'allow="accelerometer; encrypted-media; picture-in-picture"></iframe></div>')
    if parsed.path.lower().endswith(('.mp4', '.webm', '.ogg')):
        return f'<video class="video-player" controls preload="metadata" src="{safe(url)}"></video>'
    return (f'<a href="{safe(url)}" target="_blank" rel="noopener noreferrer" class="btn-primary" '
            'style="padding:8px 14px; font-size:12px;">▶ Buka Video</a>')


# =========================================================
# ⚠️ ISIKAN NOMOR GOPAY & NAMA ASLI KAMU DI SINI:
GOPAY_NUMBER = "083857533722"  # Ganti dengan Nomor HP GoPay Kamu
GOPAY_NAME = "NAUFAL HANIF JABRAN SUKMA"     # Nama Akun GoPay Kamu
# =========================================================

def get_equipment_options(cursor, kind):
    """Daftar pilihan dropdown alat gym ('category' atau 'status'), urut sesuai waktu ditambahkan."""
    rows = cursor.execute("SELECT name FROM equipment_options WHERE kind = ? ORDER BY id", (kind,)).fetchall()
    return [r[0] for r in rows]


PROTECTED_EQUIPMENT_STATUS = ('Tersedia', 'Perbaikan')  # dipakai logika grafik & hitungan inventaris


def clean_option_name(value):
    return ' '.join((value or '').split())[:40]


def equipment_option_exists(cursor, kind, name):
    row = cursor.execute("SELECT name FROM equipment_options WHERE kind = ? AND name = ?", (kind, name or '')).fetchone()
    return row[0] if row else None


def equipment_options_panel(csrf_token, kind, title, placeholder, items, in_use):
    """Kotak kecil: tambah kategori/status baru + daftar yang sudah ada (bisa dihapus jika belum dipakai)."""
    chips = ''
    for it in items:
        locked = (kind == 'status' and it in PROTECTED_EQUIPMENT_STATUS) or it in in_use
        btn = ('' if locked else
               f'<form action="/action?menu=manage_equipment" method="POST" style="display:inline;margin:0;" '
               f'onsubmit="return confirm(\'Hapus pilihan ini?\');">'
               f'<input type="hidden" name="action_type" value="delete_equipment_option">'
               f'<input type="hidden" name="csrf_token" value="{csrf_token}">'
               f'<input type="hidden" name="kind" value="{kind}"><input type="hidden" name="name" value="{html.escape(it, quote=True)}">'
               f'<button type="submit" title="Hapus" style="background:none;border:0;color:#f87171;cursor:pointer;font-size:15px;padding:0 0 0 6px;">×</button></form>')
        chips += (f'<span style="display:inline-flex;align-items:center;background:rgba(245,176,0,.12);border:1px solid rgba(245,176,0,.35);'
                  f'color:#f5b000;padding:5px 12px;border-radius:999px;font-size:13px;margin:0 8px 8px 0;">{html.escape(it)}{btn}</span>')
    return (
        f'<div class="panel-box" style="flex:1;min-width:280px;margin-bottom:0;"><h3 style="margin-bottom:14px;">{title}</h3>'
        f'<form action="/action?menu=manage_equipment" method="POST" style="display:flex;gap:10px;align-items:flex-start;">'
        f'<input type="hidden" name="action_type" value="add_equipment_option">'
        f'<input type="hidden" name="csrf_token" value="{csrf_token}"><input type="hidden" name="kind" value="{kind}">'
        f'<input type="text" name="name" maxlength="40" required placeholder="{placeholder}" style="margin-bottom:0;">'
        f'<button type="submit" class="btn-primary" style="white-space:nowrap;">Tambah</button></form>'
        f'<div style="margin-top:16px;">{chips}</div></div>')


def equipment_form_html(csrf_token, categories, statuses):
    def sel(field, label, options, default=None):
        opts = ''.join(f'<option value="{html.escape(o, quote=True)}"{" selected" if o == default else ""}>{html.escape(o)}</option>' for o in options)
        return f'<label>{label}</label><select name="{field}" required>{opts}</select>'
    return (
        '<form action="/action?menu=manage_equipment" method="POST">'
        '<input type="hidden" name="action_type" value="add_equipment">'
        f'<input type="hidden" name="csrf_token" value="{csrf_token}">'
        '<label>Nama Alat</label><input type="text" name="equipment_name" required>'
        + sel('category', 'Kategori', categories)
        + sel('status', 'Status', statuses, 'Tersedia')
        + '<button type="submit" class="btn-primary">Tambah Alat</button></form>')


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
    # Migrasi aman untuk check-in QR: tambah kolom pencatat (admin yang memindai) & keterangan.
    # Data check-in lama tetap utuh; tidak ada database/tabel baru.
    cursor.execute("PRAGMA table_info(checkins)")
    checkin_cols = {row[1] for row in cursor.fetchall()}
    for column, sql_type in (('scanned_by', 'INTEGER'), ('note', 'TEXT')):
        if column not in checkin_cols:
            cursor.execute(f'ALTER TABLE checkins ADD COLUMN {column} {sql_type}')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_checkins_user_time ON checkins(user_id, checkin_time)')
    conn.commit()
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
    # Opsi dropdown Data Alat Gym (kategori & status) disimpan di database, bukan di kode,
    # supaya admin bisa menambah pilihan baru langsung dari dashboard.
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS equipment_options (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            name TEXT NOT NULL COLLATE NOCASE,
            UNIQUE(kind, name)
        )
    ''')
    for kind, defaults in (('category', ('Cardio', 'Beban')), ('status', ('Tersedia', 'Perbaikan', 'Rusak'))):
        for nm in defaults:
            cursor.execute("INSERT OR IGNORE INTO equipment_options (kind, name) VALUES (?, ?)", (kind, nm))
    # Kategori/status yang sudah terpakai di data alat lama ikut dimasukkan agar tetap bisa dipilih.
    cursor.execute("INSERT OR IGNORE INTO equipment_options (kind, name) SELECT DISTINCT 'category', category FROM equipment WHERE category IS NOT NULL AND TRIM(category) != ''")
    cursor.execute("INSERT OR IGNORE INTO equipment_options (kind, name) SELECT DISTINCT 'status', status FROM equipment WHERE status IS NOT NULL AND TRIM(status) != ''")
    conn.commit()

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

BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
    <meta name="theme-color" content="#0f172a">
    <title>FIT HUB GYM ACCESS - {{ role.upper() }} Dashboard</title>
    <style>
        :root {
            --bg-main: #0b0f19;
            --bg-card: rgba(19, 27, 46, 0.82);
            --bg-sidebar: rgba(15, 23, 42, 0.95);
            --border-color: rgba(255, 255, 255, 0.1);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --accent-primary: #f5b000;
            
            {% if role == 'member' %}
                --role-badge-bg: rgba(245, 176, 0, 0.15);
            {% elif role == 'trainer' %}
                --role-badge-bg: rgba(0, 230, 118, 0.15);
            {% elif role == 'admin' %}
                --role-badge-bg: rgba(41, 121, 255, 0.15);
            {% elif role == 'owner' %}
                --role-badge-bg: rgba(213, 0, 249, 0.15);
            {% else %}
                --role-badge-bg: rgba(245, 176, 0, 0.15);
            {% endif %}
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', 'Segoe UI', Tahoma, sans-serif; }
        body { background-color: var(--bg-main); color: var(--text-main); display: flex; height: 100vh; overflow: hidden; }
        
        .sidebar { width: 270px; background-color: var(--bg-sidebar); border-right: 1px solid var(--border-color); display: flex; flex-direction: column; z-index: 10; backdrop-filter: blur(10px); }
        .sidebar-brand { padding: 24px; font-size: 17px; font-weight: 800; color: #f5b000; border-bottom: 1px solid var(--border-color); display: flex; align-items: center; justify-content: space-between; letter-spacing: 0.5px; }
        .role-pill { font-size: 10px; padding: 4px 8px; border-radius: 20px; background: var(--role-badge-bg); color: var(--accent-primary); font-weight: 600; text-transform: uppercase; }
        
        .sidebar-menu { list-style: none; padding: 20px 0; overflow-y: auto; flex-grow: 1; }
        .sidebar-menu li a { display: block; padding: 14px 24px; color: var(--text-muted); text-decoration: none; font-size: 14px; font-weight: 500; transition: all 0.3s ease; border-left: 3px solid transparent; }
        .sidebar-menu li a:hover, .sidebar-menu li a.active { background: rgba(255, 255, 255, 0.05); color: var(--text-main); border-left-color: #f5b000; }
        .sidebar-menu li a.active { color: #f5b000; font-weight: 600; }
        
        .sidebar-footer { padding: 20px 24px; border-top: 1px solid var(--border-color); }
        .btn-logout { display: block; padding: 12px; text-align: center; background: rgba(239, 68, 68, 0.1); color: var(--danger); text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 14px; border: 1px solid rgba(239, 68, 68, 0.2); transition: 0.2s; }
        .btn-logout:hover { background: var(--danger); color: #fff; }

        .main-container { flex-grow: 1; display: flex; flex-direction: column; overflow: hidden; position: relative; }
        .header { height: 75px; background: rgba(19, 27, 46, 0.85); backdrop-filter: blur(12px); border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center; padding: 0 35px; box-shadow: 0 4px 20px rgba(0,0,0,0.4); z-index: 5; }
        .header-title { font-size: 18px; font-weight: 700; color: var(--text-main); }
        .user-info { font-size: 14px; color: var(--text-muted); display: flex; align-items: center; gap: 10px; } 
        .user-info span { color: #f5b000; font-weight: 700; background: var(--role-badge-bg); padding: 5px 12px; border-radius: 6px; }
        
        .content { 
            padding: 35px; 
            overflow-y: auto; 
            flex-grow: 1; 
            position: relative;
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            transition: background-image 0.4s ease-in-out;
        }

        {% if bg_url %}
        .content::before {
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0; bottom: 0;
            background: linear-gradient(180deg, rgba(11, 15, 25, 0.88) 0%, rgba(11, 15, 25, 0.95) 100%);
            z-index: 1;
        }
        {% endif %}

        .content-inner {
            position: relative;
            z-index: 2;
        }

        .card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: var(--bg-card); backdrop-filter: blur(12px); padding: 22px; border-radius: 14px; border: 1px solid var(--border-color); box-shadow: 0 8px 24px rgba(0,0,0,0.4); position: relative; overflow: hidden; transition: transform 0.2s; }
        .card:hover { transform: translateY(-3px); border-color: rgba(245, 176, 0, 0.3); }
        .card::before { content: ''; position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: #f5b000; }
        .card h3 { font-size: 12px; color: var(--text-muted); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.8px; font-weight: 600; }
        .card .value { font-size: 26px; font-weight: 800; color: var(--text-main); }

        table { width: 100%; border-collapse: separate; border-spacing: 0; background: var(--bg-card); backdrop-filter: blur(12px); border-radius: 12px; overflow: hidden; border: 1px solid var(--border-color); margin-top: 15px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
        th, td { padding: 15px 18px; text-align: left; border-bottom: 1px solid var(--border-color); font-size: 14px; }
        th { background: rgba(0,0,0,0.4); color: #f5b000; font-weight: 700; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; } 
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: rgba(255,255,255,0.02); }
        
        .badge { padding: 5px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; display: inline-block; letter-spacing: 0.3px; }
        .badge-success { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
        .badge-warning { background: rgba(245, 158, 11, 0.15); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge-danger { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
        
        form label { display: block; margin-bottom: 8px; font-size: 13px; color: var(--text-muted); font-weight: 600; }
        form input, form select, form textarea { width: 100%; padding: 12px 16px; background: rgba(11, 15, 25, 0.8); border: 1px solid var(--border-color); border-radius: 8px; color: #fff; margin-bottom: 20px; font-size: 14px; transition: border-color 0.2s; }
        form input:focus, form select:focus, form textarea:focus { border-color: #f5b000; outline: none; box-shadow: 0 0 0 3px rgba(245, 176, 0, 0.15); }
        
        .btn-primary { background: #f5b000; color: #121212; padding: 12px 24px; border: none; border-radius: 8px; font-weight: 800; cursor: pointer; transition: background 0.2s, transform 0.1s; font-size: 14px; box-shadow: 0 4px 15px rgba(245, 176, 0, 0.2); text-decoration: none; display: inline-block; }
        .btn-primary:hover { background: #d99b00; transform: translateY(-1px); }
        .btn-danger { background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); padding: 6px 14px; border-radius: 6px; font-weight: 700; cursor: pointer; font-size: 12px; transition: 0.2s; }
        .btn-danger:hover { background: var(--danger); color: #fff; }
        
        .panel-box { background: var(--bg-card); backdrop-filter: blur(12px); padding: 28px; border-radius: 16px; border: 1px solid var(--border-color); margin-bottom: 25px; box-shadow: 0 10px 30px rgba(0,0,0,0.4); }
        .search-box { padding: 12px 18px; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; color: #fff; width: 100%; max-width: 320px; margin-bottom: 20px; font-size: 14px; }
        
        h2 { font-size: 22px; font-weight: 800; color: var(--text-main); margin-bottom: 8px; }
        p { color: var(--text-muted); font-size: 14px; line-height: 1.5; }
        
        .motto-tag { font-size: 11px; text-transform: uppercase; letter-spacing: 2px; color: #f5b000; font-weight: 800; margin-bottom: 4px; display: block; }
        
        .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.85); backdrop-filter: blur(8px); display: none; justify-content: center; align-items: center; z-index: 1000; }
        .modal-box { background: #131b2e; border: 1px solid var(--border-color); border-top: 4px solid #f5b000; padding: 35px; border-radius: 20px; width: 90%; max-width: 520px; box-shadow: 0 20px 50px rgba(0,0,0,0.8); position: relative; }
        .payment-method-card { background: #0b0f19; border: 1px solid var(--border-color); border-radius: 10px; padding: 15px; margin-bottom: 12px; cursor: pointer; transition: 0.2s; display: flex; align-items: center; justify-content: space-between; }
        .payment-method-card:hover, .payment-method-card.selected { border-color: #f5b000; background: rgba(245, 176, 0, 0.05); }

        .video-wrap { position: relative; width: 100%; max-width: 340px; aspect-ratio: 16 / 9; border-radius: 10px; overflow: hidden; background: #000; border: 1px solid var(--border-color); }
        .video-wrap iframe { position: absolute; inset: 0; width: 100%; height: 100%; border: 0; }
        .video-player { width: 100%; max-width: 340px; border-radius: 10px; background: #000; }
        .target-bar { height: 8px; background: rgba(255,255,255,0.1); border-radius: 99px; overflow: hidden; margin-top: 10px; }
        .target-bar > div { height: 100%; background: #f5b000; border-radius: 99px; }

        .header-right { display: flex; align-items: center; gap: 14px; }
        .bell-wrap { position: relative; }
        .bell { position: relative; background: rgba(255,255,255,0.06); border: 1px solid var(--border-color); color: var(--text-main); width: 42px; height: 42px; border-radius: 10px; font-size: 18px; cursor: pointer; }
        .bell:hover { border-color: #f5b000; }
        .bell:focus-visible, .bell-head button:focus-visible { outline: 3px solid #ffc933; outline-offset: 2px; }
        .bell-badge { position: absolute; top: -6px; right: -6px; min-width: 20px; height: 20px; padding: 0 5px; border-radius: 10px; background: #ef4444; color: #fff; font-size: 11px; font-weight: 800; display: grid; place-items: center; }
        .bell-badge[hidden], .bell-panel[hidden] { display: none; }
        .bell-panel { position: absolute; right: 0; top: 52px; width: 360px; max-width: 92vw; max-height: 70vh; overflow-y: auto; background: #131b2e; border: 1px solid var(--border-color); border-radius: 12px; box-shadow: 0 20px 50px rgba(0,0,0,0.6); z-index: 60; }
        .bell-head { display: flex; justify-content: space-between; align-items: center; padding: 14px 16px; border-bottom: 1px solid var(--border-color); position: sticky; top: 0; background: #131b2e; }
        .bell-head button { background: none; border: 0; color: #f5b000; font-size: 12px; font-weight: 700; cursor: pointer; }
        .nitem { display: block; width: 100%; text-align: left; background: none; border: 0; border-bottom: 1px solid rgba(255,255,255,0.06); padding: 12px 16px 12px 26px; color: var(--text-main); cursor: pointer; position: relative; }
        .nitem:hover { background: rgba(255,255,255,0.05); }
        .nitem.unread::before { content: ''; position: absolute; left: 11px; top: 19px; width: 8px; height: 8px; border-radius: 50%; background: #f5b000; }
        .nitem b { display: block; font-size: 14px; }
        .nitem span { display: block; font-size: 13px; color: var(--text-muted); margin-top: 2px; }
        .nitem small { display: block; font-size: 11px; color: #64748b; margin-top: 4px; }
        .bell-empty { padding: 26px 16px; text-align: center; color: var(--text-muted); font-size: 14px; }
        .toast-stack { position: fixed; right: 20px; bottom: 20px; z-index: 100; display: grid; gap: 10px; }
        .toast { width: 330px; max-width: 90vw; background: #131b2e; border: 1px solid #f5b000; border-left-width: 5px; border-radius: 10px; padding: 12px 16px; box-shadow: 0 16px 40px rgba(0,0,0,0.6); cursor: pointer; animation: toastIn .3s ease; }
        .toast b { display: block; font-size: 14px; color: #f5b000; }
        .toast span { font-size: 13px; color: var(--text-main); }
        @keyframes toastIn { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: none; } }
        @media (prefers-reduced-motion: reduce) { .toast { animation: none; } }

        @media (max-width: 1024px) {
            .owner-grid-split { grid-template-columns: 1fr !important; }
        }

        /* ---------- Tombol menu (titik tiga) & drawer: hanya tampil di HP/tablet ---------- */
        .menu-toggle, .drawer-close, .sidebar-overlay { display: none; }
        .table-scroll { width: 100%; overflow-x: auto; -webkit-overflow-scrolling: touch; }
        .table-scroll > table { margin-top: 15px; }

        @media (max-width: 860px) {
            body { height: 100vh; height: 100dvh; }
            .menu-toggle { display: grid; place-items: center; width: 42px; height: 42px; flex: none; background: rgba(255,255,255,0.06); border: 1px solid var(--border-color); border-radius: 10px; color: var(--text-main); cursor: pointer; }
            .menu-toggle:hover, .menu-toggle:focus-visible { border-color: #f5b000; outline: none; }
            .menu-toggle svg { width: 22px; height: 22px; fill: currentColor; }
            .drawer-close { display: grid; place-items: center; width: 34px; height: 34px; background: rgba(255,255,255,0.06); border: 1px solid var(--border-color); border-radius: 8px; color: var(--text-main); font-size: 18px; line-height: 1; cursor: pointer; flex: none; }

            .sidebar { position: fixed; top: 0; bottom: 0; left: 0; width: 280px; max-width: 84vw; z-index: 200; transform: translateX(-102%); transition: transform .28s ease; background-color: #0f172a; box-shadow: none; padding-top: env(safe-area-inset-top); }
            body.menu-open .sidebar { transform: none; box-shadow: 12px 0 40px rgba(0,0,0,0.6); }
            .sidebar-overlay { display: block; position: fixed; inset: 0; z-index: 150; background: rgba(0,0,0,0.6); backdrop-filter: blur(2px); opacity: 0; pointer-events: none; transition: opacity .28s ease; }
            body.menu-open .sidebar-overlay { opacity: 1; pointer-events: auto; }
            body.menu-open { overflow: hidden; }
            .sidebar-brand { padding: 16px 18px; font-size: 16px; gap: 8px; }
            .sidebar-brand .brand-left { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
            .sidebar-menu { padding: 10px 0; }
            .sidebar-menu li a { padding: 15px 20px; font-size: 15px; }
            .sidebar-footer { padding: 14px 18px calc(14px + env(safe-area-inset-bottom)); }

            .header { height: 62px; padding: 0 14px; gap: 10px; justify-content: flex-start; }
            .header-left { display: flex; align-items: center; gap: 10px; min-width: 0; flex: 1; }
            .user-info { font-size: 12px; min-width: 0; gap: 6px; }
            .user-info span { padding: 4px 9px; max-width: 46vw; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; }
            .header-right { margin-left: auto; }

            .content { padding: 16px 14px 28px; }
            h2 { font-size: 19px; }
            p { font-size: 13px; }
            .card-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; margin-bottom: 20px; }
            .card { padding: 16px 14px 16px 18px; border-radius: 12px; }
            .card:hover { transform: none; }
            .card .value { font-size: 20px; word-break: break-word; }
            .card h3 { font-size: 11px; }
            .panel-box { padding: 18px 16px; border-radius: 14px; margin-bottom: 18px; }
            [style*="minmax(300px"], .owner-grid-split { grid-template-columns: 1fr !important; }
            .owner-grid-split > *, [style*="grid-template-columns"] > * { min-width: 0; }
            .panel-box { min-width: 0; max-width: 100%; }
            [style*="min-width:200px"], [style*="min-width:280px"] { min-width: 100% !important; }

            .table-scroll > table, .table-scroll table { margin-top: 10px; }
            .table-scroll.wide > table { min-width: 560px; }
            .table-scroll.wide td { white-space: nowrap; }
            th, td { padding: 11px 12px; font-size: 13px; }
            th { font-size: 10px; white-space: nowrap; }
            th[style*="width"] { width: auto !important; }

            form input, form select, form textarea { font-size: 16px; padding: 12px 14px; margin-bottom: 16px; }
            .search-box { max-width: none; font-size: 16px; }
            .btn-primary { padding: 13px 20px; }
            form .btn-primary { width: 100%; text-align: center; }

            .modal-box { padding: 22px 18px; width: 94%; max-height: 92vh; overflow-y: auto; border-radius: 16px; }
            .video-wrap, .video-player { max-width: 100%; }

            .bell-panel { position: fixed; top: 68px; left: 10px; right: 10px; width: auto; max-width: none; max-height: 70vh; }
            .toast-stack { left: 12px; right: 12px; bottom: calc(12px + env(safe-area-inset-bottom)); }
            .toast { width: 100%; max-width: none; }
        }
        @media (max-width: 380px) {
            .card-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="sidebar-overlay" id="sidebarOverlay"></div>
    <div class="sidebar" id="sidebar" aria-label="Menu navigasi">
        <div class="sidebar-brand">
            <span class="brand-left">⚡ FIT HUB GYM <span class="role-pill">{{ role }}</span></span>
            <button type="button" class="drawer-close" id="drawerClose" aria-label="Tutup menu">✕</button>
        </div>
        <ul class="sidebar-menu">
            {% if role == 'member' %}
                <li><a href="/dashboard?menu=dashboard" class="{{ 'active' if menu=='dashboard' }}">📊 Dashboard Utama</a></li>
                <li><a href="/dashboard?menu=packages" class="{{ 'active' if menu=='packages' }}">📦 Paket Membership</a></li>
                <li><a href="/dashboard?menu=checkin" class="{{ 'active' if menu=='checkin' }}">📷 Check-in QR Code</a></li>
                <li><a href="/dashboard?menu=workouts" class="{{ 'active' if menu=='workouts' }}">🏋️ Program Latihan</a></li>
                <li><a href="/dashboard?menu=progress" class="{{ 'active' if menu=='progress' }}">📈 Progres & Perkembangan</a></li>
            {% elif role == 'trainer' %}
                <li><a href="/dashboard?menu=dashboard" class="{{ 'active' if menu=='dashboard' }}">📊 Dashboard Trainer</a></li>
                <li><a href="/dashboard?menu=assign_workout" class="{{ 'active' if menu=='assign_workout' }}">📋 Program Latihan Member</a></li>
                <li><a href="/dashboard?menu=set_target" class="{{ 'active' if menu=='set_target' }}">🎯 Target Latihan Member</a></li>
                <li><a href="/dashboard?menu=monitor_progress" class="{{ 'active' if menu=='monitor_progress' }}">📅 Progres & Jadwal Member</a></li>
            {% elif role == 'admin' %}
                <li><a href="/dashboard?menu=dashboard" class="{{ 'active' if menu=='dashboard' }}">📊 Dashboard Admin</a></li>
                <li><a href="/dashboard?menu=manage_members" class="{{ 'active' if menu=='manage_members' }}">👥 Kelola Member</a></li>
                <li><a href="/dashboard?menu=manage_packages" class="{{ 'active' if menu=='manage_packages' }}">📦 Kelola Paket Membership</a></li>
                <li><a href="/dashboard?menu=manage_equipment" class="{{ 'active' if menu=='manage_equipment' }}">⚙️ Data Alat Gym</a></li>
                <li><a href="/dashboard?menu=manage_payments" class="{{ 'active' if menu=='manage_payments' }}">💰 Kelola Pembayaran</a></li>
                <li><a href="/dashboard?menu=manage_trainers" class="{{ 'active' if menu=='manage_trainers' }}">🏋️ Kelola Trainer</a></li>
                <li><a href="/dashboard?menu=scan" class="{{ 'active' if menu=='scan' }}">📷 Scan Check-in</a></li>
                <li><a href="/dashboard?menu=visit_report" class="{{ 'active' if menu=='visit_report' }}">🧾 Laporan Kunjungan</a></li>
            {% elif role == 'owner' %}
                <li><a href="/dashboard?menu=dashboard" class="{{ 'active' if menu=='dashboard' }}">📊 Dashboard Eksekutif</a></li>
                <li><a href="/dashboard?menu=visit_report" class="{{ 'active' if menu=='visit_report' }}">🧾 Laporan Kunjungan</a></li>
            {% endif %}
            <li><a href="/dashboard?menu=account" class="{{ 'active' if menu=='account' }}">🔐 Akun Saya</a></li>
        </ul>
        <div class="sidebar-footer">
            <a href="/logout" class="btn-logout">Keluar Sistem</a>
        </div>
    </div>
    
    <div class="main-container">
        <div class="header">
            <div class="header-left">
                <button type="button" class="menu-toggle" id="menuToggle" aria-label="Buka menu" aria-controls="sidebar" aria-expanded="false">
                    <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="5" r="2.2"/><circle cx="12" cy="12" r="2.2"/><circle cx="12" cy="19" r="2.2"/></svg>
                </button>
                <div class="user-info">Akun: <span>{{ session.name }}</span></div>
            </div>
            <div class="header-right">
                <div class="bell-wrap">
                    <button type="button" class="bell" id="bellBtn" aria-label="Notifikasi" aria-haspopup="true" aria-expanded="false">🔔<span class="bell-badge" id="bellBadge" hidden>0</span></button>
                    <div class="bell-panel" id="bellPanel" hidden>
                        <div class="bell-head"><b>Notifikasi</b><button type="button" id="bellAll">Tandai semua dibaca</button></div>
                        <div id="bellList"><div class="bell-empty">Belum ada notifikasi.</div></div>
                    </div>
                </div>
            </div>
        </div>
        <div class="content" {% if bg_url %}style="background-image: url('{{ bg_url }}');"{% endif %}>
            <div class="content-inner">
                {% block content %}{% endblock %}
            </div>
        </div>
    </div>
    <div class="toast-stack" id="toasts" aria-live="polite"></div>
    <script>
    (function () {
        var body = document.body, tgl = document.getElementById('menuToggle');
        function setMenu(open) {
            body.classList.toggle('menu-open', open);
            tgl.setAttribute('aria-expanded', String(open));
            tgl.setAttribute('aria-label', open ? 'Tutup menu' : 'Buka menu');
        }
        tgl.addEventListener('click', function () { setMenu(!body.classList.contains('menu-open')); });
        document.getElementById('sidebarOverlay').addEventListener('click', function () { setMenu(false); });
        document.getElementById('drawerClose').addEventListener('click', function () { setMenu(false); });
        document.querySelectorAll('.sidebar-menu a').forEach(function (a) { a.addEventListener('click', function () { setMenu(false); }); });
        document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { setMenu(false); } });
        window.addEventListener('resize', function () { if (window.innerWidth > 860) { setMenu(false); } });

        /* Bungkus semua tabel agar bisa digeser ke samping di layar kecil */
        document.querySelectorAll('.content table').forEach(function (t) {
            var p = t.parentElement;
            if (p && p.classList.contains('table-scroll')) { return; }
            var w = document.createElement('div'); w.className = 'table-scroll';
            var row = t.rows[0]; if (row && row.cells.length >= 4) { w.classList.add('wide'); }
            t.parentNode.insertBefore(w, t); w.appendChild(t);
        });
    })();
    (function () {
        var csrf = "{{ csrf_token }}";
        var baseTitle = document.title, lastId = null;
        var btn = document.getElementById('bellBtn'), panel = document.getElementById('bellPanel');
        var badge = document.getElementById('bellBadge'), list = document.getElementById('bellList');
        function safeLink(l) { return (typeof l === 'string' && l.charAt(0) === '/' && l.charAt(1) !== '/') ? l : null; }
        function when(t) { return t ? t.slice(8, 10) + '/' + t.slice(5, 7) + ' ' + t.slice(11, 16) : ''; }
        function mark(id) {
            var b = new URLSearchParams(); if (id) { b.set('id', id); } else { b.set('all', '1'); }
            return fetch('/notifications/read', { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': csrf }, body: b });
        }
        function go(n) { mark(n.id).then(function () { var l = safeLink(n.link); if (l) { location.href = l; } else { load(); } }); }
        function render(d) {
            badge.hidden = !d.unread; badge.textContent = d.unread > 99 ? '99+' : d.unread;
            document.title = (d.unread ? '(' + d.unread + ') ' : '') + baseTitle;
            list.textContent = '';
            if (!d.items.length) { var e = document.createElement('div'); e.className = 'bell-empty'; e.textContent = 'Belum ada notifikasi.'; list.appendChild(e); return; }
            d.items.forEach(function (n) {
                var it = document.createElement('button'); it.type = 'button'; it.className = 'nitem' + (n.is_read ? '' : ' unread');
                var t = document.createElement('b'); t.textContent = n.title;
                var m = document.createElement('span'); m.textContent = n.message || '';
                var w = document.createElement('small'); w.textContent = when(n.created_at);
                it.appendChild(t); it.appendChild(m); it.appendChild(w);
                it.addEventListener('click', function () { go(n); });
                list.appendChild(it);
            });
        }
        function toast(n) {
            var box = document.getElementById('toasts'), el = document.createElement('div'); el.className = 'toast';
            var t = document.createElement('b'); t.textContent = n.title;
            var m = document.createElement('span'); m.textContent = n.message || '';
            el.appendChild(t); el.appendChild(m);
            el.addEventListener('click', function () { go(n); });
            box.appendChild(el); setTimeout(function () { el.remove(); }, 9000);
        }
        function load() {
            fetch('/notifications', { credentials: 'same-origin', cache: 'no-store' })
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (d) {
                    if (!d) { return; }
                    if (lastId !== null) {
                        d.items.filter(function (i) { return i.id > lastId && !i.is_read; }).reverse().forEach(toast);
                    }
                    if (d.items.length) { lastId = Math.max(lastId || 0, d.items[0].id); } else if (lastId === null) { lastId = 0; }
                    render(d);
                }).catch(function () {});
        }
        btn.addEventListener('click', function (e) {
            e.stopPropagation(); panel.hidden = !panel.hidden; btn.setAttribute('aria-expanded', String(!panel.hidden));
        });
        document.addEventListener('click', function (e) { if (!panel.hidden && !panel.contains(e.target)) { panel.hidden = true; btn.setAttribute('aria-expanded', 'false'); } });
        document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { panel.hidden = true; btn.setAttribute('aria-expanded', 'false'); } });
        document.getElementById('bellAll').addEventListener('click', function () { mark(null).then(load); });
        document.addEventListener('visibilitychange', function () { if (!document.hidden) { load(); } });
        load(); setInterval(load, 12000);
    })();
    </script>
</body>
</html>
'''

LOGIN_HTML = '''
<!DOCTYPE html>
<html lang="id">
<head><meta charset="UTF-8"><title>Login - FIT HUB GYM ACCESS</title></head>
<body style="background: linear-gradient(rgba(11, 15, 25, 0.75), rgba(11, 15, 25, 0.85)), url('{{ login_bg_img }}'); background-size: cover; background-position: center; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; font-family: 'Inter', sans-serif;">
    <div style="background: rgba(19, 27, 46, 0.85); backdrop-filter: blur(12px); padding: 45px; border-radius: 20px; box-shadow: 0 20px 40px rgba(0,0,0,0.6); width: 100%; max-width: 420px; border: 1px solid rgba(255, 255, 255, 0.1); border-top: 4px solid #f5b000;">
        <h2 style="text-align: center; margin-bottom: 25px; color: #f8fafc; font-weight: 800; font-size: 24px; letter-spacing: 0.5px;">FIT HUB GYM <span style="color: #f5b000;">ACCESS</span></h2>
        {% if error %}<div style="background: rgba(239,68,68,.15); border: 1px solid rgba(239,68,68,.45); color: #fca5a5; padding: 10px 14px; border-radius: 8px; font-size: 13px; margin-bottom: 18px; text-align: center;">{{ error }}</div>{% endif %}
        <form method="POST">
            <div style="margin-bottom: 20px;">
                <label style="display: block; margin-bottom: 8px; font-size: 13px; color: #94a3b8; font-weight: 600;">Kode Unik / Nama / Email</label>
                <input type="text" name="login_input" required placeholder="Contoh: MEM001 / Andi Pratama" style="width: 100%; padding: 12px 16px; background: rgba(11, 15, 25, 0.9); border: 1px solid #1e293b; border-radius: 8px; color: #fff; font-size: 15px; box-sizing: border-box;">
            </div>
            <div style="margin-bottom: 25px;">
                <label style="display: block; margin-bottom: 8px; font-size: 13px; color: #94a3b8; font-weight: 600;">Password</label>
                <input type="password" name="password" required placeholder="••••••••" style="width: 100%; padding: 12px 16px; background: rgba(11, 15, 25, 0.9); border: 1px solid #1e293b; border-radius: 8px; color: #fff; font-size: 15px; box-sizing: border-box;">
            </div>
            <button type="submit" style="width: 100%; padding: 14px; background: #f5b000; border: none; border-radius: 8px; color: #0b0f19; font-size: 15px; font-weight: 800; cursor: pointer; box-shadow: 0 4px 15px rgba(245,176,0,0.3);">MASUK SISTEM</button>
        </form>
        <p style="text-align: center; margin-top: 20px; font-size: 14px; color: #94a3b8;">Belum punya akun? <a href="/daftar" style="color: #f5b000; font-weight: 700; text-decoration: none;">Daftar jadi member</a></p>
    </div>
</body>
</html>
'''

VISITOR_LANDING_HTML = r'''<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FIT HUB GYM - Better Than Yesterday</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Big+Shoulders+Display:wght@800;900&amp;family=Figtree:wght@400;600;800&amp;display=swap" rel="stylesheet">
<style>
  :root { --ink:#0a0c10; --steel:#141821; --steel2:#1c212c; --line:rgba(255,255,255,.12); --text:#f3f4f6; --mute:#9aa3b2; --gold:#f5b000; --gold2:#ffc933; --ok:#34d399; --bad:#f87171; --paper:#eceff3; --pink:#10131a; --pmute:#566070; --pline:#d3d9e2; }
  * { box-sizing:border-box; margin:0; padding:0; }
  html { scroll-behavior:smooth; scroll-padding-top:76px; }
  body { font-family:'Figtree','Segoe UI',system-ui,sans-serif; background:var(--ink); color:var(--text); line-height:1.6; overflow-x:hidden; }
  a { color:inherit; text-decoration:none; }
  a:focus-visible, .btn:focus-visible { outline:3px solid var(--gold2); outline-offset:3px; }
  .wrap { width:100%; max-width:1180px; margin:0 auto; padding:0 24px; }
  .disp { font-family:'Big Shoulders Display','Impact','Arial Narrow',sans-serif; font-weight:900; text-transform:uppercase; line-height:.95; letter-spacing:.01em; }

  /* NAV */
  nav { position:fixed; top:0; left:0; right:0; z-index:50; background:rgba(10,12,16,.86); backdrop-filter:blur(12px); border-bottom:1px solid var(--line); }
  nav .wrap { display:flex; align-items:center; justify-content:space-between; height:68px; gap:16px; }
  .brand { display:flex; align-items:center; gap:10px; font-size:24px; white-space:nowrap; }
  .brand i { font-style:normal; display:grid; place-items:center; width:34px; height:34px; background:var(--gold); color:var(--ink); border-radius:4px; font-size:20px; }
  .links { display:flex; gap:28px; font-size:14px; font-weight:600; color:var(--mute); }
  .links a:hover { color:var(--gold); }
  .nav-actions { display:flex; gap:10px; align-items:center; }
  .btn { display:inline-block; padding:13px 24px; border-radius:6px; font-weight:800; font-size:15px; border:2px solid transparent; cursor:pointer; transition:transform .15s, background .2s, color .2s, border-color .2s; text-align:center; }
  .btn:hover { transform:translateY(-2px); }
  .btn-gold { background:var(--gold); color:var(--ink); }
  .btn-gold:hover { background:var(--gold2); }
  .btn-line { border-color:rgba(255,255,255,.28); color:var(--text); }
  .btn-line:hover { border-color:var(--gold); color:var(--gold); }
  .btn-ink { background:var(--ink); color:var(--gold); }
  .btn-ink:hover { background:#000; }
  .btn-ink-line { border-color:var(--ink); color:var(--ink); }
  .btn-ink-line:hover { background:var(--ink); color:var(--gold); }
  .btn-sm { padding:9px 16px; font-size:13px; }

  /* HERO */
  .hero { position:relative; isolation:isolate; min-height:100vh; display:flex; align-items:center; padding:116px 0 80px; overflow:hidden; }
  .hero::before { content:''; position:absolute; inset:0; z-index:-2; background:url('{{ hero_img }}') center/cover no-repeat; filter:grayscale(1) contrast(1.15); opacity:.3; }
  .hero::after { content:''; position:absolute; inset:0; z-index:-1; background:linear-gradient(90deg, var(--ink) 18%, rgba(10,12,16,.55) 100%), linear-gradient(180deg, transparent 72%, var(--ink)); }
  .hero .wrap { display:grid; grid-template-columns:1.15fr .85fr; gap:56px; align-items:center; }
  h1 { font-size:clamp(56px,9.4vw,138px); margin-bottom:26px; }
  h1 .out { display:block; color:transparent; -webkit-text-stroke:2px var(--gold); }
  .lead { font-size:18px; color:#cbd2dd; max-width:520px; margin-bottom:32px; }
  .cta { display:flex; flex-wrap:wrap; gap:12px; }

  /* TARGET CARD */
  .gauge { background:rgba(20,24,33,.9); border:1px solid var(--line); border-top:4px solid var(--gold); border-radius:10px; padding:26px; box-shadow:0 30px 70px rgba(0,0,0,.55); }
  .g-head { display:flex; justify-content:space-between; align-items:baseline; gap:12px; margin-bottom:22px; }
  .g-head h2 { font-size:30px; }
  .g-head small { color:var(--mute); font-size:12px; text-align:right; }
  .meter { margin-bottom:22px; }
  .m-top { display:flex; justify-content:space-between; align-items:baseline; font-weight:600; color:var(--mute); font-size:14px; }
  .m-top b { color:var(--text); font-size:26px; font-family:'Big Shoulders Display','Impact',sans-serif; font-weight:900; }
  .bar { height:12px; background:var(--steel2); border-radius:3px; margin:8px 0 6px; overflow:hidden; }
  .bar i { display:block; height:100%; width:var(--to); background:linear-gradient(90deg, var(--gold), var(--gold2)); animation:fill 1.5s .5s cubic-bezier(.2,.8,.2,1) both; }
  @keyframes fill { from { width:0; } to { width:var(--to); } }
  .m-sub { display:flex; justify-content:space-between; font-size:12px; color:var(--mute); }
  .m-sub b { color:var(--gold); }
  .g-row { display:flex; align-items:center; gap:14px; padding:14px 0; border-top:1px solid var(--line); font-size:14px; }
  .g-row strong { display:block; font-size:15px; }
  .g-row span { color:var(--mute); font-size:13px; }
  .play { flex:none; width:40px; height:40px; border-radius:50%; background:var(--gold); position:relative; }
  .play::after { content:''; position:absolute; left:16px; top:12px; border-left:12px solid var(--ink); border-top:8px solid transparent; border-bottom:8px solid transparent; }
  .qrmini { flex:none; width:40px; height:40px; border-radius:6px; background:#fff; display:grid; place-items:center; }
  .qrmini::after { content:''; width:22px; height:22px; background:
    conic-gradient(from 90deg at 1px 1px, transparent 25%, var(--ink) 0) 0 0/6px 6px; border:3px solid var(--ink); }

  /* STATS */
  .strip { background:var(--steel); border-top:1px solid var(--line); border-bottom:1px solid var(--line); }
  .strip .wrap { display:grid; grid-template-columns:repeat(4,1fr); }
  .stat { padding:30px 20px; border-left:1px solid var(--line); }
  .stat:first-child { border-left:0; }
  .stat .n { font-size:64px; color:var(--gold); }
  .stat .l { font-size:14px; color:var(--mute); font-weight:600; }

  .sec { padding:104px 0; }
  .paper { background:var(--paper); color:var(--pink); }
  .paper .sub { color:var(--pmute); }
  h2.big { font-size:clamp(40px,6vw,76px); margin-bottom:14px; }
  .sub { color:var(--mute); font-size:17px; max-width:520px; }

  /* WHY */
  .why { display:grid; grid-template-columns:.8fr 1.2fr; gap:64px; align-items:start; }
  .why .head { position:sticky; top:100px; }
  .row { display:grid; grid-template-columns:24px 1fr; gap:18px; padding:28px 0; border-top:1px solid var(--line); }
  .row:last-child { border-bottom:1px solid var(--line); }
  .row::before { content:''; width:12px; height:12px; margin-top:10px; background:var(--gold); }
  .row h3 { font-size:34px; margin-bottom:6px; }
  .row p { color:var(--mute); max-width:520px; }

  /* PLANS */
  .plans { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:20px; margin-top:48px; align-items:stretch; }
  .plan { position:relative; display:flex; flex-direction:column; background:#fff; border:1px solid var(--pline); border-radius:6px; padding:34px 28px; }
  .plan.best { background:var(--ink); color:var(--text); border-color:var(--ink); box-shadow:0 24px 60px rgba(10,12,16,.3); }
  .ribbon { position:absolute; top:-14px; left:24px; background:var(--gold); color:var(--ink); font-size:12px; font-weight:800; padding:4px 12px; border-radius:3px; }
  .plan h3 { font-size:30px; }
  .plan .dur { font-size:14px; color:var(--pmute); margin-bottom:18px; }
  .plan.best .dur { color:var(--mute); }
  .plan .price { font-size:58px; line-height:1; }
  .plan .price small { font-size:22px; margin-right:4px; }
  .plan .per { font-size:14px; font-weight:800; margin:6px 0 22px; }
  .plan.best .per { color:var(--gold); }
  .plan ul { list-style:none; margin-bottom:28px; flex-grow:1; }
  .plan li { font-size:14px; padding:8px 0 8px 26px; position:relative; border-top:1px solid var(--pline); }
  .plan.best li { border-color:var(--line); }
  .plan li::before { content:'\2713'; position:absolute; left:0; font-weight:900; color:#0f9d6e; }
  .plan .btn { width:100%; }
  .plan:not(.best) .btn-gold { background:var(--ink); color:var(--gold); }
  .qris-note { margin-top:30px; display:flex; align-items:center; gap:12px; font-size:15px; font-weight:600; }
  .qris-note b { background:var(--ink); color:var(--gold); padding:3px 10px; border-radius:3px; font-size:13px; }

  /* TRAINERS */
  .trainers { display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:16px; margin-top:44px; }
  .trainer { position:relative; overflow:hidden; aspect-ratio:4/5; display:flex; flex-direction:column; justify-content:flex-end; padding:20px; background:var(--steel); border:1px solid var(--line); border-radius:6px; }
  .trainer .ini { position:absolute; top:-8px; right:6px; font-size:190px; color:transparent; -webkit-text-stroke:2px rgba(245,176,0,.55); }
  .trainer h3 { position:relative; font-size:28px; }
  .trainer p { position:relative; color:var(--gold); font-size:13px; font-weight:800; }

  /* FACILITIES */
  .fac { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-top:44px; }
  .fac-box { background:#fff; border:1px solid var(--pline); border-radius:6px; padding:26px; }
  .fac-box h3 { display:flex; justify-content:space-between; align-items:baseline; font-size:28px; margin-bottom:16px; }
  .fac-box h3 small { font-family:'Figtree',sans-serif; text-transform:none; font-size:13px; color:var(--pmute); font-weight:600; }
  .chips { display:flex; flex-wrap:wrap; gap:8px; }
  .chip { font-size:13px; font-weight:600; padding:6px 12px 6px 24px; border-radius:20px; background:var(--paper); position:relative; }
  .chip::before { content:''; position:absolute; left:10px; top:50%; width:8px; height:8px; margin-top:-4px; border-radius:50%; background:#0f9d6e; }
  .chip.off { color:var(--pmute); text-decoration:line-through; }
  .chip.off::before { background:#dc2626; }
  .legend { margin-top:18px; font-size:13px; color:var(--pmute); }

  /* STEPS */
  .steps { display:grid; grid-template-columns:repeat(3,1fr); gap:0; margin-top:48px; }
  .step { padding:0 28px 0 0; border-top:3px solid var(--gold); padding-top:22px; margin-right:20px; }
  .step .no { font-size:84px; color:var(--gold); }
  .step h3 { font-size:30px; margin:4px 0 8px; }
  .step p { color:var(--mute); font-size:15px; }
  .step .tag { display:inline-block; margin-top:12px; font-size:13px; font-weight:800; background:var(--gold); color:var(--ink); padding:3px 10px; border-radius:3px; }

  /* FINAL */
  .final { background:var(--gold); color:var(--ink); padding:96px 0; }
  .final h2 { font-size:clamp(44px,8vw,112px); max-width:900px; margin-bottom:20px; }
  .final p { font-size:18px; font-weight:600; max-width:520px; margin-bottom:30px; }
  .final .cta { gap:12px; }
  footer { padding:26px 0; font-size:13px; color:var(--mute); border-top:1px solid var(--line); }
  footer .wrap { display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px; }

  @media (prefers-reduced-motion:reduce) { .bar i { animation:none; } html { scroll-behavior:auto; } .btn { transition:none; } }
  @media (max-width:980px) {
    .hero .wrap, .why { grid-template-columns:1fr; gap:40px; } .why .head { position:static; }
    .links { display:none; } .strip .wrap { grid-template-columns:repeat(2,1fr); }
    .stat:nth-child(3) { border-left:0; } .stat:nth-child(n+3) { border-top:1px solid var(--line); }
    .fac, .steps { grid-template-columns:1fr; } .step { margin:0 0 28px; }
    .sec { padding:76px 0; }
  }
  @media (max-width:560px) { .wrap { padding:0 16px; } .hide-sm { display:none; } .stat .n { font-size:48px; } .hero { padding-top:100px; } .gauge { padding:20px; } }
</style>
</head>
<body>

<nav>
  <div class="wrap">
    <a href="#beranda" class="brand disp"><i>FH</i> Fit Hub Gym</a>
    <div class="links">
      <a href="#keunggulan">Keunggulan</a><a href="#paket">Paket</a><a href="#trainer">Trainer</a><a href="#fasilitas">Fasilitas</a><a href="#cara">Cara bergabung</a>
    </div>
    <div class="nav-actions">
      <a href="/daftar" class="btn btn-gold btn-sm hide-sm">Daftar member</a>
      <a href="/login" class="btn btn-line btn-sm">Masuk akun</a>
    </div>
  </div>
</nav>

<header class="hero" id="beranda">
  <div class="wrap">
    <div>
      <h1 class="disp">Lebih baik<span class="out">dari kemarin.</span></h1>
      <p class="lead">Program latihan dari trainer pribadi, video panduan di setiap gerakan, dan target berat badan serta body fat yang dipantau sampai tercapai.</p>
      <div class="cta">
        <a href="/daftar" class="btn btn-gold">Daftar sekarang</a>
        <a href="#paket" class="btn btn-line">Lihat paket</a>
      </div>
    </div>
    <aside class="gauge" aria-label="Contoh tampilan target di akun member">
      <div class="g-head"><h2 class="disp">Target tubuhmu</h2><small>Contoh tampilan<br>di akun member</small></div>
      <div class="meter" style="--to:46%">
        <div class="m-top"><span>Berat badan</span><b>82 kg</b></div>
        <div class="bar"><i></i></div>
        <div class="m-sub"><span>Awal 88 kg</span><span>Tercapai <b>46%</b></span><span>Target 75 kg</span></div>
      </div>
      <div class="meter" style="--to:40%">
        <div class="m-top"><span>Body fat</span><b>24%</b></div>
        <div class="bar"><i></i></div>
        <div class="m-sub"><span>Awal 28%</span><span>Tercapai <b>40%</b></span><span>Target 18%</span></div>
      </div>
      <div class="g-row"><span class="play"></span><div><strong>Push &amp; Core Workout</strong><span>Setiap gerakan ada video panduan</span></div></div>
      <div class="g-row"><span class="qrmini"></span><div><strong>Check-in QR Code</strong><span>Masuk gym tanpa kartu dan antre</span></div></div>
    </aside>
  </div>
</header>

<div class="strip">
  <div class="wrap">
    <div class="stat"><div class="n disp">{{ packages|length }}</div><div class="l">Paket membership</div></div>
    <div class="stat"><div class="n disp">{{ trainers|length }}</div><div class="l">Trainer</div></div>
    <div class="stat"><div class="n disp">{{ equipment|length }}</div><div class="l">Alat gym</div></div>
    <div class="stat"><div class="n disp">{{ available_count }}</div><div class="l">Alat siap pakai</div></div>
  </div>
</div>

<section class="sec" id="keunggulan">
  <div class="wrap why">
    <div class="head">
      <h2 class="big disp">Progresmu terlihat jelas</h2>
      <p class="sub">Setiap member punya pendamping dan sistem yang mencatat perubahannya dari hari pertama.</p>
    </div>
    <div>
      <div class="row"><div><h3 class="disp">Trainer pribadi</h3><p>Trainer menyusun program khusus untukmu: gerakan, set, repetisi, dan beban.</p></div></div>
      <div class="row"><div><h3 class="disp">Video panduan gerakan</h3><p>Setiap program dilengkapi video, jadi gerakanmu benar dan latihan lebih aman.</p></div></div>
      <div class="row"><div><h3 class="disp">Target terukur</h3><p>Berat badan dan body fat dicatat dari awal sampai target, lengkap dengan persentase pencapaian.</p></div></div>
      <div class="row"><div><h3 class="disp">Check-in QR Code</h3><p>Scan QR dari akun member untuk masuk. Tanpa kartu, tanpa antre.</p></div></div>
    </div>
  </div>
</section>

<section class="sec paper" id="paket">
  <div class="wrap">
    <h2 class="big disp">Pilih paketmu</h2>
    <p class="sub">Makin panjang durasinya, makin hemat biaya per bulan.</p>
    <div class="plans">
      {% for p in packages %}
      <div class="plan{% if p.best %} best{% endif %}">
        {% if p.best %}<div class="ribbon">Paling hemat</div>{% endif %}
        <h3 class="disp">{{ p.name }}</h3>
        <div class="dur">{{ p.months }} bulan akses penuh</div>
        <div class="price disp"><small>Rp</small>{{ p.price_fmt }}</div>
        <div class="per">Sekitar Rp {{ p.per_month_fmt }} per bulan</div>
        <ul>
          <li>Akses semua alat gym</li>
          <li>Program latihan dari trainer</li>
          <li>Video panduan gerakan</li>
          <li>Pantau target dan progres tubuh</li>
          <li>Check-in QR Code</li>
        </ul>
        <a href="/daftar?paket={{ p.id }}" class="btn btn-gold">Ambil paket ini</a>
      </div>
      {% else %}
      <p class="sub" style="grid-column:1/-1;">Paket sedang disiapkan. Hubungi admin untuk info terbaru.</p>
      {% endfor %}
    </div>
    <div class="qris-note"><b>QRIS</b> Bayar langsung saat mendaftar, tanpa perlu chat admin dulu.</div>
  </div>
</section>

<section class="sec" id="trainer">
  <div class="wrap">
    <h2 class="big disp">Kenali trainermu</h2>
    <p class="sub">Mereka yang akan menemani perjalanan kebugaranmu.</p>
    <div class="trainers">
      {% for t in trainers %}
      <div class="trainer"><span class="ini disp" aria-hidden="true">{{ t.initial }}</span><h3 class="disp">{{ t.name }}</h3><p>Personal trainer</p></div>
      {% else %}
      <p class="sub" style="grid-column:1/-1;">Profil trainer akan segera tersedia.</p>
      {% endfor %}
    </div>
  </div>
</section>

<section class="sec paper" id="fasilitas">
  <div class="wrap">
    <h2 class="big disp">Alat lengkap dan terawat</h2>
    <p class="sub">Ketersediaan alat diperbarui oleh admin gym.</p>
    <div class="fac">
      {% for cat in equipment_groups %}
      <div class="fac-box">
        <h3 class="disp">{{ cat.name }} <small>{{ cat.rows|length }} alat</small></h3>
        <div class="chips">{% for e in cat.rows %}<span class="chip{% if e.status != 'Tersedia' %} off{% endif %}" title="{{ e.status }}">{{ e.name }}</span>{% endfor %}</div>
      </div>
      {% else %}
      <p class="sub" style="grid-column:1/-1;">Data alat belum tersedia.</p>
      {% endfor %}
    </div>
    <p class="legend">Titik hijau berarti alat tersedia. Titik merah dan teks dicoret berarti sedang tidak bisa dipakai.</p>
  </div>
</section>

<section class="sec" id="cara">
  <div class="wrap">
    <h2 class="big disp">Jadi member dalam 3 langkah</h2>
    <p class="sub">Informasi gym bisa kamu lihat tanpa login. Daftar langsung di sini, tanpa chat admin dulu.</p>
    <div class="steps">
      <div class="step"><div class="no disp">1</div><h3 class="disp">Buat akun</h3><p>Isi nama, email, dan password, lalu pilih paket yang kamu mau.</p></div>
      <div class="step"><div class="no disp">2</div><h3 class="disp">Bayar via QRIS</h3><p>Scan QRIS sesuai total paket, lalu unggah bukti pembayaran. Setelah itu kamu langsung masuk ke area member.</p><span class="tag">Scan dari aplikasi apa saja</span></div>
      <div class="step"><div class="no disp">3</div><h3 class="disp">Mulai latihan</h3><p>Admin memverifikasi pembayaranmu dan kamu mendapat notifikasi. Setelah itu program, video, dan target tubuh siap dipakai.</p></div>
    </div>
  </div>
</section>

<section class="final">
  <div class="wrap">
    <h2 class="disp">Hari ini hari yang baik untuk mulai.</h2>
    <p>Langkah pertama yang paling berat. Kami temani sampai targetmu tercapai.</p>
    <div class="cta">
      <a href="/daftar" class="btn btn-ink">Daftar jadi member</a>
      <a href="/login" class="btn btn-ink-line">Sudah member? Masuk</a>
      {% if wa_general %}<a href="{{ wa_general }}" target="_blank" rel="noopener noreferrer" class="btn btn-ink-line">Tanya admin via WhatsApp</a>{% endif %}
    </div>
  </div>
</section>
<footer><div class="wrap"><span>&copy; FIT HUB GYM</span><span>Better Than Yesterday</span></div></footer>

</body>
</html>
'''

SCAN_RESULT_HTML = '''
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check-in Gym</title>
</head>
{% set color = '#10b981' if r.ok else ('#f59e0b' if r.code in ('duplicate', 'login') else '#ef4444') %}
<body style="background:#0b0f19; color:#f8fafc; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; font-family:'Inter', sans-serif;">
    <div style="background:#131b2e; padding:35px; border-radius:18px; border:1px solid #1e293b; border-top:4px solid {{ color }}; max-width:400px; width:90%; text-align:center; box-shadow:0 15px 35px rgba(0,0,0,0.5);">
        <div style="font-size:50px; margin-bottom:10px;">{{ '✅' if r.ok else ('⚠️' if r.code in ('duplicate', 'login') else '⛔') }}</div>
        <h2 style="color:{{ color }}; margin-bottom:10px;">{{ r.title }}</h2>
        <p style="color:#94a3b8; font-size:14px; margin-bottom:20px; line-height:1.5;">{{ r.message }}</p>
        {% if r.name %}
        <div style="background:#0b0f19; padding:15px; border-radius:10px; text-align:left; font-size:14px; line-height:1.8; margin-bottom:20px; border:1px solid #1e293b;">
            <b>Nama Member:</b> {{ r.name }}<br>
            <b>Kode Member:</b> {{ r.member_code }}<br>
            <b>Paket:</b> {{ r.package }}<br>
            <b>Sisa Membership:</b> {{ r.days }} hari<br>
            <b>Waktu:</b> {{ r.time }}
        </div>
        {% endif %}
        {% if r.code == 'login' %}
        <a href="/login" style="display:inline-block; padding:12px 20px; background:#f5b000; color:#121212; text-decoration:none; font-weight:bold; border-radius:8px; font-size:14px;">Login Admin</a>
        {% else %}
        <a href="/dashboard?menu=scan" style="display:inline-block; padding:12px 20px; background:#f5b000; color:#121212; text-decoration:none; font-weight:bold; border-radius:8px; font-size:14px;">Scan Berikutnya</a>
        {% endif %}
    </div>
</body>
</html>
'''

REGISTER_HTML = r'''<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Daftar Member - FIT HUB GYM</title>
<style>
  :root { --ink:#0a0c10; --card:#141821; --line:rgba(255,255,255,.14); --text:#f3f4f6; --mute:#9aa3b2; --gold:#f5b000; --gold2:#ffc933; --bad:#f87171; --ok:#34d399; }
  * { box-sizing:border-box; margin:0; padding:0; font-family:'Figtree','Segoe UI',system-ui,sans-serif; }
  body { min-height:100vh; background:var(--ink); color:var(--text); display:grid; place-items:center; padding:24px 16px; position:relative; isolation:isolate; }
  body::before { content:''; position:fixed; inset:0; z-index:-1; background:linear-gradient(rgba(10,12,16,.82), rgba(10,12,16,.92)), url('{{ hero_img }}') center/cover no-repeat; filter:grayscale(.6); }
  a { color:var(--gold); text-decoration:none; font-weight:700; }
  a:hover { text-decoration:underline; }
  :focus-visible { outline:3px solid var(--gold2); outline-offset:2px; }
  .card { width:100%; max-width:980px; background:var(--card); border:1px solid var(--line); border-radius:14px; display:grid; grid-template-columns:.9fr 1.1fr; gap:36px; padding:40px; box-shadow:0 30px 80px rgba(0,0,0,.6); }
  .logo { display:flex; align-items:center; gap:10px; font-weight:900; font-size:18px; margin-bottom:28px; }
  .logo i { font-style:normal; display:grid; place-items:center; width:34px; height:34px; background:var(--gold); color:var(--ink); border-radius:4px; font-size:15px; }
  h1 { font-size:30px; line-height:1.2; margin-bottom:12px; }
  .desc { color:var(--mute); font-size:15px; max-width:340px; }
  .steps { list-style:none; margin-top:34px; display:grid; gap:12px; }
  .steps li { display:flex; align-items:center; gap:12px; color:var(--mute); font-weight:600; font-size:14px; }
  .steps b { width:28px; height:28px; border-radius:50%; display:grid; place-items:center; border:2px solid var(--line); font-size:13px; }
  .steps li.on { color:var(--text); } .steps li.on b { border-color:var(--gold); background:var(--gold); color:var(--ink); }
  .steps li.done b { border-color:var(--ok); color:var(--ok); }
  .err { background:rgba(248,113,113,.12); border:1px solid rgba(248,113,113,.5); color:#fecaca; padding:10px 14px; border-radius:8px; font-size:14px; margin-bottom:16px; }
  .err:empty { display:none; }
  .fld { position:relative; margin-bottom:18px; }
  .fld input[type=text], .fld input[type=email], .fld input[type=tel], .fld input[type=password] { width:100%; padding:20px 14px 8px; background:transparent; border:1px solid #3b4252; border-radius:6px; color:#fff; font-size:16px; }
  .fld input:focus { border-color:var(--gold); outline:none; box-shadow:0 0 0 1px var(--gold); }
  .fld label { position:absolute; left:14px; top:15px; color:var(--mute); pointer-events:none; transition:all .15s; font-size:15px; }
  .fld input:focus + label, .fld input:not(:placeholder-shown) + label { top:5px; font-size:11px; color:var(--gold); }
  .fld.bad input { border-color:var(--bad); box-shadow:0 0 0 1px var(--bad); }
  .fld .msg { display:none; color:var(--bad); font-size:12px; margin-top:4px; }
  .fld.bad .msg { display:block; }
  .two { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
  .hint { color:var(--mute); font-size:13px; margin:-6px 0 14px; }
  .chk { display:flex; align-items:center; gap:10px; font-size:14px; color:var(--mute); cursor:pointer; margin-bottom:6px; }
  .chk input { width:18px; height:18px; accent-color:var(--gold); }
  .pk, .pm { display:flex; align-items:center; gap:14px; padding:14px 16px; border:1px solid #3b4252; border-radius:8px; margin-bottom:10px; cursor:pointer; position:relative; }
  .pk:has(input:checked), .pm:has(input:checked) { border-color:var(--gold); background:rgba(245,176,0,.08); }
  .pk input, .pm input { accent-color:var(--gold); width:18px; height:18px; flex:none; }
  .pk .n { font-weight:800; } .pk .d { color:var(--mute); font-size:13px; }
  .pk .p { margin-left:auto; text-align:right; font-weight:900; font-size:18px; }
  .pk .p small { display:block; font-size:12px; color:var(--gold); font-weight:700; }
  .tag { position:absolute; top:-9px; left:14px; background:var(--gold); color:var(--ink); font-size:11px; font-weight:800; padding:1px 8px; border-radius:3px; }
  .sum { background:var(--ink); border:1px solid var(--line); border-radius:8px; padding:14px 16px; margin-bottom:14px; display:flex; justify-content:space-between; align-items:center; gap:10px; }
  .sum .n { font-weight:800; color:var(--gold); } .sum .t { font-size:22px; font-weight:900; }
  .pay { background:var(--ink); border:1px solid rgba(245,176,0,.35); border-radius:8px; padding:16px; text-align:center; margin:12px 0 16px; }
  .pay img.q { width:100%; max-width:300px; background:#fff; border-radius:8px; display:block; margin:8px auto; }
  .pay small { display:block; color:var(--mute); font-size:12px; }
  .pay code { color:var(--gold); font-size:20px; font-weight:800; }
  .proof { border:1px dashed var(--gold); border-radius:8px; padding:14px; background:rgba(245,176,0,.05); }
  .proof label { font-weight:700; font-size:14px; display:block; margin-bottom:8px; }
  .proof img { display:none; max-width:100%; max-height:180px; margin-top:10px; border-radius:6px; }
  .actions { display:flex; justify-content:space-between; align-items:center; gap:12px; margin-top:26px; }
  .btn { padding:13px 26px; border:0; border-radius:6px; font-weight:800; font-size:15px; cursor:pointer; background:var(--gold); color:var(--ink); }
  .btn:hover { background:var(--gold2); } .btn:disabled { opacity:.6; cursor:wait; }
  .btn.ghost { background:transparent; color:var(--gold); }
  .btn.ghost:hover { background:rgba(245,176,0,.1); }
  [hidden] { display:none !important; }
  .right section { display:none; } .right section.on { display:block; }
  @media (max-width:820px) { .card { grid-template-columns:1fr; padding:26px 20px; gap:24px; } .steps { display:flex; gap:18px; margin-top:20px; } .steps span { display:none; } .steps li.on span { display:inline; } .desc { max-width:none; } }
  @media (max-width:440px) { .two { grid-template-columns:1fr; } }
</style>
</head>
<body>
<main class="card">
  <div class="left">
    <div class="logo"><i>FH</i> FIT HUB GYM</div>
    <h1 id="ttl">Buat akun FIT HUB</h1>
    <p class="desc" id="dsc">Isi data dirimu. Email dan password ini dipakai untuk masuk ke akun member.</p>
    <ol class="steps" aria-label="Langkah pendaftaran">
      <li data-s="1"><b>1</b><span>Data akun</span></li>
      <li data-s="2"><b>2</b><span>Pilih paket</span></li>
      <li data-s="3"><b>3</b><span>Pembayaran</span></li>
    </ol>
  </div>

  <form class="right" id="f" method="POST" action="/daftar" enctype="multipart/form-data" novalidate>
    <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
    <div class="err" id="err" role="alert">{{ error or '' }}</div>

    <section data-step="1">
      <div class="fld"><input type="text" name="name" id="name" maxlength="60" autocomplete="name" placeholder=" " value="{{ vals.name }}"><label for="name">Nama lengkap</label><div class="msg"></div></div>
      <div class="fld"><input type="email" name="email" id="email" maxlength="100" autocomplete="email" placeholder=" " value="{{ vals.email }}"><label for="email">Email</label><div class="msg"></div></div>
      <div class="fld"><input type="tel" name="phone" id="phone" maxlength="20" autocomplete="tel" inputmode="tel" placeholder=" " value="{{ vals.phone }}"><label for="phone">Nomor WhatsApp / HP</label><div class="msg"></div></div>
      <div class="two">
        <div class="fld"><input type="password" name="password" id="pw" minlength="8" autocomplete="new-password" placeholder=" "><label for="pw">Password</label><div class="msg"></div></div>
        <div class="fld"><input type="password" name="confirm" id="pw2" autocomplete="new-password" placeholder=" "><label for="pw2">Konfirmasi</label><div class="msg"></div></div>
      </div>
      <p class="hint">Gunakan 8 karakter atau lebih.</p>
      <label class="chk"><input type="checkbox" id="show"> Tampilkan password</label>
    </section>

    <section data-step="2">
      {% for p in packages %}
      <label class="pk">
        {% if p.best %}<span class="tag">Paling hemat</span>{% endif %}
        <input type="radio" name="package_id" value="{{ p.id }}" data-name="{{ p.name }}" data-price="{{ p.price_fmt }}"{% if p.id == preselect %} checked{% endif %}>
        <span><span class="n">{{ p.name }}</span><br><span class="d">{{ p.months }} bulan akses penuh</span></span>
        <span class="p">Rp {{ p.price_fmt }}<small>Sekitar Rp {{ p.per_month_fmt }} per bulan</small></span>
      </label>
      {% else %}
      <p class="desc">Paket belum tersedia. Silakan hubungi admin.</p>
      {% endfor %}
      <div class="msg" id="pkmsg" style="color:var(--bad);font-size:13px;display:none;">Pilih salah satu paket.</div>
    </section>

    <section data-step="3">
      <div class="sum"><div><div class="d" style="color:var(--mute);font-size:13px;">Paket dipilih</div><div class="n" id="sName">-</div></div><div class="t" id="sPrice">Rp 0</div></div>
      <label class="pm"><input type="radio" name="payment_method" value="qris" checked><span><b>Scan QRIS</b><br><small style="color:var(--mute)">Dari aplikasi bank atau e-wallet apa saja</small></span></label>
      <label class="pm"><input type="radio" name="payment_method" value="gopay_direct"><span><b>Transfer GoPay / DANA</b><br><small style="color:var(--mute)">Ke nomor HP pengelola</small></span></label>
      <div class="pay" id="payQris">
        <a href="/qris_image" target="_blank" rel="noopener"><img class="q" src="/qris_image" alt="QRIS pembayaran FIT HUB GYM"></a>
        <b>Bayar sebesar <span id="sPrice2" style="color:var(--gold)">Rp 0</span></b>
        <small>QRIS ini tidak memuat nominal, jadi isi sendiri sesuai total. Ketuk gambar untuk memperbesar.</small>
      </div>
      <div class="pay" id="payGopay" hidden>
        <small>Nomor GoPay / DANA</small><code>{{ gopay_number }}</code>
        <small>Atas nama {{ gopay_name }}</small>
      </div>
      <div class="proof">
        <label for="proof">Unggah bukti pembayaran (wajib)</label>
        <input type="file" name="payment_proof" id="proof" accept="image/png,image/jpeg,image/webp">
        <img id="prev" alt="Pratinjau bukti pembayaran">
        <small style="display:block;color:var(--mute);font-size:12px;margin-top:8px;">JPG, PNG, atau WebP, maksimal 5 MB. Membership aktif setelah admin memastikan uang masuk.</small>
      </div>
    </section>

    <div class="actions">
      <a href="/login" id="toLogin">Sudah punya akun? Masuk</a>
      <button type="button" class="btn ghost" id="back" hidden>Kembali</button>
      <button type="button" class="btn" id="next">Berikutnya</button>
      <button type="submit" class="btn" id="send" hidden>Kirim dan masuk</button>
    </div>
  </form>
</main>

<script>
(function () {
  var step = {{ start_step }};
  var TT = ['', 'Buat akun FIT HUB', 'Pilih paket membership', 'Bayar dan kirim bukti'];
  var DD = ['', 'Isi data dirimu. Email dan password ini dipakai untuk masuk ke akun member.',
    'Makin panjang durasinya, makin hemat biaya per bulan.',
    'Bayar sesuai total, lalu unggah bukti. Setelah mengirim, kamu langsung masuk ke area member.'];
  var $ = function (id) { return document.getElementById(id); };
  var f = $('f'), errBox = $('err');

  function show(n) {
    step = n;
    document.querySelectorAll('section[data-step]').forEach(function (s) { s.classList.toggle('on', +s.dataset.step === n); });
    document.querySelectorAll('.steps li').forEach(function (li) {
      var k = +li.dataset.s; li.classList.toggle('on', k === n); li.classList.toggle('done', k < n);
    });
    $('ttl').textContent = TT[n]; $('dsc').textContent = DD[n];
    $('back').hidden = n === 1; $('toLogin').hidden = n !== 1;
    $('next').hidden = n === 3; $('send').hidden = n !== 3;
    if (n === 3) fillSummary();
    window.scrollTo(0, 0);
  }
  function bad(id, msg) {
    var fld = $(id).closest('.fld'); fld.classList.add('bad'); fld.querySelector('.msg').textContent = msg;
  }
  function clearBad() { document.querySelectorAll('.fld.bad').forEach(function (x) { x.classList.remove('bad'); }); errBox.textContent = ''; }
  function chosen() { return f.querySelector('input[name=package_id]:checked'); }
  function fillSummary() {
    var c = chosen(); if (!c) return;
    $('sName').textContent = c.dataset.name; $('sPrice').textContent = 'Rp ' + c.dataset.price; $('sPrice2').textContent = 'Rp ' + c.dataset.price;
  }

  async function step1() {
    clearBad(); var ok = true, first = null;
    function need(id, cond, msg) { if (!cond) { bad(id, msg); ok = false; if (!first) first = id; } }
    var name = $('name').value.trim().replace(/\s+/g, ' ');
    need('name', name.length >= 2 && name.length <= 60 && !/[<>"'&`\\]/.test(name), 'Nama 2-60 karakter, tanpa tanda < > " \' & ` atau garis miring terbalik.');
    var em = $('email').value.trim();
    need('email', /^[^\s@<>"'&`\\]+@[^\s@<>"'&`\\]+\.[^\s@<>"'&`\\]+$/.test(em), 'Masukkan alamat email yang valid.');
    need('phone', /^\+?[0-9]{9,15}$/.test($('phone').value.replace(/[\s-]/g, '')), 'Nomor HP 9-15 angka.');
    need('pw', $('pw').value.length >= 8, 'Minimal 8 karakter.');
    need('pw2', $('pw2').value === $('pw').value && $('pw2').value !== '', 'Password tidak sama.');
    if (ok) {
      try {
        var r = await fetch('/daftar/cek-email?e=' + encodeURIComponent(em), { credentials: 'same-origin' });
        var j = await r.json();
        if (!j.ok) { bad('email', j.msg || 'Email ini sudah terdaftar. Coba masuk.'); ok = false; first = 'email'; }
      } catch (e) { /* server akan memeriksa ulang saat dikirim */ }
    }
    if (first) $(first).focus();
    return ok;
  }

  $('next').addEventListener('click', async function () {
    if (step === 1) { var b = this; b.disabled = true; var ok = await step1(); b.disabled = false; if (ok) show(2); }
    else if (step === 2) { if (!chosen()) { $('pkmsg').style.display = 'block'; return; } show(3); }
  });
  $('back').addEventListener('click', function () { show(step - 1); });
  f.addEventListener('input', function (e) { var fld = e.target.closest && e.target.closest('.fld'); if (fld) fld.classList.remove('bad'); });
  f.querySelectorAll('input[name=package_id]').forEach(function (r) { r.addEventListener('change', function () { $('pkmsg').style.display = 'none'; }); });
  $('show').addEventListener('change', function () { $('pw').type = $('pw2').type = this.checked ? 'text' : 'password'; });
  f.querySelectorAll('input[name=payment_method]').forEach(function (r) {
    r.addEventListener('change', function () { var q = f.querySelector('input[name=payment_method]:checked').value === 'qris'; $('payQris').hidden = !q; $('payGopay').hidden = q; });
  });
  $('proof').addEventListener('change', function () {
    var file = this.files[0], p = $('prev'); errBox.textContent = '';
    if (!file) { p.style.display = 'none'; return; }
    if (!/^image\/(png|jpeg|webp)$/.test(file.type) || file.size > 5 * 1024 * 1024) {
      errBox.textContent = 'Bukti harus berupa JPG, PNG, atau WebP maksimal 5 MB.'; this.value = ''; p.style.display = 'none'; return;
    }
    p.src = URL.createObjectURL(file); p.style.display = 'block';
  });
  f.addEventListener('keydown', function (e) { if (e.key === 'Enter' && e.target.tagName === 'INPUT' && e.target.type !== 'submit') { e.preventDefault(); if (!$('next').hidden) $('next').click(); } });
  f.addEventListener('submit', function (e) {
    if (!$('proof').files[0]) { e.preventDefault(); errBox.textContent = 'Unggah bukti pembayaran dulu.'; return; }
    var s = $('send'); s.disabled = true; s.textContent = 'Mengirim...';
  });
  show(step);
})();
</script>
</body>
</html>
'''

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
    page = render_template_string(
        REGISTER_HTML, error=error, start_step=start_step,
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
            return render_template_string(LOGIN_HTML, error=f'Terlalu banyak percobaan gagal. Coba lagi sekitar {minutes} menit.'), 429

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
            after_login = session.get('after_login', '')
            session.clear()
            session['user_id'] = user['id']
            session['name'] = user['name']
            session['role'] = user['role']
            session['unique_code'] = user['unique_code']
            if user['role'] == 'admin' and re.fullmatch(r'/qr_checkin/[0-9a-f.]{20,80}', after_login or ''):
                return redirect(after_login)
            return redirect(url_for('dashboard'))

        record_login_fail(ip, login_input)
        error = 'Akun atau password salah.'
        return render_template_string(LOGIN_HTML, error=error), 401
    return render_template_string(LOGIN_HTML, error=error)

@app.route('/api/my_qr')
def api_my_qr():
    """QR check-in milik member yang sedang login. Dipanggil ulang otomatis oleh halaman sebelum kedaluwarsa."""
    if session.get('role') != 'member':
        return jsonify(error='forbidden', message='Hanya untuk akun member.'), 403
    with sqlite3.connect(DB_PATH) as conn:
        active = member_is_active(conn, session['user_id'])
    if not active:
        resp = jsonify(error='inactive', message='Membership Anda belum aktif, jadi QR check-in belum tersedia.')
        resp.status_code = 403
    else:
        url = request.host_url + 'qr_checkin/' + make_qr_token(session['user_id'])
        svg = qr_svg(url)
        if svg is None:
            resp = jsonify(error='lib', message='Pustaka QR belum terpasang di server. Jalankan: pip install -r requirements.txt')
            resp.status_code = 500
        else:
            resp = jsonify(svg=svg, ttl=QR_TOKEN_TTL)
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/qr_checkin/<token>')
def qr_checkin(token):
    """Dibuka saat admin memindai QR member dengan kamera HP biasa. Wajib login sebagai admin."""
    if 'user_id' not in session:
        session['after_login'] = request.path       # setelah login admin langsung kembali ke sini
        return render_template_string(SCAN_RESULT_HTML, r={
            'ok': False, 'code': 'login', 'title': 'LOGIN ADMIN DIPERLUKAN',
            'message': 'Check-in hanya bisa diproses oleh admin gym. Login sebagai admin, lalu pindai ulang QR member.'}), 401
    if session.get('role') != 'admin':
        return render_template_string(SCAN_RESULT_HTML, r={
            'ok': False, 'code': 'forbidden', 'title': 'AKSES DITOLAK',
            'message': 'Hanya akun admin yang dapat memproses check-in. Member cukup menunjukkan QR ke admin di pintu masuk.'}), 403
    res = process_checkin(token, session['user_id'])
    resp = make_response(render_template_string(SCAN_RESULT_HTML, r=res))
    resp.headers['Cache-Control'] = 'no-store'
    return resp


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Dipakai pemindai kamera / scanner barcode di menu Scan Check-in (admin)."""
    if session.get('role') != 'admin':
        return jsonify(ok=False, code='forbidden', title='AKSES DITOLAK', message='Hanya admin.'), 403
    if not csrf_header_valid():
        return jsonify(ok=False, code='csrf', title='SESI KEDALUWARSA', message='Muat ulang halaman lalu coba lagi.'), 400
    if not rate_ok('scan', str(session['user_id']), 120, 60):
        return jsonify(ok=False, code='rate', title='TERLALU CEPAT', message='Terlalu banyak pemindaian. Tunggu sebentar.'), 429
    body = request.get_json(silent=True) or {}
    res = process_checkin(str(body.get('token', ''))[:400], session['user_id'])
    res['recent'] = recent_scans()
    resp = jsonify(res)
    resp.headers['Cache-Control'] = 'no-store'
    return resp


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
    return render_template_string(
        VISITOR_LANDING_HTML,
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
        notice = (f'<div style="background:{bg}; border:1px solid {color}; color:{color}; padding:10px 14px; '
                  f'border-radius:8px; font-size:13px; margin-bottom:16px;">{html.escape(text)}</div>')
    return f'''
        <div class="panel-box">
            <h3>Pengaturan Akun</h3>
            {notice}
            <form action="/action" method="POST" style="margin-top:15px;">
                <input type="hidden" name="action_type" value="update_account">
                <input type="hidden" name="csrf_token" value="{csrf_token}">
                <label>Nama Lengkap</label>
                <input type="text" name="name" value="{html.escape(current_name, quote=True)}" required minlength="2" maxlength="60">
                <label>Password Saat Ini <small style="font-weight:400;">(wajib diisi hanya jika ingin ganti password)</small></label>
                <input type="password" name="current_password" autocomplete="current-password" placeholder="Password saat ini">
                <label>Password Baru</label>
                <input type="password" name="new_password" minlength="{MIN_PASSWORD_LEN}" autocomplete="new-password" placeholder="Minimal {MIN_PASSWORD_LEN} karakter, kosongkan jika tidak diganti">
                <label>Ulangi Password Baru</label>
                <input type="password" name="confirm_password" autocomplete="new-password" placeholder="Ulangi password baru">
                <button type="submit" class="btn-primary">Simpan Perubahan</button>
            </form>
        </div>
    '''


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
        'manage_trainers': _BG_CARDIO, 'scan': _BG_CARDIO, 'visit_report': _BG_GYM, 'account': _BG_CALM,
    },
    'owner': {
        'dashboard': _BG_GYM, 'visit_report': _BG_FLOOR, 'account': _BG_CALM,
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
        '<svg viewBox="0 0 200 200" role="img" style="width:100%; max-width:220px;" '
        f'aria-label="Sisa masa aktif {remaining} dari {total} hari">'
        f'<circle cx="100" cy="100" r="{r}" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="22"/>'
        f'<circle cx="100" cy="100" r="{r}" fill="none" stroke="#f5b000" stroke-width="22" stroke-linecap="round" '
        f'stroke-dasharray="{circ * frac:.2f} {circ:.2f}" transform="rotate(-90 100 100)"/>'
        f'<text x="100" y="98" text-anchor="middle" fill="#f8fafc" font-size="34" font-weight="800">{remaining}</text>'
        '<text x="100" y="120" text-anchor="middle" fill="#94a3b8" font-size="12">hari tersisa</text>'
        '</svg>'
    )


def _bars_svg(labels, values, aria='Grafik jumlah check-in'):
    w, h = 460, 230
    left, right, top, bottom = 34, 10, 22, 36
    plot_w, plot_h = w - left - right, h - top - bottom
    peak = max(values + [4])
    step = max(1, -(-peak // 4))          # pembulatan ke atas
    top_val = step * 4
    out = [f'<svg viewBox="0 0 {w} {h}" role="img" style="width:100%;" aria-label="{html.escape(aria)}">']
    for i in range(5):
        y = top + plot_h - plot_h * i / 4
        out.append(f'<line x1="{left}" y1="{y:.1f}" x2="{w - right}" y2="{y:.1f}" stroke="rgba(255,255,255,0.08)"/>')
        out.append(f'<text x="{left - 6}" y="{y + 4:.1f}" text-anchor="end" fill="#94a3b8" font-size="10">{step * i}</text>')
    slot = plot_w / max(1, len(values))
    bar_w = min(46, slot * 0.55)
    for i, (lab, val) in enumerate(zip(labels, values)):
        x = left + slot * i + (slot - bar_w) / 2
        bh = plot_h * val / top_val
        y = top + plot_h - bh
        out.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{max(bh, 0):.1f}" rx="5" fill="#f5b000"/>')
        out.append(f'<text x="{x + bar_w / 2:.1f}" y="{y - 6:.1f}" text-anchor="middle" fill="#f8fafc" font-size="11" font-weight="700">{val}</text>')
        out.append(f'<text x="{x + bar_w / 2:.1f}" y="{h - 14}" text-anchor="middle" fill="#94a3b8" font-size="10">{html.escape(lab)}</text>')
    out.append('</svg>')
    return ''.join(out)


def _donut_multi_svg(parts, center_value, center_label, aria='Grafik donat'):
    """Donat beberapa segmen. parts = [(label, nilai, warna), ...]."""
    import math
    r = 70
    circ = 2 * math.pi * r
    total = sum(v for _, v, _ in parts)
    out = [f'<svg viewBox="0 0 200 200" role="img" style="width:100%; max-width:220px;" aria-label="{html.escape(aria)}">',
           f'<circle cx="100" cy="100" r="{r}" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="22"/>']
    cum = 0.0
    if total > 0:
        for _, v, color in parts:
            if v <= 0:
                continue
            seg = circ * v / total
            out.append(f'<circle cx="100" cy="100" r="{r}" fill="none" stroke="{color}" stroke-width="22" '
                       f'stroke-dasharray="{seg:.2f} {circ - seg:.2f}" stroke-dashoffset="{-cum:.2f}" '
                       'transform="rotate(-90 100 100)"/>')
            cum += seg
    out.append(f'<text x="100" y="100" text-anchor="middle" fill="#f8fafc" font-size="30" font-weight="800">{html.escape(str(center_value))}</text>')
    out.append(f'<text x="100" y="120" text-anchor="middle" fill="#94a3b8" font-size="12">{html.escape(center_label)}</text>')
    out.append('</svg>')
    return ''.join(out)


def _legend_html(parts):
    return ''.join(
        f'<div><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:{color};margin-right:8px;"></span>'
        f'{html.escape(label)}: <b>{value}</b></div>' for label, value, color in parts)


def _donut_panel(title, subtitle, parts, center_value, center_label, empty_text):
    if sum(v for _, v, _ in parts) <= 0:
        body = f'<p style="padding:30px 0; color:#94a3b8;">{html.escape(empty_text)}</p>'
    else:
        body = (f'<div style="display:flex; align-items:center; gap:18px; flex-wrap:wrap;">'
                f'{_donut_multi_svg(parts, center_value, center_label, title)}'
                f'<div style="font-size:13px; line-height:1.9;">{_legend_html(parts)}</div></div>')
    return (f'<div class="panel-box" style="margin-bottom:0;"><h3>{title}</h3>'
            f'<p style="margin-bottom:10px;">{subtitle}</p>{body}</div>')


def _bars_panel(title, subtitle, labels, values, empty_text):
    if sum(values) <= 0:
        body = f'<p style="padding:30px 0; color:#94a3b8;">{html.escape(empty_text)}</p>'
    else:
        body = _bars_svg(labels, values, title)
    return (f'<div class="panel-box" style="margin-bottom:0;"><h3>{title}</h3>'
            f'<p style="margin-bottom:10px;">{subtitle}</p>{body}</div>')


def _chart_grid(*panels):
    return ('<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:20px; margin:25px 0;">'
            + ''.join(panels) + '</div>')


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
        return ('<div class="panel-box"><h3>📊 Grafik Paket</h3>'
                '<p style="margin:8px 0 16px;">Belum ada paket aktif, jadi grafik belum bisa ditampilkan. '
                'Grafik muncul setelah pembayaran paket diverifikasi admin.</p>'
                '<a href="/dashboard?menu=packages" class="btn-primary">Lihat Paket Membership</a></div>')

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
    return f"""
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:20px; margin-bottom:25px;">
            <div class="panel-box" style="margin-bottom:0;">
                <h3>⏳ Masa Aktif {pkg_name}</h3>
                <p style="margin-bottom:10px;">Durasi paket {months} bulan ({months * 30} hari).</p>
                <div style="display:flex; align-items:center; gap:18px; flex-wrap:wrap;">
                    {_donut_svg(remaining, total)}
                    <div style="font-size:13px; line-height:1.9;">
                        <div><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#f5b000;margin-right:8px;"></span>Sisa: <b>{remaining} hari</b></div>
                        <div><span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:rgba(255,255,255,0.25);margin-right:8px;"></span>Terpakai: <b>{used} hari</b></div>
                    </div>
                </div>
            </div>
            <div class="panel-box" style="margin-bottom:0;">
                <h3>🏃 Kehadiran Check-in ({scope})</h3>
                <p style="margin-bottom:10px;">Total <b>{total_ci}</b> kali check-in pada periode ini.</p>
                {_bars_svg(labels, values)}
            </div>
        </div>
    """

# ---------------------------------------------------------------------------
# Halaman check-in (member), pemindai (admin), dan Laporan Kunjungan (admin & owner)
# ---------------------------------------------------------------------------
MEMBER_QR_HTML = '''
<span class="motto-tag">NO EXCUSES</span>
<h2>Check-in QR Code</h2>
<p style="margin-bottom:20px;">Tunjukkan QR ini ke admin di pintu masuk untuk dipindai. QR berganti otomatis dan hanya berlaku sebentar, jadi tidak bisa difoto lalu dipakai orang lain.</p>
<div class="panel-box" style="text-align:center;">
    <div id="qrBox" style="background:#fff; padding:12px; display:inline-block; width:260px; max-width:100%; min-height:260px; border-radius:12px; margin-bottom:12px;"></div>
    <div id="qrBarWrap" style="max-width:260px; height:6px; margin:0 auto 10px; background:rgba(255,255,255,.12); border-radius:99px; overflow:hidden;"><div id="qrBar" style="height:100%; width:0; background:#f5b000; transition:width 1s linear;"></div></div>
    <p id="qrMsg" style="font-size:13px;">Memuat QR...</p>
    <p style="font-size:12px; margin-top:8px;">Jangan kirim tangkapan layar QR ini ke siapa pun.</p>
</div>
<h3>Riwayat Check-in</h3>
<table><tr><th>Waktu (WIB)</th><th>Status</th><th>Keterangan</th></tr>__ROWS__</table>
<script>
(function () {
  var box = document.getElementById('qrBox'), msg = document.getElementById('qrMsg'), bar = document.getElementById('qrBar');
  var expireAt = 0, ttl = 90, loading = false;
  function say(t, bad) { msg.textContent = t; msg.style.color = bad ? '#fca5a5' : '#94a3b8'; }
  function load() {
    if (loading) return;
    loading = true;
    fetch('/api/my_qr', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); })
      .then(function (x) {
        loading = false;
        if (!x.ok) { box.innerHTML = ''; expireAt = 0; bar.style.width = '0'; say(x.j.message || 'QR tidak tersedia.', true); return; }
        box.innerHTML = x.j.svg;
        var s = box.querySelector('svg');
        if (s) {
          var w = s.getAttribute('width'), h = s.getAttribute('height');
          if (w && h && !s.getAttribute('viewBox')) s.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
          s.removeAttribute('width'); s.removeAttribute('height');
          s.style.width = '100%'; s.style.height = 'auto'; s.style.display = 'block';
          s.setAttribute('role', 'img'); s.setAttribute('aria-label', 'QR check-in');
        }
        ttl = x.j.ttl || 90;
        expireAt = Date.now() + ttl * 1000;
        tick();
      })
      .catch(function () { loading = false; say('Gagal memuat QR. Periksa koneksi internet Anda.', true); });
  }
  function tick() {
    if (!expireAt) return;
    var left = Math.max(0, Math.round((expireAt - Date.now()) / 1000));
    bar.style.width = Math.min(100, left * 100 / ttl) + '%';
    say('QR diperbarui otomatis dalam ' + left + ' detik.');
    if (left <= 20) load();
  }
  setInterval(tick, 1000);
  document.addEventListener('visibilitychange', function () { if (!document.hidden) load(); });
  load();
})();
</script>
'''

ADMIN_SCAN_HTML = '''
<span class="motto-tag">GERBANG MASUK</span>
<h2>Scan Check-in Member</h2>
<p style="margin-bottom:20px;">Pindai QR dari halaman <b>Check-in QR Code</b> milik member. Hanya QR yang masih berlaku, milik member dengan membership aktif, yang akan diterima.</p>
<div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:20px;">
  <div class="panel-box" style="margin-bottom:0;">
    <h3>📷 Kamera</h3>
    <div style="position:relative; background:#000; border-radius:12px; overflow:hidden; margin:12px 0; aspect-ratio:4/3; max-width:420px;">
      <video id="scanVideo" playsinline muted style="width:100%; height:100%; object-fit:cover; display:none;"></video>
      <div id="scanIdle" style="position:absolute; inset:0; display:grid; place-items:center; color:#94a3b8; font-size:13px; text-align:center; padding:16px;">Kamera belum aktif</div>
    </div>
    <button type="button" id="scanStart" class="btn-primary">Aktifkan Kamera</button>
    <p id="scanHint" style="font-size:12px; margin-top:10px;"></p>
    <h3 style="margin-top:22px;">⌨️ Scanner USB / Ketik Manual</h3>
    <form id="scanForm" autocomplete="off" style="display:flex; gap:10px; margin-top:10px;">
      <input type="text" id="scanInput" placeholder="Arahkan scanner ke QR, atau tempel isi QR di sini" maxlength="400" style="margin-bottom:0;">
      <button type="submit" class="btn-primary">Proses</button>
    </form>
  </div>
  <div class="panel-box" style="margin-bottom:0;">
    <h3>Hasil Pemindaian</h3>
    <div id="scanResult" aria-live="polite" style="margin:12px 0; padding:18px; border-radius:12px; border:1px solid rgba(255,255,255,.1); color:#94a3b8; font-size:14px;">Menunggu QR...</div>
    <h3 style="margin-top:20px;">Aktivitas Terakhir</h3>
    <table id="scanRecent" style="margin-top:8px;"><tr><th>Member</th><th>Waktu</th><th>Status</th></tr>__RECENT__</table>
  </div>
</div>
<script src="/static/js/jsQR.js"></script>
<script>
(function () {
  var CSRF = '__CSRF__';
  var video = document.getElementById('scanVideo'), idle = document.getElementById('scanIdle');
  var startBtn = document.getElementById('scanStart'), hint = document.getElementById('scanHint');
  var form = document.getElementById('scanForm'), input = document.getElementById('scanInput');
  var out = document.getElementById('scanResult'), recent = document.getElementById('scanRecent');
  var busy = false, lastRaw = '', lastAt = 0, stream = null, resetTimer = null;
  var COLORS = { ok: '#10b981', duplicate: '#f59e0b', denied: '#ef4444', expired: '#ef4444', invalid: '#ef4444' };

  function el(tag, text, css) { var e = document.createElement(tag); if (text != null) e.textContent = text; if (css) e.style.cssText = css; return e; }

  function showResult(r) {
    var c = r.ok ? COLORS.ok : (COLORS[r.code] || '#ef4444');
    out.innerHTML = '';
    out.style.borderColor = c; out.style.background = 'rgba(255,255,255,.03)'; out.style.color = '#f8fafc';
    out.appendChild(el('div', (r.ok ? '✅ ' : '⛔ ') + (r.title || ''), 'font-size:20px; font-weight:800; color:' + c + '; margin-bottom:6px;'));
    out.appendChild(el('div', r.message || '', 'color:#94a3b8; margin-bottom:' + (r.name ? '12px' : '0') + ';'));
    if (r.name) {
      out.appendChild(el('div', r.name + ' (' + r.member_code + ')', 'font-weight:700; font-size:16px;'));
      out.appendChild(el('div', 'Paket: ' + r.package + ' · Sisa ' + r.days + ' hari', 'color:#94a3b8; font-size:13px; margin-top:2px;'));
    }
    clearTimeout(resetTimer);
    resetTimer = setTimeout(function () {
      out.textContent = 'Menunggu QR...'; out.style.borderColor = 'rgba(255,255,255,.1)'; out.style.color = '#94a3b8';
    }, 8000);
  }

  function showRecent(list) {
    while (recent.rows.length > 1) recent.deleteRow(1);
    list.forEach(function (x) {
      var tr = recent.insertRow();
      tr.insertCell().textContent = x.name + ' (' + x.unique_code + ')';
      tr.insertCell().textContent = x.checkin_time;
      tr.insertCell().textContent = x.status;
    });
  }

  function send(raw) {
    raw = (raw || '').trim();
    if (!raw || busy) return;
    var now = Date.now();
    if (raw === lastRaw && now - lastAt < 5000) return;   // kamera membaca QR yang sama berkali-kali
    lastRaw = raw; lastAt = now; busy = true;
    fetch('/api/scan', { method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF },
      body: JSON.stringify({ token: raw }) })
      .then(function (r) { return r.json(); })
      .then(function (r) { showResult(r); if (r.recent) showRecent(r.recent); })
      .catch(function () { showResult({ ok: false, code: 'invalid', title: 'GAGAL TERHUBUNG', message: 'Server tidak merespons. Coba lagi.' }); })
      .then(function () { busy = false; input.value = ''; input.focus(); });
  }

  form.addEventListener('submit', function (e) { e.preventDefault(); lastRaw = ''; send(input.value); });
  input.focus();

  function startLoop() {
    var detector = null;
    if ('BarcodeDetector' in window) { try { detector = new BarcodeDetector({ formats: ['qr_code'] }); } catch (e) { detector = null; } }
    var canvas = document.createElement('canvas'), ctx = canvas.getContext('2d', { willReadFrequently: true });
    function next() { setTimeout(loop, 200); }
    function loop() {
      if (!stream) return;
      if (detector) {
        detector.detect(video).then(function (codes) { if (codes.length) send(codes[0].rawValue); }).catch(function () {}).then(next);
        return;
      }
      if (video.readyState >= 2 && video.videoWidth && window.jsQR) {
        var w = Math.min(640, video.videoWidth), h = Math.round(w * video.videoHeight / video.videoWidth);
        canvas.width = w; canvas.height = h;
        ctx.drawImage(video, 0, 0, w, h);
        var img = ctx.getImageData(0, 0, w, h);
        var res = window.jsQR(img.data, w, h, { inversionAttempts: 'dontInvert' });
        if (res && res.data) send(res.data);
      }
      next();
    }
    loop();
  }

  startBtn.addEventListener('click', function () {
    if (!window.isSecureContext || !navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      if (location.protocol === 'http:' && __HTTPS_ON__) {   // browser memblokir kamera di http://<IP>; pindah otomatis ke versi HTTPS (sesi login tetap berlaku)
        hint.textContent = 'Memindahkan ke koneksi aman (HTTPS) supaya kamera bisa dipakai...';
        location.href = 'https://' + location.hostname + ':__HTTPS_PORT__/dashboard?menu=scan&cam=1';
        return;
      }
      hint.textContent = __HTTPS_ON__ ? 'Kamera tidak tersedia di browser ini. Pakai scanner USB atau kolom manual di bawah.'
        : 'HTTPS belum aktif di server. Hentikan aplikasi, jalankan: pip install -r requirements.txt, lalu python app.py lagi. Sementara itu pakai scanner USB atau kolom manual di bawah.';
      return;
    }
    startBtn.disabled = true; hint.textContent = 'Membuka kamera...';
    navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false }).then(function (s) {
      stream = s; video.srcObject = s; video.style.display = 'block'; idle.style.display = 'none';
      startBtn.textContent = 'Kamera Aktif'; hint.textContent = 'Arahkan kamera ke QR di layar HP member.';
      return video.play();
    }).then(startLoop).catch(function (err) {
      startBtn.disabled = false;
      hint.textContent = (err && err.name === 'NotAllowedError') ? 'Akses kamera ditolak. Klik ikon gembok di address bar, izinkan Kamera, lalu coba lagi.'
        : (err && err.name === 'NotFoundError') ? 'Kamera tidak ditemukan di perangkat ini.' : 'Kamera tidak bisa dibuka. Pastikan tidak dipakai aplikasi lain.';
    });
  });
  if (location.search.indexOf('cam=1') !== -1 && window.isSecureContext) startBtn.click();   // setelah dipindah ke HTTPS
  window.addEventListener('pagehide', function () { if (stream) stream.getTracks().forEach(function (t) { t.stop(); }); });
})();
</script>
'''


HTTP_PORT, HTTPS_PORT = 8080, 8443
HTTPS_ENABLED = False      # diaktifkan di bagian bawah file bila sertifikat HTTPS berhasil dibuat


def member_checkin_html(checkins):
    rows = ''.join(
        f"<tr><td>{safe(c['checkin_time'])}</td>"
        f"<td><span class='badge {'badge-success' if c['status'] == 'Berhasil' else 'badge-danger'}'>{safe(c['status'])}</span></td>"
        f"<td>{safe(c['note'] if 'note' in c.keys() and c['note'] else '-')}</td></tr>"
        for c in checkins) or "<tr><td colspan='3'>Belum ada riwayat check-in.</td></tr>"
    return MEMBER_QR_HTML.replace('__ROWS__', rows)


def admin_scan_html(csrf_token):
    rows = ''.join(
        f"<tr><td>{safe(r['name'])} ({safe(r['unique_code'])})</td><td>{safe(r['checkin_time'])}</td>"
        f"<td>{safe(r['status'])}</td></tr>" for r in recent_scans()) or ''
    return ADMIN_SCAN_HTML.replace('__HTTPS_ON__', 'true' if HTTPS_ENABLED else 'false').replace('__HTTPS_PORT__', str(HTTPS_PORT)).replace('__RECENT__', rows).replace('__CSRF__', html.escape(csrf_token, quote=True))


# ---- Laporan kunjungan ----
def _parse_day(value, fallback):
    try:
        return datetime.strptime(str(value or '')[:10], '%Y-%m-%d').date()
    except ValueError:
        return fallback


def visit_filters(args):
    today = datetime.now().date()
    d_from = _parse_day(args.get('from'), today.replace(day=1))
    d_to = _parse_day(args.get('to'), today)
    if d_to < d_from:
        d_from, d_to = d_to, d_from
    if (d_to - d_from).days > 365:
        d_from = d_to - timedelta(days=365)
    status = args.get('status', 'all')
    if status not in ('all', 'Berhasil', 'Ditolak'):
        status = 'all'
    member = ' '.join(str(args.get('member', '')).split())[:60]
    return {'from': d_from, 'to': d_to, 'status': status, 'member': member}


def visit_rows(f):
    sql = ("SELECT c.id, c.checkin_time, c.status, c.note, u.name, u.unique_code, s.name AS staff_name "
           "FROM checkins c JOIN users u ON u.id = c.user_id LEFT JOIN users s ON s.id = c.scanned_by "
           "WHERE substr(c.checkin_time, 1, 10) BETWEEN ? AND ?")
    params = [f['from'].isoformat(), f['to'].isoformat()]
    if f['status'] != 'all':
        sql += " AND c.status = ?"
        params.append(f['status'])
    if f['member']:
        like = '%' + f['member'].replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        sql += " AND (u.name LIKE ? ESCAPE '\\' OR u.unique_code LIKE ? ESCAPE '\\')"
        params += [like, like]
    sql += " ORDER BY c.id DESC"
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(sql, params).fetchall()


def _visit_buckets(f, days_list):
    """Kelompokkan kunjungan agar grafik tetap terbaca: harian (<=14 hari), mingguan (<=12 minggu), selebihnya bulanan."""
    span = (f['to'] - f['from']).days + 1
    if span <= 14:
        keys = [f['from'] + timedelta(days=i) for i in range(span)]
        labels = [k.strftime('%d/%m') for k in keys]
        values = [sum(1 for d in days_list if d == k) for k in keys]
        return labels, values, 'per hari'
    if span <= 84:
        n = -(-span // 7)
        starts = [f['from'] + timedelta(days=7 * i) for i in range(n)]
        labels = [s.strftime('%d/%m') for s in starts]
        values = [sum(1 for d in days_list if s <= d <= s + timedelta(days=6)) for s in starts]
        return labels, values, 'per minggu (tanggal awal minggu)'
    keys, y, m = [], f['from'].year, f['from'].month
    while (y, m) <= (f['to'].year, f['to'].month):
        keys.append((y, m))
        m += 1
        if m == 13:
            y, m = y + 1, 1
    labels = [_BULAN[k[1] - 1] + f" {str(k[0])[2:]}" for k in keys]
    values = [sum(1 for d in days_list if (d.year, d.month) == k) for k in keys]
    return labels, values, 'per bulan'


def visit_report_html(args, role):
    f = visit_filters(args)
    rows = visit_rows(f)
    ok = [r for r in rows if r['status'] == 'Berhasil']
    denied = sum(1 for r in rows if r['status'] == 'Ditolak')
    days_list, hours, per_member = [], {}, {}
    for r in ok:
        t = str(r['checkin_time'])
        try:
            days_list.append(datetime.strptime(t[:10], '%Y-%m-%d').date())
            hours[int(t[11:13])] = hours.get(int(t[11:13]), 0) + 1
        except ValueError:
            continue
        key = (r['unique_code'], r['name'])
        per_member[key] = per_member.get(key, 0) + 1
    span = (f['to'] - f['from']).days + 1
    unique = len(per_member)
    avg = f"{len(ok) / span:.1f}".replace('.', ',')
    peak = max(hours, key=lambda h: hours[h]) if hours else None
    peak_txt = f"{peak:02d}.00–{peak + 1:02d}.00" if peak is not None else '-'

    labels, values, scope = _visit_buckets(f, days_list)
    day_chart = _bars_svg(labels, values, 'Grafik kunjungan')
    h0, h1 = min([6] + list(hours)), max([21] + list(hours))
    hour_labels = [f'{h:02d}' for h in range(h0, h1 + 1)]
    hour_chart = _bars_svg(hour_labels, [hours.get(h, 0) for h in range(h0, h1 + 1)], 'Grafik jam ramai')

    top = sorted(per_member.items(), key=lambda kv: (-kv[1], kv[0][1]))[:5]
    top_rows = ''.join(f"<tr><td>{safe(c)}</td><td><b>{safe(n)}</b></td><td>{v}x</td></tr>" for (c, n), v in top) \
        or "<tr><td colspan='3'>Belum ada kunjungan pada periode ini.</td></tr>"

    shown = rows[:200]
    table_rows = ''.join(
        f"<tr><td>{safe(r['checkin_time'])}</td><td><b>{safe(r['name'])}</b> <small style='color:#94a3b8;'>({safe(r['unique_code'])})</small></td>"
        f"<td><span class='badge {'badge-success' if r['status'] == 'Berhasil' else 'badge-danger'}'>{safe(r['status'])}</span></td>"
        f"<td>{safe(r['note'] or '-')}</td><td>{safe(r['staff_name'] or '-')}</td></tr>" for r in shown) \
        or "<tr><td colspan='5' style='text-align:center; color:#94a3b8;'>Tidak ada data pada filter ini.</td></tr>"
    more = f"<p style='margin-top:8px; font-size:12px;'>Menampilkan 200 terbaru dari {len(rows)} data. Unduh CSV untuk data lengkap.</p>" if len(rows) > 200 else ''

    qs = f"from={f['from'].isoformat()}&to={f['to'].isoformat()}&status={f['status']}&member={quote(f['member'])}"
    status_opts = ''.join(f"<option value='{v}'{' selected' if f['status'] == v else ''}>{t}</option>"
                          for v, t in (('all', 'Semua'), ('Berhasil', 'Berhasil'), ('Ditolak', 'Ditolak')))
    return f'''
        <span class="motto-tag">LAPORAN KUNJUNGAN</span>
        <h2>Laporan Kunjungan Member</h2>
        <p style="margin-bottom:20px;">Data diambil langsung dari check-in QR Code. Periode {f['from']:%d/%m/%Y} – {f['to']:%d/%m/%Y}.</p>
        <form method="GET" action="/dashboard" class="panel-box" style="display:flex; gap:14px; flex-wrap:wrap; align-items:flex-end;">
            <input type="hidden" name="menu" value="visit_report">
            <div><label>Dari</label><input type="date" name="from" value="{f['from'].isoformat()}" style="margin-bottom:0;"></div>
            <div><label>Sampai</label><input type="date" name="to" value="{f['to'].isoformat()}" style="margin-bottom:0;"></div>
            <div><label>Member (nama / kode)</label><input type="text" name="member" value="{safe(f['member'])}" maxlength="60" placeholder="Semua member" style="margin-bottom:0;"></div>
            <div><label>Status</label><select name="status" style="margin-bottom:0;">{status_opts}</select></div>
            <button type="submit" class="btn-primary">Terapkan</button>
            <a href="/visit_report.csv?{qs}" class="btn-primary" style="background:transparent; border:1px solid #f5b000; color:#f5b000;">Unduh CSV</a>
            <button type="button" class="btn-primary" onclick="window.print()" style="background:transparent; border:1px solid #f5b000; color:#f5b000;">Cetak / PDF</button>
        </form>
        <div class="card-grid">
            <div class="card"><h3>Total Kunjungan</h3><div class="value">{len(ok)}</div></div>
            <div class="card"><h3>Member Berbeda</h3><div class="value">{unique}</div></div>
            <div class="card"><h3>Rata-rata / Hari</h3><div class="value">{avg}</div></div>
            <div class="card"><h3>Jam Paling Ramai</h3><div class="value" style="font-size:20px;">{peak_txt}</div></div>
            <div class="card"><h3>Check-in Ditolak</h3><div class="value" style="color:var(--warning);">{denied}</div></div>
        </div>
        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(300px, 1fr)); gap:20px; margin-bottom:25px;">
            <div class="panel-box" style="margin-bottom:0;"><h3>🏃 Kunjungan {scope}</h3>{day_chart}</div>
            <div class="panel-box" style="margin-bottom:0;"><h3>🕒 Jam Ramai</h3>{hour_chart}</div>
        </div>
        <div class="panel-box">
            <h3 style="margin-bottom:10px;">🏆 Member Paling Rajin</h3>
            <table><tr><th>Kode</th><th>Nama</th><th>Kunjungan</th></tr>{top_rows}</table>
        </div>
        <h3 style="margin:10px 0 12px;">Daftar Kunjungan</h3>
        <div style="overflow-x:auto;"><table><tr><th>Waktu</th><th>Member</th><th>Status</th><th>Keterangan</th><th>Dipindai oleh</th></tr>{table_rows}</table></div>
        {more}
    '''


def _csv_cell(value):
    text = '' if value is None else str(value)
    return "'" + text if text[:1] in ('=', '+', '-', '@', '\t', '\r') else text   # cegah formula injection di Excel


@app.route('/visit_report.csv')
def visit_report_csv():
    if session.get('role') not in ('admin', 'owner'):
        abort(403)
    f = visit_filters(request.args)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(['Waktu', 'Kode Member', 'Nama', 'Status', 'Keterangan', 'Dipindai oleh'])
    for r in visit_rows(f):
        w.writerow([_csv_cell(x) for x in (r['checkin_time'], r['unique_code'], r['name'], r['status'], r['note'] or '', r['staff_name'] or '')])
    resp = make_response('﻿' + buf.getvalue())
    resp.headers['Content-Type'] = 'text/csv; charset=utf-8'
    resp.headers['Content-Disposition'] = f'attachment; filename="laporan-kunjungan-{f["from"]}_{f["to"]}.csv"'
    resp.headers['Cache-Control'] = 'no-store'
    return resp


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
        data['equipment_categories'] = get_equipment_options(cursor, 'category')
        data['equipment_statuses'] = get_equipment_options(cursor, 'status')
        cursor.execute("""SELECT payments.*, users.name,
                                  membership_packages.package_name
                           FROM payments JOIN users ON payments.member_id = users.id
                           LEFT JOIN membership_packages ON payments.package_id = membership_packages.id
                           ORDER BY CASE WHEN payments.status='Pending' THEN 0 ELSE 1 END,
                                    payments.id DESC""")
        data['payments'] = cursor.fetchall()
        cursor.execute("SELECT COUNT(*) FROM users WHERE role='member'")
        data['total_members'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM checkins WHERE status = 'Berhasil'")
        data['total_checkins'] = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM payments WHERE status = 'Pending'")
        data['pending_payments'] = cursor.fetchone()[0]
        since = (datetime.now().date() - timedelta(days=6)).isoformat()
        cursor.execute("SELECT substr(checkin_time, 1, 10) AS d, COUNT(*) AS n FROM checkins "
                       "WHERE status = 'Berhasil' AND substr(checkin_time, 1, 10) >= ? GROUP BY d", (since,))
        data['checkin_by_day'] = {r['d']: r['n'] for r in cursor.fetchall()}
        cursor.execute("SELECT COUNT(*) FROM checkins WHERE status = 'Berhasil' AND checkin_time LIKE ?", (datetime.now().strftime('%Y-%m-%d') + '%',))
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
        cursor.execute("SELECT COUNT(*) FROM checkins WHERE status = 'Berhasil' AND checkin_time LIKE ?", (f"{today_str}%",))
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
        cursor.execute("SELECT COUNT(*) FROM checkins WHERE status = 'Berhasil'")
        data['total_checkins'] = cursor.fetchone()[0]

        # 7b. Kunjungan bulan ini (check-in berhasil)
        cursor.execute("SELECT COUNT(*) FROM checkins WHERE status = 'Berhasil' AND substr(checkin_time, 1, 7) = ?", (today_str[:7],))
        data['visits_month'] = cursor.fetchone()[0]

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
            profile_box = f'''
            <div class="panel-box">
                <h3>Profil Member</h3>
                <table style="margin-top:12px;">
                    <tr><th style="width:200px;">Kode Member</th><td>{html.escape(str(u['unique_code']))}</td></tr>
                    <tr><th>Nama</th><td>{html.escape(str(u['name']))}</td></tr>
                    <tr><th>Email</th><td>{html.escape(str(u['email'] or '-'))}</td></tr>
                    <tr><th>Nomor HP</th><td>{html.escape(str(u['phone'] or '-'))}</td></tr>
                    <tr><th>Paket</th><td>{pk_name}</td></tr>
                    <tr><th>Status Paket</th><td>{pf_status}</td></tr>
                    <tr><th>Sisa Membership</th><td>{pf_days} Hari</td></tr>
                </table>
            </div>'''
        body_content = f'''
            <span class="motto-tag">AKUN SAYA</span>
            <h2>Akun Saya</h2>
            <p style="margin-bottom:20px;">Lihat profil, ubah nama tampilan, atau ganti password Anda. Kode akun: <b>{html.escape(session.get('unique_code', ''))}</b></p>
            {profile_box}
            {account_form_html(csrf_token, session.get('name', ''), session.pop('account_msg', None))}
        '''
    elif role == 'admin' and menu == 'scan':
        body_content = admin_scan_html(csrf_token)
    elif role in ('admin', 'owner') and menu == 'visit_report':
        body_content = visit_report_html(request.args, role)
    elif role == 'member':
        if menu == 'dashboard':
            p = data['profile'] or {'remaining_days': 0, 'status_paket': 'Belum Aktif'}
            pend = [x for x in data['payments'] if x['status'] == 'Pending']
            pending_banner = ''
            if pend:
                pending_banner = ('<div class="panel-box" style="border-left:4px solid #f59e0b; margin-bottom:20px;">'
                                  f'<b>Pembayaran {safe(pend[0]["package_name"])} sedang diverifikasi admin.</b><br>'
                                  '<span style="font-size:13px; color:#94a3b8;">Membership aktif setelah admin memastikan uang masuk. Kamu akan mendapat notifikasi.</span></div>')
            body_content = f'''
                <span class="motto-tag">BETTER THAN YESTERDAY</span>
                <h2>Dashboard Utama Member</h2>
                <p style="margin-bottom:25px;">Selamat datang kembali, <b>{session['name']}</b>!</p>
                {pending_banner}
                <div class="card-grid">
                    <div class="card"><h3>Sisa Hari Membership</h3><div class="value">{p["remaining_days"]} Hari</div></div>
                    <div class="card"><h3>Status Paket Aktif</h3><div class="value" style="font-size:18px; color:var(--success);">{p["status_paket"]}</div></div>
                    <div class="card"><h3>Jadwal Latihan Hari Ini</h3><div class="value" style="font-size:16px;">Push & Core Workout</div></div>
                </div>
                {member_package_charts(data['profile'], data['active_package'], data['checkins'])}
            '''
        elif menu == 'packages':
            pay_rows = "".join([f"<tr><td>#TRX-{p['id']}</td><td>{safe(p['package_name'])}</td><td>Rp {p['amount']:,.0f}</td><td>{safe(p['payment_date'])}</td><td><span class='badge {'badge-success' if p['status']=='Lunas' else ('badge-danger' if p['status']=='Ditolak' else 'badge-warning')}'>{safe(p['status'])}</span></td></tr>" for p in data['payments']])
            if not pay_rows:
                pay_rows = '<tr><td colspan="5">Belum ada transaksi pembayaran.</td></tr>'
            rows = "".join([f"<tr><td><b>{pkg['package_name']}</b></td><td>{pkg['duration_months']} Bulan ({pkg['duration_months']*30} Hari)</td><td>Rp {pkg['price']:,.0f}</td><td><button class='btn-primary' style='padding:8px 16px; font-size:13px;' onclick='openPaymentModal({pkg["id"]}, \"{pkg["package_name"]}\", {pkg["price"]}, {pkg["duration_months"]})'>Pilih Paket</button></td></tr>" for pkg in data['packages']])
            body_content = f'''
                <span class="motto-tag">MEMBERSHIP ACCESS</span>
                <h2>Paket Membership</h2>
                <p style="margin-bottom:20px;">Pilihan paket fleksibel untuk kebutuhan kebugaran Anda.</p>
                <table><tr><th>Nama Paket</th><th>Durasi</th><th>Harga</th><th>Aksi</th></tr>{rows}</table>

                <h3 id="riwayat-pembayaran" style="margin:32px 0 8px;">💳 Riwayat Pembayaran</h3>
                <p style="margin-bottom:14px;">Pembayaran baru berstatus <b>Pending</b> sampai admin memverifikasi uang masuk. Bukti upload saja belum berarti lunas.</p>
                <div style="overflow-x:auto;"><table style="margin-bottom:25px;"><tr><th>ID Transaksi</th><th>Paket</th><th>Jumlah</th><th>Tanggal</th><th>Status</th></tr>{pay_rows}</table></div>

                <!-- MODAL CHECKOUT PEMBAYARAN GOPAY & QRIS -->
                <div id="paymentModal" class="modal-overlay">
                    <div class="modal-box" style="max-height:90vh; overflow-y:auto;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
                            <h3 style="font-size:18px; color:#f8fafc;">Checkout Pembayaran Gym</h3>
                            <button onclick="closePaymentModal()" style="background:none; border:none; color:#94a3b8; font-size:20px; cursor:pointer;">✕</button>
                        </div>
                        
                        <div style="background:#0b0f19; padding:15px; border-radius:10px; margin-bottom:20px; border:1px solid rgba(255,255,255,0.1);">
                            <div style="font-size:13px; color:#94a3b8;">Paket Yang Dipilih:</div>
                            <div id="modalPackageName" style="font-size:18px; font-weight:bold; color:#f5b000;">-</div>
                            <div id="modalPackagePrice" style="font-size:20px; font-weight:800; color:#fff; margin-top:5px;">Rp 0</div>
                        </div>

                        <form action="/action" method="POST" enctype="multipart/form-data">
                            <input type="hidden" name="csrf_token" value="{csrf_token}">
                            <input type="hidden" name="action_type" value="process_payment">
                            <input type="hidden" name="package_id" id="inputPackageId">
                            <!-- Harga/durasi hanya dihitung oleh server dari database -->
                            
                            <label style="margin-bottom:12px; display:block;">Pilih Metode Pembayaran:</label>
                            
                            <div class="payment-method-card" onclick="selectPaymentMethod('qris')">
                                <div><b>📱 Scan QRIS Pembayaran Gym</b><br><small style="color:#94a3b8;">Gunakan aplikasi pembayaran yang mendukung QRIS.</small></div>
                                <input type="radio" name="payment_method" id="radioQris" value="qris" required>
                            </div>

                            <div class="payment-method-card" onclick="selectPaymentMethod('gopay_direct')">
                                <div><b>💙 Direct GoPay / Transfer Nomor HP</b><br><small style="color:#94a3b8;">Transfer langsung ke Nomor GoPay Pengelola</small></div>
                                <input type="radio" name="payment_method" id="radioGopay" value="gopay_direct">
                            </div>

                            <!-- DETAIL QRIS -->
                            <div id="qrisDetail" style="display:none; text-align:center; padding:15px; background:#0b0f19; border-radius:10px; margin:15px 0; border:1px solid rgba(245, 176, 0, 0.3);">
                                <p style="font-size:13px; color:#f8fafc; font-weight:bold; margin-bottom:10px;">Scan QRIS di Bawah Ini:</p>
                                <a href="/qris_image" target="_blank" rel="noopener" title="Ketuk untuk memperbesar"><img src="/qris_image" style="width:100%; max-width:340px; height:auto; border-radius:8px; background:#fff; display:block; margin:0 auto;" alt="QRIS Pembayaran Gym"></a>
                                <p style="font-size:14px; color:#f8fafc; margin-top:12px;">Nominal yang dibayar: <b id="modalQrisAmount" style="color:#f5b000; font-size:18px;">Rp 0</b></p>
                                <p style="font-size:12px; color:#94a3b8; margin-top:4px;">QRIS ini tidak memuat nominal, jadi isi sendiri sesuai total di atas.</p>
                                <p style="font-size:12px; color:#94a3b8; margin-top:10px;">Nama merchant pada QRIS: <b style="color:#f5b000;">Gym fitnes, Wisata</b>. Pastikan tujuan pembayaran sesuai yang tampil di aplikasi Anda.</p>
                                <p style="font-size:12px; color:#f59e0b; margin-top:8px;">QRIS ini memerlukan pengecekan transaksi secara manual. Menekan tombol konfirmasi bukan bukti pembayaran berhasil.</p>
                            </div>

                            <!-- DETAIL GOPAY DIRECT -->
                            <div id="gopayDetail" style="display:none; padding:15px; background:#0b0f19; border-radius:10px; margin:15px 0; font-size:13px; border:1px solid rgba(245, 176, 0, 0.3);">
                                <b>Nomor HP GoPay / DANA:</b><br>
                                <code style="color:#f5b000; font-size:18px; font-weight:bold;">{GOPAY_NUMBER}</code><br>
                                <b>Atas Nama:</b> {GOPAY_NAME}<br>
                                <small style="color:#94a3b8; display:block; margin-top:6px;">Lakukan transfer GoPay/DANA sesuai nominal harga paket di atas.</small>
                            </div>

                            <div style="background:rgba(245,176,0,0.06); border:1px solid rgba(245,176,0,0.25); border-radius:10px; padding:15px; margin-top:15px;">
                                <label for="paymentProof" style="color:#f8fafc;">Upload Bukti Pembayaran (wajib)</label>
                                <input type="file" name="payment_proof" id="paymentProof" accept="image/png,image/jpeg,image/webp" required style="margin-bottom:8px;">
                                <p style="font-size:12px;">Format JPG, PNG, atau WebP, maksimum 5 MB. Admin akan mencocokkan bukti dengan riwayat transaksi yang benar-benar masuk ke rekening/merchant.</p>
                            </div>
                            <button type="submit" class="btn-primary" style="width:100%; margin-top:15px; padding:14px;">KIRIM BUKTI — MENUNGGU VERIFIKASI</button>
                        </form>
                    </div>
                </div>

                <script>
                    function openPaymentModal(id, name, price, duration) {{
                        document.getElementById('paymentModal').style.display = 'flex';
                        document.getElementById('modalPackageName').innerText = name;
                        document.getElementById('modalPackagePrice').innerText = 'Rp ' + price.toLocaleString('id-ID');
                        document.getElementById('inputPackageId').value = id;
                        document.getElementById('modalQrisAmount').innerText = 'Rp ' + price.toLocaleString('id-ID');
                        selectPaymentMethod('qris');
                        // Harga dan durasi selalu diambil ulang dari database saat transaksi disimpan.
                    }}
                    function closePaymentModal() {{
                        document.getElementById('paymentModal').style.display = 'none';
                    }}
                    function selectPaymentMethod(type) {{
                        document.getElementById('qrisDetail').style.display = (type === 'qris') ? 'block' : 'none';
                        document.getElementById('gopayDetail').style.display = (type === 'gopay_direct') ? 'block' : 'none';
                        if(type === 'qris') document.getElementById('radioQris').checked = true;
                        if(type === 'gopay_direct') document.getElementById('radioGopay').checked = true;
                    }}
                </script>
            '''
        elif menu == 'checkin':
            body_content = member_checkin_html(data['checkins'])
        elif menu == 'workouts':
            rows = "".join([f"<tr><td><b>{safe(w['exercise_name'])}</b></td><td>{w['sets']} Set</td><td>{w['reps']} Rep</td><td>{w['weight_kg']} kg</td><td>{safe(w['schedule_date'])} {safe(w['schedule_time'])}</td><td>{video_html(w['video_url'])}</td><td><span class='badge {'badge-success' if w['status']=='Selesai' else 'badge-warning'}'>{safe(w['status'])}</span></td></tr>" for w in data['workouts']])
            if not rows:
                rows = '<tr><td colspan="7">Belum ada program latihan dari trainer.</td></tr>'
            body_content = f'''
                <span class="motto-tag">DISCIPLINE BUILDS RESULTS</span>
                <h2>Program Latihan</h2>
                <p style="margin-bottom:20px;">Daftar latihan langsung dari trainer pribadi Anda, lengkap dengan video panduan gerakan.</p>
                <div style="overflow-x:auto;"><table><tr><th>Latihan</th><th>Set</th><th>Repetisi</th><th>Beban</th><th>Jadwal</th><th>Video Panduan</th><th>Status</th></tr>{rows}</table></div>
            '''
        elif menu == 'progress':
            rows = "".join([f"<tr><td>{pr['recorded_date']}</td><td>{pr['weight']} kg</td><td>{pr['body_fat']}%</td><td>{pr['stomach_circumference']} cm</td></tr>" for pr in data['progress']])
            t = data['target']
            last = data['progress'][0] if data['progress'] else None
            if t:
                target_section = '<h3 style="margin-bottom:12px;">🎯 Target dari Trainer</h3><div class="card-grid">' \
                    + target_card('Berat Badan', 'kg', t['start_weight'], last['weight'] if last else None, t['target_weight']) \
                    + target_card('Body Fat', '%', t['start_body_fat'], last['body_fat'] if last else None, t['target_body_fat']) \
                    + '</div>'
                if t['notes']:
                    target_section += f"<p style='margin-bottom:20px;'>Catatan trainer: {safe(t['notes'])}</p>"
            else:
                target_section = '<p style="margin-bottom:20px;">Trainer belum menetapkan target untuk Anda.</p>'
            body_content = f'''
                <span class="motto-tag">SMALL STEPS BIG CHANGES</span>
                <h2>Progres & Perkembangan Fisik</h2>
                <p style="margin-bottom:20px;">Rekam jejak perubahan tubuh Anda.</p>
                {target_section}
                <table><tr><th>Tanggal</th><th>Berat Badan</th><th>Body Fat</th><th>Lingkar Perut</th></tr>{rows}</table>
            '''

    elif role == 'trainer':
        if menu == 'dashboard':
            body_content = f'''
                <h2>Dashboard Trainer</h2>
                <p style="margin-bottom:25px;">Selamat bertugas, <b>{session['name']}</b>!</p>
                <div class="card-grid">
                    <div class="card"><h3>Member Binaan Aktif</h3><div class="value">{len(data['members'])} Orang</div></div>
                    <div class="card"><h3>Program Latihan Aktif</h3><div class="value">{len(data['workouts'])} Program</div></div>
                    <div class="card"><h3>Member Terbaru</h3><div class="value" style="font-size:16px;">{data['members'][0]['name'] if data['members'] else '-'}</div></div>
                </div>
                {trainer_charts(data['workouts'], data['members'])}
            '''
        elif menu == 'assign_workout':
            options = "".join([f"<option value='{m['id']}'>{safe(m['name'])} ({safe(m['unique_code'])})</option>" for m in data['members']])
            sent_rows = "".join([f"<tr><td>{safe(w['member_name'])}</td><td>{safe(w['exercise_name'])} ({w['sets']}x{w['reps']})</td><td>{safe(w['schedule_date'])} {safe(w['schedule_time'])}</td><td>{'🎬 Ada video' if w['video_url'] else '—'}</td></tr>" for w in data['workouts']])
            if not sent_rows:
                sent_rows = '<tr><td colspan="4">Belum ada program yang dikirim.</td></tr>'
            body_content = f'''
                <h2>Program Latihan Member</h2>
                <div class="panel-box">
                    <form action="/action" method="POST">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <input type="hidden" name="action_type" value="add_workout">
                        <label>Pilih Member Binaan</label><select name="member_id" required>{options}</select>
                        <label>Nama Latihan (Bench Press, Squat, Plank)</label><input type="text" name="exercise_name" required maxlength="100">
                        <div style="display:flex; gap:15px;">
                            <div style="flex:1;"><label>Set</label><input type="number" name="sets" min="1" required></div>
                            <div style="flex:1;"><label>Repetisi</label><input type="number" name="reps" min="1" required></div>
                            <div style="flex:1;"><label>Beban (kg)</label><input type="number" step="0.5" min="0" name="weight_kg" required></div>
                        </div>
                        <div style="display:flex; gap:15px;">
                            <div style="flex:1;"><label>Tanggal Latihan</label><input type="date" name="schedule_date" required></div>
                            <div style="flex:1;"><label>Jam Latihan</label><input type="time" name="schedule_time" required></div>
                        </div>
                        <label>Link Video Panduan (opsional)</label>
                        <input type="url" name="video_url" maxlength="500" placeholder="https://www.youtube.com/watch?v=... atau link file .mp4" style="margin-bottom:8px;">
                        <p style="margin-bottom:20px; font-size:12px;">Link YouTube tampil sebagai pemutar di dashboard member. Link file .mp4/.webm juga didukung.</p>
                        <button type="submit" class="btn-primary">Kirim Program Latihan</button>
                    </form>
                </div>
                <h3>Program yang Sudah Dikirim</h3>
                <div style="overflow-x:auto;"><table><tr><th>Member</th><th>Latihan</th><th>Jadwal</th><th>Video</th></tr>{sent_rows}</table></div>
            '''
        elif menu == 'set_target':
            tmap = {t['member_id']: t for t in data['targets']}
            mmap = {m['id']: m for m in data['members']}
            opt_list = []
            for m in data['members']:
                tg = tmap.get(m['id'])
                opt_list.append(
                    f"<option value='{m['id']}' data-lw='{attr_num(m['last_weight'])}' data-lbf='{attr_num(m['last_body_fat'])}' "
                    f"data-sw='{attr_num(tg['start_weight']) if tg else ''}' data-tw='{attr_num(tg['target_weight']) if tg else ''}' "
                    f"data-sbf='{attr_num(tg['start_body_fat']) if tg else ''}' data-tbf='{attr_num(tg['target_body_fat']) if tg else ''}' "
                    f"data-notes='{safe(tg['notes']) if tg else ''}'>{safe(m['name'])} ({safe(m['unique_code'])})</option>")
            options = "".join(opt_list)
            trows = ""
            for t in data['targets']:
                m = mmap.get(t['member_id'])
                cur_w = m['last_weight'] if m else None
                cur_bf = m['last_body_fat'] if m else None
                pw = progress_pct(t['start_weight'], cur_w, t['target_weight'])
                pbf = progress_pct(t['start_body_fat'], cur_bf, t['target_body_fat'])
                trows += (f"<tr><td><b>{safe(t['member_name'])}</b><br><small style='color:var(--text-muted);'>{safe(t['unique_code'])}</small></td>"
                          f"<td>{fmt_num(t['start_weight'])} → <b>{fmt_num(t['target_weight'])}</b> kg<br><small style='color:var(--text-muted);'>Saat ini {fmt_num(cur_w)} kg{' · ' + str(pw) + '%' if pw is not None else ''}</small></td>"
                          f"<td>{fmt_num(t['start_body_fat'])} → <b>{fmt_num(t['target_body_fat'])}</b> %<br><small style='color:var(--text-muted);'>Saat ini {fmt_num(cur_bf)} %{' · ' + str(pbf) + '%' if pbf is not None else ''}</small></td>"
                          f"<td>{safe(t['notes'] or '-')}</td></tr>")
            if not trows:
                trows = '<tr><td colspan="4">Belum ada target yang ditetapkan.</td></tr>'
            body_content = f'''
                <h2>Target Latihan Member</h2>
                <p style="margin-bottom:20px;">Isi berat badan &amp; body fat awal, lalu targetnya. Jika member sudah punya target, form terisi otomatis dan bisa diperbarui.</p>
                <div class="panel-box">
                    <form action="/action" method="POST">
                        <input type="hidden" name="csrf_token" value="{csrf_token}">
                        <input type="hidden" name="action_type" value="set_target">
                        <label>Pilih Member Binaan</label><select name="member_id" id="targetMember" required>{options}</select>
                        <div style="display:flex; gap:15px; flex-wrap:wrap;">
                            <div style="flex:1; min-width:200px;"><label>Berat Badan Awal (kg)</label><input type="number" step="0.1" min="20" max="300" name="start_weight" id="startWeight" required></div>
                            <div style="flex:1; min-width:200px;"><label>Target Berat Badan (kg)</label><input type="number" step="0.1" min="20" max="300" name="target_weight" id="targetWeight" required></div>
                        </div>
                        <div style="display:flex; gap:15px; flex-wrap:wrap;">
                            <div style="flex:1; min-width:200px;"><label>Body Fat Awal (%)</label><input type="number" step="0.1" min="2" max="60" name="start_body_fat" id="startBodyFat" required></div>
                            <div style="flex:1; min-width:200px;"><label>Target Body Fat (%)</label><input type="number" step="0.1" min="2" max="60" name="target_body_fat" id="targetBodyFat" required></div>
                        </div>
                        <label>Catatan Target</label><textarea rows="3" name="notes" id="targetNotes" maxlength="500"></textarea>
                        <button type="submit" class="btn-primary">Simpan Target</button>
                    </form>
                </div>
                <h3>Target Aktif Member</h3>
                <div style="overflow-x:auto;"><table><tr><th>Member</th><th>Berat Badan (awal → target)</th><th>Body Fat (awal → target)</th><th>Catatan</th></tr>{trows}</table></div>
                <script>
                    (function() {{
                        var sel = document.getElementById('targetMember');
                        function setVal(id, v) {{ document.getElementById(id).value = v || ''; }}
                        function fill() {{
                            var o = sel.options[sel.selectedIndex];
                            if (!o) return;
                            var d = o.dataset;
                            setVal('startWeight', d.sw || d.lw);
                            setVal('targetWeight', d.tw);
                            setVal('startBodyFat', d.sbf || d.lbf);
                            setVal('targetBodyFat', d.tbf);
                            setVal('targetNotes', d.notes);
                        }}
                        sel.addEventListener('change', fill);
                        fill();
                    }})();
                </script>
            '''
        elif menu == 'monitor_progress':
            rows = ""
            for w in data['workouts']:
                dt_obj = datetime.strptime(w['schedule_date'], '%Y-%m-%d') if w['schedule_date'] else datetime.now()
                day_name = ['Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu', 'Minggu'][dt_obj.weekday()]
                month_name = ['Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni', 'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember'][dt_obj.month - 1]
                rows += f"<tr><td>{w['member_name']}</td><td>{w['exercise_name']} ({w['sets']}x{w['reps']})</td><td>{dt_obj.day} {month_name} {dt_obj.year} ({day_name}) - {w['schedule_time']}</td><td><span class='badge {'badge-success' if w['status']=='Selesai' else 'badge-warning'}'>{w['status']}</span></td></tr>"
            body_content = f'<h2>Progres & Jadwal Member</h2><table><tr><th>Member</th><th>Latihan</th><th>Jadwal</th><th>Status</th></tr>{rows}</table>'

    elif role == 'admin':
        if menu == 'dashboard':
            signup_rows = "".join([
                f"<tr><td>{safe(s['unique_code'])}</td><td><b>{safe(s['name'])}</b></td><td>{safe(s['phone'] or '-')}</td>"
                f"<td>{safe(s['package_name'] or '-')}</td><td>{safe((s['registered_at'] or '-')[:16])}</td>"
                f"<td><span class='badge {'badge-success' if s['pay_status']=='Lunas' else ('badge-danger' if s['pay_status']=='Ditolak' else 'badge-warning')}'>{safe(s['pay_status'] or '-')}</span></td></tr>"
                for s in data['new_signups']]) or "<tr><td colspan='6'>Belum ada pendaftar mandiri.</td></tr>"
            body_content = f'''
                <h2>Dashboard Admin Operasional</h2>
                <div class="card-grid">
                    <div class="card"><h3>Total Member</h3><div class="value">{data['total_members']} Orang</div></div>
                    <div class="card"><h3>Check-in Hari Ini</h3><div class="value">{data['checkins_today']} Sesi</div><a href="/dashboard?menu=scan" style="color:#f5b000; font-size:13px; font-weight:700;">Scan Check-in</a> &middot; <a href="/dashboard?menu=visit_report" style="color:#f5b000; font-size:13px; font-weight:700;">Laporan</a></div>
                    <div class="card"><h3>Inventaris Layak</h3><div class="value">{round(sum(1 for e in data['equipment'] if e['status'] == 'Tersedia') * 100 / len(data['equipment'])) if data['equipment'] else 0}%</div></div>
                    <div class="card"><h3>Pembayaran Menunggu Verifikasi</h3><div class="value" style="color:var(--warning);">{data['pending_payments']}</div><a href="/dashboard?menu=manage_payments" style="color:#f5b000; font-size:13px; font-weight:700;">Buka Kelola Pembayaran</a></div>
                </div>
                {admin_charts(data['payments'], data['equipment'], data['checkin_by_day'])}
                <h3 style="margin:28px 0 12px;">Pendaftar Terbaru</h3>
                <div style="overflow-x:auto;"><table><tr><th>Kode</th><th>Nama</th><th>Telepon</th><th>Paket</th><th>Mendaftar</th><th>Pembayaran</th></tr>{signup_rows}</table></div>
            '''
        elif menu == 'manage_members':
            rows = "".join([f"<tr><td>{m['unique_code']}</td><td><b>{m['name']}</b></td><td>{m['email']}</td><td>{m['phone'] or '-'}</td><td><form action='/action' method='POST' style='display:inline;'><input type='hidden' name='action_type' value='delete_user'><input type='hidden' name='id' value='{m['id']}'><button type='submit' class='btn-danger'>Hapus</button></form></td></tr>" for m in data['members']])
            body_content = f'''
                <h2>Kelola Data Member</h2>
                <div class="panel-box">
                    <h3>➕ Tambah Member Baru</h3>
                    <form action="/action" method="POST" style="margin-top:15px;">
                        <input type="hidden" name="action_type" value="add_user">
                        <input type="hidden" name="role" value="member">
                        <label>Nama Lengkap Member</label><input type="text" name="name" required placeholder="Contoh: Rina Wijaya">
                        <label>Email</label><input type="email" name="email" required placeholder="rina@gmail.com">
                        <label>Nomor Telepon</label><input type="text" name="phone" placeholder="08123456789">
                        <label>Password Akun</label><input type="password" name="password" required minlength="8" autocomplete="new-password" placeholder="Minimal 8 karakter">
                        <button type="submit" class="btn-primary">Daftarkan Member Baru</button>
                    </form>
                </div>
                <h3>Daftar Member Terdaftar</h3>
                <form method="GET" action="/dashboard"><input type="hidden" name="menu" value="manage_members"><input type="text" name="q" class="search-box" placeholder="Cari member..." value="{search_query}"></form>
                <table><tr><th>Kode Unik</th><th>Nama Member</th><th>Email</th><th>Telepon</th><th>Aksi</th></tr>{rows}</table>
            '''
        elif menu == 'manage_trainers':
            rows = "".join([f"<tr><td>{t['unique_code']}</td><td><b>{t['name']}</b></td><td>{t['email']}</td><td>{t['phone'] or '-'}</td><td><form action='/action' method='POST' style='display:inline;'><input type='hidden' name='action_type' value='delete_user'><input type='hidden' name='id' value='{t['id']}'><button type='submit' class='btn-danger'>Hapus</button></form></td></tr>" for t in data['trainers']])
            body_content = f'''
                <h2>Kelola Data Trainer</h2>
                <div class="panel-box">
                    <h3>➕ Tambah Trainer Baru</h3>
                    <form action="/action" method="POST" style="margin-top:15px;">
                        <input type="hidden" name="action_type" value="add_user">
                        <input type="hidden" name="role" value="trainer">
                        <label>Nama Lengkap Trainer</label><input type="text" name="name" required placeholder="Contoh: Coach Hendra">
                        <label>Email</label><input type="email" name="email" required placeholder="hendra@gym.com">
                        <label>Nomor Telepon</label><input type="text" name="phone" placeholder="0812998877">
                        <label>Password Akun</label><input type="password" name="password" required minlength="8" autocomplete="new-password" placeholder="Minimal 8 karakter">
                        <button type="submit" class="btn-primary">Daftarkan Trainer Baru</button>
                    </form>
                </div>
                <h3>Daftar Trainer Aktif</h3>
                <table><tr><th>Kode Unik</th><th>Nama Trainer</th><th>Email</th><th>Telepon</th><th>Aksi</th></tr>{rows}</table>
            '''
        elif menu == 'manage_packages':
            rows = "".join([f"<tr><td>{p['package_name']}</td><td>{p['duration_months']} Bulan</td><td>Rp {p['price']:,.0f}</td><td><span class='badge badge-success'>{p['status']}</span></td></tr>" for p in data['packages']])
            body_content = f'<h2>Kelola Paket Membership</h2><table><tr><th>Paket</th><th>Durasi</th><th>Harga</th><th>Status</th></tr>{rows}</table>'
        elif menu == 'manage_equipment':
            rows = "".join([f"<tr><td>{safe(eq['equipment_name'])}</td><td>{safe(eq['category'])}</td><td><span class='badge {'badge-success' if eq['status']=='Tersedia' else ('badge-warning' if eq['status']=='Perbaikan' else 'badge-danger')}'>{safe(eq['status'])}</span></td></tr>" for eq in data['equipment']])
            body_content = f'''
                <h2>Data Alat Gym</h2>
                <div style="display:flex;gap:25px;flex-wrap:wrap;margin-bottom:25px;">
                    {equipment_options_panel(csrf_token, 'category', '🏷️ Kategori Alat', 'Kategori baru, mis. Fungsional', data['equipment_categories'], {e['category'] for e in data['equipment']})}
                    {equipment_options_panel(csrf_token, 'status', '📌 Status Alat', 'Status baru, mis. Dipinjam', data['equipment_statuses'], {e['status'] for e in data['equipment']})}
                </div>
                <div class="panel-box">
                    <h3 style="margin-bottom:14px;">➕ Tambah Alat</h3>
                    {equipment_form_html(csrf_token, data['equipment_categories'], data['equipment_statuses'])}
                </div>
                <table><tr><th>Nama Alat</th><th>Kategori</th><th>Status</th></tr>{rows}</table>
            '''
        elif menu == 'manage_payments':
            rows = ""
            for p in data['payments']:
                status = p['status']
                badge_class = 'badge-success' if status == 'Lunas' else ('badge-danger' if status == 'Ditolak' else 'badge-warning')
                method = {'qris': 'QRIS', 'gopay_direct': 'Transfer'}.get(p['payment_method'], '—')
                proof = (f"<a href='/payment_proof/{p['id']}' target='_blank' class='btn-primary' style='padding:6px 10px; font-size:11px;'>Lihat Bukti</a>"
                         if p['proof_filename'] else '—')
                if status == 'Pending':
                    action_buttons = f"""
                      <form action='/action' method='POST' style='display:inline-block; margin:2px;'>
                        <input type='hidden' name='csrf_token' value='{csrf_token}'>
                        <input type='hidden' name='action_type' value='verify_payment'>
                        <input type='hidden' name='payment_id' value='{p['id']}'>
                        <button class='btn-primary' style='padding:7px 11px; font-size:11px;' type='submit'>Verifikasi Lunas</button>
                      </form>
                      <form action='/action' method='POST' style='display:inline-block; margin:2px;'>
                        <input type='hidden' name='csrf_token' value='{csrf_token}'>
                        <input type='hidden' name='action_type' value='reject_payment'>
                        <input type='hidden' name='payment_id' value='{p['id']}'>
                        <button class='btn-danger' type='submit'>Tolak</button>
                      </form>
                    """
                else:
                    action_buttons = 'Sudah diproses'
                rows += f"""<tr><td>#TRX-{p['id']}</td><td><b>{p['name']}</b></td>
                    <td>{p['package_name'] or '-'}</td><td>Rp {p['amount']:,.0f}</td>
                    <td>{method}</td><td>{p['payment_date']}</td>
                    <td>{proof}</td><td><span class='badge {badge_class}'>{status}</span></td>
                    <td>{action_buttons}</td></tr>"""
            if not rows:
                rows = '<tr><td colspan="9">Belum ada transaksi.</td></tr>'
            body_content = f"""<h2>Kelola & Verifikasi Pembayaran Member</h2>
                <p style='margin-bottom:20px;'>Cek bukti transfer <b>dan mutasi dana masuk</b> pada akun merchant. Hanya klik Verifikasi Lunas setelah jumlah, waktu, dan penerima cocok.</p>
                <div class='panel-box' style='overflow-x:auto;'>
                    <table><tr><th>ID</th><th>Member</th><th>Paket</th><th>Nominal</th><th>Metode</th>
                    <th>Tanggal</th><th>Bukti</th><th>Status</th><th>Aksi Admin</th></tr>{rows}</table>
                </div>"""

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
            chart_content = '<div style="text-align:center; padding:50px; color:#94a3b8;">Belum ada data transaksi lunas untuk ditampilkan pada grafik.</div>'
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
                
                svg_items.append(f'''
                    <g>
                        <rect x="{x}" y="{y}" width="{bar_width}" height="{bar_h}" fill="#f5b000" rx="6" opacity="0.9">
                            <title>{m_label}: Rp {val:,.0f}</title>
                        </rect>
                        <text x="{x + bar_width/2}" y="{chart_height - 12}" fill="#94a3b8" font-size="11" text-anchor="middle">{m_label}</text>
                        <text x="{x + bar_width/2}" y="{y - 8}" fill="#f8fafc" font-size="10" font-weight="bold" text-anchor="middle">Rp {val/1000:,.0f}k</text>
                    </g>
                ''')
            chart_content = f'''
                <svg viewBox="0 0 550 {chart_height}" style="width:100%; height:auto; max-height:220px;">
                    <line x1="30" y1="{chart_height-30}" x2="520" y2="{chart_height-30}" stroke="rgba(255,255,255,0.1)" stroke-width="1"/>
                    {"".join(svg_items)}
                </svg>
            '''

        pay_rows = ""
        if data['recent_payments']:
            for p in data['recent_payments']:
                pay_rows += f"<tr><td><b>{p['member_name']}</b></td><td>{p['package_name'] or 'Membership'}</td><td>{p['payment_date']}</td><td><b>Rp {p['amount']:,.0f}</b></td><td><span class='badge badge-success'>{p['status']}</span></td></tr>"
        else:
            pay_rows = "<tr><td colspan='5' style='text-align:center; color:#94a3b8;'>Belum ada riwayat transaksi.</td></tr>"

        checkin_rows = ""
        if data['recent_checkins']:
            for c in data['recent_checkins']:
                checkin_rows += f"<tr><td><b>{safe(c['member_name'])}</b> <small style='color:#94a3b8;'>({safe(c['unique_code'])})</small></td><td>{safe(c['checkin_time'])}</td><td><span class='badge {'badge-success' if c['status'] == 'Berhasil' else 'badge-danger'}'>{safe(c['status'])}</span></td></tr>"
        else:
            checkin_rows = "<tr><td colspan='3' style='text-align:center; color:#94a3b8;'>Belum ada check-in hari ini.</td></tr>"

        alert_box = ""
        if data['expiring_soon'] > 0:
            alert_box += f'''
                <div style="background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.35); padding: 16px 22px; border-radius: 12px; margin-bottom: 25px; display: flex; align-items: center; justify-content: space-between;">
                    <div style="display: flex; align-items: center; gap: 14px;">
                        <span style="font-size: 22px;">⚠️</span>
                        <div>
                            <b style="color: #f59e0b; font-size: 14px;">Pemberitahuan Penting: {data['expiring_soon']} Member Masa Aktifnya Segera Berakhir (&le; 7 hari)</b>
                            <p style="color: #94a3b8; font-size: 12px; margin: 2px 0 0 0;">Harap koordinasikan dengan tim admin untuk melakukan follow-up perpanjangan paket.</p>
                        </div>
                    </div>
                    <span class="badge badge-warning">Perlu Perhatian</span>
                </div>
            '''

        body_content = f'''
            <span class="motto-tag">EXECUTIVE BUSINESS MONITORING</span>
            <h2>Dashboard Eksekutif Owner</h2>
            <p style="margin-bottom:25px;">Selamat datang kembali, <b>{session['name']}</b>. Berikut adalah laporan performa bisnis "FIT HUB GYM ACCESS".</p>
            
            {alert_box}

            <!-- 6 KARTU STATISTIK UTAMA -->
            <div class="card-grid">
                <div class="card">
                    <h3>Total Pendapatan Gym</h3>
                    <div class="value" style="color: #f5b000;">{formatted_revenue}</div>
                    <small style="color: var(--success); font-size: 11px;">Akumulasi Lunas</small>
                </div>
                <div class="card">
                    <h3>Total Member Aktif</h3>
                    <div class="value">{data['total_active_members']} <span style="font-size: 14px; color: var(--text-muted);">Org</span></div>
                    <small style="color: var(--success); font-size: 11px;">Masa Aktif &gt; 0 Hari</small>
                </div>
                <div class="card">
                    <h3>Check-in Hari Ini</h3>
                    <div class="value">{data['checkins_today']} <span style="font-size: 14px; color: var(--text-muted);">Sesi</span></div>
                    <small style="color: var(--text-muted); font-size: 11px;">Live Hari Ini</small>
                </div>
                <div class="card">
                    <h3>Kunjungan Bulan Ini</h3>
                    <div class="value">{data['visits_month']} <span style="font-size: 14px; color: var(--text-muted);">Sesi</span></div>
                    <a href="/dashboard?menu=visit_report" style="color:#f5b000; font-size:11px; font-weight:700;">Buka Laporan Kunjungan</a>
                </div>
                <div class="card">
                    <h3>Total Member</h3>
                    <div class="value">{data['total_members']} <span style="font-size: 14px; color: var(--text-muted);">Org</span></div>
                    <small style="color: var(--text-muted); font-size: 11px;">Terdaftar di Sistem</small>
                </div>
                <div class="card">
                    <h3>Segera Berakhir</h3>
                    <div class="value" style="color: var(--warning);">{data['expiring_soon']} <span style="font-size: 14px; color: var(--text-muted);">Org</span></div>
                    <small style="color: var(--warning); font-size: 11px;">Masa Aktif &le; 7 Hari</small>
                </div>
                <div class="card">
                    <h3>Transaksi Berhasil</h3>
                    <div class="value">{data['successful_transactions']} <span style="font-size: 14px; color: var(--text-muted);">Trx</span></div>
                    <small style="color: var(--success); font-size: 11px;">Status Lunas</small>
                </div>
            </div>

            <!-- GRAFIK PENDAPATAN & RINGKASAN -->
            <div class="owner-grid-split" style="display: grid; grid-template-columns: 2fr 1fr; gap: 24px; margin-bottom: 30px;">
                <div class="panel-box" style="max-width: 100%; margin-bottom: 0;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                        <div>
                            <h3 style="font-size: 16px; color: #f8fafc;">Grafik Tren Pendapatan Bulanan</h3>
                            <p style="font-size: 12px; color: #94a3b8; margin: 2px 0 0 0;">Perkembangan omset pendapatan dari transaksi lunas</p>
                        </div>
                        <span class="badge badge-success">Real-Time Data</span>
                    </div>
                    {chart_content}
                </div>

                <div class="panel-box" style="max-width: 100%; margin-bottom: 0; display: flex; flex-direction: column; justify-content: space-between;">
                    <div>
                        <h3 style="font-size: 16px; color: #f8fafc; margin-bottom: 10px;">Ringkasan Operasional</h3>
                        <p style="font-size: 12px; color: #94a3b8; margin-bottom: 20px;">Indikator kesehatan bisnis gym.</p>
                        
                        <div style="display: flex; flex-direction: column; gap: 14px;">
                            <div style="background: rgba(11, 15, 25, 0.6); padding: 12px 15px; border-radius: 10px; border: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-size: 13px; color: #94a3b8;">Rata-rata Trx</span>
                                <b style="color: #f5b000; font-size: 13px;">Rp {int(data['total_revenue'] / data['successful_transactions']) if data['successful_transactions'] > 0 else 0:,.0f}</b>
                            </div>
                            <div style="background: rgba(11, 15, 25, 0.6); padding: 12px 15px; border-radius: 10px; border: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-size: 13px; color: #94a3b8;">Akumulasi Check-in</span>
                                <b style="color: #10b981; font-size: 13px;">{data['total_checkins']} Sesi</b>
                            </div>
                            <div style="background: rgba(11, 15, 25, 0.6); padding: 12px 15px; border-radius: 10px; border: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center;">
                                <span style="font-size: 13px; color: #94a3b8;">Sistem Server</span>
                                <b style="color: #10b981; font-size: 13px;">🟢 Online (WIB)</b>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- TABEL TRANSAKSI TERBARU & CHECK-IN -->
            <div class="owner-grid-split" style="display: grid; grid-template-columns: 1.4fr 1fr; gap: 24px; margin-bottom: 30px;">
                <div class="panel-box" style="max-width: 100%; margin-bottom: 0;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <h3 style="font-size: 16px; color: #f8fafc;">Transaksi Pembayaran Terbaru</h3>
                        <span style="font-size: 12px; color: #94a3b8;">5 Teratas</span>
                    </div>
                    <table style="margin-top: 5px;">
                        <tr>
                            <th>Member</th>
                            <th>Paket</th>
                            <th>Tanggal</th>
                            <th>Jumlah</th>
                            <th>Status</th>
                        </tr>
                        {pay_rows}
                    </table>
                </div>

                <div class="panel-box" style="max-width: 100%; margin-bottom: 0;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                        <h3 style="font-size: 16px; color: #f8fafc;">Aktivitas Check-in Terbaru</h3>
                        <a href="/dashboard?menu=visit_report" style="font-size: 12px; color: #f5b000; font-weight:700;">Laporan lengkap &rarr;</a>
                    </div>
                    <table style="margin-top: 5px;">
                        <tr>
                            <th>Member</th>
                            <th>Waktu</th>
                            <th>Status</th>
                        </tr>
                        {checkin_rows}
                    </table>
                </div>
            </div>

            <!-- LAPORAN KEUANGAN & REKAPITULASI -->
            <div class="panel-box" style="max-width:100%;">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
                    <div>
                        <h3 style="font-size:18px; color: #f8fafc;">Laporan Keuangan & Rekapitulasi Bulanan</h3>
                        <p style="font-size:12px; color:#94a3b8; margin:2px 0 0 0;">Rekapitulasi performa bisnis gym secara komprehensif.</p>
                    </div>
                    <button class="btn-primary" onclick="window.print()">Export PDF / Print</button>
                </div>
                <table>
                    <tr>
                        <th>Bulan</th>
                        <th>Total Member Terdaftar</th>
                        <th>Total Pendapatan Lunas</th>
                        <th>Akumulasi Check-in</th>
                    </tr>
                    <tr>
                        <td><b>{datetime.now().strftime('%B %Y')}</b></td>
                        <td>{data['total_members']} Orang</td>
                        <td><b style="color: #f5b000;">{formatted_revenue}</b></td>
                        <td>{data['total_checkins']} Sesi</td>
                    </tr>
                </table>
            </div>
        '''

    full_html = BASE_TEMPLATE.replace('{% block content %}{% endblock %}', body_content)
    return render_template_string(full_html, role=role, menu=menu, bg_url=bg_url, csrf_token=csrf_token)

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

    elif action_type in ('add_equipment', 'add_equipment_option', 'delete_equipment_option'):
        if session.get('role') != 'admin':
            conn.close()
            abort(403)
        if not csrf_valid():
            conn.close()
            abort(400, description='Form kedaluwarsa. Muat ulang halaman dan coba lagi.')
        if action_type == 'add_equipment':
            name = request.form.get('equipment_name', '').strip()[:100]
            category = equipment_option_exists(cursor, 'category', request.form.get('category'))
            status = equipment_option_exists(cursor, 'status', request.form.get('status'))
            if not name or not category or not status:
                conn.close()
                abort(400, description='Nama alat, kategori, dan status wajib diisi dari pilihan yang tersedia.')
            cursor.execute("INSERT INTO equipment (equipment_name, category, status) VALUES (?, ?, ?)", (name, category, status))
        else:
            kind = request.form.get('kind')
            if kind not in ('category', 'status'):
                conn.close()
                abort(400)
            name = clean_option_name(request.form.get('name'))
            if action_type == 'add_equipment_option':
                if not name:
                    conn.close()
                    abort(400, description='Nama tidak boleh kosong.')
                cursor.execute("INSERT OR IGNORE INTO equipment_options (kind, name) VALUES (?, ?)", (kind, name))
            else:
                col = 'category' if kind == 'category' else 'status'
                used = cursor.execute(f"SELECT COUNT(*) FROM equipment WHERE {col} = ? COLLATE NOCASE", (name,)).fetchone()[0]
                if used or (kind == 'status' and name in PROTECTED_EQUIPMENT_STATUS):
                    conn.close()
                    abort(400, description='Pilihan ini masih dipakai alat atau merupakan status bawaan sistem.')
                cursor.execute("DELETE FROM equipment_options WHERE kind = ? AND name = ?", (kind, name))
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


def local_ips():
    import socket
    ips = {'127.0.0.1'}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
            sk.connect(('10.255.255.255', 1))      # tidak mengirim data; hanya mencari IP LAN aktif
            ips.add(sk.getsockname()[0])
    except OSError:
        pass
    try:
        ips.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    return sorted(ips)


def ensure_https_cert(ips):
    """Buat sertifikat HTTPS lokal (self-signed) agar kamera browser bisa dipakai di jaringan gym.
    Disimpan di cert.pem / key.pem dan dibuat ulang otomatis jika IP komputer berubah."""
    import ipaddress
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    cert_path, key_path, ips_path = BASE_DIR / 'cert.pem', BASE_DIR / 'key.pem', BASE_DIR / 'cert_ips.txt'
    if cert_path.exists() and key_path.exists() and ips_path.exists() \
            and set(ips_path.read_text().split()) >= set(ips):
        return str(cert_path), str(key_path)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'FIT HUB GYM lokal')])
    san = [x509.DNSName('localhost')] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=825)).add_extension(x509.SubjectAlternativeName(san), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))
    ips_path.write_text(' '.join(ips))
    return str(cert_path), str(key_path)


if __name__ == '__main__':
    init_db()
    if len(sys.argv) >= 3 and sys.argv[1] == 'reset-password':
        reset_password_cli(sys.argv[2])
        sys.exit(0)
    ips = local_ips()
    try:
        ssl_ctx = ensure_https_cert(ips)
    except Exception as exc:       # pustaka cryptography belum terpasang, dll.
        ssl_ctx = None
        print(f"[INFO] HTTPS tidak aktif ({exc}). Jalankan: pip install -r requirements.txt")
    HTTPS_ENABLED = bool(ssl_ctx)
    if not ssl_ctx:
        app.run(debug=False, host='0.0.0.0', port=HTTP_PORT)
    else:
        import threading
        threading.Thread(target=lambda: app.run(debug=False, host='0.0.0.0', port=HTTP_PORT, use_reloader=False),
                         daemon=True).start()
        print("\n" + "=" * 60)
        print("Akses biasa : " + ", ".join(f"http://{i}:{HTTP_PORT}" for i in ips))
        print("Akses HTTPS : " + ", ".join(f"https://{i}:{HTTPS_PORT}" for i in ips))
        print("Untuk SCAN KAMERA, admin buka alamat https:// (klik Lanjutkan/Advanced saat ada peringatan sertifikat).")
        print("=" * 60 + "\n")
        app.run(debug=False, host='0.0.0.0', port=HTTPS_PORT, ssl_context=ssl_ctx, use_reloader=False)