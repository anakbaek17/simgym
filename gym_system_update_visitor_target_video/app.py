from flask import Flask, request, redirect, url_for, session, render_template_string, send_from_directory, abort
import sqlite3
import os
import secrets
from pathlib import Path
from datetime import datetime
import html
import re
from urllib.parse import urlparse, parse_qs, quote

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

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.executemany("INSERT INTO users (unique_code, name, email, password, role, phone) VALUES (?, ?, ?, ?, ?, ?)", [
            ('OWN001', 'Budi Santoso', 'budi@gym.com', 'password123', 'owner', '081234567800'),
            ('ADM001', 'Siti Aminah', 'siti@gym.com', 'password123', 'admin', '081234567801'),
            ('TRN001', 'Rian Fitness', 'rian@gym.com', 'password123', 'trainer', '081234567802'),
            ('MEM001', 'Andi Pratama', 'andi@gym.com', 'password123', 'member', '081234567803')
        ])
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

    # Visitor tidak memakai akun/login lagi (beranda publik). Bersihkan akun demo VIS001 dari versi sebelumnya.
    cursor.execute("DELETE FROM users WHERE role = 'visitor' AND unique_code = 'VIS001' AND email = 'visitor@gym.com'")
    conn.commit()
    conn.close()

BASE_TEMPLATE = '''
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
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

        @media (max-width: 1024px) {
            .owner-grid-split { grid-template-columns: 1fr !important; }
        }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-brand">
            ⚡ FIT HUB GYM
            <span class="role-pill">{{ role }}</span>
        </div>
        <ul class="sidebar-menu">
            {% if role == 'member' %}
                <li><a href="/?menu=dashboard" class="{{ 'active' if menu=='dashboard' }}">📊 Dashboard Utama</a></li>
                <li><a href="/?menu=packages" class="{{ 'active' if menu=='packages' }}">📦 Paket Membership</a></li>
                <li><a href="/?menu=checkin" class="{{ 'active' if menu=='checkin' }}">📷 Check-in QR Code</a></li>
                <li><a href="/?menu=workouts" class="{{ 'active' if menu=='workouts' }}">🏋️ Program Latihan</a></li>
                <li><a href="/?menu=progress" class="{{ 'active' if menu=='progress' }}">📈 Progres & Perkembangan</a></li>
                <li><a href="/?menu=profile" class="{{ 'active' if menu=='profile' }}">💳 Pembayaran & Profil</a></li>
            {% elif role == 'trainer' %}
                <li><a href="/?menu=dashboard" class="{{ 'active' if menu=='dashboard' }}">📊 Dashboard Trainer</a></li>
                <li><a href="/?menu=assign_workout" class="{{ 'active' if menu=='assign_workout' }}">📋 Program Latihan Member</a></li>
                <li><a href="/?menu=set_target" class="{{ 'active' if menu=='set_target' }}">🎯 Target Latihan Member</a></li>
                <li><a href="/?menu=monitor_progress" class="{{ 'active' if menu=='monitor_progress' }}">📅 Progres & Jadwal Member</a></li>
            {% elif role == 'admin' %}
                <li><a href="/?menu=dashboard" class="{{ 'active' if menu=='dashboard' }}">📊 Dashboard Admin</a></li>
                <li><a href="/?menu=manage_members" class="{{ 'active' if menu=='manage_members' }}">👥 Kelola Member</a></li>
                <li><a href="/?menu=manage_packages" class="{{ 'active' if menu=='manage_packages' }}">📦 Kelola Paket Membership</a></li>
                <li><a href="/?menu=manage_equipment" class="{{ 'active' if menu=='manage_equipment' }}">⚙️ Data Alat Gym</a></li>
                <li><a href="/?menu=manage_payments" class="{{ 'active' if menu=='manage_payments' }}">💰 Kelola Pembayaran</a></li>
                <li><a href="/?menu=manage_trainers" class="{{ 'active' if menu=='manage_trainers' }}">🏋️ Kelola Trainer</a></li>
            {% elif role == 'owner' %}
                <li><a href="/?menu=dashboard" class="{{ 'active' if menu=='dashboard' }}">📊 Dashboard Eksekutif</a></li>
            {% endif %}
        </ul>
        <div class="sidebar-footer">
            <a href="/logout" class="btn-logout">Keluar Sistem</a>
        </div>
    </div>
    
    <div class="main-container">
        <div class="header">
            <div class="user-info">Akun: <span>{{ session.name }}</span></div>
        </div>
        <div class="content" {% if bg_url %}style="background-image: url('{{ bg_url }}');"{% endif %}>
            <div class="content-inner">
                {% block content %}{% endblock %}
            </div>
        </div>
    </div>
</body>
</html>
'''

LOGIN_HTML = '''
<!DOCTYPE html>
<html lang="id">
<head><meta charset="UTF-8"><title>Login - FIT HUB GYM ACCESS</title></head>
<body style="background: linear-gradient(rgba(11, 15, 25, 0.75), rgba(11, 15, 25, 0.85)), url('{{ url_for("static", filename="images/login-bg.png") }}'); background-size: cover; background-position: center; color: #f8fafc; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; font-family: 'Inter', sans-serif;">
    <div style="background: rgba(19, 27, 46, 0.85); backdrop-filter: blur(12px); padding: 45px; border-radius: 20px; box-shadow: 0 20px 40px rgba(0,0,0,0.6); width: 100%; max-width: 420px; border: 1px solid rgba(255, 255, 255, 0.1); border-top: 4px solid #f5b000;">
        <h2 style="text-align: center; margin-bottom: 25px; color: #f8fafc; font-weight: 800; font-size: 24px; letter-spacing: 0.5px;">FIT HUB GYM <span style="color: #f5b000;">ACCESS</span></h2>
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
        <div style="font-size: 12px; color: #94a3b8; text-align: center; margin-top: 25px; line-height: 1.6;">
            <b>Akun Demo Default:</b><br>
            Member: <b>Andi Pratama</b> (MEM001)<br>
            Trainer: <b>Rian Fitness</b> (TRN001)<br>
            Admin: <b>Siti Aminah</b> (ADM001) | Owner: <b>Budi Santoso</b> (OWN001)<br>
            Password semua: <code>password123</code>
        </div>
        <div style="text-align:center; margin-top:18px;"><a href="/" style="color:#f5b000; font-size:13px; font-weight:700; text-decoration:none;">← Kembali ke Beranda</a></div>
    </div>
</body>
</html>
'''

VISITOR_LANDING_HTML = '''<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FIT HUB GYM - Better Than Yesterday</title>
<style>
  :root { --bg:#0b0f19; --bg2:#101728; --card:rgba(19,27,46,.85); --line:rgba(255,255,255,.1); --text:#f8fafc; --muted:#94a3b8; --gold:#f5b000; --neon:#38bdf8; --ok:#10b981; --warn:#f59e0b; --bad:#ef4444; }
  * { box-sizing:border-box; margin:0; padding:0; font-family:'Inter','Segoe UI',Tahoma,sans-serif; }
  html { scroll-behavior:smooth; scroll-padding-top:84px; }
  body { background:var(--bg); color:var(--text); line-height:1.6; overflow-x:hidden; }
  a { color:inherit; text-decoration:none; }
  .wrap { width:100%; max-width:1180px; margin:0 auto; padding:0 24px; }

  /* NAV */
  nav { position:fixed; top:0; left:0; right:0; z-index:50; background:rgba(11,15,25,.82); backdrop-filter:blur(14px); border-bottom:1px solid var(--line); }
  nav .wrap { display:flex; align-items:center; justify-content:space-between; height:68px; gap:16px; }
  .brand { font-weight:800; font-size:18px; letter-spacing:.5px; color:var(--gold); white-space:nowrap; }
  .brand span { color:var(--text); }
  .links { display:flex; gap:26px; font-size:14px; color:var(--muted); font-weight:600; }
  .links a:hover { color:var(--gold); }
  .nav-actions { display:flex; align-items:center; gap:10px; }
  .btn { display:inline-block; padding:12px 22px; border-radius:10px; font-weight:800; font-size:14px; border:1px solid transparent; cursor:pointer; transition:transform .15s, background .2s, border-color .2s; }
  .btn:hover { transform:translateY(-2px); }
  .btn-gold { background:var(--gold); color:#121212; box-shadow:0 6px 22px rgba(245,176,0,.28); }
  .btn-gold:hover { background:#ffc21f; }
  .btn-ghost { border-color:var(--line); color:var(--text); background:rgba(255,255,255,.04); }
  .btn-ghost:hover { border-color:var(--gold); color:var(--gold); }
  .btn-sm { padding:9px 16px; font-size:13px; }
  .pill { font-size:10px; font-weight:800; letter-spacing:1px; text-transform:uppercase; padding:4px 9px; border-radius:20px; background:rgba(56,189,248,.14); color:var(--neon); border:1px solid rgba(56,189,248,.3); }

  /* HERO */
  .hero { position:relative; min-height:100vh; display:flex; align-items:center; padding:120px 0 70px;
    background:linear-gradient(100deg, rgba(11,15,25,.96) 8%, rgba(11,15,25,.78) 52%, rgba(11,15,25,.55) 100%), url('{{ url_for("static", filename="images/login-bg.png") }}') center/cover no-repeat; }
  .hero::after { content:''; position:absolute; left:0; right:0; bottom:0; height:140px; background:linear-gradient(180deg, transparent, var(--bg)); }
  .hero .wrap { position:relative; z-index:2; display:grid; grid-template-columns:1.15fr .85fr; gap:50px; align-items:center; }
  .eyebrow { display:inline-block; font-size:12px; font-weight:800; letter-spacing:3px; text-transform:uppercase; color:var(--gold); margin-bottom:16px; }
  h1 { font-size:clamp(38px,6vw,68px); line-height:1.05; font-weight:900; letter-spacing:-1px; margin-bottom:20px; }
  h1 em { font-style:normal; color:var(--gold); text-shadow:0 0 40px rgba(245,176,0,.35); }
  .lead { font-size:18px; color:#cbd5e1; max-width:560px; margin-bottom:30px; }
  .cta { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:34px; }
  .trust { display:flex; flex-wrap:wrap; gap:22px; font-size:13px; color:var(--muted); }
  .trust b { color:var(--text); }
  .photo-card { position:relative; border-radius:22px; overflow:hidden; border:1px solid var(--line); box-shadow:0 0 0 1px rgba(56,189,248,.15), 0 30px 70px rgba(0,0,0,.6), 0 0 80px rgba(56,189,248,.12); aspect-ratio:4/5; }
  .photo-card img { width:100%; height:100%; object-fit:cover; display:block; }
  .photo-card .tag { position:absolute; left:16px; bottom:16px; right:16px; background:rgba(11,15,25,.82); backdrop-filter:blur(10px); border:1px solid var(--line); border-radius:14px; padding:12px 16px; font-size:13px; }
  .photo-card .tag b { color:var(--gold); }

  /* STATS */
  .stats { position:relative; z-index:3; margin-top:-34px; }
  .stats .grid { display:grid; grid-template-columns:repeat(4,1fr); gap:16px; }
  .stat { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:22px; text-align:center; backdrop-filter:blur(10px); }
  .stat .n { font-size:34px; font-weight:900; color:var(--gold); }
  .stat .l { font-size:12px; text-transform:uppercase; letter-spacing:1px; color:var(--muted); font-weight:700; }

  section { padding:84px 0 0; }
  .sec-head { text-align:center; max-width:680px; margin:0 auto 44px; }
  .sec-head .eyebrow { margin-bottom:10px; }
  h2 { font-size:clamp(28px,4vw,40px); font-weight:900; letter-spacing:-.5px; margin-bottom:10px; }
  .sec-head p { color:var(--muted); font-size:16px; }

  /* FEATURES */
  .features { display:grid; grid-template-columns:repeat(4,1fr); gap:18px; }
  .feat { background:var(--card); border:1px solid var(--line); border-radius:16px; padding:26px; transition:transform .2s, border-color .2s; }
  .feat:hover { transform:translateY(-5px); border-color:rgba(245,176,0,.4); }
  .feat .ic { width:50px; height:50px; border-radius:14px; display:grid; place-items:center; font-size:24px; background:rgba(245,176,0,.12); border:1px solid rgba(245,176,0,.25); margin-bottom:16px; }
  .feat h3 { font-size:17px; margin-bottom:6px; }
  .feat p { font-size:14px; color:var(--muted); }

  /* PACKAGES */
  .plans { display:grid; grid-template-columns:repeat(auto-fit,minmax(260px,1fr)); gap:20px; align-items:stretch; }
  .plan { position:relative; background:var(--card); border:1px solid var(--line); border-radius:20px; padding:32px 28px; display:flex; flex-direction:column; transition:transform .2s; }
  .plan:hover { transform:translateY(-6px); }
  .plan.best { border-color:var(--gold); box-shadow:0 0 0 1px var(--gold), 0 20px 50px rgba(245,176,0,.12); background:linear-gradient(180deg, rgba(245,176,0,.08), var(--card) 40%); }
  .ribbon { position:absolute; top:-13px; left:50%; transform:translateX(-50%); background:var(--gold); color:#121212; font-size:11px; font-weight:900; letter-spacing:1px; padding:5px 14px; border-radius:20px; white-space:nowrap; }
  .plan h3 { font-size:20px; margin-bottom:4px; }
  .plan .dur { color:var(--muted); font-size:14px; margin-bottom:18px; }
  .plan .price { font-size:34px; font-weight:900; }
  .plan .per { font-size:13px; color:var(--gold); font-weight:700; margin-bottom:20px; }
  .plan ul { list-style:none; margin-bottom:26px; flex-grow:1; }
  .plan li { font-size:14px; color:#cbd5e1; padding:7px 0 7px 26px; position:relative; border-bottom:1px solid rgba(255,255,255,.05); }
  .plan li::before { content:'✓'; position:absolute; left:0; color:var(--ok); font-weight:900; }
  .plan .btn { text-align:center; width:100%; }

  /* TRAINERS */
  .trainers { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:18px; }
  .trainer { background:var(--card); border:1px solid var(--line); border-radius:18px; padding:28px 22px; text-align:center; }
  .avatar { width:84px; height:84px; margin:0 auto 14px; border-radius:50%; display:grid; place-items:center; font-size:30px; font-weight:900; color:#121212; background:linear-gradient(135deg,var(--gold),#ffdd7a); box-shadow:0 0 0 4px rgba(245,176,0,.18); }
  .trainer h3 { font-size:18px; }
  .trainer p { font-size:13px; color:var(--muted); margin-top:4px; }

  /* FACILITIES */
  .fac { display:grid; grid-template-columns:1fr 1fr; gap:22px; }
  .fac-box { background:var(--card); border:1px solid var(--line); border-radius:18px; padding:26px; }
  .fac-box h3 { display:flex; justify-content:space-between; align-items:center; margin-bottom:14px; font-size:18px; }
  .fac-box h3 small { font-size:12px; color:var(--muted); font-weight:700; }
  .chips { display:flex; flex-wrap:wrap; gap:8px; }
  .chip { font-size:13px; padding:7px 12px; border-radius:20px; background:rgba(255,255,255,.05); border:1px solid var(--line); }
  .chip.off { opacity:.55; text-decoration:line-through; }

  /* STEPS */
  .steps { display:grid; grid-template-columns:repeat(3,1fr); gap:18px; counter-reset:s; }
  .step { background:var(--card); border:1px solid var(--line); border-radius:18px; padding:28px 24px; position:relative; }
  .step::before { counter-increment:s; content:counter(s); position:absolute; top:-16px; left:22px; width:34px; height:34px; border-radius:50%; background:var(--gold); color:#121212; font-weight:900; display:grid; place-items:center; }
  .step h3 { margin-bottom:6px; font-size:17px; }
  .step p { font-size:14px; color:var(--muted); }

  /* FINAL CTA */
  .final { margin-top:90px; padding:70px 0; text-align:center; background:radial-gradient(ellipse at 50% 0%, rgba(245,176,0,.16), transparent 60%), var(--bg2); border-top:1px solid var(--line); }
  .final h2 { font-size:clamp(30px,5vw,46px); }
  .final p { color:var(--muted); max-width:560px; margin:0 auto 28px; }
  footer { padding:26px 0; text-align:center; font-size:13px; color:var(--muted); border-top:1px solid var(--line); }
  .fade { opacity:0; transform:translateY(22px); transition:opacity .7s ease, transform .7s ease; }
  .fade.in { opacity:1; transform:none; }
  @media (prefers-reduced-motion:reduce) { .fade { opacity:1; transform:none; transition:none; } html { scroll-behavior:auto; } }

  @media (max-width:980px) {
    .hero .wrap { grid-template-columns:1fr; } .photo-card { max-width:420px; aspect-ratio:16/10; }
    .features { grid-template-columns:repeat(2,1fr); } .stats .grid { grid-template-columns:repeat(2,1fr); }
    .fac, .steps { grid-template-columns:1fr; } .links { display:none; }
  }
  @media (max-width:560px) { .features { grid-template-columns:1fr; } .hide-sm { display:none; } .wrap { padding:0 16px; } }
</style>
</head>
<body>

<nav>
  <div class="wrap">
    <a href="#beranda" class="brand">⚡ FIT HUB <span>GYM</span></a>
    <div class="links">
      <a href="#keunggulan">Keunggulan</a><a href="#paket">Paket</a><a href="#trainer">Trainer</a><a href="#fasilitas">Fasilitas</a><a href="#cara">Cara Bergabung</a>
    </div>
    <div class="nav-actions">
      {% if wa_general %}<a href="{{ wa_general }}" target="_blank" rel="noopener noreferrer" class="btn btn-gold btn-sm">Daftar Member</a>{% endif %}
      <a href="/login" class="btn btn-ghost btn-sm">Masuk</a>
    </div>
  </div>
</nav>

<header class="hero" id="beranda">
  <div class="wrap">
    <div>
      <span class="eyebrow">Better than yesterday</span>
      <h1>Bentuk tubuh impianmu mulai <em>hari ini.</em></h1>
      <p class="lead">Latihan terarah bersama trainer pribadi, program yang dilengkapi video panduan, dan target berat badan &amp; body fat yang dipantau langsung. Semua ada di FIT HUB GYM.</p>
      <div class="cta">
        {% if wa_general %}<a href="{{ wa_general }}" target="_blank" rel="noopener noreferrer" class="btn btn-gold">💬 Tanya &amp; Daftar via WhatsApp</a>{% endif %}
        <a href="#paket" class="btn btn-ghost">Lihat Paket Membership</a>
      </div>
      <div class="trust">
        <span>🏋️ <b>{{ trainers|length }}</b> trainer</span>
        <span>⚙️ <b>{{ equipment|length }}</b> alat gym</span>
        <span>📷 Check-in QR cepat</span>
      </div>
    </div>
    <div class="photo-card">
      <img src="{{ url_for('static', filename='images/login-bg.png') }}" alt="Suasana area latihan FIT HUB GYM">
      <div class="tag"><b>Suasana FIT HUB GYM</b><br>Area latihan nyaman dengan pencahayaan neon &amp; alat lengkap.</div>
    </div>
  </div>
</header>

<div class="stats">
  <div class="wrap"><div class="grid">
    <div class="stat"><div class="n">{{ packages|length }}</div><div class="l">Paket Membership</div></div>
    <div class="stat"><div class="n">{{ trainers|length }}</div><div class="l">Trainer</div></div>
    <div class="stat"><div class="n">{{ equipment|length }}</div><div class="l">Alat Gym</div></div>
    <div class="stat"><div class="n">{{ available_count }}</div><div class="l">Alat Siap Pakai</div></div>
  </div></div>
</div>

<section id="keunggulan">
  <div class="wrap">
    <div class="sec-head fade"><span class="eyebrow">Kenapa FIT HUB</span><h2>Lebih dari sekadar tempat nge-gym</h2><p>Setiap member mendapat pendampingan dan sistem yang membuat progres terlihat jelas.</p></div>
    <div class="features">
      <div class="feat fade"><div class="ic">🏋️</div><h3>Trainer Pribadi</h3><p>Trainer menyusun program latihan khusus untukmu: latihan, set, repetisi, dan beban.</p></div>
      <div class="feat fade"><div class="ic">🎬</div><h3>Video Panduan Gerakan</h3><p>Setiap program dilengkapi video, jadi gerakan benar dan latihan lebih aman.</p></div>
      <div class="feat fade"><div class="ic">🎯</div><h3>Target Terukur</h3><p>Berat badan dan body fat dicatat dari awal sampai target, lengkap dengan persentase pencapaian.</p></div>
      <div class="feat fade"><div class="ic">📷</div><h3>Check-in QR Code</h3><p>Masuk gym cukup scan QR dari akun member. Tanpa antre, tanpa kartu.</p></div>
    </div>
  </div>
</section>

<section id="paket">
  <div class="wrap">
    <div class="sec-head fade"><span class="eyebrow">Paket Membership</span><h2>Pilih paket yang cocok untukmu</h2><p>Makin panjang durasinya, makin hemat biaya per bulan.</p></div>
    <div class="plans">
      {% for p in packages %}
      <div class="plan fade{% if p.best %} best{% endif %}">
        {% if p.best %}<div class="ribbon">★ PALING HEMAT</div>{% endif %}
        <h3>{{ p.name }}</h3>
        <div class="dur">{{ p.months }} bulan akses penuh</div>
        <div class="price">Rp {{ p.price_fmt }}</div>
        <div class="per">≈ Rp {{ p.per_month_fmt }} / bulan</div>
        <ul>
          <li>Akses semua alat gym</li>
          <li>Program latihan dari trainer</li>
          <li>Video panduan gerakan</li>
          <li>Pantau target &amp; progres tubuh</li>
          <li>Check-in QR Code</li>
        </ul>
        {% if p.wa %}<a href="{{ p.wa }}" target="_blank" rel="noopener noreferrer" class="btn {{ 'btn-gold' if p.best else 'btn-ghost' }}">Ambil Paket Ini</a>{% endif %}
      </div>
      {% else %}
      <p style="text-align:center; color:var(--muted); grid-column:1/-1;">Paket sedang disiapkan. Hubungi admin untuk info terbaru.</p>
      {% endfor %}
    </div>
  </div>
</section>

<section id="trainer">
  <div class="wrap">
    <div class="sec-head fade"><span class="eyebrow">Tim Pelatih</span><h2>Dibimbing trainer berpengalaman</h2><p>Kenali trainer yang akan menemani perjalanan kebugaranmu.</p></div>
    <div class="trainers">
      {% for t in trainers %}
      <div class="trainer fade"><div class="avatar">{{ t.initial }}</div><h3>{{ t.name }}</h3><p>Personal Trainer</p></div>
      {% else %}
      <p style="text-align:center; color:var(--muted); grid-column:1/-1;">Profil trainer akan segera tersedia.</p>
      {% endfor %}
    </div>
  </div>
</section>

<section id="fasilitas">
  <div class="wrap">
    <div class="sec-head fade"><span class="eyebrow">Fasilitas</span><h2>Alat yang lengkap &amp; terawat</h2><p>Ketersediaan alat diperbarui oleh admin gym.</p></div>
    <div class="fac">
      {% for cat in equipment_groups %}
      <div class="fac-box fade">
        <h3>{{ cat.name }} <small>{{ cat.rows|length }} alat</small></h3>
        <div class="chips">{% for e in cat.rows %}<span class="chip{% if e.status != 'Tersedia' %} off{% endif %}" title="{{ e.status }}">{{ e.name }}</span>{% endfor %}</div>
      </div>
      {% else %}
      <p style="text-align:center; color:var(--muted); grid-column:1/-1;">Data alat belum tersedia.</p>
      {% endfor %}
    </div>
  </div>
</section>

<section id="cara">
  <div class="wrap">
    <div class="sec-head fade"><span class="eyebrow">Cara Bergabung</span><h2>Jadi member dalam 3 langkah</h2><p>Akun member diberikan admin setelah pendaftaran dan pembayaran terverifikasi.</p></div>
    <div class="steps">
      <div class="step fade"><h3>Hubungi admin</h3><p>Pilih paket lalu chat admin lewat WhatsApp untuk mendaftar.</p></div>
      <div class="step fade"><h3>Bayar via QRIS</h3><p>Lakukan pembayaran dan kirim bukti. Admin memverifikasinya.</p></div>
      <div class="step fade"><h3>Mulai latihan</h3><p>Akun member aktif: dapat program dari trainer, video, dan target tubuhmu.</p></div>
    </div>
  </div>
</section>

<div class="final">
  <div class="wrap fade">
    <h2>Siap jadi versi terbaik dirimu?</h2>
    <p>Langkah pertama paling berat, tapi kami temani sampai target tercapai.</p>
    {% if wa_general %}<a href="{{ wa_general }}" target="_blank" rel="noopener noreferrer" class="btn btn-gold">💬 Daftar Jadi Member Sekarang</a>{% endif %}
    <a href="/login" class="btn btn-ghost" style="margin-left:8px;">Sudah member? Masuk</a>
  </div>
</div>
<footer>© FIT HUB GYM · Better Than Yesterday</footer>

<script>
  (function () {
    var els = document.querySelectorAll('.fade');
    if (!('IntersectionObserver' in window)) { els.forEach(function (e) { e.classList.add('in'); }); return; }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) { en.target.classList.add('in'); io.unobserve(en.target); } });
    }, { threshold: 0.12 });
    els.forEach(function (e) { io.observe(e); });
  })();
</script>
</body>
</html>
'''

SCAN_RESULT_HTML = '''
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check-in Gym Success</title>
</head>
<body style="background:#0b0f19; color:#f8fafc; display:flex; justify-content:center; align-items:center; min-height:100vh; margin:0; font-family:'Inter', sans-serif;">
    <div style="background:#131b2e; padding:35px; border-radius:18px; border:1px solid #1e293b; border-top:4px solid #10b981; max-width:380px; width:90%; text-align:center; box-shadow:0 15px 35px rgba(0,0,0,0.5);">
        <div style="font-size:50px; margin-bottom:10px;">✅</div>
        <h2 style="color:#10b981; margin-bottom:10px;">CHECK-IN BERHASIL</h2>
        <p style="color:#94a3b8; font-size:14px; margin-bottom:20px;">Akses gerbang pintu gym telah diverifikasi secara otomatis.</p>
        
        <div style="background:#0b0f19; padding:15px; border-radius:10px; text-align:left; font-size:14px; line-height:1.8; margin-bottom:20px; border:1px solid #1e293b;">
            <b>Nama Member:</b> {{ user['name'] }}<br>
            <b>Kode Unik:</b> {{ user['unique_code'] }}<br>
            <b>Waktu Masuk:</b> {{ time_now }}<br>
            <b>Status Pintu:</b> <span style="color:#10b981; font-weight:bold;">TERBUKA</span>
        </div>
        
        <a href="/" style="display:inline-block; padding:12px 20px; background:#f5b000; color:#121212; text-decoration:none; font-weight:bold; border-radius:8px; font-size:14px;">Kembali ke Dashboard</a>
    </div>
</body>
</html>
'''

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
    if request.method == 'POST':
        login_input = request.form.get('login_input', '').strip().lower()
        password = request.form.get('password', '').strip()
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE (LOWER(unique_code) = ? OR LOWER(name) = ? OR LOWER(email) = ?) AND password = ?", 
                       (login_input, login_input, login_input, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['name'] = user['name']
            session['role'] = user['role']
            session['unique_code'] = user['unique_code']
            return redirect(url_for('dashboard'))
    return render_template_string(LOGIN_HTML)

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
        return render_template_string(SCAN_RESULT_HTML, user=user, time_now=current_wib_time)
    
    conn.close()
    return "<h1>QR Code Tidak Valid</h1>", 400

def render_visitor_landing():
    """Halaman utama publik (tanpa login) untuk calon member: hanya informasi umum gym."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT package_name, duration_months, price FROM membership_packages WHERE status = 'Aktif' ORDER BY duration_months, price")
    packages = cursor.fetchall()
    cursor.execute("SELECT name FROM users WHERE role = 'trainer' ORDER BY name")
    trainers = cursor.fetchall()
    cursor.execute("SELECT equipment_name, category, status FROM equipment ORDER BY category, equipment_name")
    equipment = cursor.fetchall()
    cursor.execute("SELECT phone FROM users WHERE role = 'admin' AND phone IS NOT NULL AND phone != '' ORDER BY id LIMIT 1")
    admin_row = cursor.fetchone()
    conn.close()

    phone = ''.join(ch for ch in ((admin_row['phone'] if admin_row else '') or '') if ch.isdigit())
    if phone.startswith('0'):
        phone = '62' + phone[1:]

    def wa_link(text):
        return f'https://wa.me/{phone}?text={quote(text)}' if phone else ''

    per_month = [p['price'] / max(p['duration_months'], 1) for p in packages]
    best_idx = per_month.index(min(per_month)) if len(packages) > 1 else -1
    package_cards = [{
        'name': p['package_name'],
        'months': p['duration_months'],
        'price_fmt': f"{p['price']:,.0f}".replace(',', '.'),
        'per_month_fmt': f"{per_month[i]:,.0f}".replace(',', '.'),
        'best': i == best_idx,
        'wa': wa_link(f"Halo admin FIT HUB GYM, saya tertarik mengambil {p['package_name']}. Mohon info pendaftarannya."),
    } for i, p in enumerate(packages)]
    trainer_cards = [{'name': t['name'], 'initial': (t['name'] or '?').strip()[:1].upper()} for t in trainers]
    groups = {}
    for e in equipment:
        groups.setdefault(e['category'], []).append({'name': e['equipment_name'], 'status': e['status']})
    equipment_groups = [{'name': k, 'rows': v} for k, v in groups.items()]
    return render_template_string(
        VISITOR_LANDING_HTML,
        packages=package_cards, trainers=trainer_cards,
        equipment=equipment, equipment_groups=equipment_groups,
        available_count=sum(1 for e in equipment if e['status'] == 'Tersedia'),
        wa_general=wa_link("Halo admin FIT HUB GYM, saya tertarik menjadi member. Mohon info pendaftarannya."))


@app.route('/')
def dashboard():
    # Beranda publik: siapa pun (visitor) bisa melihat tanpa login. Member/staf yang sudah login masuk ke dashboard-nya.
    if 'user_id' not in session or session.get('role') == 'visitor':
        return render_visitor_landing()
    
    menu = request.args.get('menu', 'dashboard')
    search_query = request.args.get('q', '').strip().lower()
    role = session['role']
    user_id = session['user_id']
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    data = {}
    bg_url = None
    csrf_token = session.setdefault('payment_csrf', secrets.token_urlsafe(32))

    if role == 'member':
        MEMBER_BACKGROUNDS = {
            'dashboard': 'https://images.unsplash.com/photo-1534438327276-14e5300c3a48?auto=format&fit=crop&w=1920&q=80',
            'packages': 'https://images.unsplash.com/photo-1540497077202-7c8a3999166f?auto=format&fit=crop&w=1920&q=80',
            'checkin': 'https://images.unsplash.com/photo-1517838277536-f5f99be501cd?auto=format&fit=crop&w=1920&q=80',
            'workouts': 'https://images.unsplash.com/photo-1517963879433-6ad2b056d712?auto=format&fit=crop&w=1920&q=80',
            'progress': 'https://images.unsplash.com/photo-1517836357463-d25dfeac3438?auto=format&fit=crop&w=1920&q=80',
            'profile': 'https://images.unsplash.com/photo-1499750310107-5fef28a66643?auto=format&fit=crop&w=1920&q=80'
        }
        bg_url = MEMBER_BACKGROUNDS.get(menu, MEMBER_BACKGROUNDS['dashboard'])

        cursor.execute("SELECT * FROM member_profiles WHERE user_id = ?", (user_id,))
        data['profile'] = cursor.fetchone()
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
    
    if role == 'member':
        if menu == 'dashboard':
            p = data['profile'] or {'remaining_days': 0, 'status_paket': 'Belum Aktif'}
            body_content = f'''
                <span class="motto-tag">BETTER THAN YESTERDAY</span>
                <h2>Dashboard Utama Member</h2>
                <p style="margin-bottom:25px;">Selamat datang kembali, <b>{session['name']}</b>!</p>
                <div class="card-grid">
                    <div class="card"><h3>Sisa Hari Membership</h3><div class="value">{p["remaining_days"]} Hari</div></div>
                    <div class="card"><h3>Status Paket Aktif</h3><div class="value" style="font-size:18px; color:var(--success);">{p["status_paket"]}</div></div>
                    <div class="card"><h3>Jadwal Latihan Hari Ini</h3><div class="value" style="font-size:16px;">Push & Core Workout</div></div>
                </div>
            '''
        elif menu == 'packages':
            rows = "".join([f"<tr><td><b>{pkg['package_name']}</b></td><td>{pkg['duration_months']} Bulan ({pkg['duration_months']*30} Hari)</td><td>Rp {pkg['price']:,.0f}</td><td><button class='btn-primary' style='padding:8px 16px; font-size:13px;' onclick='openPaymentModal({pkg["id"]}, \"{pkg["package_name"]}\", {pkg["price"]}, {pkg["duration_months"]})'>Pilih Paket</button></td></tr>" for pkg in data['packages']])
            body_content = f'''
                <span class="motto-tag">MEMBERSHIP ACCESS</span>
                <h2>Paket Membership</h2>
                <p style="margin-bottom:20px;">Pilihan paket fleksibel untuk kebutuhan kebugaran Anda.</p>
                <table><tr><th>Nama Paket</th><th>Durasi</th><th>Harga</th><th>Aksi</th></tr>{rows}</table>

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
                                <img src="/qris_image" style="width:100%; max-width:340px; height:auto; border-radius:8px; background:#fff; display:block; margin:0 auto;" alt="QRIS Pembayaran Gym">
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
            rows = "".join([f"<tr><td>{c['checkin_time']}</td><td><span class='badge badge-success'>{c['status']}</span></td></tr>" for c in data['checkins']])
            qr_valid_url = f"{request.host_url}qr_checkin/{session['unique_code']}"
            
            body_content = f'''
                <span class="motto-tag">NO EXCUSES</span>
                <h2>Check-in QR Code</h2>
                <p style="margin-bottom:20px;">Arahkan Kamera HP / Google Lens ke QR Code ini untuk check-in otomatis.</p>
                <div class="panel-box" style="text-align:center;">
                    <div style="background:#fff; padding:15px; display:inline-block; border-radius:12px; margin-bottom:15px;">
                        <img src="https://quickchart.io/qr?text={qr_valid_url}&size=200" alt="QR Valid">
                    </div>
                    <br>
                    <a href="/qr_checkin/{session['unique_code']}" target="_blank" class="btn-primary">Simulasikan Scan Masuk</a>
                </div>
                <h3>Riwayat Check-in</h3><table><tr><th>Waktu (WIB)</th><th>Status</th></tr>{rows}</table>
            '''
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
        elif menu == 'profile':
            rows = "".join([f"<tr><td>#TRX-{p['id']}</td><td>{p['package_name']}</td><td>Rp {p['amount']:,.0f}</td><td>{p['payment_date']}</td><td><span class='badge {'badge-success' if p['status']=='Lunas' else ('badge-danger' if p['status']=='Ditolak' else 'badge-warning')}'>{p['status']}</span></td></tr>" for p in data['payments']])
            body_content = f'''
                <span class="motto-tag">HEALTH IS WEALTH</span>
                <h2>Pembayaran & Profil</h2>
                <p style="margin-bottom:20px;">Pembayaran baru berstatus <b>Pending</b> sampai admin memverifikasi uang masuk. Bukti upload saja belum berarti lunas.</p>
                <table style="margin-bottom:25px;"><tr><th>ID Transaksi</th><th>Paket</th><th>Jumlah</th><th>Tanggal</th><th>Status</th></tr>{rows}</table>
                <div class="panel-box">
                    <h3>Pengaturan Profil Pribadi</h3>
                    <form onsubmit="event.preventDefault(); alert('Profil berhasil diperbarui!');" style="margin-top:15px;">
                        <label>Nama Lengkap</label><input type="text" value="{session['name']}">
                        <label>Password Baru</label><input type="password" placeholder="Kosongkan jika tidak diubah">
                        <button type="submit" class="btn-primary">Simpan Perubahan</button>
                    </form>
                </div>
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
            body_content = f'''
                <h2>Dashboard Admin Operasional</h2>
                <div class="card-grid">
                    <div class="card"><h3>Total Member</h3><div class="value">{data['total_members']} Orang</div></div>
                    <div class="card"><h3>Check-in Hari Ini</h3><div class="value">{data['total_checkins']} Sesi</div></div>
                    <div class="card"><h3>Inventaris Layak</h3><div class="value">96%</div></div>
                </div>
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
                        <label>Password Akun</label><input type="password" name="password" required value="password123">
                        <button type="submit" class="btn-primary">Daftarkan Member Baru</button>
                    </form>
                </div>
                <h3>Daftar Member Terdaftar</h3>
                <form method="GET" action="/"><input type="hidden" name="menu" value="manage_members"><input type="text" name="q" class="search-box" placeholder="Cari member..." value="{search_query}"></form>
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
                        <label>Password Akun</label><input type="password" name="password" required value="password123">
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
            rows = "".join([f"<tr><td>{eq['equipment_name']}</td><td>{eq['category']}</td><td><span class='badge {'badge-success' if eq['status']=='Tersedia' else ('badge-warning' if eq['status']=='Perbaikan' else 'badge-danger')}'>{eq['status']}</span></td></tr>" for eq in data['equipment']])
            body_content = f'''
                <h2>Data Alat Gym</h2>
                <div class="panel-box">
                    <form action="/action" method="POST">
                        <input type="hidden" name="action_type" value="add_equipment">
                        <label>Nama Alat</label><input type="text" name="equipment_name" required>
                        <label>Kategori</label><select name="category"><option value="Cardio">Cardio</option><option value="Beban">Beban</option></select>
                        <label>Status</label><select name="status"><option value="Tersedia">Tersedia</option><option value="Perbaikan">Perbaikan</option><option value="Rusak">Rusak</option></select>
                        <button type="submit" class="btn-primary">Tambah Alat</button>
                    </form>
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
                checkin_rows += f"<tr><td><b>{c['member_name']}</b> <small style='color:#94a3b8;'>({c['unique_code']})</small></td><td>{c['checkin_time']}</td><td><span class='badge badge-success'>{c['status']}</span></td></tr>"
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
                        <span style="font-size: 12px; color: #94a3b8;">Live Log</span>
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
    return render_template_string(full_html, role=role, menu=menu, bg_url=bg_url)

@app.route('/action', methods=['POST'])
def action():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if session.get('role') == 'visitor':
        abort(403, description='Akun visitor hanya dapat melihat data.')

    action_type = request.form.get('action_type')
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

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
            conn.commit()
        except Exception:
            proof_path.unlink(missing_ok=True)
            raise
        finally:
            conn.close()
        # Membership TIDAK berubah saat member mengunggah bukti.
        return redirect(url_for('dashboard', menu='profile'))

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
                if profile:
                    cursor.execute("""UPDATE member_profiles
                            SET remaining_days=MAX(0, COALESCE(remaining_days, 0)) + ?,
                                package_id=?, status_paket=?
                            WHERE user_id=?""", (additional_days, p[3], status_name, p[2]))
                else:
                    cursor.execute("""INSERT INTO member_profiles
                            (user_id, package_id, remaining_days, status_paket)
                            VALUES (?, ?, ?, ?)""", (p[2], p[3], additional_days, status_name))
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
        password = request.form.get('password').strip()
        
        prefix = 'MEM' if role == 'member' else 'TRN'
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = ?", (role,))
        count = cursor.fetchone()[0] + 1
        unique_code = f"{prefix}{count:03d}"

        try:
            cursor.execute("INSERT INTO users (unique_code, name, email, password, role, phone) VALUES (?, ?, ?, ?, ?, ?)",
                           (unique_code, name, email, password, role, phone))
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
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(debug=False, host='0.0.0.0', port=8080)