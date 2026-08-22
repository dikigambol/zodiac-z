import os
import hashlib
from datetime import date
from flask import request

try:
    import pymysql
    import pymysql.cursors
    HAS_PYMYSQL = True
except ImportError:
    HAS_PYMYSQL = False

DAILY_AI_LIMIT = 2

# Config MySQL (dari .env atau default credentials)
MYSQL_HOST = os.environ.get('MYSQL_HOST', '194.233.65.45')
MYSQL_PORT = int(os.environ.get('MYSQL_PORT', 3306))
MYSQL_DB = os.environ.get('MYSQL_DB', 'uj7e3mhs_peace_orc')
MYSQL_USER = os.environ.get('MYSQL_USER', 'uj7e3mhs_db_peace_orc')
MYSQL_PASSWORD = os.environ.get('MYSQL_PASSWORD', 'peaceorc986')

_MEMORY_STORE = {}

def _get_mysql_connection():
    if not HAS_PYMYSQL:
        return None
    return pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DB,
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=2,
        read_timeout=3,
        write_timeout=3,
        autocommit=True
    )

def init_db():
    try:
        conn = _get_mysql_connection()
        if conn:
            with conn.cursor() as cursor:
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ai_quota (
                        client_id VARCHAR(191) PRIMARY KEY,
                        quota_date VARCHAR(20) NOT NULL,
                        used_count INT NOT NULL DEFAULT 0,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                        INDEX idx_quota_date (quota_date)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
                ''')
            conn.close()
    except Exception:
        pass

# Initialize DB safely
init_db()

def get_ip_id():
    """
    Menghasilkan Hash berbasis Alamat IP Klien.
    Proteksi super strict agar pengguna tidak bisa bypass walau hapus localStorage/Cookies/Incognito.
    """
    try:
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            ip = forwarded.split(',')[0].strip()
        else:
            ip = request.remote_addr or '127.0.0.1'
        return f"ip_{hashlib.md5(ip.encode('utf-8')).hexdigest()}"
    except Exception:
        return "ip_default"

def get_fp_id():
    """
    Menghasilkan Fingerprint Hash berbasis IP + User-Agent.
    Dipakai sebagai proteksi ganda jika browser berganti tab/UA.
    """
    try:
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            ip = forwarded.split(',')[0].strip()
        else:
            ip = request.remote_addr or '127.0.0.1'

        user_agent = request.headers.get('User-Agent', 'unknown_ua')
        fp_raw = f"{ip}_{user_agent}"
        return f"fp_{hashlib.md5(fp_raw.encode('utf-8')).hexdigest()}"
    except Exception:
        return "fp_default"

def get_client_id():
    """
    Identifikasi perangkat secara strict & multi-layer:
    1. Header X-Device-Id (dikirim otomatis oleh JS via LocalStorage)
    2. Cookie _z_device_id
    3. Parameter JSON device_id
    4. Fallback: Hash IP + User-Agent
    """
    try:
        raw_id = None
        dev_header = request.headers.get('X-Device-Id')
        if dev_header and len(dev_header) >= 8:
            raw_id = dev_header

        if not raw_id:
            cookie_id = request.cookies.get('_z_device_id')
            if cookie_id and len(cookie_id) >= 8:
                raw_id = cookie_id

        if not raw_id and request.is_json:
            json_data = request.get_json(silent=True) or {}
            json_dev_id = json_data.get('device_id')
            if json_dev_id and len(json_dev_id) >= 8:
                raw_id = json_dev_id

        if raw_id:
            for prefix in ('dev_', 'cookie_', 'json_', 'device_'):
                if raw_id.startswith(prefix):
                    raw_id = raw_id[len(prefix):]
                    break
            return f"device_{raw_id}"

        return get_fp_id()
    except Exception:
        return get_fp_id()

def _db_get_batch_count(keys_list, today_str):
    global _MEMORY_STORE
    unique_keys = [k for k in set(keys_list) if k]
    if not unique_keys:
        return 0

    max_count = 0
    try:
        conn = _get_mysql_connection()
        if conn:
            with conn.cursor() as cursor:
                format_strings = ','.join(['%s'] * len(unique_keys))
                query = f"SELECT used_count FROM ai_quota WHERE quota_date = %s AND client_id IN ({format_strings})"
                cursor.execute(query, [today_str] + unique_keys)
                rows = cursor.fetchall()
                for r in rows:
                    max_count = max(max_count, r['used_count'])
            conn.close()
    except Exception:
        pass

    for k in unique_keys:
        mem_val = _MEMORY_STORE.get(k, {})
        if mem_val.get('date') == today_str:
            max_count = max(max_count, mem_val.get('count', 0))

    return max_count

def _db_set_batch_count(keys_list, today_str, count):
    global _MEMORY_STORE
    unique_keys = [k for k in set(keys_list) if k]
    if not unique_keys:
        return

    for k in unique_keys:
        _MEMORY_STORE[k] = {'date': today_str, 'count': count}

    try:
        conn = _get_mysql_connection()
        if conn:
            with conn.cursor() as cursor:
                records = [(k, today_str, count) for k in unique_keys]
                cursor.executemany('''
                    INSERT INTO ai_quota (client_id, quota_date, used_count)
                    VALUES (%s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        quota_date = VALUES(quota_date),
                        used_count = VALUES(used_count)
                ''', records)
            conn.close()
    except Exception:
        pass

def check_ai_quota(client_id=None):
    """
    STRICT PER-DEVICE AI RATE LIMITER:
    Memeriksa kuota AI harian per perangkat (Maksimal persis 2x / hari) via Database MySQL.
    Menggabungkan Device UUID + Browser Fingerprint (IP + UserAgent).
    - Berbeda Perangkat di Wi-Fi yang sama (HP vs Laptop): Mendapatkan kuota 2x masing-masing.
    - Hapus LocalStorage / Cookie / Incognito di perangkat yang sama: Tetap TERBLOKIR.
    - Pindah Menu (Ramalan -> Kecocokan -> Roasting): Tetap TERBLOKIR.
    """
    try:
        if not client_id:
            client_id = get_client_id()

        today_str = date.today().isoformat()

        fp_id = get_fp_id()

        keys_to_check = [client_id, fp_id]
        if client_id.startswith('device_'):
            raw = client_id[7:]
            keys_to_check.extend([f"dev_{raw}", f"cookie_{raw}", f"json_{raw}"])

        effective_count = _db_get_batch_count(keys_to_check, today_str)

        if effective_count >= DAILY_AI_LIMIT:
            notice = f"Kuota mode AI harian Anda telah habis (Maksimal {DAILY_AI_LIMIT}x per hari per perangkat). Beralih ke Data Prediksi Statis."
            return False, effective_count, DAILY_AI_LIMIT, notice

        return True, effective_count, DAILY_AI_LIMIT, None
    except Exception:
        # Emergency Fallback: Jangan pernah menggagalkan aplikasi jika terjadi error tak terduga
        return True, 0, DAILY_AI_LIMIT, None

def increment_ai_quota(client_id=None):
    """
    Menambah hitungan penggunaan AI harian per perangkat pada Device UUID dan Fingerprint (IP + UserAgent).
    """
    try:
        if not client_id:
            client_id = get_client_id()

        today_str = date.today().isoformat()

        is_allowed, current_count, limit, notice = check_ai_quota(client_id)
        new_count = current_count + 1

        fp_id = get_fp_id()

        keys_to_update = [client_id, fp_id]
        if client_id.startswith('device_'):
            raw = client_id[7:]
            keys_to_update.extend([f"dev_{raw}", f"cookie_{raw}", f"json_{raw}"])

        _db_set_batch_count(keys_to_update, today_str, new_count)

        return new_count
    except Exception:
        return 1









