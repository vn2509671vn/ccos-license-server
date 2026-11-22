"""Lightweight License Management Server for CCOS Automation.

Supports both SQLite (local file) and PostgreSQL (Render/Supabase via DATABASE_URL),
environment-driven configuration ($PORT, $SECRET_KEY, $ADMIN_PASSWORD),
and session-secured Admin Web Dashboard and APIs.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import sqlite3
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Generator, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Core Configurations
DB_PATH = Path(__file__).parent / "licenses.db"
SECRET_KEY = os.environ.get("SECRET_KEY", "CCOS_LICENSE_HMAC_SECRET_KEY_2026_VERY_SECURE")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123456")
DATABASE_URL = os.environ.get("DATABASE_URL")

# Database Connection Pool & Strategy
USE_POSTGRES = False
pg_pool: Any = None

if DATABASE_URL:
    try:
        import psycopg2
        import psycopg2.extras
        from psycopg2.pool import ThreadedConnectionPool

        dsn = DATABASE_URL.strip()
        # Render sometimes provides postgres:// which psycopg2 accepts or needs postgresql://
        if dsn.startswith("postgres://"):
            dsn = "postgresql://" + dsn[11:]

        pg_pool = ThreadedConnectionPool(1, 10, dsn=dsn, connect_timeout=6)
        # Test connection immediately
        _test_conn = pg_pool.getconn()
        pg_pool.putconn(_test_conn)
        USE_POSTGRES = True
        logger.info("Connected successfully to PostgreSQL database from DATABASE_URL.")
    except Exception as exc:
        logger.warning(
            "Failed to initialize PostgreSQL from DATABASE_URL (%s). Falling back to SQLite.",
            exc,
        )
        USE_POSTGRES = False
        pg_pool = None


class UniversalCursor:
    """Cursor adapter wrapping SQLite or PostgreSQL cursor with parameter translation."""

    def __init__(self, raw_cursor: Any, is_pg: bool) -> None:
        self._cur = raw_cursor
        self.is_pg = is_pg

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        if self.is_pg:
            # Replace SQLite '?' placeholder with PostgreSQL '%s'
            sql = sql.replace("?", "%s")
        return self._cur.execute(sql, params)

    def fetchone(self) -> Any:
        return self._cur.fetchone()

    def fetchall(self) -> list[Any]:
        return self._cur.fetchall()


class UniversalConnection:
    """Connection adapter yielding UniversalCursor."""

    def __init__(self, raw_conn: Any, is_pg: bool) -> None:
        self.raw_conn = raw_conn
        self.is_pg = is_pg

    def cursor(self) -> UniversalCursor:
        if self.is_pg:
            import psycopg2.extras

            cur = self.raw_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            cur = self.raw_conn.cursor()
        return UniversalCursor(cur, is_pg=self.is_pg)

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        cur = self.cursor()
        return cur.execute(sql, params)

    def commit(self) -> None:
        self.raw_conn.commit()

    def rollback(self) -> None:
        self.raw_conn.rollback()


@contextmanager
def get_db() -> Generator[UniversalConnection, None, None]:
    """Provide a transactional database connection (PostgreSQL or SQLite)."""
    if USE_POSTGRES and pg_pool is not None:
        raw_conn = pg_pool.getconn()
        conn = UniversalConnection(raw_conn, is_pg=True)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            pg_pool.putconn(raw_conn)
    else:
        raw_conn = sqlite3.connect(str(DB_PATH))
        raw_conn.row_factory = sqlite3.Row
        conn = UniversalConnection(raw_conn, is_pg=False)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            raw_conn.close()


def init_db() -> None:
    """Initialize database table schema and indexes."""
    with get_db() as conn:
        if USE_POSTGRES:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS licenses (
                    id SERIAL PRIMARY KEY,
                    license_key VARCHAR(100) UNIQUE NOT NULL,
                    client_name TEXT,
                    hwid TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    note TEXT
                )
                """
            )
        else:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS licenses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    license_key TEXT UNIQUE NOT NULL,
                    client_name TEXT,
                    hwid TEXT,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    is_active INTEGER DEFAULT 1,
                    note TEXT
                )
                """
            )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_key ON licenses(license_key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_hwid ON licenses(hwid)")


init_db()


# Token and Key Helpers
def generate_key_string() -> str:
    """Generate a clean license key: CCOS-XXXX-XXXX-XXXX."""
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    p1 = "".join(secrets.choice(chars) for _ in range(4))
    p2 = "".join(secrets.choice(chars) for _ in range(4))
    p3 = "".join(secrets.choice(chars) for _ in range(4))
    return f"CCOS-{p1}-{p2}-{p3}"


def sign_token(license_key: str, hwid: str, expires_at: str) -> str:
    """Generate HMAC-SHA256 signature for client license token."""
    data = f"{license_key}|{hwid}|{expires_at}".encode("utf-8")
    return hmac.new(SECRET_KEY.encode("utf-8"), data, hashlib.sha256).hexdigest()


# Admin Authentication Helpers
def create_admin_token() -> str:
    """Create a signed, time-stamped admin session token valid for 7 days."""
    ts = int(datetime.now(timezone.utc).timestamp())
    sig_data = f"admin_session:{ts}:{SECRET_KEY}".encode("utf-8")
    sig = hashlib.sha256(sig_data).hexdigest()
    return f"{ts}.{sig}"


def verify_admin_token(token: str) -> bool:
    """Verify signed admin token signature and expiration (7 days)."""
    if not token or "." not in token:
        return False
    try:
        parts = token.split(".", 1)
        ts = int(parts[0])
        sig = parts[1]
        now = int(datetime.now(timezone.utc).timestamp())
        # Valid for 7 days (604,800 seconds)
        if now - ts > 7 * 86400 or ts > now + 300:
            return False
        expected_sig = hashlib.sha256(f"admin_session:{ts}:{SECRET_KEY}".encode("utf-8")).hexdigest()
        return hmac.compare_digest(sig, expected_sig)
    except Exception:
        return False


def is_admin_authenticated(request: Optional[Request]) -> bool:
    """Check if request carries a valid admin session cookie or Bearer token."""
    if request is None:
        return True

    # 1. Check HttpOnly cookie
    cookie_token = request.cookies.get("admin_token")
    if cookie_token and verify_admin_token(cookie_token):
        return True

    # 2. Check Authorization Bearer header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        bearer_token = auth_header.split(" ", 1)[1].strip()
        if verify_admin_token(bearer_token):
            return True

    return False


def verify_admin(request: Request) -> None:
    """FastAPI route dependency ensuring admin authorization."""
    if not is_admin_authenticated(request):
        raise HTTPException(
            status_code=401,
            detail="Chưa đăng nhập hoặc phiên làm việc đã hết hạn. Vui lòng đăng nhập Admin.",
        )


# FastAPI Application
app = FastAPI(
    title="CCOS License Server",
    description="Máy chủ quản lý giấy phép và kích hoạt bản quyền CCOS Automation",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request / Response Schemas
class ActivateRequest(BaseModel):
    license_key: str
    hwid: str
    client_name: Optional[str] = ""


class VerifyRequest(BaseModel):
    license_key: str
    hwid: str
    token: Optional[str] = ""


class AdminLoginRequest(BaseModel):
    password: str


class CreateKeyRequest(BaseModel):
    days: int = Field(default=30, ge=1)
    client_name: Optional[str] = ""
    note: Optional[str] = ""


class ExtendKeyRequest(BaseModel):
    license_key: str
    days: int = Field(default=30, ge=1)


class KeyActionRequest(BaseModel):
    license_key: str


# Public Client Endpoints
@app.post("/api/license/activate")
def activate_license(req: ActivateRequest) -> dict[str, Any]:
    """Client activation endpoint. Binds key to client's HWID upon first use."""
    key = req.license_key.strip().upper()
    hwid = req.hwid.strip().upper()
    if not key or not hwid:
        return {"success": False, "message": "Thiếu mã kích hoạt hoặc mã máy HWID."}

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM licenses WHERE license_key = ?", (key,))
        row = cursor.fetchone()

        if not row:
            return {"success": False, "message": "Mã bản quyền không tồn tại trên hệ thống."}

        if not row["is_active"]:
            return {"success": False, "message": "Mã bản quyền này đã bị tạm khóa hoặc vô hiệu hóa."}

        # Check expiration
        exp_dt = datetime.fromisoformat(row["expires_at"])
        now = datetime.now()
        if now > exp_dt:
            return {
                "success": False,
                "message": f"Mã bản quyền đã hết hạn vào ngày {exp_dt.strftime('%d/%m/%Y %H:%M')}.",
            }

        current_hwid = row["hwid"]
        if current_hwid:
            # Key already bound to a hardware ID
            if current_hwid.upper() != hwid:
                return {
                    "success": False,
                    "message": "Mã bản quyền này đã được kích hoạt trên một thiết bị khác. Vui lòng liên hệ Admin để đổi máy.",
                }
        else:
            # Bind key to this machine HWID
            client_name = req.client_name or row["client_name"] or "Khách hàng"
            cursor.execute(
                "UPDATE licenses SET hwid = ?, client_name = ? WHERE license_key = ?",
                (hwid, client_name, key),
            )

        days_left = max(0, (exp_dt - now).days)
        token = sign_token(key, hwid, row["expires_at"])

        return {
            "success": True,
            "message": "Kích hoạt bản quyền thành công!",
            "token": token,
            "expires_at": row["expires_at"],
            "days_left": days_left,
            "client_name": row["client_name"] or req.client_name,
        }


@app.post("/api/license/verify")
def verify_license(req: VerifyRequest) -> dict[str, Any]:
    """Client verification endpoint."""
    key = req.license_key.strip().upper()
    hwid = req.hwid.strip().upper()

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM licenses WHERE license_key = ?", (key,))
        row = cursor.fetchone()

        if not row:
            return {"success": False, "message": "Bản quyền không hợp lệ."}

        if not row["is_active"]:
            return {"success": False, "message": "Bản quyền đã bị khóa bởi quản trị viên."}

        if row["hwid"] and row["hwid"].upper() != hwid:
            return {"success": False, "message": "Mã máy không khớp với bản quyền đã đăng ký."}

        exp_dt = datetime.fromisoformat(row["expires_at"])
        now = datetime.now()
        if now > exp_dt:
            return {
                "success": False,
                "message": f"Bản quyền đã hết hạn từ ngày {exp_dt.strftime('%d/%m/%Y %H:%M')}.",
            }

        days_left = max(0, (exp_dt - now).days)
        expected_token = sign_token(key, hwid, row["expires_at"])
        if req.token and req.token.strip() and req.token.strip() != expected_token:
            return {"success": False, "message": "Chữ ký token không hợp lệ hoặc đã bị thay đổi."}

        return {
            "success": True,
            "message": "Bản quyền hợp lệ.",
            "expires_at": row["expires_at"],
            "days_left": days_left,
            "token": expected_token,
        }


# Admin Authentication Endpoints
@app.post("/api/admin/login")
def admin_login(req: AdminLoginRequest) -> JSONResponse:
    """Admin login endpoint setting secure HttpOnly cookie and returning bearer token."""
    if secrets.compare_digest(req.password.strip(), ADMIN_PASSWORD.strip()):
        token = create_admin_token()
        resp = JSONResponse(
            content={"success": True, "token": token, "message": "Đăng nhập Admin thành công!"}
        )
        resp.set_cookie(
            key="admin_token",
            value=token,
            max_age=7 * 86400,
            httponly=True,
            samesite="lax",
        )
        return resp
    return JSONResponse(
        status_code=401,
        content={"success": False, "message": "Mật khẩu quản trị viên không chính xác."},
    )


@app.post("/api/admin/logout")
def admin_logout() -> JSONResponse:
    """Admin logout endpoint clearing session cookie."""
    resp = JSONResponse(content={"success": True, "message": "Đã đăng xuất phiên Admin."})
    resp.delete_cookie(key="admin_token")
    return resp


# Protected Admin Management Endpoints
@app.post("/api/admin/create-key", dependencies=[Depends(verify_admin)])
def create_key(req: CreateKeyRequest) -> dict[str, Any]:
    """Generate a new license key with given duration."""
    key = generate_key_string()
    now = datetime.now()
    expires_at = (now + timedelta(days=req.days)).isoformat()
    created_at = now.isoformat()

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO licenses (license_key, client_name, hwid, created_at, expires_at, is_active, note)
            VALUES (?, ?, NULL, ?, ?, 1, ?)
            """,
            (key, req.client_name, created_at, expires_at, req.note),
        )

    return {
        "success": True,
        "message": f"Tạo mã kích hoạt thành công: {key}",
        "license_key": key,
        "expires_at": expires_at,
        "days": req.days,
    }


@app.post("/api/admin/extend-key", dependencies=[Depends(verify_admin)])
def extend_key(req: ExtendKeyRequest) -> dict[str, Any]:
    """Extend expiration of an existing license key by N days."""
    key = req.license_key.strip().upper()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM licenses WHERE license_key = ?", (key,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Không tìm thấy mã bản quyền.")

        now = datetime.now()
        current_exp = datetime.fromisoformat(row["expires_at"])
        # If already expired, extend from now; if still active, extend from current expiration
        base_dt = current_exp if current_exp > now else now
        new_exp = (base_dt + timedelta(days=req.days)).isoformat()

        cursor.execute(
            "UPDATE licenses SET expires_at = ?, is_active = 1 WHERE license_key = ?",
            (new_exp, key),
        )

    days_left = max(0, (datetime.fromisoformat(new_exp) - now).days)
    return {
        "success": True,
        "message": f"Đã gia hạn thêm {req.days} ngày cho {key}.",
        "new_expires_at": new_exp,
        "days_left": days_left,
    }


@app.post("/api/admin/toggle-key", dependencies=[Depends(verify_admin)])
def toggle_key(req: KeyActionRequest) -> dict[str, Any]:
    """Toggle is_active state of a key."""
    key = req.license_key.strip().upper()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT is_active FROM licenses WHERE license_key = ?", (key,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Không tìm thấy mã bản quyền.")

        new_status = 0 if row["is_active"] else 1
        cursor.execute(
            "UPDATE licenses SET is_active = ? WHERE license_key = ?",
            (new_status, key),
        )

    action_label = "Mở khóa" if new_status == 1 else "Khóa"
    return {"success": True, "message": f"Đã {action_label} mã {key}.", "is_active": new_status}


@app.post("/api/admin/reset-hwid", dependencies=[Depends(verify_admin)])
def reset_hwid(req: KeyActionRequest) -> dict[str, Any]:
    """Unbind HWID from a license key so the customer can activate on another machine."""
    key = req.license_key.strip().upper()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE licenses SET hwid = NULL WHERE license_key = ?", (key,))

    return {"success": True, "message": f"Đã xóa liên kết máy (HWID) cho mã {key}."}


@app.post("/api/admin/delete-key", dependencies=[Depends(verify_admin)])
def delete_key(req: KeyActionRequest) -> dict[str, Any]:
    """Delete a key permanently."""
    key = req.license_key.strip().upper()
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM licenses WHERE license_key = ?", (key,))

    return {"success": True, "message": f"Đã xóa mã {key}."}


@app.get("/api/admin/keys", dependencies=[Depends(verify_admin)])
def get_all_keys() -> list[dict[str, Any]]:
    """Return all license keys."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM licenses ORDER BY id DESC")
        rows = cursor.fetchall()

    results = []
    now = datetime.now()
    for r in rows:
        exp_dt = datetime.fromisoformat(r["expires_at"])
        days_left = (exp_dt - now).days if exp_dt > now else 0
        is_expired = exp_dt <= now
        results.append(
            {
                "id": r["id"],
                "license_key": r["license_key"],
                "client_name": r["client_name"] or "",
                "hwid": r["hwid"] or "",
                "created_at": r["created_at"],
                "expires_at": r["expires_at"],
                "is_active": bool(r["is_active"]),
                "note": r["note"] or "",
                "days_left": days_left,
                "is_expired": is_expired,
            }
        )
    return results


# Admin Login UI (HTML)
ADMIN_LOGIN_HTML = """<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Đăng nhập Admin - CCOS License Server</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #0F4C81;
            --primary-hover: #1565C0;
            --bg: #F4F6F9;
            --card: #FFFFFF;
            --text: #263238;
            --border: #CFD8DC;
            --danger: #D32F2F;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        body {
            background: linear-gradient(135deg, #0F4C81 0%, #1A237E 100%);
            min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px;
        }
        .login-card {
            background: var(--card); border-radius: 12px; width: 100%; max-width: 420px;
            padding: 36px 32px; box-shadow: 0 10px 30px rgba(0,0,0,0.25);
        }
        .login-header { text-align: center; margin-bottom: 28px; }
        .login-header h1 { font-size: 20px; color: var(--primary); font-weight: 700; margin-bottom: 8px; }
        .login-header p { font-size: 13.5px; color: #607D8B; }
        .form-group { margin-bottom: 20px; }
        label { display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; color: #455A64; }
        .input-wrap { position: relative; }
        input[type="password"], input[type="text"] {
            width: 100%; padding: 11px 14px; border: 1.5px solid var(--border);
            border-radius: 7px; font-size: 14px; outline: none; transition: border-color 0.2s;
        }
        input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(15, 76, 129, 0.15); }
        button.btn-submit {
            width: 100%; padding: 11px; background: var(--primary); color: white;
            border: none; border-radius: 7px; font-size: 15px; font-weight: 600;
            cursor: pointer; transition: background 0.2s; margin-top: 8px;
        }
        button.btn-submit:hover { background: var(--primary-hover); }
        .error-msg {
            color: var(--danger); font-size: 13px; margin-top: 12px;
            background: #FFEBEE; padding: 8px 12px; border-radius: 6px;
            display: none; border-left: 4px solid var(--danger);
        }
        .footer-note { text-align: center; margin-top: 24px; font-size: 12px; color: #90A4AE; }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="login-header">
            <h1>🔐 CCOS License Admin</h1>
            <p>Vui lòng nhập mật khẩu quản trị viên để tiếp tục</p>
        </div>
        <form id="login-form" onsubmit="handleLogin(event)">
            <div class="form-group">
                <label for="admin-pass">Mật khẩu Admin:</label>
                <div class="input-wrap">
                    <input type="password" id="admin-pass" placeholder="Nhập mật khẩu..." required autofocus>
                </div>
                <div class="error-msg" id="error-box"></div>
            </div>
            <button type="submit" class="btn-submit" id="btn-login">Đăng Nhập Quản Trị</button>
        </form>
        <div class="footer-note">CCOS Automation &bull; Cloud License Management</div>
    </div>

    <script>
        async function handleLogin(e) {
            e.preventDefault();
            const pass = document.getElementById("admin-pass").value;
            const errBox = document.getElementById("error-box");
            const btn = document.getElementById("btn-login");

            errBox.style.display = "none";
            btn.disabled = true;
            btn.innerText = "Đang xác thực...";

            try {
                const res = await fetch("/api/admin/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ password: pass })
                });
                const data = await res.json();
                if (res.ok && data.success) {
                    window.location.reload();
                } else {
                    errBox.innerText = data.message || "Mật khẩu quản trị viên không chính xác!";
                    errBox.style.display = "block";
                }
            } catch (err) {
                errBox.innerText = "Lỗi kết nối máy chủ: " + err.message;
                errBox.style.display = "block";
            } finally {
                btn.disabled = false;
                btn.innerText = "Đăng Nhập Quản Trị";
            }
        }
    </script>
</body>
</html>
"""

# Admin Dashboard UI (HTML/CSS/JS)
ADMIN_HTML = """<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CCOS License Management Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #0F4C81;
            --primary-hover: #1565C0;
            --success: #2E7D32;
            --danger: #C62828;
            --warning: #EF6C00;
            --bg: #F4F6F9;
            --card: #FFFFFF;
            --text: #263238;
            --text-muted: #607D8B;
            --border: #E0E0E0;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        body { background: var(--bg); color: var(--text); padding-bottom: 50px; }
        header {
            background: linear-gradient(135deg, #0F4C81 0%, #1A237E 100%);
            color: white; padding: 20px 32px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;
        }
        header h1 { font-size: 20px; font-weight: 700; display: flex; align-items: center; gap: 10px; }
        .header-actions { display: flex; align-items: center; gap: 12px; }
        .badge-admin { background: rgba(255,255,255,0.2); padding: 5px 12px; border-radius: 20px; font-size: 13px; font-weight: 500; }
        .btn-logout {
            background: #FF5252; color: white; border: none; padding: 6px 14px;
            border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; transition: background 0.2s;
        }
        .btn-logout:hover { background: #D32F2F; }

        .container { max-width: 1240px; margin: 28px auto; padding: 0 20px; }
        
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 18px; margin-bottom: 24px; }
        .stat-card {
            background: var(--card); border-radius: 10px; padding: 18px 22px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05); border-left: 5px solid var(--primary);
        }
        .stat-card.green { border-color: var(--success); }
        .stat-card.orange { border-color: var(--warning); }
        .stat-card.red { border-color: var(--danger); }
        .stat-label { font-size: 13px; color: var(--text-muted); font-weight: 500; text-transform: uppercase; }
        .stat-val { font-size: 28px; font-weight: 700; margin-top: 6px; }

        .card {
            background: var(--card); border-radius: 10px; padding: 22px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05); margin-bottom: 24px;
        }
        .card-title { font-size: 17px; font-weight: 600; margin-bottom: 16px; color: var(--primary); }

        .form-row { display: flex; gap: 14px; flex-wrap: wrap; align-items: flex-end; }
        .form-group { display: flex; flex-direction: column; gap: 6px; flex: 1; min-width: 180px; }
        label { font-size: 13px; font-weight: 600; color: #455A64; }
        input, select {
            padding: 9px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: 14px; outline: none;
        }
        input:focus { border-color: var(--primary); box-shadow: 0 0 0 2px rgba(15, 76, 129, 0.2); }
        button {
            padding: 9px 18px; border-radius: 6px; border: none; font-weight: 600; cursor: pointer;
            transition: all 0.2s; font-size: 14px; display: inline-flex; align-items: center; gap: 6px;
        }
        .btn-primary { background: var(--primary); color: white; }
        .btn-primary:hover { background: var(--primary-hover); }
        .btn-success { background: #E8F5E9; color: var(--success); border: 1px solid #A5D6A7; }
        .btn-success:hover { background: var(--success); color: white; }
        .btn-danger { background: #FFEBEE; color: var(--danger); border: 1px solid #FFCDD2; }
        .btn-danger:hover { background: var(--danger); color: white; }
        .btn-secondary { background: #ECEFF1; color: #455A64; border: 1px solid #CFD8DC; }
        .btn-secondary:hover { background: #CFD8DC; }

        table { width: 100%; border-collapse: collapse; margin-top: 12px; }
        th, td { padding: 12px 14px; text-align: left; font-size: 13.5px; border-bottom: 1px solid var(--border); }
        th { background: #F8FAFC; color: #455A64; font-weight: 600; }
        tr:hover { background: #FAFAFA; }
        .badge {
            display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600;
        }
        .badge-active { background: #E8F5E9; color: #2E7D32; }
        .badge-locked { background: #FFEBEE; color: #C62828; }
        .badge-expired { background: #FFF3E0; color: #EF6C00; }

        .key-text { font-family: monospace; font-size: 14px; font-weight: 600; color: #0F4C81; letter-spacing: 0.5px; }
        .copy-btn { padding: 2px 6px; font-size: 11px; margin-left: 6px; background: #ECEFF1; border-radius: 4px; }
        .toast {
            position: fixed; bottom: 24px; right: 24px; background: #37474F; color: white;
            padding: 12px 20px; border-radius: 6px; box-shadow: 0 4px 14px rgba(0,0,0,0.2);
            font-size: 14px; z-index: 9999; display: none; animation: fadeIn 0.3s;
        }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    </style>
</head>
<body>
    <header>
        <h1>🔐 CCOS License Server Dashboard</h1>
        <div class="header-actions">
            <span class="badge-admin">Admin Authenticated</span>
            <button class="btn-logout" onclick="logout()">🚪 Đăng Xuất</button>
        </div>
    </header>

    <div class="container">
        <!-- Stats Summary -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Tổng số Key</div>
                <div class="stat-val" id="stat-total">0</div>
            </div>
            <div class="stat-card green">
                <div class="stat-label">Đang Hoạt Động</div>
                <div class="stat-val" id="stat-active" style="color: var(--success);">0</div>
            </div>
            <div class="stat-card orange">
                <div class="stat-label">Đã Gắn Máy (HWID)</div>
                <div class="stat-val" id="stat-bound" style="color: var(--warning);">0</div>
            </div>
            <div class="stat-card red">
                <div class="stat-label">Hết Hạn / Tạm Khóa</div>
                <div class="stat-val" id="stat-expired" style="color: var(--danger);">0</div>
            </div>
        </div>

        <!-- Create Key Card -->
        <div class="card">
            <div class="card-title">➕ Tạo Key Bản Quyền Mới</div>
            <div class="form-row">
                <div class="form-group">
                    <label>Tên Khách Hàng / Đơn Vị:</label>
                    <input type="text" id="new-client" placeholder="Ví dụ: Đại lý VNPT Hà Nội">
                </div>
                <div class="form-group" style="max-width: 160px;">
                    <label>Thời Hạn (Ngày):</label>
                    <input type="number" id="new-days" value="30" min="1">
                </div>
                <div class="form-group">
                    <label>Ghi Chú:</label>
                    <input type="text" id="new-note" placeholder="Thông tin liên hệ, gói mua...">
                </div>
                <button class="btn-primary" onclick="createKey()" style="height: 38px;">
                    ✨ Tạo Key Ngay
                </button>
            </div>
        </div>

        <!-- License Keys List -->
        <div class="card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; flex-wrap: wrap; gap: 10px;">
                <div class="card-title" style="margin-bottom: 0;">📋 Danh Sách Bản Quyền Đã Cấp</div>
                <input type="text" id="search-input" onkeyup="filterTable()" placeholder="🔍 Tìm kiếm key, khách hàng, HWID..." style="width: 280px;">
            </div>

            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>STT</th>
                            <th>Mã License Key</th>
                            <th>Khách Hàng</th>
                            <th>Mã Máy (HWID)</th>
                            <th>Hạn Dùng</th>
                            <th>Còn Lại</th>
                            <th>Trạng Thái</th>
                            <th>Thao Tác Quản Lý</th>
                        </tr>
                    </thead>
                    <tbody id="license-table-body">
                        <tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 24px;">Đang tải dữ liệu...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="toast" id="toast-msg"></div>

    <script>
        let allKeys = [];

        function showToast(msg) {
            const toast = document.getElementById("toast-msg");
            toast.innerText = msg;
            toast.style.display = "block";
            setTimeout(() => { toast.style.display = "none"; }, 3200);
        }

        async function apiFetch(url, options = {}) {
            options.credentials = "include";
            const res = await fetch(url, options);
            if (res.status === 401) {
                showToast("Phiên đăng nhập đã hết hạn. Đang chuyển hướng...");
                setTimeout(() => { window.location.reload(); }, 1200);
                throw new Error("Unauthorized");
            }
            return res;
        }

        async function logout() {
            try {
                await apiFetch("/api/admin/logout", { method: "POST" });
            } finally {
                window.location.reload();
            }
        }

        async function fetchKeys() {
            try {
                const res = await apiFetch("/api/admin/keys");
                allKeys = await res.json();
                renderTable(allKeys);
                updateStats(allKeys);
            } catch (err) {
                console.error("Lỗi nạp danh sách key:", err);
            }
        }

        function updateStats(keys) {
            document.getElementById("stat-total").innerText = keys.length;
            const active = keys.filter(k => k.is_active && !k.is_expired).length;
            const bound = keys.filter(k => k.hwid && k.hwid.trim() !== "").length;
            const expired = keys.filter(k => !k.is_active || k.is_expired).length;
            document.getElementById("stat-active").innerText = active;
            document.getElementById("stat-bound").innerText = bound;
            document.getElementById("stat-expired").innerText = expired;
        }

        function renderTable(keys) {
            const tbody = document.getElementById("license-table-body");
            if (!keys.length) {
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 24px;">Chưa có key nào. Hãy tạo key đầu tiên!</td></tr>';
                return;
            }

            tbody.innerHTML = keys.map((k, idx) => {
                const expDate = new Date(k.expires_at).toLocaleString("vi-VN");
                let statusBadge = "";
                if (!k.is_active) {
                    statusBadge = '<span class="badge badge-locked">Đã Khóa</span>';
                } else if (k.is_expired) {
                    statusBadge = '<span class="badge badge-expired">Hết Hạn</span>';
                } else {
                    statusBadge = '<span class="badge badge-active">Hoạt Động</span>';
                }

                const hwidDisplay = k.hwid ? `<span style="font-family: monospace;">${k.hwid}</span>` : '<span style="color: #9E9E9E; font-style: italic;">Chưa kích hoạt</span>';

                return `
                    <tr>
                        <td>${idx + 1}</td>
                        <td>
                            <span class="key-text">${k.license_key}</span>
                            <button class="copy-btn" onclick="copyText('${k.license_key}')">Copy</button>
                        </td>
                        <td><strong>${escapeHtml(k.client_name || "---")}</strong><br><small style="color: #78909C;">${escapeHtml(k.note || "")}</small></td>
                        <td>${hwidDisplay}</td>
                        <td>${expDate}</td>
                        <td><strong>${k.days_left} ngày</strong></td>
                        <td>${statusBadge}</td>
                        <td>
                            <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                                <button class="btn-success" title="Gia hạn thêm 30 ngày" onclick="extendKey('${k.license_key}', 30)">+30 Ngày</button>
                                <button class="btn-secondary" title="Bật/Tắt khóa" onclick="toggleKey('${k.license_key}')">${k.is_active ? 'Khóa' : 'Mở'}</button>
                                ${k.hwid ? `<button class="btn-secondary" title="Gỡ máy cũ để kích hoạt máy mới" onclick="resetHWID('${k.license_key}')">Reset HWID</button>` : ''}
                                <button class="btn-danger" title="Xóa vĩnh viễn" onclick="deleteKey('${k.license_key}')">Xóa</button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join("");
        }

        function escapeHtml(str) {
            return (str || "").replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[m]);
        }

        function copyText(txt) {
            navigator.clipboard.writeText(txt);
            showToast("Đã sao chép: " + txt);
        }

        async function createKey() {
            const client = document.getElementById("new-client").value.trim();
            const days = parseInt(document.getElementById("new-days").value) || 30;
            const note = document.getElementById("new-note").value.trim();

            const res = await apiFetch("/api/admin/create-key", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ client_name: client, days: days, note: note })
            });
            const data = await res.json();
            if (data.success) {
                showToast("Đã tạo Key: " + data.license_key);
                document.getElementById("new-client").value = "";
                document.getElementById("new-note").value = "";
                fetchKeys();
            }
        }

        async function extendKey(key, days) {
            const res = await apiFetch("/api/admin/extend-key", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ license_key: key, days: days })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                fetchKeys();
            }
        }

        async function toggleKey(key) {
            const res = await apiFetch("/api/admin/toggle-key", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ license_key: key })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                fetchKeys();
            }
        }

        async function resetHWID(key) {
            if (!confirm(`Bạn có chắc chắn muốn gỡ liên kết máy cho key ${key}?`)) return;
            const res = await apiFetch("/api/admin/reset-hwid", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ license_key: key })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                fetchKeys();
            }
        }

        async function deleteKey(key) {
            if (!confirm(`Cảnh báo: Bạn có chắc chắn muốn xóa vĩnh viễn key ${key}?`)) return;
            const res = await apiFetch("/api/admin/delete-key", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ license_key: key })
            });
            const data = await res.json();
            if (data.success) {
                showToast(data.message);
                fetchKeys();
            }
        }

        function filterTable() {
            const q = document.getElementById("search-input").value.toLowerCase();
            const filtered = allKeys.filter(k => 
                k.license_key.toLowerCase().includes(q) ||
                (k.client_name && k.client_name.toLowerCase().includes(q)) ||
                (k.hwid && k.hwid.toLowerCase().includes(q)) ||
                (k.note && k.note.toLowerCase().includes(q))
            );
            renderTable(filtered);
        }

        fetchKeys();
        setInterval(fetchKeys, 15000);
    </script>
</body>
</html>
"""


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request = None) -> HTMLResponse:
    """Serve the Web Admin Dashboard if authenticated, else render login form."""
    if request is not None and not is_admin_authenticated(request):
        return HTMLResponse(content=ADMIN_LOGIN_HTML)
    return HTMLResponse(content=ADMIN_HTML)


@app.get("/")
def index() -> dict[str, Any]:
    """Root endpoint."""
    return {
        "service": "CCOS License Server",
        "status": "online",
        "admin_dashboard": "/admin",
        "docs": "/docs",
        "database": "postgresql" if USE_POSTGRES else "sqlite",
    }


def run_server(host: str = "0.0.0.0", port: Optional[int] = None) -> None:
    """Run uvicorn server directly, reading $PORT environment variable for Render cloud."""
    import uvicorn

    if port is None:
        port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()
