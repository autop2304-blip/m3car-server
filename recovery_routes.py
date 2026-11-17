"""
M3CAR Driver Password Recovery & Admin Auth Routes for Render (Python / Flask / Gunicorn).

Drop-in module for the separate Render backend repository (https://m3car-server.onrender.com).
Uses existing `drivers.json` storage (no new database) and Python 3 standard library cryptography:
- scrypt password & recovery code hashing (byte-for-byte compatible with Node.js crypto.scrypt)
- HMAC-SHA256 signed Admin & Driver Bearer tokens
- Timing-safe comparisons (`hmac.compare_digest`)
- Thread-safe atomic JSON writes (`os.replace`)
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from flask import Blueprint, Request, Response, jsonify, make_response, request
except ImportError:  # pragma: no cover - allows standalone Python testing without Flask installed
    Blueprint = None  # type: ignore[assignment]
    Request = Any  # type: ignore[assignment,misc]
    Response = Any  # type: ignore[assignment,misc]
    jsonify = None  # type: ignore[assignment]
    make_response = None  # type: ignore[assignment]
    request = None  # type: ignore[assignment]


DEFAULT_ADMIN_CODE_SHA256 = (
    "a908081aae8d37b4a67184aae945148aa6954b56e068067de718e6692db02d22"
)
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 64
SCRYPT_MAXMEM = 32 * 1024 * 1024
ADMIN_SESSION_TTL_SEC = 24 * 60 * 60
DRIVER_SESSION_TTL_SEC = 24 * 60 * 60
RECOVERY_CODE_TTL_SEC = 24 * 60 * 60

_DRIVERS_FILE_LOCK = threading.RLock()
_RATE_LIMIT_LOCK = threading.Lock()
_FAILED_ATTEMPTS: Dict[str, List[float]] = {}

_PLACEHOLDER_SECRETS = {
    "ADMIN_ACCESS_CODE",
    "MY_ADMIN_ACCESS_CODE",
    "YOUR_ADMIN_ACCESS_CODE",
    "ADMIN_SESSION_SECRET",
    "MY_ADMIN_SESSION_SECRET",
    "CHANGE_ME",
}


def _clean_env_secret(name: str) -> str:
    val = (os.environ.get(name) or "").strip()
    if (val.startswith('"') and val.endswith('"')) or (
        val.startswith("'") and val.endswith("'")
    ):
        val = val[1:-1].strip()
    if val.upper() in _PLACEHOLDER_SECRETS:
        return ""
    return val


def get_expected_admin_sha256() -> str:
    env_code = _clean_env_secret("ADMIN_ACCESS_CODE")
    if env_code:
        return hashlib.sha256(env_code.encode("utf-8")).hexdigest()
    return DEFAULT_ADMIN_CODE_SHA256


def get_session_secret() -> str:
    env_secret = _clean_env_secret("ADMIN_SESSION_SECRET")
    if len(env_secret) >= 16:
        return env_secret
    return hashlib.sha256(
        f"m3car-session-key:{get_expected_admin_sha256()}".encode("utf-8")
    ).hexdigest()


def get_drivers_json_path() -> str:
    env_path = (os.environ.get("DRIVERS_JSON_PATH") or "").strip()
    if env_path:
        return env_path
    return os.path.join(os.getcwd(), "drivers.json")


def normalize_phone_canonical(raw: Any) -> str:
    digits = re.sub(r"\D", "", str(raw or ""))
    if not digits:
        return ""
    if digits.startswith("0062"):
        digits = "0" + digits[4:]
    elif digits.startswith("620"):
        digits = "0" + digits[3:]
    elif digits.startswith("62"):
        digits = "0" + digits[2:]
    elif digits.startswith("8"):
        digits = "0" + digits
    return digits


def normalize_plate(raw: Any) -> str:
    return re.sub(r"\s+", "", str(raw or "").upper())


def normalize_name(raw: Any) -> str:
    return re.sub(r"\s+", " ", str(raw or "").strip().lower())


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(encoded: str) -> bytes:
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode((encoded + padding).encode("ascii"))


def hash_scrypt(secret: str) -> str:
    salt = secrets.token_hex(16)
    derived = hashlib.scrypt(
        secret.encode("utf-8"),
        salt=salt.encode("utf-8"),
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=SCRYPT_MAXMEM,
        dklen=SCRYPT_DKLEN,
    )
    return f"scrypt${salt}${derived.hex()}"


def verify_password_hash(secret: str, stored_hash: str) -> bool:
    if not secret or not isinstance(stored_hash, str):
        return False
    stored = stored_hash.strip()
    if stored.startswith("scrypt$"):
        parts = stored.split("$")
        if len(parts) != 3 or not parts[1] or not parts[2]:
            return False
        _, salt, expected_hex = parts
        try:
            derived = hashlib.scrypt(
                secret.encode("utf-8"),
                salt=salt.encode("utf-8"),
                n=SCRYPT_N,
                r=SCRYPT_R,
                p=SCRYPT_P,
                maxmem=SCRYPT_MAXMEM,
                dklen=SCRYPT_DKLEN,
            )
            return hmac.compare_digest(derived.hex(), expected_hex.lower())
        except Exception:
            return False
    if re.fullmatch(r"[a-fA-F0-9]{64}", stored):
        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        return hmac.compare_digest(digest.lower(), stored.lower())
    return False


def sign_token(payload: Dict[str, Any]) -> str:
    encoded = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(
        get_session_secret().encode("utf-8"),
        encoded.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return f"{encoded}.{_b64url_encode(sig)}"


def verify_token(token: Optional[str], expected_role: str) -> Optional[Dict[str, Any]]:
    if not token or not isinstance(token, str) or "." not in token:
        return None
    parts = token.split(".", 1)
    if len(parts) != 2:
        return None
    encoded, provided_sig = parts
    if not encoded or not provided_sig:
        return None
    expected_sig = _b64url_encode(
        hmac.new(
            get_session_secret().encode("utf-8"),
            encoded.encode("utf-8"),
            hashlib.sha256,
        ).digest()
    )
    if not hmac.compare_digest(provided_sig, expected_sig):
        return None
    try:
        decoded = json.loads(_b64url_decode(encoded).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(decoded, dict) or decoded.get("role") != expected_role:
        return None
    exp = decoded.get("exp")
    if not isinstance(exp, (int, float)) or exp <= time.time() * 1000:
        return None
    return decoded


def extract_bearer_token(headers: Dict[str, Any]) -> str:
    for k, v in (headers or {}).items():
        if str(k).lower() == "authorization" and isinstance(v, str):
            val = v.strip()
            if val.lower().startswith("bearer "):
                return val[7:].strip()
    return ""


def _check_rate_limit(key: str, max_attempts: int = 10, window_sec: int = 300) -> Tuple[bool, int]:
    now = time.time()
    cutoff = now - window_sec
    with _RATE_LIMIT_LOCK:
        recent = [t for t in _FAILED_ATTEMPTS.get(key, []) if t > cutoff]
        if len(recent) >= max_attempts:
            retry_after = max(1, int(recent[0] + window_sec - now))
            _FAILED_ATTEMPTS[key] = recent
            return False, retry_after
        _FAILED_ATTEMPTS[key] = recent
        return True, 0


def _record_failed_attempt(key: str, window_sec: int = 300) -> Tuple[bool, int]:
    now = time.time()
    cutoff = now - window_sec
    with _RATE_LIMIT_LOCK:
        recent = [t for t in _FAILED_ATTEMPTS.get(key, []) if t > cutoff]
        recent.append(now)
        _FAILED_ATTEMPTS[key] = recent
        if len(recent) > 10:
            retry_after = max(1, int(recent[0] + window_sec - now))
            return False, retry_after
        return True, 0


def _clear_failed_attempts(key: str) -> None:
    with _RATE_LIMIT_LOCK:
        _FAILED_ATTEMPTS.pop(key, None)


def _read_drivers_file(path: str) -> Tuple[List[Dict[str, Any]], str]:
    """Return (drivers_list, shape_mode) where shape_mode is 'list' or 'dict'."""
    if not os.path.exists(path):
        return [], "list"
    with open(path, "r", encoding="utf-8") as fh:
        raw_text = fh.read().strip()
    if not raw_text:
        return [], "list"
    data = json.loads(raw_text)
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)], "list"
    if isinstance(data, dict) and isinstance(data.get("drivers"), list):
        return [d for d in data["drivers"] if isinstance(d, dict)], "dict"
    return [], "list"


def _write_drivers_file(path: str, drivers: List[Dict[str, Any]], shape_mode: str = "list") -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp_path = f"{path}.tmp.{os.getpid()}.{threading.get_ident()}"
    payload: Any = {"drivers": drivers} if shape_mode == "dict" else drivers
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    os.replace(tmp_path, path)


def _find_driver_index(
    drivers: List[Dict[str, Any]], driver_id: str = "", phone: str = ""
) -> int:
    clean_id = (driver_id or "").strip()
    clean_phone = normalize_phone_canonical(phone)
    if clean_id:
        for idx, d in enumerate(drivers):
            if str(d.get("id") or "").strip() == clean_id:
                return idx
    if clean_phone:
        for idx, d in enumerate(drivers):
            for field in ("phoneNormalized", "phone", "no_hp", "telepon", "hp"):
                if normalize_phone_canonical(d.get(field)) == clean_phone and not d.get("isDeleted"):
                    return idx
    return -1


def _resolve_effective_approval(driver: Dict[str, Any]) -> str:
    raw = str(driver.get("status") or "").strip().lower()
    if raw in ("blocked", "diblokir"):
        return "blocked"
    if raw in ("rejected", "ditolak"):
        return "rejected"
    if raw in ("approved", "active", "aktif"):
        return "approved"
    return "pending"


def _parse_iso_future(iso_str: str) -> bool:
    if not iso_str or not isinstance(iso_str, str):
        return False
    val = iso_str.strip()
    if val.endswith("Z"):
        val = val[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(val)
    except Exception:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.timestamp() > time.time()


def _utc_iso_after(seconds: int) -> str:
    return (
        dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=seconds)
    ).isoformat().replace("+00:00", "Z")


def _utc_iso_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


class RecoveryBackendService:
    """Framework-agnostic handler logic backed by existing `drivers.json`."""

    def __init__(self, drivers_json_path: Optional[str] = None):
        self._explicit_path = drivers_json_path

    @property
    def drivers_path(self) -> str:
        return self._explicit_path or get_drivers_json_path()

    def handle_admin_login(
        self, body: Dict[str, Any], client_ip: str = "unknown"
    ) -> Tuple[int, Dict[str, Any]]:
        lock_key = f"admin:{client_ip}"
        allowed, retry_after = _check_rate_limit(lock_key)
        if not allowed:
            return 429, {
                "ok": False,
                "code": "ACCOUNT_TEMP_LOCKED",
                "retryAfterSec": retry_after,
                "message": f"Terlalu banyak percobaan Kode Admin salah. Tunggu {retry_after} detik lagi.",
            }

        raw_code = str(body.get("code") or "").strip()
        if not raw_code:
            return 400, {"ok": False, "message": "Kode Admin wajib diisi."}

        input_sha = hashlib.sha256(raw_code.encode("utf-8")).hexdigest()
        expected_sha = get_expected_admin_sha256()
        if not hmac.compare_digest(input_sha.lower(), expected_sha.lower()):
            still_ok, retry_sec = _record_failed_attempt(lock_key)
            if not still_ok:
                return 429, {
                    "ok": False,
                    "code": "ACCOUNT_TEMP_LOCKED",
                    "retryAfterSec": retry_sec,
                    "message": f"Terlalu banyak percobaan Kode Admin salah. Tunggu {retry_sec} detik lagi.",
                }
            return 401, {"ok": False, "message": "Kode Salah"}

        _clear_failed_attempts(lock_key)
        now_ms = int(time.time() * 1000)
        exp_ms = now_ms + ADMIN_SESSION_TTL_SEC * 1000
        payload = {
            "role": "admin",
            "name": "Admin Pusat M3CAR",
            "jti": secrets.token_hex(16),
            "iat": now_ms,
            "exp": exp_ms,
        }
        token = sign_token(payload)
        return 200, {
            "ok": True,
            "authenticated": True,
            "token": token,
            "expiresAt": exp_ms,
            "user": {
                "id": "admin-root",
                "name": payload["name"],
                "role": "admin",
            },
        }

    def handle_generate_recovery_code(
        self, body: Dict[str, Any], headers: Dict[str, Any]
    ) -> Tuple[int, Dict[str, Any]]:
        admin_token = extract_bearer_token(headers)
        admin_payload = verify_token(admin_token, "admin")
        if not admin_payload:
            return 401, {
                "ok": False,
                "authenticated": False,
                "message": "Akses ditolak. Hanya Admin yang sudah login yang dapat membuat kode pemulihan.",
            }

        driver_id = str(body.get("driverId") or "").strip()
        driver_phone = normalize_phone_canonical(body.get("phone") or "")
        if not driver_id and not driver_phone:
            return 400, {"ok": False, "message": "ID Driver wajib diisi."}

        recovery_code = str(100000 + secrets.randbelow(900000))
        recovery_code_hash = hash_scrypt(recovery_code)
        recovery_code_expires_at = _utc_iso_after(RECOVERY_CODE_TTL_SEC)
        now_iso = _utc_iso_now()

        stored_in_drivers_json = False
        resolved_driver_id = driver_id
        with _DRIVERS_FILE_LOCK:
            drivers, shape_mode = _read_drivers_file(self.drivers_path)
            idx = _find_driver_index(drivers, driver_id=driver_id, phone=driver_phone)
            if idx >= 0:
                target = dict(drivers[idx])
                if target.get("isDeleted"):
                    return 404, {"ok": False, "message": "Akun driver tidak ditemukan."}
                resolved_driver_id = str(target.get("id") or driver_id)
                # Preserve status, balance, saldo, approvedByAdmin, etc.
                # NEVER store plaintext recoveryCode.
                target.pop("recoveryCode", None)
                target["recoveryCodeHash"] = recovery_code_hash
                target["recoveryCodeExpiresAt"] = recovery_code_expires_at
                target["recoveryCodeUsed"] = False
                target["recoveryCodeCreatedAt"] = now_iso
                target["updatedAt"] = now_iso
                drivers[idx] = target
                _write_drivers_file(self.drivers_path, drivers, shape_mode)
                stored_in_drivers_json = True

        return 200, {
            "ok": True,
            "driverId": resolved_driver_id,
            "recoveryCode": recovery_code,
            "recoveryCodeHash": recovery_code_hash,
            "recoveryCodeExpiresAt": recovery_code_expires_at,
            "storedInDriversJson": stored_in_drivers_json,
        }

    def handle_recover_password(
        self, body: Dict[str, Any], client_ip: str = "unknown"
    ) -> Tuple[int, Dict[str, Any]]:
        phone = normalize_phone_canonical(body.get("phone") or "")
        driver_id = str(body.get("driverId") or "").strip()
        recovery_code = str(body.get("recoveryCode") or "").strip()
        new_password = body.get("newPassword")
        confirm_password = body.get("confirmPassword")

        if not phone:
            return 400, {"ok": False, "message": "Nomor HP terdaftar wajib diisi."}

        if not isinstance(new_password, str) or len(new_password) < 4 or not new_password.strip():
            return 400, {
                "ok": False,
                "message": "Kata sandi baru minimal 4 karakter dan tidak boleh hanya spasi.",
            }
        if len(new_password) > 128:
            return 400, {"ok": False, "message": "Kata sandi maksimal 128 karakter."}
        if confirm_password is not None and new_password != confirm_password:
            return 400, {"ok": False, "message": "Konfirmasi kata sandi baru tidak cocok."}

        rate_key = f"recover:{client_ip}:{phone}"
        allowed, retry_after = _check_rate_limit(rate_key)
        if not allowed:
            return 429, {
                "ok": False,
                "retryAfterSec": retry_after,
                "message": f"Terlalu banyak percobaan pemulihan. Coba lagi dalam {retry_after} detik.",
            }

        with _DRIVERS_FILE_LOCK:
            drivers, shape_mode = _read_drivers_file(self.drivers_path)
            idx = _find_driver_index(drivers, driver_id=driver_id, phone=phone)
            auth_driver: Optional[Dict[str, Any]] = dict(drivers[idx]) if idx >= 0 else None

            if auth_driver and auth_driver.get("isDeleted"):
                return 401, {"ok": False, "message": "Nomor HP atau Nomor Polisi tidak cocok."}

            if auth_driver and _resolve_effective_approval(auth_driver) == "blocked":
                return 403, {
                    "ok": False,
                    "blocked": True,
                    "message": "Akun Driver Anda sedang DIBLOKIR oleh Admin. Hubungi Admin Pusat M3CAR.",
                }

            stored_phone = (
                normalize_phone_canonical(
                    auth_driver.get("phoneNormalized")
                    or auth_driver.get("phone")
                    or auth_driver.get("no_hp")
                    or auth_driver.get("telepon")
                )
                if auth_driver
                else normalize_phone_canonical(body.get("storedPhone") or "")
            )
            if not stored_phone or phone != stored_phone:
                return 400, {"ok": False, "message": "Nomor HP atau Nomor Polisi tidak cocok."}

            stored_name_raw = str(
                (auth_driver or {}).get("name")
                or (auth_driver or {}).get("nama")
                or body.get("storedName")
                or "Driver M3CAR"
            )

            verified_identity = False
            if recovery_code:
                if auth_driver is not None:
                    stored_code_hash = str(auth_driver.get("recoveryCodeHash") or "").strip()
                    stored_exp = str(auth_driver.get("recoveryCodeExpiresAt") or "").strip()
                    already_used = bool(auth_driver.get("recoveryCodeUsed"))
                else:
                    stored_code_hash = str(body.get("storedRecoveryCodeHash") or "").strip()
                    stored_exp = str(body.get("storedRecoveryExpiresAt") or "").strip()
                    already_used = False

                if (
                    not stored_code_hash
                    or already_used
                    or not _parse_iso_future(stored_exp)
                    or not verify_password_hash(recovery_code, stored_code_hash)
                ):
                    _record_failed_attempt(rate_key)
                    return 401, {
                        "ok": False,
                        "message": "Kode Pemulihan dari Admin tidak valid, sudah digunakan, atau sudah kedaluwarsa.",
                    }
                verified_identity = True
            else:
                plate = normalize_plate(body.get("plateNumber") or "")
                stored_plate = normalize_plate(
                    (auth_driver or {}).get("plateNumber")
                    or (auth_driver or {}).get("plate")
                    or (auth_driver or {}).get("plat")
                    or body.get("storedPlate")
                    or ""
                )
                full_name = normalize_name(body.get("fullName") or "")
                stored_name = normalize_name(stored_name_raw)
                if stored_plate:
                    if plate and plate == stored_plate and (not full_name or full_name == stored_name):
                        verified_identity = True
                elif full_name and stored_name and full_name == stored_name:
                    verified_identity = True

            if not verified_identity:
                _record_failed_attempt(rate_key)
                return 401, {"ok": False, "message": "Nomor HP atau Nomor Polisi tidak cocok."}

            _clear_failed_attempts(rate_key)
            password_hash = hash_scrypt(new_password)
            password_updated_at = _utc_iso_now()

            if idx >= 0 and auth_driver is not None:
                # Atomically save new passwordHash and invalidate recovery code (single-use).
                # Approval status, balance, saldo, and other fields remain untouched.
                auth_driver["passwordHash"] = password_hash
                auth_driver["hasPassword"] = True
                auth_driver["passwordUpdatedAt"] = password_updated_at
                auth_driver["recoveryCodeHash"] = None
                auth_driver["recoveryCodeExpiresAt"] = None
                auth_driver["recoveryCodeUsed"] = True
                auth_driver["recoveryCodeUsedAt"] = password_updated_at
                auth_driver.pop("recoveryCode", None)
                auth_driver["updatedAt"] = password_updated_at
                drivers[idx] = auth_driver
                _write_drivers_file(self.drivers_path, drivers, shape_mode)

        effective = _resolve_effective_approval(auth_driver) if auth_driver else "approved"
        admin_deactivated = bool((auth_driver or {}).get("adminDeactivated"))
        can_login = (not auth_driver) or (effective == "approved" and not admin_deactivated)
        resolved_id = str((auth_driver or {}).get("id") or driver_id)

        response_body: Dict[str, Any] = {
            "ok": True,
            "canLogin": can_login,
            "passwordHash": password_hash,
            "hasPassword": True,
            "clearRecovery": True,
            "passwordUpdatedAt": password_updated_at,
        }
        if can_login:
            now_ms = int(time.time() * 1000)
            exp_ms = now_ms + DRIVER_SESSION_TTL_SEC * 1000
            drv_token = sign_token(
                {
                    "role": "driver",
                    "driverId": resolved_id,
                    "phone": phone,
                    "name": stored_name_raw,
                    "jti": secrets.token_hex(16),
                    "iat": now_ms,
                    "exp": exp_ms,
                }
            )
            response_body["token"] = drv_token
            response_body["expiresAt"] = exp_ms
        else:
            response_body["pendingApproval"] = effective == "pending"
            response_body["rejected"] = effective == "rejected"
            response_body["deactivated"] = admin_deactivated

        return 200, response_body

    def handle_verify_password(
        self, body: Dict[str, Any], client_ip: str = "unknown"
    ) -> Tuple[int, Dict[str, Any]]:
        phone = normalize_phone_canonical(body.get("phone") or "")
        driver_id = str(body.get("driverId") or "").strip()
        password = body.get("password")

        if not phone or not isinstance(password, str) or not password:
            return 401, {
                "ok": False,
                "message": "Kata Sandi Salah / Belum Daftar, Silahkan Daftar Dulu",
            }

        rate_key = f"login:{client_ip}:{phone}"
        allowed, retry_after = _check_rate_limit(rate_key)
        if not allowed:
            return 429, {
                "ok": False,
                "retryAfterSec": retry_after,
                "message": f"Terlalu banyak percobaan login. Tunggu {retry_after} detik lagi.",
            }

        with _DRIVERS_FILE_LOCK:
            drivers, _ = _read_drivers_file(self.drivers_path)
            idx = _find_driver_index(drivers, driver_id=driver_id, phone=phone)
            if idx < 0:
                return 401, {
                    "ok": False,
                    "message": "Kata Sandi Salah / Belum Daftar, Silahkan Daftar Dulu",
                }
            drv = drivers[idx]

        if drv.get("isDeleted"):
            return 401, {
                "ok": False,
                "message": "Kata Sandi Salah / Belum Daftar, Silahkan Daftar Dulu",
            }

        stored_hash = str(
            drv.get("passwordHash") or drv.get("encryptedPassword") or drv.get("encrypted") or ""
        ).strip()
        if not stored_hash:
            return 409, {
                "ok": False,
                "needsFirstPassword": True,
                "driverId": str(drv.get("id") or driver_id),
                "driverPhone": phone,
                "driverName": str(drv.get("name") or drv.get("nama") or "Driver M3CAR"),
                "message": "Akun Driver lama terdeteksi! Silakan buat Kata Sandi Baru terlebih dahulu.",
            }

        if not verify_password_hash(password, stored_hash):
            _record_failed_attempt(rate_key)
            return 401, {
                "ok": False,
                "message": "Kata Sandi Salah / Belum Daftar, Silahkan Daftar Dulu",
            }

        _clear_failed_attempts(rate_key)
        effective = _resolve_effective_approval(drv)
        if effective == "blocked":
            return 403, {
                "ok": False,
                "blocked": True,
                "code": "DRIVER_BLOCKED",
                "message": "Akun Driver Anda sedang DIBLOKIR oleh Admin.",
            }
        if effective == "rejected":
            return 403, {
                "ok": False,
                "rejected": True,
                "code": "DRIVER_REJECTED",
                "message": "Pendaftaran Driver Anda DITOLAK Admin.",
            }
        if effective != "approved":
            return 403, {
                "ok": False,
                "pendingApproval": True,
                "code": "DRIVER_PENDING_APPROVAL",
                "message": "Akun Driver Anda masih MENUNGGU PERSETUJUAN ADMIN. Belum dapat beroperasi.",
            }
        if drv.get("adminDeactivated"):
            return 403, {
                "ok": False,
                "deactivated": True,
                "code": "DRIVER_DEACTIVATED",
                "message": "Akun Driver Anda sedang DINONAKTIFKAN oleh Admin.",
            }

        resolved_id = str(drv.get("id") or driver_id)
        name_raw = str(drv.get("name") or drv.get("nama") or "Driver M3CAR")
        now_ms = int(time.time() * 1000)
        exp_ms = now_ms + DRIVER_SESSION_TTL_SEC * 1000
        token = sign_token(
            {
                "role": "driver",
                "driverId": resolved_id,
                "phone": phone,
                "name": name_raw,
                "jti": secrets.token_hex(16),
                "iat": now_ms,
                "exp": exp_ms,
            }
        )
        return 200, {
            "ok": True,
            "verified": True,
            "token": token,
            "expiresAt": exp_ms,
            "user": {
                "id": resolved_id,
                "phone": phone,
                "name": name_raw,
                "role": "driver",
            },
        }


def _apply_cors_headers(resp: Response) -> Response:
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = (
        "Content-Type, Authorization, X-Firebase-AppCheck"
    )
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def register_recovery_routes(app: Any, drivers_json_path: Optional[str] = None) -> None:
    """Attach admin login + driver password recovery routes to an existing Flask app."""
    if Blueprint is None:
        raise RuntimeError("Flask must be installed to register recovery Flask routes.")

    service = RecoveryBackendService(drivers_json_path=drivers_json_path)

    def _client_ip() -> str:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()[:64]
        return (request.remote_addr or "unknown")[:64]

    def _json_resp(status_code: int, body: Dict[str, Any]) -> Response:
        resp = make_response(jsonify(body), status_code)
        return _apply_cors_headers(resp)

    def _preflight() -> Response:
        resp = make_response("", 204)
        return _apply_cors_headers(resp)

    @app.route("/api/admin/login", methods=["POST", "OPTIONS"])
    def m3car_admin_login() -> Response:
        if request.method == "OPTIONS":
            return _preflight()
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            body = {}
        status, payload = service.handle_admin_login(body, client_ip=_client_ip())
        return _json_resp(status, payload)

    @app.route("/api/driver/generate-recovery-code", methods=["POST", "OPTIONS"])
    def m3car_generate_recovery_code() -> Response:
        if request.method == "OPTIONS":
            return _preflight()
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            body = {}
        status, payload = service.handle_generate_recovery_code(
            body, headers=dict(request.headers)
        )
        return _json_resp(status, payload)

    @app.route("/api/driver/recover-password", methods=["POST", "OPTIONS"])
    def m3car_recover_password() -> Response:
        if request.method == "OPTIONS":
            return _preflight()
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            body = {}
        status, payload = service.handle_recover_password(body, client_ip=_client_ip())
        return _json_resp(status, payload)

    @app.route("/api/driver/verify-password", methods=["POST", "OPTIONS"])
    def m3car_verify_password() -> Response:
        if request.method == "OPTIONS":
            return _preflight()
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            body = {}
        status, payload = service.handle_verify_password(body, client_ip=_client_ip())
        return _json_resp(status, payload)
