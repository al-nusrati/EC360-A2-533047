"""
auth_service.py - QuickCart Microservices : Authentication Service
Jira Story : QM-5  Customer Registration with Email Verification

Implements the registration endpoint (POST /api/v1/auth/register),
salted PBKDF2-HMAC-SHA256 password hashing and e-mail verification tokens.
Standard library only, so it runs on any Python 3.9+ without pip installs.
"""
import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass, field

PBKDF2_ITERATIONS = 310_000          # OWASP 2023 recommendation for SHA-256
SALT_BYTES = 16
TOKEN_TTL_SECONDS = 24 * 60 * 60     # verification link valid for 24 h
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


def hash_password(password: str, salt: bytes = None) -> str:
    """Return 'pbkdf2_sha256$iterations$salt_hex$hash_hex'."""
    salt = salt or secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time check of a password against a stored hash string."""
    _, iterations, salt_hex, hash_hex = stored.split("$")
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex), int(iterations))
    return hmac.compare_digest(digest.hex(), hash_hex)


def password_is_strong(password: str) -> bool:
    """At least 8 chars with an upper-case letter, a lower-case letter and a digit."""
    return (len(password) >= 8 and re.search(r"[A-Z]", password) is not None
            and re.search(r"[a-z]", password) is not None
            and re.search(r"\d", password) is not None)


@dataclass
class User:
    email: str
    password_hash: str
    is_verified: bool = False
    created_at: float = field(default_factory=time.time)


class AuthService:
    """In-memory user store; a real deployment swaps this for the QM-5 DB schema."""

    def __init__(self, clock=time.time):
        self.users = {}            # email -> User
        self.tokens = {}           # token -> (email, expiry_timestamp)
        self.outbox = []           # e-mails queued for the async worker
        self.clock = clock

    def register(self, email: str, password: str):
        """POST /api/v1/auth/register -> (HTTP status, JSON body)."""
        email = (email or "").strip().lower()
        if not EMAIL_RE.match(email):
            return 422, {"error": "invalid_email"}
        if not password_is_strong(password or ""):
            return 422, {"error": "weak_password"}
        if email in self.users:
            return 409, {"error": "email_already_registered"}

        self.users[email] = User(email, hash_password(password))
        token = secrets.token_urlsafe(32)
        self.tokens[token] = (email, self.clock() + TOKEN_TTL_SECONDS)
        self.outbox.append({"to": email, "template": "verify_email", "token": token})
        return 201, {"email": email, "status": "pending_verification"}

    def verify_email(self, token: str):
        """GET /api/v1/auth/verify?token=... -> (HTTP status, JSON body)."""
        entry = self.tokens.pop(token, None)
        if entry is None:
            return 400, {"error": "invalid_token"}
        email, expiry = entry
        if self.clock() > expiry:
            return 410, {"error": "token_expired"}
        self.users[email].is_verified = True
        return 200, {"email": email, "status": "verified"}

    def login(self, email: str, password: str):
        """Only verified users with the right password may log in."""
        user = self.users.get((email or "").strip().lower())
        if user is None or not verify_password(password, user.password_hash):
            return 401, {"error": "invalid_credentials"}
        if not user.is_verified:
            return 403, {"error": "email_not_verified"}
        return 200, {"email": user.email, "status": "authenticated"}
