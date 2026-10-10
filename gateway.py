import os
import re
import time
import logging
from collections import defaultdict
from urllib.parse import unquote
import bcrypt
import jwt
import pyotp
import httpx
from fastapi import FastAPI, Request, Response, HTTPException
from pydantic import BaseModel, Field

# Docs pages switched off so the API layout is not public
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

BACKEND = "http://127.0.0.1:9000"
SECRET_KEY = os.environ["GATEWAY_SECRET_KEY"]
ALGORITHM = "HS256"
TOKEN_MINUTES = 15

LOGIN_LIMIT = 5      # login attempts per minute
API_LIMIT = 20       # other requests per minute
REQUEST_LOG = defaultdict(list)

ALERT_FAILS = 3      # failed logins from one IP that raise an alert
ALERT_WINDOW = 300   # seconds (5 minutes)
FAILED_LOGINS = defaultdict(list)

# Audit logging: every security event goes to audit.log
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
_handler = logging.FileHandler("audit.log", encoding="utf-8")
_handler.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
audit_logger.addHandler(_handler)


def audit(event, ip, user="-", detail=""):
    detail = str(detail).replace("\n", " ").replace("\r", " ")[:200]
    audit_logger.info(f"{event} | ip={ip} | user={user} | {detail}")


# Input validation rules
PATH_OK = re.compile(r"^[A-Za-z0-9_/-]*$")
BAD_PATTERNS = [
    re.compile(r"<\s*script", re.I),
    re.compile(r"javascript:", re.I),
    re.compile(r"\bon\w+\s*=", re.I),
    re.compile(r"\bunion\b.+\bselect\b", re.I),
    re.compile(r"\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", re.I),
    re.compile(r"\bdrop\s+table\b", re.I),
    re.compile(r"'\s*or\s*'", re.I),
    re.compile(r"--"),
    re.compile(r"\.\./"),
]


def is_suspicious(text):
    text = unquote(text)
    return any(p.search(text) for p in BAD_PATTERNS)


def rate_limit(key, limit, ip, window=60):
    now = time.time()
    recent = [t for t in REQUEST_LOG[key] if now - t < window]
    if len(recent) >= limit:
        REQUEST_LOG[key] = recent
        audit("RATE_LIMITED", ip, "-", f"key={key}")
        raise HTTPException(
            status_code=429, detail="Too many requests. Try again later."
        )
    recent.append(now)
    REQUEST_LOG[key] = recent


def record_failed_login(ip, user):
    """Monitoring: raise an alert when one IP fails to log in too often."""
    now = time.time()
    recent = [t for t in FAILED_LOGINS[ip] if now - t < ALERT_WINDOW]
    recent.append(now)
    FAILED_LOGINS[ip] = recent
    if len(recent) >= ALERT_FAILS:
        msg = f"{len(recent)} failed logins in {ALERT_WINDOW // 60} minutes"
        audit("ALERT_BRUTE_FORCE", ip, user, msg)
        print(f"[ALERT] Possible brute-force attack from {ip}: {msg}")


def hash_pw(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


# Demo users. Passwords are stored hashed, never as plain text.
# otp_secret is the 2FA secret, now read from the environment.
USERS = {
    "admin": {
        "password": hash_pw("Admin#1234"),
        "role": "admin",
        "otp_secret": os.environ["ADMIN_OTP_SECRET"],
    },
    "ali": {
        "password": hash_pw("User#1234"),
        "role": "user",
        "otp_secret": os.environ["ALI_OTP_SECRET"],
    },
}


class LoginData(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_]{3,20}$")
    password: str = Field(min_length=1, max_length=64)
    otp: str = Field(pattern=r"^[0-9]{6}$")


@app.post("/login")
def login(data: LoginData, request: Request):
    ip = request.client.host
    rate_limit(f"login:{ip}", LOGIN_LIMIT, ip)
    user = USERS.get(data.username)
    if not user or not bcrypt.checkpw(data.password.encode(), user["password"]):
        audit("LOGIN_FAILED", ip, data.username, "bad username or password")
        record_failed_login(ip, data.username)
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not pyotp.TOTP(user["otp_secret"]).verify(data.otp, valid_window=1):
        audit("LOGIN_FAILED_2FA", ip, data.username, "wrong 2FA code")
        record_failed_login(ip, data.username)
        raise HTTPException(status_code=401, detail="Invalid 2FA code")
    payload = {
        "sub": data.username,
        "role": user["role"],
        "exp": int(time.time()) + TOKEN_MINUTES * 60,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    audit("LOGIN_SUCCESS", ip, data.username, f"role={user['role']}")
    return {"access_token": token, "token_type": "bearer"}  # nosec B105


def check_token(request: Request, ip):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        audit("TOKEN_REJECTED", ip, "-", "missing token")
        raise HTTPException(status_code=401, detail="Missing token")
    try:
        return jwt.decode(auth[7:], SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        audit("TOKEN_REJECTED", ip, "-", "invalid or expired token")
        raise HTTPException(status_code=401, detail="Invalid or expired token")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def forward(path: str, request: Request):
    ip = request.client.host
    rate_limit(f"api:{ip}", API_LIMIT, ip)
    user = check_token(request, ip)
    name = user["sub"]
    if path.startswith("admin") and user["role"] != "admin":
        audit("ACCESS_DENIED", ip, name, f"admin-only path=/{path}")
        raise HTTPException(status_code=403, detail="Admins only")

    body = await request.body()
    if (
        not PATH_OK.match(path)
        or is_suspicious(request.url.query)
        or is_suspicious(body.decode("utf-8", errors="ignore"))
    ):
        audit("INPUT_BLOCKED", ip, name, f"path=/{path} query={request.url.query}")
        raise HTTPException(status_code=400, detail="Blocked: suspicious input")

    async with httpx.AsyncClient() as client:
        r = await client.request(
            request.method,
            f"{BACKEND}/{path}",
            content=body,
            params=request.query_params,
        )
    audit("REQUEST_OK", ip, name, f"{request.method} /{path} -> {r.status_code}")
    return Response(
        content=r.content,
        status_code=r.status_code,
        media_type=r.headers.get("content-type"),
        headers={
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )