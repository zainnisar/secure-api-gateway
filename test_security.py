import os
import sys
import base64
import json
import httpx
import jwt
import pyotp

GATEWAY = "http://127.0.0.1:8000"
results = []


def check(name, got, expected):
    ok = got == expected
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name} (expected {expected}, got {got})")


def login(user, password, otp):
    return httpx.post(
        f"{GATEWAY}/login",
        json={"username": user, "password": password, "otp": otp},
    )


def get(path, token=None, params=None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return httpx.get(f"{GATEWAY}{path}", headers=headers, params=params).status_code


def b64(data):
    raw = json.dumps(data).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


print("--- Authentication and 2FA ---")
ali_otp = pyotp.TOTP(os.environ["ALI_OTP_SECRET"]).now()
admin_otp = pyotp.TOTP(os.environ["ADMIN_OTP_SECRET"]).now()

r = login("ali", "User#1234", ali_otp)
check("Login with correct password and 2FA code", r.status_code, 200)
ali_token = r.json().get("access_token")

check("Login with wrong password", login("ali", "WrongPass1", ali_otp).status_code, 401)
check("Login with wrong 2FA code", login("ali", "User#1234", "000000").status_code, 401)

r = login("admin", "Admin#1234", admin_otp)
admin_token = r.json().get("access_token")

print("--- Token attacks ---")
check("Request with no token", get("/students"), 401)
check("Request with fake token", get("/students", "fake123"), 401)

forged = jwt.encode(
    {"sub": "ali", "role": "admin", "exp": 9999999999},
    "wrong-key-wrong-key-wrong-key-12345",
    algorithm="HS256",
)
check("Forged admin token (wrong signing key)", get("/admin/reports", forged), 401)

none_token = (
    b64({"alg": "none", "typ": "JWT"})
    + "."
    + b64({"sub": "ali", "role": "admin", "exp": 9999999999})
    + "."
)
check("Token with algorithm 'none'", get("/admin/reports", none_token), 401)

print("--- Attack surface ---")
check("API docs page is not public", get("/docs"), 401)
check("OpenAPI schema is not public", get("/openapi.json"), 401)

print("--- Access control (RBAC) ---")
check("User reads normal data", get("/students", ali_token), 200)
check("User tries admin page", get("/admin/reports", ali_token), 403)
check("Admin opens admin page", get("/admin/reports", admin_token), 200)

print("--- Input attacks ---")
check("SQL injection", get("/students", ali_token, {"search": "' OR 1=1 --"}), 400)
check("XSS script injection", get("/students", ali_token, {"search": "<script>alert(1)</script>"}), 400)
check("Path traversal", get("/students", ali_token, {"file": "../../etc/passwd"}), 400)

print("--- Rate limiting ---")
codes = [login("ali", "wrong", "000000").status_code for _ in range(3)]
check("Repeated logins get blocked (429)", 429 in codes, True)

print("--- Monitoring ---")
with open("audit.log", encoding="utf-8") as f:
    alerted = "ALERT_BRUTE_FORCE" in f.read()
check("Brute-force alert written to audit.log", alerted, True)

print(f"\nResult: {sum(results)}/{len(results)} tests passed")
sys.exit(0 if all(results) else 1)