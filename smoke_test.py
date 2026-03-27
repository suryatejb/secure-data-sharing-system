"""Quick smoke test for all 12 fix scenarios."""
import urllib.request, json, urllib.parse

BASE = "http://localhost:8000"

def login(username, password):
    data = urllib.parse.urlencode(
        {"username": username, "password": password, "grant_type": "password"}
    ).encode()
    req = urllib.request.Request(BASE + "/auth/login", data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    resp = urllib.request.urlopen(req)
    return json.loads(resp.read())["access_token"]

def get(path, token):
    req = urllib.request.Request(BASE + path)
    req.add_header("Authorization", f"Bearer {token}")
    try:
        resp = urllib.request.urlopen(req)
        return resp.getcode(), json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

def post(path, token, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(BASE + path, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        resp = urllib.request.urlopen(req)
        return resp.getcode(), json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())

PASS = "[PASS]"
FAIL = "[FAIL]"
results = []

def check(label, condition, detail=""):
    tag = PASS if condition else FAIL
    msg = f"  {tag} {label}"
    if detail:
        msg += f"\n         {detail}"
    print(msg)
    results.append(condition)

print("=" * 60)
print("SMOKE TESTS")
print("=" * 60)

# 1. Admin reads raw data (RBAC + BLP both pass)
tok_admin = login("admin", "admin123")
code, body = get("/data/raw", tok_admin)
check("admin GET /data/raw -> 200 ALLOWED", code == 200,
      f"records={body.get('record_count')}")

# 2. Mallory reads raw data: RBAC passes (SeniorAnalyst has data:raw:read)
#    but BLP No-Read-Up blocks (CONFIDENTIAL=1 < SECRET=2)
tok_mallory = login("mallory", "mallory123")
code, body = get("/data/raw", tok_mallory)
err = body.get("detail", {})
check("mallory GET /data/raw -> 403 BLP_DENIED (RBAC passed, BLP blocked)",
      code == 403 and isinstance(err, dict) and "No Read Up" in err.get("error", ""),
      f"detail.error={err.get('error') if isinstance(err, dict) else err}")

# 3. Curator writes a record: RBAC passes (data:write), BLP passes (SECRET=2 <= SECRET=2)
tok_curator = login("curator", "curator123")
payload = {"age": 35, "zipcode": "10001", "gender": "M", "disease": "Flu", "salary": 60000}
code, body = post("/data/records", tok_curator, payload)
check("curator POST /data/records -> 201 ALLOWED",
      code == 201,
      f"checks={body.get('security_checks_passed')}")

# 4. Admin writes a record: RBAC passes (data:write),
#    BLP No-Write-Down BLOCKS (TOP_SECRET=3 > SECRET=2)
code, body = post("/data/records", tok_admin, payload)
err = body.get("detail", {})
check("admin POST /data/records -> 403 BLP_WRITE_DENIED (No-Write-Down)",
      code == 403 and isinstance(err, dict) and "Write Down" in err.get("error", ""),
      f"detail.error={err.get('error') if isinstance(err, dict) else err}")

# 5. Admin GET /admin/users (users:manage permission -> previously dead permission)
code, body = get("/admin/users", tok_admin)
usernames = [u["username"] for u in body] if isinstance(body, list) else []
check("admin GET /admin/users -> 200 ALLOWED",
      code == 200 and len(usernames) >= 5,
      f"users={usernames}")

# 6. Alice cannot access /admin/users (no users:manage permission)
tok_alice = login("alice_analyst", "analyst123")
code, body = get("/admin/users", tok_alice)
err = body.get("detail", {})
check("alice GET /admin/users -> 403 RBAC_DENIED",
      code == 403 and isinstance(err, dict) and err.get("error") == "RBAC Access Denied",
      f"error={err.get('error') if isinstance(err, dict) else err}")

# 7. Guest cannot access /data/anonymized (RBAC)
tok_bob = login("bob_guest", "guest123")
code, body = get("/data/anonymized", tok_bob)
check("bob GET /data/anonymized -> 403 RBAC_DENIED",
      code == 403,
      f"code={code}")

# 8. Rate limiting: 5 bad logins -> 429
print()
print("Testing rate limiting (5 bad logins)...")
for i in range(5):
    data = urllib.parse.urlencode(
        {"username": "nobody", "password": "wrong", "grant_type": "password"}
    ).encode()
    req = urllib.request.Request(BASE + "/auth/login", data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        urllib.request.urlopen(req)
    except urllib.error.HTTPError:
        pass

data = urllib.parse.urlencode(
    {"username": "nobody", "password": "wrong2", "grant_type": "password"}
).encode()
req = urllib.request.Request(BASE + "/auth/login", data=data, method="POST")
req.add_header("Content-Type", "application/x-www-form-urlencoded")
try:
    urllib.request.urlopen(req)
    rate_code = 200
except urllib.error.HTTPError as e:
    rate_code = e.code
check("6th bad login from same IP -> 429 Too Many Requests",
      rate_code == 429,
      f"code={rate_code}")

print()
print("=" * 60)
passed = sum(results)
total = len(results)
print(f"RESULT: {passed}/{total} tests passed")
if passed == total:
    print("All checks passed!")
else:
    print("Some checks failed — review output above.")
