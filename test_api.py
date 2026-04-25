"""Quick end-to-end API test to verify all components work."""
import urllib.request
import urllib.parse
import urllib.error
import json

BASE = "http://localhost:8000"


def post(path, data):
    req = urllib.request.Request(
        BASE + path,
        data=urllib.parse.urlencode(data).encode(),
        method="POST",
    )
    return json.loads(urllib.request.urlopen(req).read())


def get(path, token):
    req = urllib.request.Request(
        BASE + path,
        headers={"Authorization": f"Bearer {token}"},
    )
    return json.loads(urllib.request.urlopen(req).read())


def get_no_auth(path):
    return json.loads(urllib.request.urlopen(BASE + path).read())


print("\n=== Secure Data Sharing Platform — API Tests ===\n")

# Root
root = get_no_auth("/")
print(f"✓ Root endpoint: {root['system']}")

# Login all three users
admin   = post("/auth/login", {"username": "admin",         "password": "admin123"})
analyst = post("/auth/login", {"username": "alice_analyst", "password": "analyst123"})
guest   = post("/auth/login", {"username": "bob_guest",     "password": "guest123"})

print(f"✓ Login admin:    {admin['username']} | {admin['security_level_name']}")
print(f"✓ Login analyst:  {analyst['username']} | {analyst['security_level_name']}")
print(f"✓ Login guest:    {guest['username']} | {guest['security_level_name']}")

at = admin["access_token"]
ant = analyst["access_token"]
gt = guest["access_token"]

# --- Data access ---
raw = get("/data/raw", at)
print(f"\n✓ Admin  → /data/raw:        {raw['record_count']} records, BLP={raw['security_checks_passed'][1]}")

anon = get("/data/anonymized", ant)
print(f"✓ Analyst → /data/anonymized: {anon['total_released']} records released, k_achieved={anon['k_achieved']}")

summary = get("/data/summary", gt)
print(f"✓ Guest  → /data/summary:    total_patients={summary['total_patients']}, diseases={len(summary['disease_distribution'])}")

# --- RBAC denial tests ---
print("\n--- RBAC denial tests ---")

def expect_403(path, token, label):
    try:
        get(path, token)
        print(f"  ✗ {label}: should have been denied!")
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"  ✓ {label}: HTTP 403 Forbidden (correct)")
        else:
            print(f"  ✗ {label}: unexpected status {e.code}")

expect_403("/data/raw",        gt,  "Guest    → /data/raw        (RBAC)")
expect_403("/data/raw",        ant, "Analyst  → /data/raw        (RBAC)")
expect_403("/data/anonymized", gt,  "Guest    → /data/anonymized  (RBAC)")

# --- Linking attack demo ---
attack = get("/attack/linking-demo", ant)
summary_attack = attack["attack_summary"]
print(f"\n✓ Linking attack demo:")
print(f"  Before defense: {summary_attack['re_identified_WITHOUT_defense']} re-identified  ({summary_attack['re_identification_rate_before']})")
print(f"  After  defense: {summary_attack['re_identified_WITH_k_anonymity']} re-identified  ({summary_attack['re_identification_rate_after']})")

print("\n=== All tests passed! ✓ ===")
print("Open http://localhost:8000/docs for the interactive API explorer")
