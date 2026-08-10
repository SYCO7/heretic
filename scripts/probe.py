"""Probe a target with the profile's real login, and dump what candidate
endpoints actually return — so we can tune roe.yaml to the REAL API.

    PYTHONPATH=src python scripts/probe.py http://localhost:8888
"""
import sys
from pathlib import Path

sys.path.insert(0, "src")
from heretic.config import load_config
from heretic.core.session_mgr import SessionManager

URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8888"
PROFILE = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("targets/crapi")

cfg = load_config(roe=PROFILE / "roe.yaml", accounts=PROFILE / "accounts.yaml",
                  url=URL, model="fake")
sm = SessionManager(cfg)
sm.login_all()
print("logged-in roles:", sm.roles())
print("login errors   :", sm.login_errors, "\n")

# candidate crAPI endpoints — we learn the real ones + whether data exists
PATHS = [
    "/identity/api/v2/user/dashboard",
    "/identity/api/v2/vehicle/vehicles",
    "/workshop/api/shop/products",
    "/workshop/api/shop/orders",
    "/workshop/api/mechanic/",
    "/community/api/v2/community/posts/recent",
]

for role in [r for r in sm.roles() if r != "guest"]:
    print("=" * 20, role, "=" * 20)
    for p in PATHS:
        try:
            r = sm.get_as(role, p)
            print(f"{r.status_code}  GET {p}")
            print(f"     {r.text[:280]}\n")
        except Exception as e:
            print(f"ERR  GET {p}: {e}\n")
