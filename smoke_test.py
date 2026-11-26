"""Basic post-deployment smoke test. Usage: py smoke_test.py http://localhost:8000"""
import sys
import urllib.error
import urllib.request

base = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip("/")
checks = [("/health/live", 200), ("/health/ready", 200), ("/", 200)]
failed = False

for path, expected in checks:
    request = urllib.request.Request(base + path, headers={"X-Request-ID": "datalineage-release-smoke"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except Exception as exc:
        print(f"FAIL {path}: {type(exc).__name__}")
        failed = True
        continue
    if status == expected:
        print(f"PASS {path}: HTTP {status}")
    else:
        print(f"FAIL {path}: expected HTTP {expected}, received HTTP {status}")
        failed = True

sys.exit(1 if failed else 0)
