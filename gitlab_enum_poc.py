#!/usr/bin/env python3
"""
GitLab OIDC Condition Key Enumeration PoC
H1 #3739444 - proves namespace_id and project_id are publicly enumerable
with zero authentication via the Projects API.
"""

import urllib.request
import json
import sys

def enumerate(project_path):
    encoded = project_path.replace("/", "%2F")
    url = f"https://gitlab.com/api/v4/projects/{encoded}"

    # Explicitly show no auth headers
    req = urllib.request.Request(url, headers={"User-Agent": "poc-enum-no-auth"})

    print(f"[*] Request URL : {url}")
    print(f"[*] Auth headers: NONE")
    print(f"[*] Token used  : NONE")
    print()

    with urllib.request.urlopen(req) as resp:
        print(f"[*] HTTP status : {resp.status}")
        data = json.loads(resp.read())

    project_id   = data["id"]
    namespace_id = data["namespace"]["id"]
    namespace    = data["namespace"]["path"]
    path         = data["path_with_namespace"]
    visibility   = data["visibility"]

    print(f"[+] path             : {path}")
    print(f"[+] visibility       : {visibility}")
    print(f"[+] project_id       : {project_id}")
    print(f"[+] namespace_id     : {namespace_id}")
    print()
    print(f"[*] sub claim        : project_path:{path}:ref_type:branch:ref:main")
    print()
    print(f"[*] Proposed 'secure' AWS trust policy condition keys:")
    print(f'    "gitlab.com:namespace_id": "{namespace_id}"')
    print(f'    "gitlab.com:project_id"  : "{project_id}"')
    print()
    print(f"[!] Both values retrieved with zero auth from path alone.")
    print(f"[!] Path is already embedded in the sub claim being targeted.")
    print(f"[!] These are not secrets. They are public sequential integers.")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "gitlab-org/gitlab"
    enumerate(path)
