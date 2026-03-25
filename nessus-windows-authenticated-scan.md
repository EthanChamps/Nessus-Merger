# Nessus Authenticated Windows Compliance Scan — Cheat Sheet

---

## Windows Host Configuration

### Required Services

| Service | Startup Type |
|---|---|
| Windows Management Instrumentation (WMI) | Automatic |
| Remote Registry | Manual or Automatic* |
| Server (LanmanServer) | Automatic |
| File and Printer Sharing | Enabled |

> *If set to Manual, check **"Start the Remote Registry service during the scan"** in Nessus credentials — plugins 42897/42898 handle start/stop automatically.

---

### Firewall — Required Inbound Rules

```
TCP 135          — DCOM/RPC endpoint mapper (WMI)
TCP 139          — NetBIOS session service
TCP 445          — SMB
TCP 49152–65535  — Dynamic RPC (WMI data channel)
```

Enable these predefined inbound rule groups in Windows Firewall:

- **Windows Management Instrumentation (WMI-In)**
- **Windows Management Instrumentation (DCOM-In)**
- **Windows Management Instrumentation (ASync-In)**
- **File and Printer Sharing (SMB-In)**
- **File and Printer Sharing (NetBIOS Session Service)**

---

### Administrative Shares

Required: `ADMIN$`, `C$`, `IPC$`

Re-enable if disabled (common on Windows 10 workstations):

```
HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
  AutoShareServer = 1   (servers)
  AutoShareWks    = 1   (workstations)
```

---

### Authentication Model

`Local Security Policy > Security Options > Network access: Sharing and security model for local accounts`

Set to: **Classic — local users authenticate as themselves**
(Not "Guest only")

---

### UAC Registry Fix

Required for non-built-in local admin accounts. Without this, UAC token filtering causes scan failure.

```
Key:   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
Name:  LocalAccountTokenFilterPolicy
Type:  DWORD
Value: 1
```

**Command-line:**

```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

| Account Type | UAC Token Filtering | Fix Needed |
|---|---|---|
| Built-in Administrator (RID 500) | Not filtered | None |
| Local non-built-in admin account | Filtered — scan fails | `LocalAccountTokenFilterPolicy = 1` |
| Domain account in local Admins | Not filtered | None |

---

### Other Requirements

- PowerShell 5.0+ installed
- Add Nessus scanner IP to AV/EDR exclusions (Defender, Symantec EP, etc.)

---

## Account Requirements

| Scenario | Required Account |
|---|---|
| Standalone / workgroup machines | Local account in Administrators group |
| Domain-joined machines | Domain account added to local Admins via GPO |
| Domain Controllers | Domain Administrator account only |

---

### Domain Deployment via GPO (Recommended)

1. Create a dedicated service account (e.g., `svc_nessus`) in AD
2. Create a Security Group: `Nessus Local Access`
3. Add `svc_nessus` to the group
4. Create a GPO → `Computer Config > Policies > Windows Settings > Security Settings > Restricted Groups`
5. Add `Nessus Local Access` as a member of local **Administrators**
6. Link GPO to the target computer OUs
7. Run `gpupdate /force` on targets

---

## Nessus Scan Configuration

### Scan Policy Settings

1. **New Scan** → choose **Advanced Scan** or a **Compliance** template
2. **Settings > Discovery > Host Discovery**: Disable "Ping the remote host" if ICMP is blocked (prevents hosts from being skipped)
3. **Settings > Assessment**: Enable "Safe checks" for production environments
4. **Compliance tab**: Add the relevant audit file (CIS Benchmark, DISA STIG, etc.)

---

### Credential Configuration

**Credentials tab > Host > Windows**

| Field | Value |
|---|---|
| Authentication method | Password (most common), Hash, Kerberos, or SPNEGO |
| Username | Account name |
| Password | Account password |
| Domain | Blank for local accounts; FQDN or NetBIOS name for domain accounts |

> Check **"Start the Remote Registry service during the scan"** if the service is set to Manual.

---

### Authentication Methods

| Method | Use Case |
|---|---|
| Password | Standard — most common |
| Windows Hash (LM/NTLM) | Pass-the-hash when plaintext unavailable |
| Kerberos | Domain environments with KDC accessible |
| SPNEGO | Auto-negotiates Kerberos or NTLM |

---

## Verification & Troubleshooting

### Quick Connectivity Tests

Run from the Nessus scanner or another Windows host:

```cmd
# Test anonymous SMB
net use \\<TARGET_IP>\ipc$ "" /user:""

# Test authenticated SMB + admin share access
net use \\<TARGET_IP>\ipc$    /user:<username> <password>
net use \\<TARGET_IP>\admin$  /user:<username> <password>

# Test Remote Registry
reg query \\<TARGET_IP>\hklm
```

---

### WMI Test (wbemtest)

1. Open `wbemtest`
2. Connect to `\\<target_ip>\root\cimv2` with credentials
3. Run query: `select DomainRole from Win32_ComputerSystem`
4. Any result returned = WMI is accessible

---

### Key Diagnostic Plugin IDs

| Plugin ID | What It Tells You |
|---|---|
| **10394** | "SMB Log In Possible" — confirms credentialed access worked |
| **24786** | "Scan not performed with admin privileges" — credential/UAC issue |
| 42897 | Remote Registry start (informational) |
| 42898 | Remote Registry stop (informational) |

> Check plugin **10394** output first. If it confirms credentials worked, authenticated scanning is functional.

---

### Common Failures

| Symptom | Root Cause | Fix |
|---|---|---|
| "Credentialed checks: No" in results | Any prerequisite missing | Work through checklist below |
| `NT_STATUS_LOGON_FAILURE` | Wrong creds or Guest-only auth model | Fix credentials; set auth model to Classic |
| `NT_STATUS_ACCESS_DENIED` on ADMIN$ | UAC token filtering | `LocalAccountTokenFilterPolicy = 1` |
| WMI fails | Service stopped or firewall blocking 135/dynamic RPC | Enable WMI; open TCP 135 + 49152–65535 |
| Host appears dead / skipped | ICMP ping blocked | Disable ping requirement in scan policy |
| ADMIN$ inaccessible | Win 10 disabled it | `AutoShareWks = 1` in registry |
| DC scan fails | Account not Domain Admin | Use Domain Administrator account |
| Compliance checks fail, scan succeeds | Wrong audit file or PowerShell < 5.0 | Update PowerShell; verify audit file |

---

## Full Prerequisites Checklist

```
[ ] TCP 139, 445, 135, 49152–65535 open inbound on target
[ ] WMI service running (Automatic)
[ ] Remote Registry enabled or "Start during scan" checked in Nessus
[ ] Server service (LanmanServer) running
[ ] File and Printer Sharing enabled
[ ] ADMIN$, IPC$, C$ shares accessible
[ ] Inbound firewall rules: WMI-In, WMI DCOM-In, WMI ASync-In, File & Printer Sharing
[ ] Authentication model: "Classic" (not Guest-only)
[ ] Scanning account is local Admin or domain account in local Admins group
[ ] LocalAccountTokenFilterPolicy = 1 (non-built-in local accounts)
[ ] PowerShell 5.0+ installed
[ ] AV/IPS exclusion for Nessus scanner IP
[ ] Domain Administrator account used for scanning Domain Controllers
```

---

> **Tip:** Tenable's community PowerShell verification script [`nessus_win_cred_test`](https://github.com/tecnobabble/nessus_win_cred_test) automates checking all prerequisites on a target host before scanning.
