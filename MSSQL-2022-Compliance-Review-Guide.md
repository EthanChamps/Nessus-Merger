# MS SQL Server 2022 Compliance Review Guide

**Purpose:** Generic security compliance review guide for MS SQL Server 2022 database assessments.
**Scope:** Two-day hands-on review covering authentication, authorization, auditing, encryption, configuration hardening, and patching.
**Audience:** Penetration testers and security auditors performing authorized database assessments.

---

## Table of Contents

1. [Day 1 - Discovery, Authentication & Authorization](#day-1---discovery-authentication--authorization)
2. [Day 2 - Auditing, Encryption, Hardening & Reporting](#day-2---auditing-encryption-hardening--reporting)
3. [Pre-Engagement Checklist](#pre-engagement-checklist)
4. [Connection & Initial Enumeration](#connection--initial-enumeration)
5. [Instance Configuration Review](#instance-configuration-review)
6. [Authentication & Password Policy](#authentication--password-policy)
7. [Authorization & Privileges](#authorization--privileges)
8. [Auditing & Logging](#auditing--logging)
9. [Encryption Review](#encryption-review)
10. [Network & Surface Area](#network--surface-area)
11. [Patching & Versioning](#patching--versioning)
12. [Backup & Recovery Security](#backup--recovery-security)
13. [Stored Procedures & Code Review](#stored-procedures--code-review)
14. [CIS Benchmark Quick Checks](#cis-benchmark-quick-checks)
15. [Findings Template](#findings-template)
16. [References](#references)

---

## Pre-Engagement Checklist

Before starting the review, confirm you have:

- [ ] Written authorization / Rules of Engagement signed
- [ ] Scope defined — server names, instances, databases
- [ ] Credentials provided (sysadmin-level read access recommended for audit)
- [ ] Network access confirmed (TCP 1433 or named instance ports)
- [ ] Backup/rollback plan agreed with DBA team
- [ ] Out-of-scope systems documented
- [ ] Emergency contact for the DBA team
- [ ] Tools installed: SSMS, sqlcmd, or Azure Data Studio

---

## Day 1 - Discovery, Authentication & Authorization

| Time Block | Activity |
|---|---|
| Morning (4h) | Connection, enumeration, instance config, version/patch review |
| Afternoon (4h) | Authentication review, password policy, authorization & privilege audit |

## Day 2 - Auditing, Encryption, Hardening & Reporting

| Time Block | Activity |
|---|---|
| Morning (4h) | Auditing/logging, encryption, network/surface area, backup security |
| Afternoon (4h) | Stored procedure review, CIS benchmark checks, findings write-up |

---

## Connection & Initial Enumeration

### Verifying Connection Details via SSMS

Before connecting from the command line or assessment tools, use SQL Server Management Studio (SSMS) to confirm and gather the exact connection parameters.

**Step 1 — Identify the server and instance name:**

- Open SSMS and look at the **Object Explorer** panel (left side)
- The top-level node displays the connection in the format: `SERVERNAME\INSTANCENAME (SQL Server XX.X - DOMAIN\user)`
- Use this exact `SERVERNAME\INSTANCENAME` value in your connection strings

| What You See | What It Means |
|---|---|
| `DBSRV01\SQLPROD (SQL Server 16.x ...)` | Named instance `SQLPROD` on host `DBSRV01` — connect using `DBSRV01\SQLPROD` |
| `DBSRV01 (SQL Server 16.x ...)` | Default instance — connect using just `DBSRV01` (no instance name needed) |
| Connection fails / timeout | Server unreachable — check network path, firewall rules (TCP 1433), and that the SQL Server service is running |
| `Login failed for user ...` | Server is reachable but credentials are wrong, the account is disabled, or the authentication mode does not allow your login type |

**Step 2 — Find the listening port and IP:**

Run the following query in SSMS once connected:

```sql
-- Active listener addresses and ports
SELECT DISTINCT
    local_net_address AS [ListeningIP],
    local_tcp_port AS [ListeningPort]
FROM sys.dm_exec_connections
WHERE local_net_address IS NOT NULL;
```

| Result | What It Means | If Not As Expected |
|---|---|---|
| Port `1433` | Default SQL Server port — standard configuration | If blank or different, the instance uses a non-default port. You must specify the port explicitly in connection strings (e.g., `SERVER,PORT`) |
| Port is a high/random number (e.g., `49152`) | Dynamic port assigned by SQL Server — common with named instances | Requires SQL Browser service (UDP 1434) to resolve, or use the port directly. If SQL Browser is stopped, remote clients cannot discover the port automatically |
| `local_net_address` shows `127.0.0.1` only | SQL Server is only listening on localhost | Remote connections are not possible. TCP/IP must be enabled on the correct IP in SQL Server Configuration Manager |
| Query returns no rows | TCP/IP protocol may be disabled entirely | Enable TCP/IP in SQL Server Configuration Manager → SQL Server Network Configuration → Protocols |

**Step 3 — Confirm server identity and instance details:**

```sql
SELECT
    SERVERPROPERTY('MachineName') AS [MachineName],
    SERVERPROPERTY('ServerName') AS [ServerName],
    SERVERPROPERTY('InstanceName') AS [InstanceName],
    SERVERPROPERTY('IsIntegratedSecurityOnly') AS [WindowsAuthOnly];
```

| Property | Expected | If Not As Expected |
|---|---|---|
| `MachineName` | Matches the hostname you were given in scope | If different, you may be connected to the wrong server — verify with the DBA team before proceeding |
| `ServerName` | `HOSTNAME\INSTANCE` or just `HOSTNAME` for defaults | Mismatch indicates a renamed server or alias — document this for your records |
| `InstanceName` | Matches the scoped instance name, or `NULL` for default | `NULL` = default instance. If you expected a named instance but see `NULL`, you are on the wrong instance |
| `WindowsAuthOnly` | `1` = Windows Auth only (more secure) | `0` = Mixed Mode (SQL + Windows auth). This is a finding — Mixed Mode increases attack surface. Document it and check for weak SQL login passwords |

**Step 4 — Check authentication mode in SSMS GUI:**

- Right-click the server in Object Explorer → **Properties** → **Security** page
- Under "Server authentication" you will see either:
  - **Windows Authentication mode** — only domain/Windows accounts can connect
  - **SQL Server and Windows Authentication mode** (Mixed Mode) — both SQL logins and Windows accounts can connect

| Setting | What It Means | If Not As Expected |
|---|---|---|
| Windows Authentication mode | More secure — authentication is delegated to Active Directory | This is the recommended configuration. If the engagement requires SQL Authentication, Mixed Mode must be enabled |
| Mixed Mode | SQL logins with passwords stored in SQL Server are permitted | Increases risk — SQL logins are vulnerable to brute-force attacks and may have weak/blank passwords. Flag as a finding if not business-justified |

**Step 5 — Verify TCP/IP is enabled (if connections fail):**

If you cannot connect remotely, check in **SQL Server Configuration Manager**:

1. Navigate to **SQL Server Network Configuration** → **Protocols for [INSTANCE]**
2. Verify **TCP/IP** is **Enabled**
3. Right-click TCP/IP → **Properties** → **IP Addresses** tab → check the port under **IPAll**

| Configuration | What It Means | If Not As Expected |
|---|---|---|
| TCP/IP = Enabled | Remote TCP connections are accepted | If Disabled, only local shared memory and named pipe connections work. Ask the DBA to enable TCP/IP and restart the SQL service |
| TCP Dynamic Ports = (blank), TCP Port = `1433` | Static port — predictable and standard | If Dynamic Ports has a value and TCP Port is blank, the instance uses a random port on each restart. SQL Browser (UDP 1434) must be running for clients to discover it |
| TCP Dynamic Ports = `0` | SQL Server will pick a dynamic port at startup | Same as above — note the actual port from `sys.dm_exec_connections` and use it directly if SQL Browser is unavailable |

**Step 6 — SQL Browser service (named instances):**

Named instances require the SQL Server Browser service to advertise their port on UDP 1434.

```powershell
# Check SQL Browser status (run on the server or via remote PowerShell)
Get-Service SQLBrowser | Select-Object Name, Status, StartType
```

| Status | What It Means | If Not As Expected |
|---|---|---|
| Running | Named instances can be discovered by clients automatically | Expected for environments with named instances |
| Stopped | Clients cannot resolve named instances to ports automatically | You must specify the port explicitly in your connection string (e.g., `SERVER,49152`). This is sometimes intentional as a hardening measure to reduce information disclosure |
| Disabled | Intentionally turned off — common hardening practice | Same as Stopped — use explicit ports. Document whether this was intentional |

### Connect via sqlcmd

```bash
# Windows Authentication
sqlcmd -S <ServerName>\<InstanceName> -E

# SQL Authentication
sqlcmd -S <ServerName>\<InstanceName> -U <username> -P <password>

# Specific database
sqlcmd -S <ServerName>,<Port> -U <username> -P <password> -d <DatabaseName>
```

### Server Version & Edition

```sql
-- Full version string
SELECT @@VERSION;

-- Structured version info
SELECT
    SERVERPROPERTY('MachineName') AS [MachineName],
    SERVERPROPERTY('ServerName') AS [ServerName],
    SERVERPROPERTY('InstanceName') AS [InstanceName],
    SERVERPROPERTY('ProductVersion') AS [ProductVersion],
    SERVERPROPERTY('ProductLevel') AS [ProductLevel],
    SERVERPROPERTY('ProductUpdateLevel') AS [UpdateLevel],
    SERVERPROPERTY('ProductUpdateReference') AS [KBArticle],
    SERVERPROPERTY('Edition') AS [Edition],
    SERVERPROPERTY('IsIntegratedSecurityOnly') AS [WindowsAuthOnly],
    SERVERPROPERTY('IsClustered') AS [IsClustered],
    SERVERPROPERTY('IsHadrEnabled') AS [AlwaysOnEnabled],
    SERVERPROPERTY('BuildClrVersion') AS [CLRVersion];
```

### List All Databases

```sql
SELECT
    name,
    database_id,
    state_desc,
    recovery_model_desc,
    compatibility_level,
    is_encrypted,
    is_trustworthy_on,
    is_db_chaining_on,
    create_date
FROM sys.databases
ORDER BY name;
```

### List All Instances (from OS if accessible)

```sql
-- Check for multiple instances via registry (requires xp_regread access)
EXEC xp_regread
    N'HKEY_LOCAL_MACHINE',
    N'SOFTWARE\Microsoft\Microsoft SQL Server',
    N'InstalledInstances';
```

---

## Instance Configuration Review

### Show All Configuration Options

```sql
-- All server-level settings
SELECT
    name,
    value,
    value_in_use,
    minimum,
    maximum,
    description,
    is_dynamic,
    is_advanced
FROM sys.configurations
ORDER BY name;
```

### Critical Settings to Check

```sql
-- Enable advanced options to view all
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;

-- Check critical settings individually
SELECT name, value_in_use
FROM sys.configurations
WHERE name IN (
    'clr enabled',
    'clr strict security',
    'cross db ownership chaining',
    'Database Mail XPs',
    'Ole Automation Procedures',
    'remote access',
    'remote admin connections',
    'scan for startup procs',
    'xp_cmdshell',
    'Ad Hoc Distributed Queries',
    'contained database authentication',
    'default trace enabled',
    'external scripts enabled',
    'remote data archive',
    'allow polybase export',
    'hadoop connectivity'
);
```

**Expected secure values:**

| Setting | Secure Value | Notes |
|---|---|---|
| `xp_cmdshell` | 0 | OS command execution — must be disabled |
| `clr enabled` | 0 | Unless explicitly required by application |
| `clr strict security` | 1 | Enforces SAFE assembly restrictions (SQL 2017+) |
| `cross db ownership chaining` | 0 | Prevents cross-database privilege escalation |
| `Database Mail XPs` | 0 | Unless mail functionality is required |
| `Ole Automation Procedures` | 0 | COM object access — disable |
| `remote access` | 0 | Legacy remote server feature — disable |
| `remote admin connections` | 0 | DAC should be local only (except clusters) |
| `Ad Hoc Distributed Queries` | 0 | Prevents OPENROWSET/OPENDATASOURCE abuse |
| `scan for startup procs` | 0 | Unless specific startup procs are required |
| `default trace enabled` | 1 | Should be on for basic auditing |
| `external scripts enabled` | 0 | R/Python execution — disable unless required |
| `contained database authentication` | 0 | Unless contained databases are specifically used |

---

## Authentication & Password Policy

### Authentication Mode

```sql
-- Check authentication mode
-- 1 = Windows only, 0 = Mixed mode
SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS [WindowsAuthOnly];

-- Also check via registry
EXEC xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    N'Software\Microsoft\MSSQLServer\MSSQLServer',
    N'LoginMode';
-- 1 = Windows Auth only, 2 = Mixed mode
```

> **Finding:** Mixed mode authentication is less secure. Recommend Windows Authentication only where possible.

### Enumerate All Logins

```sql
SELECT
    sp.name AS [Login],
    sp.type_desc AS [LoginType],
    sp.is_disabled AS [IsDisabled],
    sp.create_date,
    sp.modify_date,
    sp.default_database_name,
    sl.is_policy_checked AS [PasswordPolicyEnforced],
    sl.is_expiration_checked AS [PasswordExpirationEnforced],
    LOGINPROPERTY(sp.name, 'PasswordLastSetTime') AS [PasswordLastSet],
    LOGINPROPERTY(sp.name, 'DaysUntilExpiration') AS [DaysUntilExpiration],
    LOGINPROPERTY(sp.name, 'IsLocked') AS [IsLocked],
    LOGINPROPERTY(sp.name, 'LockoutTime') AS [LockoutTime],
    LOGINPROPERTY(sp.name, 'BadPasswordCount') AS [BadPasswordCount],
    LOGINPROPERTY(sp.name, 'BadPasswordTime') AS [BadPasswordTime]
FROM sys.server_principals sp
LEFT JOIN sys.sql_logins sl ON sp.principal_id = sl.principal_id
WHERE sp.type IN ('S', 'U', 'G', 'C', 'K')
ORDER BY sp.type_desc, sp.name;
```

### Check for Blank Passwords

```sql
-- SQL logins with blank passwords
SELECT name, type_desc, is_disabled
FROM sys.sql_logins
WHERE PWDCOMPARE('', password_hash) = 1;
```

### Check for Weak/Common Passwords

```sql
-- Test against common passwords (authorized testing only)
SELECT name, type_desc, is_disabled
FROM sys.sql_logins
WHERE PWDCOMPARE(name, password_hash) = 1  -- password = username
   OR PWDCOMPARE('password', password_hash) = 1
   OR PWDCOMPARE('Password1', password_hash) = 1
   OR PWDCOMPARE('Password123', password_hash) = 1
   OR PWDCOMPARE('P@ssw0rd', password_hash) = 1
   OR PWDCOMPARE('sql2022', password_hash) = 1
   OR PWDCOMPARE('sa', password_hash) = 1
   OR PWDCOMPARE('admin', password_hash) = 1
   OR PWDCOMPARE('changeme', password_hash) = 1
   OR PWDCOMPARE('Welcome1', password_hash) = 1;
```

### Password Policy Enforcement

```sql
-- SQL logins without password policy or expiration
SELECT
    name,
    is_policy_checked AS [PolicyEnforced],
    is_expiration_checked AS [ExpirationEnforced],
    is_disabled
FROM sys.sql_logins
WHERE is_policy_checked = 0
   OR is_expiration_checked = 0
ORDER BY name;
```

### SA Account Review

```sql
-- Check SA account status
SELECT
    name,
    is_disabled,
    LOGINPROPERTY(name, 'PasswordLastSetTime') AS [PasswordLastSet]
FROM sys.sql_logins
WHERE sid = 0x01;  -- SA is always SID 0x01

-- Check if SA has been renamed (CIS recommendation)
SELECT name FROM sys.server_principals WHERE sid = 0x01;
```

> **Recommendation:** SA account should be disabled and renamed. A separate named admin account should be used.

### Guest Account Status

```sql
-- Check guest user access in each database
EXEC sp_MSforeachdb '
    USE [?];
    SELECT
        DB_NAME() AS [Database],
        dp.name AS [User],
        dp.type_desc,
        perm.permission_name,
        perm.state_desc
    FROM sys.database_principals dp
    LEFT JOIN sys.database_permissions perm ON dp.principal_id = perm.grantee_principal_id
    WHERE dp.name = ''guest''
    AND perm.permission_name = ''CONNECT''
    AND perm.state_desc = ''GRANT''
    AND DB_NAME() NOT IN (''master'', ''tempdb'');
';
```

---

## Authorization & Privileges

### Sysadmin Role Members

```sql
-- All members of sysadmin
SELECT
    sp.name AS [Login],
    sp.type_desc AS [LoginType],
    sp.is_disabled
FROM sys.server_principals sp
INNER JOIN sys.server_role_members srm ON sp.principal_id = srm.member_principal_id
INNER JOIN sys.server_principals sr ON srm.role_principal_id = sr.principal_id
WHERE sr.name = 'sysadmin'
ORDER BY sp.name;
```

### All Server Role Memberships

```sql
SELECT
    sr.name AS [ServerRole],
    sp.name AS [MemberLogin],
    sp.type_desc AS [LoginType],
    sp.is_disabled
FROM sys.server_role_members srm
INNER JOIN sys.server_principals sr ON srm.role_principal_id = sr.principal_id
INNER JOIN sys.server_principals sp ON srm.member_principal_id = sp.principal_id
ORDER BY sr.name, sp.name;
```

### Server-Level Permissions

```sql
SELECT
    pr.name AS [Principal],
    pr.type_desc AS [PrincipalType],
    pe.permission_name,
    pe.state_desc AS [PermissionState],
    pe.class_desc
FROM sys.server_permissions pe
INNER JOIN sys.server_principals pr ON pe.grantee_principal_id = pr.principal_id
WHERE pr.name NOT LIKE '##%'
ORDER BY pr.name, pe.permission_name;
```

### Database-Level Users & Roles (per database)

```sql
-- Run against each target database
USE [YourDatabaseName];
GO

-- Database users and their roles
SELECT
    dp.name AS [DatabaseUser],
    dp.type_desc AS [UserType],
    dp.authentication_type_desc,
    dp.default_schema_name,
    STRING_AGG(r.name, ', ') AS [DatabaseRoles]
FROM sys.database_principals dp
LEFT JOIN sys.database_role_members drm ON dp.principal_id = drm.member_principal_id
LEFT JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
WHERE dp.type IN ('S', 'U', 'G', 'E', 'X')
    AND dp.name NOT IN ('sys', 'INFORMATION_SCHEMA', 'guest', 'dbo')
GROUP BY dp.name, dp.type_desc, dp.authentication_type_desc, dp.default_schema_name
ORDER BY dp.name;
```

### db_owner Members (per database)

```sql
USE [YourDatabaseName];
GO

SELECT
    dp.name AS [User],
    dp.type_desc
FROM sys.database_role_members drm
INNER JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
INNER JOIN sys.database_principals dp ON drm.member_principal_id = dp.principal_id
WHERE r.name = 'db_owner'
ORDER BY dp.name;
```

### Explicit Database Permissions

```sql
USE [YourDatabaseName];
GO

SELECT
    pr.name AS [Principal],
    pr.type_desc AS [PrincipalType],
    pe.permission_name,
    pe.state_desc AS [PermState],
    pe.class_desc,
    OBJECT_NAME(pe.major_id) AS [ObjectName],
    SCHEMA_NAME(o.schema_id) AS [SchemaName]
FROM sys.database_permissions pe
INNER JOIN sys.database_principals pr ON pe.grantee_principal_id = pr.principal_id
LEFT JOIN sys.objects o ON pe.major_id = o.object_id
WHERE pr.name NOT IN ('public', 'guest', 'dbo', 'sys', 'INFORMATION_SCHEMA')
    AND pr.name NOT LIKE '##%'
ORDER BY pr.name, pe.permission_name;
```

### EXECUTE AS / Impersonation Permissions

```sql
-- Server-level impersonation
SELECT
    pr.name AS [Grantor],
    pe.permission_name,
    pe.state_desc,
    pr2.name AS [CanImpersonate]
FROM sys.server_permissions pe
INNER JOIN sys.server_principals pr ON pe.grantee_principal_id = pr.principal_id
INNER JOIN sys.server_principals pr2 ON pe.major_id = pr2.principal_id
WHERE pe.permission_name = 'IMPERSONATE'
ORDER BY pr.name;
```

```sql
-- Database-level impersonation
USE [YourDatabaseName];
GO

SELECT
    dp.name AS [Grantee],
    pe.permission_name,
    pe.state_desc,
    dp2.name AS [CanImpersonate]
FROM sys.database_permissions pe
INNER JOIN sys.database_principals dp ON pe.grantee_principal_id = dp.principal_id
INNER JOIN sys.database_principals dp2 ON pe.major_id = dp2.principal_id
WHERE pe.permission_name = 'IMPERSONATE';
```

### Orphaned Users

```sql
USE [YourDatabaseName];
GO

SELECT
    dp.name AS [OrphanedUser],
    dp.type_desc,
    dp.create_date
FROM sys.database_principals dp
LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid
WHERE dp.type IN ('S', 'U')
    AND sp.sid IS NULL
    AND dp.name NOT IN ('dbo', 'guest', 'INFORMATION_SCHEMA', 'sys')
    AND dp.authentication_type != 0;
```

---

## Auditing & Logging

### SQL Server Audit Status

```sql
-- Server audits
SELECT
    a.name AS [AuditName],
    a.status_desc,
    a.type_desc AS [AuditDestination],
    a.audit_file_path,
    a.max_file_size,
    a.max_rollover_files,
    a.is_state_enabled
FROM sys.server_audits a;
```

### Audit Specifications

```sql
-- Server audit specifications
SELECT
    sa.name AS [AuditName],
    sas.name AS [SpecificationName],
    sas.is_state_enabled,
    sasd.audit_action_name,
    sasd.class_desc,
    sasd.audited_principal_name,
    sasd.audited_result
FROM sys.server_audit_specification_details sasd
INNER JOIN sys.server_audit_specifications sas ON sasd.server_specification_id = sas.server_specification_id
INNER JOIN sys.server_audits sa ON sas.audit_guid = sa.audit_guid;

-- Database audit specifications
USE [YourDatabaseName];
GO

SELECT
    sa.name AS [AuditName],
    das.name AS [SpecificationName],
    das.is_state_enabled,
    dasd.audit_action_name,
    dasd.class_desc,
    dasd.audited_principal_name,
    dasd.audited_result
FROM sys.database_audit_specification_details dasd
INNER JOIN sys.database_audit_specifications das ON dasd.database_specification_id = das.database_specification_id
INNER JOIN sys.server_audits sa ON das.audit_guid = sa.audit_guid;
```

### Default Trace Check

```sql
-- Verify default trace is enabled
SELECT name, value_in_use
FROM sys.configurations
WHERE name = 'default trace enabled';

-- Check trace file location
SELECT path FROM sys.traces WHERE is_default = 1;
```

### Error Log Configuration

```sql
-- Number of error logs retained
EXEC xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    N'Software\Microsoft\MSSQLServer\MSSQLServer',
    N'NumErrorLogs';
-- Recommendation: at least 12

-- View recent error log entries
EXEC sp_readerrorlog 0, 1, N'Login failed';
```

### Login Auditing Level

```sql
EXEC xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    N'Software\Microsoft\MSSQLServer\MSSQLServer',
    N'AuditLevel';
-- 0 = None, 1 = Success only, 2 = Failure only, 3 = Both
-- Recommendation: 3 (Both)
```

### C2 Audit Mode (legacy, informational)

```sql
SELECT name, value_in_use
FROM sys.configurations
WHERE name = 'common criteria compliance enabled';
-- 1 = enabled (provides additional auditing per Common Criteria)
```

---

## Encryption Review

### Transparent Data Encryption (TDE)

```sql
-- TDE status for all databases
SELECT
    db.name AS [Database],
    db.is_encrypted,
    dek.encryption_state,
    CASE dek.encryption_state
        WHEN 0 THEN 'No encryption key'
        WHEN 1 THEN 'Unencrypted'
        WHEN 2 THEN 'Encryption in progress'
        WHEN 3 THEN 'Encrypted'
        WHEN 4 THEN 'Key change in progress'
        WHEN 5 THEN 'Decryption in progress'
        WHEN 6 THEN 'Protection change in progress'
    END AS [EncryptionStateDesc],
    dek.key_algorithm,
    dek.key_length,
    dek.encryptor_type,
    cert.name AS [CertificateName],
    cert.expiry_date AS [CertExpiry]
FROM sys.databases db
LEFT JOIN sys.dm_database_encryption_keys dek ON db.database_id = dek.database_id
LEFT JOIN sys.certificates cert ON dek.encryptor_thumbprint = cert.thumbprint
ORDER BY db.name;
```

### TDE Certificate Backup Check

```sql
-- List TDE certificates — confirm these are backed up securely
SELECT
    name,
    subject,
    start_date,
    expiry_date,
    thumbprint,
    pvt_key_encryption_type_desc
FROM sys.certificates
WHERE name LIKE '%TDE%'
   OR thumbprint IN (SELECT encryptor_thumbprint FROM sys.dm_database_encryption_keys);
```

### Always Encrypted Configuration

```sql
USE [YourDatabaseName];
GO

-- Column master keys
SELECT
    name AS [ColumnMasterKey],
    key_store_provider_name,
    key_path,
    create_date
FROM sys.column_master_keys;

-- Column encryption keys
SELECT
    cek.name AS [ColumnEncryptionKey],
    cek.create_date,
    cmk.name AS [MasterKeyName]
FROM sys.column_encryption_keys cek
INNER JOIN sys.column_encryption_key_values cekv ON cek.column_encryption_key_id = cekv.column_encryption_key_id
INNER JOIN sys.column_master_keys cmk ON cekv.column_master_key_id = cmk.column_master_key_id;

-- Encrypted columns
SELECT
    t.name AS [Table],
    c.name AS [Column],
    c.encryption_type_desc,
    cek.name AS [EncryptionKeyName]
FROM sys.columns c
INNER JOIN sys.tables t ON c.object_id = t.object_id
INNER JOIN sys.column_encryption_keys cek ON c.column_encryption_key_id = cek.column_encryption_key_id
WHERE c.encryption_type IS NOT NULL;
```

### Connection Encryption (TLS/SSL)

```sql
-- Check if connections are encrypted
SELECT
    session_id,
    encrypt_option,
    auth_scheme,
    client_net_address,
    protocol_type
FROM sys.dm_exec_connections
WHERE session_id = @@SPID;

-- Check Force Encryption setting
EXEC xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
    N'ForceEncryption';
-- 1 = Forced, 0 = Not forced
```

### TLS Version Check

```sql
-- Check TLS version of current connection
SELECT
    session_id,
    encrypt_option,
    protocol_type,
    protocol_version
FROM sys.dm_exec_connections
WHERE session_id = @@SPID;

-- For full TLS configuration, check registry or OS-level settings
-- SQL Server 2022 supports TLS 1.3
```

### Service Master Key & Database Master Keys

```sql
-- Service master key info
SELECT *
FROM sys.symmetric_keys
WHERE name = '##MS_ServiceMasterKey##';

-- Database master keys across databases
EXEC sp_MSforeachdb '
    USE [?];
    IF EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = ''##MS_DatabaseMasterKey##'')
    SELECT DB_NAME() AS [Database], name, algorithm_desc, create_date, modify_date
    FROM sys.symmetric_keys
    WHERE name = ''##MS_DatabaseMasterKey##'';
';
```

---

## Network & Surface Area

### Listening Ports & Protocols

```sql
-- SQL Server network configuration
SELECT
    local_net_address,
    local_tcp_port,
    COUNT(*) AS [Connections]
FROM sys.dm_exec_connections
WHERE local_net_address IS NOT NULL
GROUP BY local_net_address, local_tcp_port;
```

### Linked Servers

```sql
-- Enumerate linked servers
SELECT
    ss.name AS [LinkedServer],
    ss.product,
    ss.provider,
    ss.data_source,
    ss.catalog,
    ss.is_remote_login_enabled,
    ss.is_rpc_out_enabled,
    ss.is_data_access_enabled,
    ll.remote_name AS [MappedRemoteLogin],
    ll.uses_self_credential
FROM sys.servers ss
LEFT JOIN sys.linked_logins ll ON ss.server_id = ll.server_id
WHERE ss.is_linked = 1
ORDER BY ss.name;
```

> **Risk:** Linked servers with `is_rpc_out_enabled = 1` can execute remote procedures. Review mapped credentials — avoid SA or high-privilege mappings.

### Endpoints

```sql
SELECT
    name,
    type_desc,
    state_desc,
    protocol_desc,
    port,
    ip_address,
    is_admin_endpoint
FROM sys.endpoints
WHERE type_desc != 'TSQL'
ORDER BY name;
```

### SQL Browser Service

```sql
-- If accessible, check if SQL Browser is running
-- This exposes instance names and ports on UDP 1434
-- Verify via OS: Get-Service SQLBrowser (PowerShell)
```

### Remote Access & DAC

```sql
SELECT name, value_in_use
FROM sys.configurations
WHERE name IN ('remote access', 'remote admin connections');
-- remote access should be 0
-- remote admin connections should be 0 (unless clustered)
```

---

## Patching & Versioning

### Current Patch Level

```sql
SELECT
    SERVERPROPERTY('ProductVersion') AS [Version],
    SERVERPROPERTY('ProductLevel') AS [Level],
    SERVERPROPERTY('ProductUpdateLevel') AS [CU],
    SERVERPROPERTY('ProductUpdateReference') AS [KB];
```

### Cross-Reference with Microsoft

Compare the output above against the latest SQL Server 2022 build list:
- Check the KB number against Microsoft's official SQL Server 2022 build versions page
- Verify the Cumulative Update is within the last two releases
- Note any known CVEs for the running version

### Version Compliance Table

| Component | Check |
|---|---|
| SQL Server version | Is it 2022 (16.x)? |
| Service Pack / CU | Latest or N-1 Cumulative Update? |
| OS patches | Is the host OS patched? |
| .NET Framework | Current version on host? |
| SSMS version | If installed, is it current? |

---

## Backup & Recovery Security

### Backup History & Encryption

```sql
-- Recent backup history
SELECT
    bs.database_name,
    bs.type AS [BackupType],
    CASE bs.type
        WHEN 'D' THEN 'Full'
        WHEN 'I' THEN 'Differential'
        WHEN 'L' THEN 'Log'
    END AS [BackupTypeDesc],
    bs.backup_start_date,
    bs.backup_finish_date,
    bs.is_copy_only,
    bs.is_encrypted,
    bs.key_algorithm,
    bmf.physical_device_name AS [BackupLocation]
FROM msdb.dbo.backupset bs
INNER JOIN msdb.dbo.backupmediafamily bmf ON bs.media_set_id = bmf.media_set_id
WHERE bs.backup_start_date > DATEADD(DAY, -30, GETDATE())
ORDER BY bs.database_name, bs.backup_start_date DESC;
```

### Databases Without Recent Backups

```sql
SELECT
    d.name AS [Database],
    d.recovery_model_desc,
    MAX(bs.backup_finish_date) AS [LastBackup],
    DATEDIFF(DAY, MAX(bs.backup_finish_date), GETDATE()) AS [DaysSinceBackup]
FROM sys.databases d
LEFT JOIN msdb.dbo.backupset bs ON d.name = bs.database_name
WHERE d.database_id > 4  -- exclude system DBs
GROUP BY d.name, d.recovery_model_desc
HAVING MAX(bs.backup_finish_date) IS NULL
    OR DATEDIFF(DAY, MAX(bs.backup_finish_date), GETDATE()) > 7
ORDER BY [DaysSinceBackup] DESC;
```

### Backup File Permissions

```sql
-- Check where backups are stored
SELECT DISTINCT physical_device_name
FROM msdb.dbo.backupmediafamily
WHERE physical_device_name NOT LIKE '{%'
ORDER BY physical_device_name;
-- Verify NTFS permissions on these locations restrict access to DBAs and backup service accounts only
```

---

## Stored Procedures & Code Review

### Dangerous Extended Stored Procedures

```sql
-- Check permissions on dangerous procedures
SELECT
    OBJECT_NAME(pe.major_id) AS [Procedure],
    pr.name AS [Principal],
    pe.permission_name,
    pe.state_desc
FROM sys.database_permissions pe
INNER JOIN sys.database_principals pr ON pe.grantee_principal_id = pr.principal_id
WHERE pe.major_id IN (
    OBJECT_ID('xp_cmdshell'),
    OBJECT_ID('xp_regread'),
    OBJECT_ID('xp_regwrite'),
    OBJECT_ID('xp_regdeletekey'),
    OBJECT_ID('xp_regdeletevalue'),
    OBJECT_ID('xp_servicecontrol'),
    OBJECT_ID('xp_availablemedia'),
    OBJECT_ID('xp_dirtree'),
    OBJECT_ID('xp_enumdsn'),
    OBJECT_ID('xp_loginconfig'),
    OBJECT_ID('xp_makecab'),
    OBJECT_ID('xp_subdirs'),
    OBJECT_ID('sp_OACreate'),
    OBJECT_ID('sp_OAMethod'),
    OBJECT_ID('sp_OADestroy')
)
AND pe.state_desc = 'GRANT';
```

#### Generic Finding — Excessive Permissions on Dangerous Extended Stored Procedures

Use this finding when any of the above procedures have explicit GRANT permissions to non-sysadmin principals.

```
### Finding: EXECUTE Permissions Granted on Dangerous Extended Stored Procedures

| Field | Detail |
|---|---|
| **Severity** | High |
| **CIS Reference** | CIS SQL Server 2022 Benchmark 2.11, 2.12; DISA STIG V-213987 |
| **Affected Instance** | ServerName\InstanceName |
| **Current State** | Explicit EXECUTE permissions are granted to non-administrative principals on one or more dangerous extended stored procedures (e.g., xp_cmdshell, xp_regread, xp_regwrite, xp_dirtree, xp_servicecontrol, sp_OACreate, sp_OAMethod) |
| **Evidence** | [Paste query output showing Procedure, Principal, permission_name, state_desc] |
| **Expected State** | No explicit EXECUTE permissions should be granted on extended stored procedures that provide direct access to the operating system, file system, registry, or COM objects. Only members of the sysadmin fixed server role should be able to execute these procedures, and only when the underlying feature (e.g., xp_cmdshell) is temporarily enabled for a specific administrative task |
| **Risk** | These procedures allow authenticated database users to interact directly with the host operating system. Depending on the procedure, an attacker or compromised account could: read and write registry keys (xp_regread, xp_regwrite, xp_regdeletekey) to modify SQL Server or OS configuration; execute arbitrary OS commands (xp_cmdshell) leading to full server compromise; enumerate file system paths and network shares (xp_dirtree, xp_subdirs, xp_availablemedia) for lateral movement and data discovery; control Windows services (xp_servicecontrol) to disable security tooling or stop audit services; instantiate and invoke COM objects (sp_OACreate, sp_OAMethod) to bypass SQL Server security boundaries and execute code in the OS context. Even read-only procedures such as xp_regread and xp_dirtree are dangerous — they enable reconnaissance of the host environment, credential harvesting from registry-stored secrets, and UNC path injection for NTLM relay attacks |
| **Recommendation** | Revoke explicit EXECUTE permissions on all dangerous extended stored procedures for non-administrative principals. Where application functionality depends on these procedures, migrate to safer alternatives (e.g., CLR integration with strict security, application-layer file operations) and implement compensating controls such as SQL Server Audit logging on procedure execution |
| **Remediation SQL** | See below |
```

```sql
-- Revoke permissions (repeat for each principal and procedure from the evidence)
REVOKE EXECUTE ON xp_regread TO [PrincipalName];
REVOKE EXECUTE ON xp_regwrite TO [PrincipalName];
REVOKE EXECUTE ON xp_regdeletekey TO [PrincipalName];
REVOKE EXECUTE ON xp_regdeletevalue TO [PrincipalName];
REVOKE EXECUTE ON xp_dirtree TO [PrincipalName];
REVOKE EXECUTE ON xp_subdirs TO [PrincipalName];
REVOKE EXECUTE ON xp_servicecontrol TO [PrincipalName];
REVOKE EXECUTE ON xp_availablemedia TO [PrincipalName];
REVOKE EXECUTE ON xp_enumdsn TO [PrincipalName];
REVOKE EXECUTE ON xp_loginconfig TO [PrincipalName];
REVOKE EXECUTE ON xp_makecab TO [PrincipalName];
REVOKE EXECUTE ON xp_cmdshell TO [PrincipalName];
REVOKE EXECUTE ON sp_OACreate TO [PrincipalName];
REVOKE EXECUTE ON sp_OAMethod TO [PrincipalName];
REVOKE EXECUTE ON sp_OADestroy TO [PrincipalName];
```

**Per-procedure risk reference:**

| Procedure | Category | Why It Is Dangerous |
|---|---|---|
| `xp_cmdshell` | OS command execution | Executes arbitrary operating system commands as the SQL Server service account. Full host compromise if granted to a low-privilege user |
| `xp_regread` | Registry read | Reads Windows registry keys. Can extract service account credentials, connection strings, software inventory, and security configuration |
| `xp_regwrite` | Registry write | Writes to the Windows registry. Can modify SQL Server configuration, register malicious COM objects, tamper with security settings, or establish persistence |
| `xp_regdeletekey` | Registry delete | Deletes registry keys. Can remove audit configuration, security software registration, or break services |
| `xp_regdeletevalue` | Registry delete | Deletes individual registry values. Same risks as xp_regdeletekey at a more granular level |
| `xp_dirtree` | File system enumeration | Lists directory contents on the server or across UNC paths. Enables file system reconnaissance and NTLM hash capture via UNC path injection (e.g., `xp_dirtree '\\attacker\share'`) |
| `xp_subdirs` | File system enumeration | Lists subdirectories. Same reconnaissance and NTLM relay risks as xp_dirtree |
| `xp_availablemedia` | File system enumeration | Lists available drives and media. Reveals storage layout for targeted data exfiltration |
| `xp_enumdsn` | ODBC enumeration | Lists configured ODBC data sources. Reveals other database connections and potential lateral movement targets |
| `xp_loginconfig` | Security configuration | Displays the login security configuration of the server. Reveals authentication mode and audit settings to an attacker |
| `xp_makecab` | File system write | Creates compressed cabinet (.cab) files. Can be used to stage data for exfiltration or write files to disk |
| `xp_servicecontrol` | Service management | Starts and stops Windows services. An attacker can disable antivirus, stop audit services, or shut down security monitoring |
| `sp_OACreate` | COM object instantiation | Creates instances of COM objects on the server. Provides a code execution pathway outside SQL Server's security model |
| `sp_OAMethod` | COM object method call | Invokes methods on COM objects. Combined with sp_OACreate, allows arbitrary code execution, file system access, and HTTP requests from the server |
| `sp_OADestroy` | COM object cleanup | Destroys COM object instances. Typically granted alongside sp_OACreate and sp_OAMethod — revoke as a set |

### User Stored Procedures with Dynamic SQL

```sql
USE [YourDatabaseName];
GO

-- Find procedures using dynamic SQL (potential SQL injection risk)
SELECT
    SCHEMA_NAME(o.schema_id) AS [Schema],
    o.name AS [Procedure],
    o.create_date,
    o.modify_date
FROM sys.sql_modules m
INNER JOIN sys.objects o ON m.object_id = o.object_id
WHERE o.type = 'P'
    AND (m.definition LIKE '%EXEC(%'
        OR m.definition LIKE '%EXECUTE(%'
        OR m.definition LIKE '%sp_executesql%'
        OR m.definition LIKE '%EXEC @%'
        OR m.definition LIKE '%EXEC (@%')
ORDER BY o.name;
```

### Safe SQL Injection Testing for Stored Procedures

The query above identifies stored procedures that *may* be vulnerable, but a code review is needed to confirm. This is a manual check — below is a safe, structured approach for authorized testing.

#### Step 1 — Read the procedure source code

Before executing anything, review the procedure definition to understand what it does:

```sql
-- View the full definition of a flagged procedure
EXEC sp_helptext 'dbo.YourProcedureName';

-- Or use sys.sql_modules for the full text
SELECT definition
FROM sys.sql_modules
WHERE object_id = OBJECT_ID('dbo.YourProcedureName');
```

#### Step 2 — Classify the risk by code pattern

Review the source and classify the procedure against these patterns:

| Code Pattern | Risk Level | What It Means |
|---|---|---|
| `sp_executesql @sql, N'@param INT', @param = @input` | **Low** — Parameterised dynamic SQL | Parameters are bound safely. The procedure uses dynamic SQL but inputs are not concatenated into the query string. This is the correct way to use dynamic SQL |
| `SET @sql = 'SELECT * FROM ' + QUOTENAME(@tablename)` | **Low** — Properly quoted identifiers | `QUOTENAME()` escapes identifiers (table/column names). Safe for identifiers, though still worth documenting |
| `SET @sql = 'SELECT * FROM users WHERE name = ''' + @input + ''''` | **High** — String concatenation without parameterisation | User input is concatenated directly into the SQL string. This is vulnerable to SQL injection |
| `EXEC('SELECT * FROM ' + @input)` | **High** — Unparameterised EXEC with concatenation | Same risk — raw input is injected into executed SQL. No parameterisation or escaping |
| `SET @sql = 'SELECT * FROM users WHERE id = ' + CAST(@id AS VARCHAR)` | **Medium** — Type-cast concatenation | The `CAST` to a numeric type provides *some* protection (can't inject strings), but the pattern is still unsafe and should use parameterised queries |

> **Key rule:** If user-supplied input is concatenated into a SQL string without parameterisation (`sp_executesql` with parameter binding) or proper escaping (`QUOTENAME` for identifiers), it is likely vulnerable.

#### Step 3 — Identify the procedure's parameters

```sql
-- List parameters and their types for the target procedure
SELECT
    p.name AS [Parameter],
    t.name AS [DataType],
    p.max_length,
    p.is_output
FROM sys.parameters p
INNER JOIN sys.types t ON p.system_type_id = t.system_type_id AND p.user_type_id = t.user_type_id
WHERE p.object_id = OBJECT_ID('dbo.YourProcedureName')
ORDER BY p.parameter_id;
```

| Parameter Type | Testing Notes |
|---|---|
| `VARCHAR` / `NVARCHAR` | Primary injection target — string parameters that get concatenated into dynamic SQL |
| `INT` / `BIGINT` / `DECIMAL` | Lower risk — SQL Server will reject non-numeric input at the parameter level, but test type-cast concatenation patterns |
| `OUTPUT` parameters | Not directly injectable, but check if they leak data from injected queries |

#### Step 4 — Safe test payloads (read-only, non-destructive)

> **Important:** Only use these payloads during authorized testing. Always work in a test/dev environment when possible. These payloads are designed to detect injection without modifying data.

**Principle:** Use payloads that cause observable differences (errors, timing, row count changes) without altering data.

**4a. Error-based detection — does unescaped input cause a SQL error?**

```sql
-- Pass a single quote to trigger a syntax error
-- If the procedure errors with "Unclosed quotation mark", it is concatenating input unsafely
EXEC dbo.YourProcedureName @param = N'''';
-- Expected if vulnerable: "Unclosed quotation mark after the character string"
-- Expected if safe: Normal execution or application-level validation error
```

| Result | What It Means |
|---|---|
| `Unclosed quotation mark after the character string '''.` | **Vulnerable** — the single quote broke out of the SQL string. Input is concatenated without parameterisation |
| `Incorrect syntax near ...` | **Likely vulnerable** — input is reaching the SQL parser unescaped |
| Normal execution / empty result set | **Likely safe** — input is parameterised or validated. Proceed with further tests to confirm |
| Application-level error (e.g., "Invalid input") | **Safe** — input validation is catching the payload before it reaches SQL |

**4b. Tautology test — does always-true logic change results?**

```sql
-- Normal call (note the expected row count)
EXEC dbo.YourProcedureName @param = N'test';

-- Tautology injection (should return all rows if vulnerable)
EXEC dbo.YourProcedureName @param = N'test'' OR ''1''=''1';
```

| Result | What It Means |
|---|---|
| Second call returns significantly more rows than the first | **Vulnerable** — the `OR '1'='1'` was interpreted as SQL, bypassing the WHERE clause |
| Both calls return the same results | **Likely safe** — the injected logic was treated as a literal string value |

**4c. Time-based detection — does a delay payload cause the procedure to hang?**

```sql
-- Inject a WAITFOR to see if execution is delayed
-- Use a short delay (2 seconds) to minimise impact
EXEC dbo.YourProcedureName @param = N'test''; WAITFOR DELAY ''0:0:2''--';
```

| Result | What It Means |
|---|---|
| Procedure takes ~2 seconds longer than normal | **Vulnerable** — the `WAITFOR` was executed as a separate statement, confirming injection |
| Procedure returns at normal speed | **Likely safe** — the payload was not interpreted as SQL |

**4d. UNION-based detection (read-only) — can you extract metadata?**

```sql
-- Attempt to append a UNION SELECT to extract version info
-- This is read-only and exposes no sensitive data
EXEC dbo.YourProcedureName @param = N'test'' UNION SELECT @@VERSION--';
```

| Result | What It Means |
|---|---|
| SQL Server version string appears in the output | **Vulnerable** — the UNION was executed and returned data from the injected query |
| Column count mismatch error (`All queries ... must have an equal number of expressions`) | **Vulnerable** — the injection reached the parser. The error itself confirms the vulnerability even though the output failed |
| Normal results, no version string | **Likely safe** — the payload was parameterised or escaped |

#### Step 5 — Document findings

For each vulnerable procedure, record:

```
| Field | Detail |
|---|---|
| **Procedure** | [Schema].[ProcedureName] |
| **Vulnerable Parameter** | @param_name (NVARCHAR) |
| **Pattern** | String concatenation into EXEC / sp_executesql without parameter binding |
| **Evidence** | Error-based: single quote produced "Unclosed quotation mark" error |
| **Risk** | Authenticated users calling this procedure can execute arbitrary SQL with the procedure's security context |
| **Remediation** | Refactor to use `sp_executesql` with parameter binding, or use `QUOTENAME()` for identifier inputs |
```

#### Remediation Reference

For each vulnerable pattern found, recommend the safe equivalent:

```sql
-- VULNERABLE: String concatenation
SET @sql = N'SELECT * FROM users WHERE name = ''' + @input + '''';
EXEC(@sql);

-- SAFE: Parameterised sp_executesql
SET @sql = N'SELECT * FROM users WHERE name = @name';
EXEC sp_executesql @sql, N'@name NVARCHAR(100)', @name = @input;
```

```sql
-- VULNERABLE: Dynamic table name via concatenation
SET @sql = N'SELECT * FROM ' + @tablename;
EXEC(@sql);

-- SAFE: QUOTENAME for identifiers
SET @sql = N'SELECT * FROM ' + QUOTENAME(@tablename);
EXEC sp_executesql @sql;
```

### Procedures with EXECUTE AS

```sql
USE [YourDatabaseName];
GO

SELECT
    SCHEMA_NAME(o.schema_id) AS [Schema],
    o.name AS [Procedure],
    m.execute_as_principal_id,
    dp.name AS [ExecuteAsUser]
FROM sys.sql_modules m
INNER JOIN sys.objects o ON m.object_id = o.object_id
LEFT JOIN sys.database_principals dp ON m.execute_as_principal_id = dp.principal_id
WHERE m.execute_as_principal_id IS NOT NULL
    AND m.execute_as_principal_id != -2  -- -2 = CALLER (default)
ORDER BY o.name;
```

### TRUSTWORTHY Database Setting

```sql
-- TRUSTWORTHY allows database code to access external resources
-- Should be OFF unless specifically required
SELECT
    name,
    is_trustworthy_on
FROM sys.databases
WHERE is_trustworthy_on = 1
    AND name NOT IN ('msdb');
```

---

## CIS Benchmark Quick Checks

These checks align with CIS Microsoft SQL Server 2022 Benchmark recommendations.

### CIS Section 2 — Surface Area

```sql
-- 2.1: Ad Hoc Distributed Queries disabled
-- 2.2: CLR Enabled disabled
-- 2.3: Cross DB Ownership Chaining disabled
-- 2.4: Database Mail XPs disabled
-- 2.5: Ole Automation Procedures disabled
-- 2.6: Remote Access disabled
-- 2.7: Remote Admin Connections disabled
-- 2.8: Scan For Startup Procs disabled
-- 2.9: Trustworthy OFF on user databases
-- 2.11: xp_cmdshell disabled
-- 2.13: default trace enabled
-- 2.14: CLR strict security enabled
-- 2.16: external scripts enabled disabled

-- Consolidated check:
SELECT
    name,
    value_in_use,
    CASE
        WHEN name = 'Ad Hoc Distributed Queries' AND value_in_use = 0 THEN 'PASS'
        WHEN name = 'clr enabled' AND value_in_use = 0 THEN 'PASS'
        WHEN name = 'clr strict security' AND value_in_use = 1 THEN 'PASS'
        WHEN name = 'cross db ownership chaining' AND value_in_use = 0 THEN 'PASS'
        WHEN name = 'Database Mail XPs' AND value_in_use = 0 THEN 'PASS'
        WHEN name = 'Ole Automation Procedures' AND value_in_use = 0 THEN 'PASS'
        WHEN name = 'remote access' AND value_in_use = 0 THEN 'PASS'
        WHEN name = 'remote admin connections' AND value_in_use = 0 THEN 'PASS'
        WHEN name = 'scan for startup procs' AND value_in_use = 0 THEN 'PASS'
        WHEN name = 'xp_cmdshell' AND value_in_use = 0 THEN 'PASS'
        WHEN name = 'default trace enabled' AND value_in_use = 1 THEN 'PASS'
        WHEN name = 'external scripts enabled' AND value_in_use = 0 THEN 'PASS'
        ELSE 'FAIL'
    END AS [CIS_Result]
FROM sys.configurations
WHERE name IN (
    'Ad Hoc Distributed Queries',
    'clr enabled',
    'clr strict security',
    'cross db ownership chaining',
    'Database Mail XPs',
    'Ole Automation Procedures',
    'remote access',
    'remote admin connections',
    'scan for startup procs',
    'xp_cmdshell',
    'default trace enabled',
    'external scripts enabled'
)
ORDER BY name;
```

### CIS Section 3 — Authentication

```sql
-- 3.1: Windows Authentication mode
SELECT
    CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
        WHEN 1 THEN 'PASS - Windows Auth Only'
        ELSE 'REVIEW - Mixed Mode'
    END AS [CIS_3_1_AuthMode];

-- 3.2: CHECK_POLICY ON for all SQL logins
SELECT name,
    CASE WHEN is_policy_checked = 1 THEN 'PASS' ELSE 'FAIL' END AS [CIS_3_2]
FROM sys.sql_logins
WHERE is_disabled = 0;

-- 3.3: CHECK_EXPIRATION ON for all SQL logins
SELECT name,
    CASE WHEN is_expiration_checked = 1 THEN 'PASS' ELSE 'FAIL' END AS [CIS_3_3]
FROM sys.sql_logins
WHERE is_disabled = 0;

-- 3.4: SA account disabled
SELECT name,
    CASE WHEN is_disabled = 1 THEN 'PASS' ELSE 'FAIL' END AS [CIS_3_4_SA_Disabled]
FROM sys.server_principals
WHERE sid = 0x01;

-- 3.5: SA account renamed
SELECT name,
    CASE WHEN name != 'sa' THEN 'PASS' ELSE 'FAIL' END AS [CIS_3_5_SA_Renamed]
FROM sys.server_principals
WHERE sid = 0x01;
```

### CIS Section 4 — Authorization

```sql
-- 4.2: CONNECT permission revoked from guest on user databases
EXEC sp_MSforeachdb '
    IF ''?'' NOT IN (''master'', ''tempdb'', ''msdb'')
    BEGIN
        USE [?];
        SELECT DB_NAME() AS [Database],
            CASE WHEN EXISTS(
                SELECT 1 FROM sys.database_permissions
                WHERE grantee_principal_id = DATABASE_PRINCIPAL_ID(''guest'')
                AND permission_name = ''CONNECT''
                AND state_desc = ''GRANT''
            ) THEN ''FAIL'' ELSE ''PASS'' END AS [CIS_4_2_GuestConnect];
    END
';

-- 4.3: Orphaned users check
EXEC sp_MSforeachdb '
    IF ''?'' NOT IN (''master'', ''tempdb'', ''msdb'', ''model'')
    BEGIN
        USE [?];
        SELECT DB_NAME() AS [Database], dp.name AS [OrphanedUser], ''FAIL'' AS [CIS_4_3]
        FROM sys.database_principals dp
        LEFT JOIN sys.server_principals sp ON dp.sid = sp.sid
        WHERE dp.type IN (''S'',''U'')
        AND sp.sid IS NULL
        AND dp.name NOT IN (''dbo'',''guest'',''INFORMATION_SCHEMA'',''sys'')
        AND dp.authentication_type != 0;
    END
';
```

### CIS Section 5 — Auditing

```sql
-- 5.1: Maximum number of error log files >= 12
DECLARE @NumErrorLogs INT;
EXEC master.sys.xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    N'Software\Microsoft\MSSQLServer\MSSQLServer',
    N'NumErrorLogs',
    @NumErrorLogs OUTPUT;
SELECT
    @NumErrorLogs AS [NumErrorLogs],
    CASE WHEN @NumErrorLogs >= 12 THEN 'PASS' ELSE 'FAIL' END AS [CIS_5_1];

-- 5.2: Default Trace Enabled
SELECT
    value_in_use,
    CASE WHEN value_in_use = 1 THEN 'PASS' ELSE 'FAIL' END AS [CIS_5_2]
FROM sys.configurations
WHERE name = 'default trace enabled';

-- 5.3: Login Auditing set to both failed and successful
DECLARE @AuditLevel INT;
EXEC master.sys.xp_instance_regread
    N'HKEY_LOCAL_MACHINE',
    N'Software\Microsoft\MSSQLServer\MSSQLServer',
    N'AuditLevel',
    @AuditLevel OUTPUT;
SELECT
    @AuditLevel AS [AuditLevel],
    CASE WHEN @AuditLevel = 3 THEN 'PASS' ELSE 'FAIL' END AS [CIS_5_3];

-- 5.4: SQL Server Audit configured
SELECT
    CASE WHEN EXISTS (
        SELECT 1 FROM sys.server_audits WHERE is_state_enabled = 1
    ) THEN 'PASS' ELSE 'FAIL' END AS [CIS_5_4_AuditExists];
```

---

## SQL Server Agent Security

```sql
-- Agent jobs and their owners
SELECT
    j.name AS [JobName],
    SUSER_SNAME(j.owner_sid) AS [JobOwner],
    j.enabled,
    j.date_created,
    j.date_modified,
    js.step_name,
    js.subsystem,
    js.command
FROM msdb.dbo.sysjobs j
INNER JOIN msdb.dbo.sysjobsteps js ON j.job_id = js.job_id
ORDER BY j.name, js.step_id;

-- Agent proxies
SELECT
    p.name AS [ProxyName],
    c.name AS [CredentialName],
    c.credential_identity,
    s.subsystem_name
FROM msdb.dbo.sysproxies p
INNER JOIN sys.credentials c ON p.credential_id = c.credential_id
INNER JOIN msdb.dbo.sysproxysubsystem ps ON p.proxy_id = ps.proxy_id
INNER JOIN msdb.dbo.syssubsystems s ON ps.subsystem_id = s.subsystem_id
ORDER BY p.name;
```

---

## SQL Server Service Account Review

```sql
-- Service account information
SELECT
    servicename,
    service_account,
    startup_type_desc,
    status_desc,
    instant_file_initialization_enabled
FROM sys.dm_server_services;
```

> **Recommendation:** Service accounts should be dedicated domain accounts or managed service accounts (MSAs/gMSAs), not LocalSystem, NetworkService, or domain admin accounts. Instant file initialization should be enabled for performance but understood as a minor data exposure risk.

---

## Findings Template

Use this template for each finding:

```
### Finding: [Title]

| Field | Detail |
|---|---|
| **Severity** | Critical / High / Medium / Low / Informational |
| **CIS Reference** | CIS SQL Server 2022 Benchmark Section X.X |
| **CVE** | CVE-XXXX-XXXXX (if applicable) |
| **Affected Instance** | ServerName\InstanceName |
| **Affected Database** | DatabaseName (if applicable) |
| **Current State** | [Description of what was found] |
| **Evidence** | [SQL query used and output] |
| **Expected State** | [What the compliant configuration should be] |
| **Risk** | [Business impact description] |
| **Recommendation** | [Specific remediation steps] |
| **Remediation SQL** | [SQL commands to fix, if applicable] |
```

### Example Finding

```
### Finding: xp_cmdshell Enabled

| Field | Detail |
|---|---|
| **Severity** | Critical |
| **CIS Reference** | CIS SQL Server 2022 Benchmark 2.11 |
| **Affected Instance** | DBSRV01\PROD |
| **Current State** | xp_cmdshell is enabled (value_in_use = 1) |
| **Evidence** | `SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';` — returned value_in_use = 1 |
| **Expected State** | xp_cmdshell should be disabled (value_in_use = 0) |
| **Risk** | Allows authenticated users with appropriate permissions to execute arbitrary OS commands via SQL Server, leading to potential full system compromise |
| **Recommendation** | Disable xp_cmdshell unless explicitly required by the application |
| **Remediation SQL** | `EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;` |
```

---

## Post-Review Checklist

- [ ] All instance configuration settings documented
- [ ] Authentication mode and all logins reviewed
- [ ] Password policy enforcement verified
- [ ] SA account status checked (disabled + renamed)
- [ ] All sysadmin and high-privilege role members listed
- [ ] Guest access reviewed per database
- [ ] Orphaned users identified
- [ ] Server and database audit configurations documented
- [ ] TDE status and certificate expiry checked
- [ ] Connection encryption (TLS) verified
- [ ] Linked servers and their credentials reviewed
- [ ] Dangerous extended stored procedures permissions checked
- [ ] SQL Agent jobs and proxies reviewed
- [ ] Service accounts are least-privilege
- [ ] Patch level verified against latest CU
- [ ] Backup encryption status confirmed
- [ ] CIS benchmark quick checks completed
- [ ] All findings documented with evidence and remediation

---

## References

- CIS Microsoft SQL Server 2022 Benchmark
- Microsoft SQL Server 2022 Security Best Practices documentation
- OWASP Database Security Cheat Sheet
- NIST SP 800-123 Guide to General Server Security
- DISA STIG for MS SQL Server 2022
- Microsoft SQL Server 2022 Build List (for patch verification)
