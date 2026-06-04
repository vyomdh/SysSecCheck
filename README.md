# SysSecCheck - Linux System Security Auditor

A Bash script that audits your Linux machine's security posture and prints a clear, human-readable report - no external  dependencies required.

---

## Features

|1| **Listening ports**
|2|** Last 10 failed login attempts**
|3|**Detect world-writable files**
|4|**List sudo-privileaged users**e  
|3|**Checks UFW firewall status**
|4|**Display running services**

### Colour legend
 - **GREEN** - OK,nothing to worry about
- **YELLOW** - Worth reviewing
- **RED** - Needs immediate attention

---

## Planned Imporvements
- [] SUID/SGID file detection
- [] SSH hardening checks ( PermitRootLogin, PasswordAuthentication )
- [] Cron-job review
- [] Package update status check
- [] '--quit' mode ( only show WARN/CRITICAL )


