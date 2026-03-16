# Atom — Hack The Box

**Platform:** Hack The Box  
**Difficulty:**  
**OS:** Linux

---

## Overview

Atom is a Hack The Box machine that focuses on web application and service enumeration. This write-up documents the steps taken to gain initial access and escalate privileges.

---

## Reconnaissance

### Nmap scan

```bash
nmap -sC -sV -oA atom/scan 10.10.11.xx
```

![Nmap initial scan](images/nmap-initial.png)

- Identify open ports and services.
- Note any interesting versions or default scripts output.

---

## Enumeration

### Web (HTTP/HTTPS)

- Enumerate virtual hosts or subdomains if applicable.
- Check for default credentials, admin panels, or exposed files.

![Web enumeration](images/web-enum.png)

### Other services

- Enumerate any other services (e.g., SMB, SSH, custom ports) as needed.

---

## Foothold

- Describe how initial access was obtained (e.g., vulnerable parameter, default creds, RCE).
- Include relevant commands and proof.

![Initial access](images/foothold.png)

---

## Privilege escalation

- Document the path from low-privilege user to root (or target user).
- Include any kernel exploits, misconfigurations, or credential reuse.

![Privilege escalation](images/privesc.png)

---

## Flags

- **User:** `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
- **Root:** `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`

---

## Summary

- Key takeaways and techniques used.
- References (CVEs, tools, articles) if applicable.
