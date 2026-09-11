# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 4.x dev | Yes |
| < 4.0   | No        |

## Reporting a vulnerability in HDWP itself

If you find a security vulnerability **in HDWP** (not in a target you scanned with it), please **do not open a public GitHub issue**.

Report privately via GitHub's Security Advisories:
**[Report a vulnerability](https://github.com/devmail0561-web/hdwp/security/advisories/new)**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix if you have one

You will receive an acknowledgement within 72 hours and a fix timeline within 7 days.

## Scope

In scope: the HDWP engine, CLI, API server, strategy loader, ML components.

Out of scope: vulnerabilities found *by* HDWP in third-party targets (report those to the affected vendor).

## Responsible use

HDWP is authorized for use only against systems you own or have explicit written permission to test. See `LICENSE` and the disclaimer in `README.md`.
