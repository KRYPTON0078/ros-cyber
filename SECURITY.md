# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in ROS Cyber, please report it responsibly:

1. **Do not** open a public GitHub issue for security vulnerabilities.
2. Email the maintainer with details: include steps to reproduce, impact assessment, and suggested fix if available.
3. Allow up to 72 hours for an initial response.

## Vulnerable Lab Profile

ROS Cyber includes an **intentionally vulnerable** Docker profile (`docker-compose.vuln.yml`) for educational and testing purposes. This profile must **only** be run in isolated lab environments. Never deploy the vulnerable profile to production or expose it to public networks.

## Scope

- In-scope: vulnerabilities in ROS Cyber platform code and configuration
- Out-of-scope: vulnerabilities in third-party dependencies (report upstream), general ROS2 framework issues
