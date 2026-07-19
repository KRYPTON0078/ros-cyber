# Threat Model — ROS Cyber

## Scope

Robot command path: Operator → API → Policy Engine → ROS2 cmd_vel → Physical motion

## STRIDE Analysis

| Threat | Category | Description | Mitigation (Hardened) |
|--------|----------|-------------|----------------------|
| JWT forgery | Spoofing | Attacker forges admin token | Strong secret, reject alg=none |
| Robot IDOR | Tampering | Read/modify other robot data | Object-level auth, no query override |
| cmd_vel hijack | Tampering | Inject motion via open rosbridge | SROS2, TLS, policy gating |
| Telemetry flood | DoS | Overwhelm ingestion API | Rate limiting, detection rules |
| Audit log deletion | Repudiation | Attacker covers tracks | Append-only PostgreSQL audit |
| Secret in admin API | Info Disclosure | JWT secret exposed | Admin endpoint disabled |
| Default creds | Elevation | admin/admin123! works | Credential rotation guide |
| Command injection | Elevation | Shell via params field | Input validation, allowlisting |

## Attack Trees

### Hijack Robot Motion

1. Gain network access to robot VLAN
2. Either:
   - a. Connect to unauthenticated rosbridge → publish `/cmd_vel`
   - b. Steal/forged JWT → POST command to policy API
   - c. Bypass policy in vulnerable profile
3. Robot executes unauthorized motion

**Controls:** Policy engine deny rules, SROS2 signed topics, network segmentation

## Trust Assumptions

- PostgreSQL and Redis are in trusted platform VLAN
- Vulnerable profile is never exposed to production networks
- Operators protect JWT tokens on client devices
