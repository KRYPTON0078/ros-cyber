"""MITRE ATT&CK and IEC 62443 technique mappings."""

MITRE_MAP: dict[str, str] = {
    "auth_failure": "T1110",
    "auth_brute_force": "T1110.001",
    "telemetry_flood": "T1498",
    "gps_anomaly": "T0886",
    "policy_violation": "T0855",
    "unauthorized_command": "T0855",
    "command_approved": "",
    "kill_switch": "T0881",
    "rosbridge_hijack": "T0855",
    "scanner_finding": "T1595",
    "ml_anomaly": "T0886",
}

IEC_MAP: dict[str, str] = {
    "auth_failure": "SR 1.1",
    "auth_brute_force": "SR 1.1",
    "telemetry_flood": "SR 7.1",
    "gps_anomaly": "SR 3.3",
    "policy_violation": "SR 3.3",
    "unauthorized_command": "SR 3.3",
    "kill_switch": "SR 3.1",
    "rosbridge_hijack": "SR 3.3",
    "scanner_finding": "SR 7.6",
    "ml_anomaly": "SR 3.3",
}


def map_techniques(event_type: str) -> tuple[str, str]:
    return MITRE_MAP.get(event_type, "T1190"), IEC_MAP.get(event_type, "SR 3.3")
