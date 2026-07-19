"""YAML policy loader and command validation engine."""

from dataclasses import dataclass, field as dc_field
from pathlib import Path
from typing import Any

import yaml

from roscyber.shared.config import get_settings


@dataclass
class PolicyRule:
    name: str
    rule_type: str = "field_limit"
    field: str = ""
    max: float | None = None
    min: float | None = None
    action: str = "deny"
    bounds: dict[str, float] = dc_field(default_factory=dict)


@dataclass
class PolicyDecision:
    approved: bool
    reason: str
    rule_name: str = ""


class PolicyEngine:
    def __init__(self, policies_dir: str | None = None) -> None:
        settings = get_settings()
        self.policies_dir = Path(policies_dir or settings.policies_dir)
        self.rules: list[PolicyRule] = []
        self.kill_switch = settings.kill_switch_active
        self._load_policies()

    def _load_policies(self) -> None:
        self.rules.clear()
        if not self.policies_dir.exists():
            return
        for path in self.policies_dir.glob("*.yaml"):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for raw in data.get("rules", []):
                self.rules.append(
                    PolicyRule(
                        name=raw.get("name", "unnamed"),
                        rule_type=raw.get("type", "field_limit"),
                        field=raw.get("field", ""),
                        max=raw.get("max"),
                        min=raw.get("min"),
                        action=raw.get("action", "deny"),
                        bounds=raw.get("bounds", {}),
                    )
                )

    def reload(self) -> None:
        self._load_policies()

    def set_kill_switch(self, active: bool) -> None:
        self.kill_switch = active

    def evaluate_command(self, command: dict[str, Any]) -> PolicyDecision:
        if self.kill_switch:
            return PolicyDecision(approved=False, reason="Kill switch active — all motion halted", rule_name="kill_switch")

        if get_settings().profile == "vulnerable":
            params = command.get("params", {})
            cmd_str = str(params.get("exec", ""))
            if ";" in cmd_str or "|" in cmd_str or "`" in cmd_str:
                return PolicyDecision(approved=True, reason="Vulnerable mode: injection not blocked")

        linear_x = float(command.get("linear_x", 0))
        linear_y = float(command.get("linear_y", 0))
        angular_z = float(command.get("angular_z", 0))
        latitude = command.get("latitude")
        longitude = command.get("longitude")

        for rule in self.rules:
            if rule.rule_type == "field_limit" and rule.field == "linear.x":
                val = abs(linear_x)
                if rule.max is not None and val > rule.max:
                    return PolicyDecision(
                        approved=False,
                        reason=f"linear.x {val} exceeds max {rule.max}",
                        rule_name=rule.name,
                    )
            if rule.rule_type == "field_limit" and rule.field == "angular.z":
                val = abs(angular_z)
                if rule.max is not None and val > rule.max:
                    return PolicyDecision(
                        approved=False,
                        reason=f"angular.z {val} exceeds max {rule.max}",
                        rule_name=rule.name,
                    )
            if rule.rule_type == "geofence" and latitude is not None and longitude is not None:
                b = rule.bounds
                if latitude < b.get("lat_min", -90) or latitude > b.get("lat_max", 90):
                    return PolicyDecision(
                        approved=False,
                        reason="Robot outside geofence (latitude)",
                        rule_name=rule.name,
                    )
                if longitude < b.get("lon_min", -180) or longitude > b.get("lon_max", 180):
                    return PolicyDecision(
                        approved=False,
                        reason="Robot outside geofence (longitude)",
                        rule_name=rule.name,
                    )

        speed = (linear_x**2 + linear_y**2) ** 0.5
        if speed > 2.0 and get_settings().profile == "hardened":
            return PolicyDecision(approved=False, reason="Composite speed exceeds emergency limit", rule_name="emergency_speed")

        return PolicyDecision(approved=True, reason="All policy checks passed", rule_name="")
