"""Rule-based and ML anomaly detection."""

import json
import math
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

import numpy as np

from roscyber.detection.mitre_map import map_techniques
from roscyber.shared.config import get_settings
from roscyber.shared.models import AlertSeverity


@dataclass
class DetectionResult:
    triggered: bool
    severity: AlertSeverity
    title: str
    description: str
    event_type: str
    robot_id: str
    raw_event: str


class DetectionEngine:
    def __init__(self) -> None:
        settings = get_settings()
        self.auth_failures: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=100))
        self.telemetry_counts: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=100))
        self.last_gps: dict[str, tuple[float, float, float]] = {}
        self.imu_history: dict[str, list[list[float]]] = defaultdict(list)
        self.flood_threshold = settings.telemetry_flood_threshold
        self.gps_threshold = settings.gps_jump_threshold_m

    @staticmethod
    def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        r = 6371000
        p1, p2 = math.radians(lat1), math.radians(lat2)
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = math.sin(dlat / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlon / 2) ** 2
        return 2 * r * math.asin(math.sqrt(a))

    def _check_ml_anomaly(self, robot_id: str, imu: list[float]) -> DetectionResult | None:
        history = self.imu_history[robot_id]
        history.append(imu)
        if len(history) < 10:
            return None
        arr = np.array(history[-20:])
        mean = arr.mean(axis=0)
        std = arr.std(axis=0) + 1e-6
        z = np.abs((np.array(imu) - mean) / std)
        if float(z.max()) > 4.0:
            return DetectionResult(
                triggered=True,
                severity=AlertSeverity.HIGH,
                title="ML anomaly: abnormal IMU pattern",
                description=f"Z-score {float(z.max()):.2f} on IMU vector for {robot_id}",
                event_type="ml_anomaly",
                robot_id=robot_id,
                raw_event=json.dumps({"imu": imu, "z_max": float(z.max())}),
            )
        return None

    def process_event(self, event: dict[str, Any]) -> list[DetectionResult]:
        import time

        results: list[DetectionResult] = []
        event_type = event.get("event_type", "unknown")
        robot_id = event.get("robot_id", "fleet")
        now = time.time()

        if event_type == "auth_failure":
            ip = event.get("source_ip", "unknown")
            self.auth_failures[ip].append(now)
            recent = [t for t in self.auth_failures[ip] if now - t < 60]
            if len(recent) >= 5:
                results.append(
                    DetectionResult(
                        triggered=True,
                        severity=AlertSeverity.HIGH,
                        title="Brute-force authentication attempt",
                        description=f"{len(recent)} failed logins from {ip} in 60s",
                        event_type="auth_brute_force",
                        robot_id="fleet",
                        raw_event=json.dumps(event),
                    )
                )

        if event_type == "telemetry":
            self.telemetry_counts[robot_id].append(now)
            recent = [t for t in self.telemetry_counts[robot_id] if now - t < 1]
            if len(recent) > self.flood_threshold:
                results.append(
                    DetectionResult(
                        triggered=True,
                        severity=AlertSeverity.MEDIUM,
                        title="Telemetry flood detected",
                        description=f"{len(recent)} messages/sec from {robot_id}",
                        event_type="telemetry_flood",
                        robot_id=robot_id,
                        raw_event=json.dumps(event),
                    )
                )

            lat = float(event.get("latitude", 0))
            lon = float(event.get("longitude", 0))
            if robot_id in self.last_gps:
                prev_lat, prev_lon, prev_t = self.last_gps[robot_id]
                dt = max(now - prev_t, 0.001)
                dist = self._haversine_m(prev_lat, prev_lon, lat, lon)
                if dist / dt > self.gps_threshold:
                    results.append(
                        DetectionResult(
                            triggered=True,
                            severity=AlertSeverity.CRITICAL,
                            title="Impossible GPS jump",
                            description=f"{robot_id} moved {dist:.0f}m in {dt:.2f}s",
                            event_type="gps_anomaly",
                            robot_id=robot_id,
                            raw_event=json.dumps(event),
                        )
                    )
            self.last_gps[robot_id] = (lat, lon, now)

            imu = [
                float(event.get("imu_x", 0)),
                float(event.get("imu_y", 0)),
                float(event.get("imu_z", 0)),
                float(event.get("motor_rpm", 0)),
            ]
            ml_result = self._check_ml_anomaly(robot_id, imu)
            if ml_result:
                results.append(ml_result)

        if event_type == "policy_violation":
            results.append(
                DetectionResult(
                    triggered=True,
                    severity=AlertSeverity.HIGH,
                    title="Policy violation on robot command",
                    description=event.get("reason", "Policy denied command"),
                    event_type="policy_violation",
                    robot_id=robot_id,
                    raw_event=json.dumps(event),
                )
            )

        if event_type == "command_approved":
            linear_x = abs(float(event.get("linear_x", 0)))
            if linear_x > 1.8:
                results.append(
                    DetectionResult(
                        triggered=True,
                        severity=AlertSeverity.MEDIUM,
                        title="High velocity command approved",
                        description=f"linear_x={linear_x} near policy limit",
                        event_type="unauthorized_command",
                        robot_id=robot_id,
                        raw_event=json.dumps(event),
                    )
                )

        if event_type == "kill_switch" and event.get("active"):
            results.append(
                DetectionResult(
                    triggered=True,
                    severity=AlertSeverity.CRITICAL,
                    title="Fleet kill switch activated",
                    description=f"Activated by {event.get('user', 'unknown')}",
                    event_type="kill_switch",
                    robot_id="fleet",
                    raw_event=json.dumps(event),
                )
            )

        for r in results:
            mitre, iec = map_techniques(r.event_type)
            r.raw_event = json.dumps({**json.loads(r.raw_event), "mitre": mitre, "iec": iec})

        return results
