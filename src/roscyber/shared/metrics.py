"""Prometheus metrics."""

from prometheus_client import Counter, Gauge, Histogram, generate_latest

REQUESTS_TOTAL = Counter(
    "roscyber_http_requests_total",
    "Total HTTP requests",
    ["service", "method", "endpoint", "status"],
)
REQUEST_LATENCY = Histogram(
    "roscyber_http_request_duration_seconds",
    "HTTP request latency",
    ["service", "endpoint"],
)
BLOCKED_COMMANDS = Counter("roscyber_blocked_commands_total", "Commands blocked by policy", ["robot_id"])
ALERTS_RAISED = Counter("roscyber_alerts_raised_total", "Security alerts raised", ["severity"])
ACTIVE_ROBOTS = Gauge("roscyber_active_robots", "Number of active robots in fleet")
KILL_SWITCH = Gauge("roscyber_kill_switch_active", "Kill switch state (1=active)")


def metrics_response() -> bytes:
    return generate_latest()
