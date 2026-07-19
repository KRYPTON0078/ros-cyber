# Hardening Guide — ROS Cyber

## Deployment Checklist

- [ ] Set `ROSCYBER_PROFILE=hardened`
- [ ] Generate strong `JWT_SECRET` (≥ 32 random characters)
- [ ] Rotate default admin/operator passwords
- [ ] Enable TLS termination (reverse proxy)
- [ ] Restrict rosbridge to trusted networks
- [ ] Enable SROS2 on ROS2 topics
- [ ] Run `roscyber scan --target <host>` after deployment

## SROS2 Setup (ROS2 Humble)

1. Install security packages:
   ```bash
   apt install ros-humble-sros2
   ```

2. Generate keystore:
   ```bash
   ros2 security create_keystore keystore
   ros2 security create_key keystore /robot-alpha
   ```

3. Enable security enclaves in launch files:
   ```bash
   export ROS_SECURITY_KEYSTORE=./keystore
   export ROS_SECURITY_ENABLE=true
   export ROS_SECURITY_STRATEGY=Enforce
   ```

4. Sign critical topics: `/cmd_vel`, `/odom`, `/joint_states`

## Network Segmentation

| VLAN | Members | Access |
|------|---------|--------|
| Robot | ROS2 nodes, sensors | No internet |
| Platform | ROS Cyber services | Internal only |
| Ops | SOC, Grafana | VPN required |

## TLS Configuration

Terminate TLS at nginx/Traefik:

```nginx
server {
    listen 443 ssl;
    server_name roscyber.example.com;
    ssl_certificate /etc/ssl/roscyber.crt;
    ssl_certificate_key /etc/ssl/roscyber.key;
    location / {
        proxy_pass http://ingestion:8000;
    }
}
```

## Finding Remediation Map

| Finding | Hardened Control |
|---------|-----------------|
| RC-001 JWT bypass | Algorithm allowlist, strong secret |
| RC-002 IDOR | Object-level auth, no param override |
| RC-003 GPS spoof | Detection rule + geofence policy |
| RC-004 Injection | Param validation, allowlisting |
| RC-005 Brute force | Rate limiting + detection alert |
| RC-006 rosbridge | SROS2 + TLS + scanner checks |

## Kill Switch Procedure

```bash
curl -X POST http://policy:8001/v1/kill-switch/on \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

All motion commands will be denied until `/v1/kill-switch/off` is called.
