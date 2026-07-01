# Complete Workflow Test Guide

## Architecture Overview

```
PacketFence Webhook → Listener (8000) → PDP (8001) → Action API (8002) → PacketFence/Wazuh
```

## Workflow Steps

1. **Device discovered** - PacketFence sends webhook to Listener
2. **Poll for user login** - Listener polls until user logs in (category == "uncheck")
3. **Forward to PDP** - Listener sends {ip, mac, user_pid, user_category, request_id} to PDP
4. **Get SCA score** - PDP calls Action API to get SCA score
5. **Policy decision** - PDP evaluates: SCA >= 70 → user's role, SCA < 70 → keep "uncheck"
6. **Execute action** - PDP calls Action API to change role

---

## Testing

### Terminal 1: Start Action Service
```bash
cd /Users/user/python/project/nac/orchestrator/action_service
python action_api.py
```

### Terminal 2: Start PDP Service
```bash
cd /Users/user/python/project/nac/orchestrator/pdp_service
python pdp_api.py
```

### Terminal 3: Start Listener Service
```bash
cd /Users/user/python/project/nac/orchestrator/listener_service
python listener_api.py
```

### Terminal 4: Simulate PacketFence Webhook

**Test Case 1: Device with good SCA (>= 70)**
```bash
curl -X POST http://localhost:8000/webhook/device-discovered \
  -H "Content-Type: application/json" \
  -d '{
    "mac": "50:00:00:07:00:00",
    "ip": "10.0.20.10",
    "hostname": "U_WKS0701"
  }'
```

**Expected Flow:**
1. Listener receives webhook
2. Listener polls PacketFence for user login
3. When user logs in (category == "uncheck"), Listener gets user_pid
4. Listener forwards to PDP
5. PDP calls Action API get-sca
6. PDP evaluates policy (if SCA >= 70, assign user's role)
7. PDP calls Action API change-role
8. Device gets assigned to user's role

**Test Case 2: Device with low SCA (< 70)**
```bash
curl -X POST http://localhost:8000/webhook/device-discovered \
  -H "Content-Type: application/json" \
  -d '{
    "mac": "50:00:00:08:00:00",
    "ip": "10.0.20.11",
    "hostname": "U_WKS0702"
  }'
```

**Expected Flow:**
Same as above, but if SCA < 70, device stays in "uncheck" role

---

## Logs to Watch

### Listener Service Logs:
- `device_discovered` - Webhook received
- `polling_start` - Start polling for user
- `polling_attempt` - Each poll attempt
- `user_found` - User logged in
- `forwarding_to_pdp` - Sending to PDP

### PDP Service Logs:
- `pdp_evaluate_device_start` - Request received
- `calling_action_get_sca` - Calling Action API
- `sca_retrieved` - SCA score received
- `policy_decision` - Policy matched
- `calling_action_change_role` - Calling Action API
- `role_changed` - Role change completed

### Action Service Logs:
- `get_sca_start` - Get SCA request
- `wazuh_agent_found` - Agent found
- `sca_retrieved` - SCA data retrieved
- `change_role_start` - Change role request
- `role_changed_success` - Role changed

---

## Manual Test (Without Polling)

If you want to test PDP directly without waiting for polling:

```bash
curl -X POST http://localhost:8001/pdp/evaluate-device \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "10.0.20.10",
    "mac": "50:00:00:07:00:00",
    "user_pid": "testuser",
    "user_category": "uncheck",
    "request_id": "manual-test-123"
  }'
```

---

## Troubleshooting

### Issue: Listener times out waiting for user login
- Check PacketFence: User must authenticate (802.1X or captive portal)
- Check category: Must change to "uncheck" after login
- Increase max_retries or delay in listener_api.py

### Issue: PDP cannot reach Action API
- Verify Action API is running on port 8002
- Check ACTION_API_URL in pdp_api.py

### Issue: Action API cannot reach Wazuh/PacketFence
- Verify Wazuh is running on 192.168.29.103:55000
- Verify PacketFence is running on 192.168.29.91:9999
- Check credentials in client files
