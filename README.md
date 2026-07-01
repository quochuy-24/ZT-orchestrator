# NAC System - Zero Trust Network Access Control

Hệ thống NAC (Network Access Control) với kiến trúc Zero Trust, tích hợp PacketFence, Wazuh, Active Directory và VyOS.

## Kiến trúc

```
┌─────────────────┐
│  PacketFence    │ ──► Device Discovery Webhook
│  (NAC)          │
└─────────────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ Listener Service│────►│  PDP Service    │────►│ Action Service  │
│   (Port 8000)   │     │   (Port 8001)   │     │   (Port 8002)   │
└─────────────────┘     └─────────────────┘     └─────────────────┘
         ▲                       │                       │
         │                       ▼                       ▼
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│     Wazuh       │     │  Profile Store  │     │  PacketFence    │
│  (SIEM/SCA)     │     │   (JSON File)   │     │      API        │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                          │
                                                          ▼
                                                  ┌─────────────────┐
                                                  │ Active Directory│
                                                  │   (LDAP/AD)     │
                                                  └─────────────────┘

┌─────────────────┐
│  JIT Portal     │ ──► Just-In-Time Access với OTP
│  (Port 8003)    │
└─────────────────┘
         │
         ▼
┌─────────────────┐
│  VyOS Firewall  │ ──► Dynamic ACL Rules
└─────────────────┘
```

## Các Service

### 1. Listener Service (Port 8000)
- Nhận webhook từ PacketFence (device discovered)
- Nhận webhook từ Wazuh (user logon/logoff, security alerts)
- Tạo device profile và forward đến PDP

**Endpoints:**
- `POST /webhook/device-discovered` - PacketFence device join
- `POST /webhook/wazuh-alert/` - Wazuh alerts (logon/logoff/malware)
- `GET /health` - Health check

### 2. PDP Service (Port 8001)
- Policy Decision Point - đánh giá compliance
- Tính risk score dựa trên SCA, user role, network behavior
- Quyết định role assignment hoặc isolation

**Endpoints:**
- `POST /pdp/evaluate-device` - Evaluate device compliance
- `POST /pdp/evaluate-alert` - Evaluate security alert
- `GET /health` - Health check

### 3. Action Service (Port 8002)
- Thực thi actions: isolate, change role, get SCA, get user role
- Tương tác với PacketFence API, Wazuh API, Active Directory

**Endpoints:**
- `POST /actions/isolate` - Isolate device
- `POST /actions/change-role` - Change device role
- `POST /actions/revert-to-uncheck` - Revert to uncheck (logoff)
- `POST /actions/get-sca` - Get Wazuh SCA score
- `POST /actions/get-user-role` - Get user role from AD
- `GET /health` - Health check

### 4. JIT Portal (Port 8003)
- Just-In-Time Access portal với OTP qua Telegram
- Dynamic firewall rules trên VyOS
- Role-based access control

**Endpoints:**
- `GET /api/jit/resources` - Get available resources
- `POST /api/jit/request-otp` - Request OTP
- `POST /api/jit/grant-access` - Grant access after OTP verify
- `GET /health` - Health check

## Workflow

### 1. Device Join & User Login
```
Device Join → PacketFence webhook → Listener creates profile (EVALUATING)
User Login → Wazuh rule 100001 → Listener updates username → Forward to PDP
PDP → Get SCA from Wazuh → Get user role from AD → Calculate risk score
PDP → Forward to Action → Change role in PacketFence
Profile updated: state=COMPLIANT/NON_COMPLIANT, role=IT/accounting/etc
```

### 2. User Logoff
```
User Logoff → Wazuh rule 60137 → Listener detects logoff
Listener → Action API revert-to-uncheck → PacketFence set category=125, bypass=0
Profile updated: state=LOGGED_OFF, role=uncheck
```

### 3. Security Alert (Malware)
```
Wazuh alert → Listener → Forward to PDP
PDP evaluates alert → Decision: isolate
PDP → Action API isolate → PacketFence apply security event
Profile updated: state=ISOLATED
```

### 4. JIT Access
```
User requests access → JIT Portal checks role & risk score
JIT sends OTP via Telegram → User enters OTP
JIT Portal → VyOS add firewall rule (source IP → dest IP:port)
Auto-revoke after N minutes → VyOS delete rule
```

## Cài đặt

### 1. Clone repository
```bash
cd /opt
git clone <repo-url> nac
cd nac
```

### 2. Tạo virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Cài đặt dependencies
```bash
pip install -r requirements.txt
```

### 4. Cấu hình

**PacketFence:**
- Cấu hình webhook device-discovered: `http://<listener-ip>:8000/webhook/device-discovered`

**Wazuh:**
- Cấu hình integration webhook: `http://<listener-ip>:8000/webhook/wazuh-alert/`
- Rule IDs: 100001 (logon), 60137 (logoff), hoặc tất cả alerts

**Active Directory:**
- Sửa `orchestrator/action_service/clients/ldap_client.py`:
  - LDAP server, base DN, bind credentials

**VyOS:**
- Sửa `jit_portal/services/vyos.py`:
  - VyOS IP, SSH credentials

**Telegram Bot:**
- Sửa `jit_portal/services/telegram.py`:
  - Bot token
- Sửa `jit_portal/routers/jit.py`:
  - User to chat_id mapping

### 5. Chạy tất cả services
```bash
python main.py
```

Hoặc chạy từng service riêng:
```bash
# Terminal 1 - Listener
cd orchestrator/listener_service
python listener_api.py

# Terminal 2 - PDP
cd orchestrator/pdp_service
python pdp_api.py

# Terminal 3 - Action
cd orchestrator/action_service
python action_api.py

# Terminal 4 - JIT Portal
cd jit_portal
python main.py
```

## Chạy như systemd service

### 1. Tạo service file
```bash
sudo nano /etc/systemd/system/nac.service
```

```ini
[Unit]
Description=NAC System - Zero Trust Network Access Control
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/nac
Environment="PATH=/opt/nac/venv/bin"
ExecStart=/opt/nac/venv/bin/python /opt/nac/main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 2. Enable và start service
```bash
sudo systemctl daemon-reload
sudo systemctl enable nac
sudo systemctl start nac
sudo systemctl status nac
```

### 3. Xem logs
```bash
sudo journalctl -u nac -f
```

## Testing

### Test device discovery
```bash
curl -X POST http://localhost:8000/webhook/device-discovered \
  -H "Content-Type: application/json" \
  -d '{
    "mac": "aa:bb:cc:dd:ee:ff",
    "ip": "10.0.20.100",
    "hostname": "test-device"
  }'
```

### Test Wazuh logon
```bash
curl -X POST http://localhost:8000/webhook/wazuh-alert/ \
  -H "Content-Type: application/json" \
  -d '{
    "rule": {"id": "100001", "description": "User logon"},
    "agent": {"ip": "10.0.20.100", "id": "001", "name": "TEST-PC"},
    "data": {
      "win": {
        "eventdata": {
          "targetUserName": "testuser",
          "targetDomainName": "LAB"
        }
      }
    }
  }'
```

### Test JIT access
```bash
# Get resources
curl http://localhost:8003/api/jit/resources

# Request OTP
curl -X POST http://localhost:8003/api/jit/request-otp \
  -H "Content-Type: application/json" \
  -d '{"resource_id": "linux_ssh"}'

# Grant access
curl -X POST http://localhost:8003/api/jit/grant-access \
  -H "Content-Type: application/json" \
  -d '{
    "resource_id": "linux_ssh",
    "otp_code": "123456",
    "duration_minutes": 30
  }'
```

## Troubleshooting

### Service không start
```bash
# Check logs
sudo journalctl -u nac -n 100

# Check port conflicts
sudo netstat -tulpn | grep -E "8000|8001|8002|8003"

# Test manually
cd /opt/nac
source venv/bin/activate
python main.py
```

### Profile không update
```bash
# Check profile file
cat /opt/nac/orchestrator/profiles.json

# Check permissions
ls -la /opt/nac/orchestrator/profiles.json
```

### PacketFence connection failed
```bash
# Test connectivity
curl -k https://192.168.29.91:9999/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"123"}'
```

### Wazuh connection failed
```bash
# Test connectivity
curl -k -u admin:SecretPassword https://192.168.29.103:55000/
```

## License

Internal use only
