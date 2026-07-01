# JIT Access Portal - Luồng Code Chi Tiết

## 1. Tổng quan Kiến trúc

```
User Browser (IP: 10.0.20.10)
    ↓
FastAPI Web Portal (Port 8003)
    ↓
ProfileManager (orchestrator/shared/profile_manager.py)
    ↓
Telegram Bot API (gửi OTP)
    ↓
VyOS Firewall (SSH - netmiko)
```

---

## 2. Cấu trúc File

```
jit_portal/
├── main.py                    # Entry point, khởi tạo FastAPI app
├── routers/
│   └── jit.py                # 3 API endpoints chính
├── services/
│   ├── telegram.py           # Gửi OTP qua Telegram Bot
│   └── vyos.py              # Thêm/xóa firewall rules
├── templates/
│   └── index.html           # Single Page Application (HTML/JS)
└── requirements.txt
```

---

## 3. Luồng Code Chi Tiết

### 3.1. Khởi động Application (main.py)

**File:** `main.py`

```python
app = FastAPI(...)
app.include_router(jit.router, prefix="/api/jit")
templates = Jinja2Templates(directory="templates")

@app.get("/")
async def root():
    return templates.TemplateResponse("index.html", {"request": {}})
```

**Luồng:**
1. Khởi tạo FastAPI app
2. Mount router `/api/jit` từ `routers/jit.py`
3. Serve file `index.html` tại route `/`
4. Chạy trên port 8003

---

### 3.2. User Truy Cập Web Portal

**File:** `templates/index.html`

**Luồng:**
1. User mở browser, truy cập `http://localhost:8003`
2. Browser load `index.html`
3. JavaScript tự động gọi `init()` function
4. `init()` gọi API: `GET /api/jit/resources`

**Code JavaScript:**
```javascript
async function init() {
    const response = await fetch('/api/jit/resources');
    // Nếu 403 → hiển thị lỗi "Access denied"
    // Nếu 200 → hiển thị dropdown resources
}
```

---

### 3.3. API 1: Lấy Danh Sách Resources

**File:** `routers/jit.py`

**Endpoint:** `GET /api/jit/resources`

**Luồng:**

#### Bước 1: Lấy Client IP
```python
client_ip = request.client.host  # Ví dụ: "10.0.20.10"
```

#### Bước 2: Tìm Profile theo IP
```python
def get_profile_by_ip(ip: str):
    for mac, profile in profile_manager.list_profiles().items():
        if profile.ip_address == ip:
            return {
                "ip": ip,
                "mac": mac,
                "username": profile.identity.get("username"),  # "LAB\\quochuy"
                "role": profile.identity.get("current_role"),  # "IT"
                "risk_score": profile.risk_score.get("total_score", 0),  # 10
                "telegram_chat_id": USER_TELEGRAM_MAPPING.get(username)  # "5372788511"
            }
    return None
```

**Giải thích:**
- Loop qua tất cả profiles trong ProfileManager
- So sánh `profile.ip_address` với `client_ip`
- Nếu match → trả về thông tin profile
- Lấy `telegram_chat_id` từ mapping `USER_TELEGRAM_MAPPING`

#### Bước 3: Validate Profile
```python
if not profile:
    raise HTTPException(403, "Device not found in system")

if profile["role"] not in ROLE_PERMISSIONS:
    raise HTTPException(403, "Your role does not have JIT access permissions")

if profile["risk_score"] > 30:
    raise HTTPException(403, "Device has high risk score")
```

**Điều kiện từ chối:**
- Profile không tồn tại
- Role không có trong `ROLE_PERMISSIONS` (chỉ có IT và accounting)
- Risk score > 30

#### Bước 4: Lọc Resources theo Role
```python
ROLE_PERMISSIONS = {
    "IT": ["linux_ssh", "linux_sql", "win_rdp", "pf_admin", "wazuh_admin"],
    "accounting": []
}

allowed_resources = ROLE_PERMISSIONS.get(profile["role"], [])

resources_list = [
    {"id": res_id, **RESOURCES[res_id]}
    for res_id in allowed_resources
    if res_id in RESOURCES
]
```

**Ví dụ Output (Role = IT):**
```json
{
  "username": "LAB\\quochuy",
  "role": "IT",
  "resources": [
    {"id": "linux_ssh", "name": "Linux Server (SSH)", "ip": "10.0.40.100", "port": 22},
    {"id": "linux_sql", "name": "Linux Server (SQL Database)", "ip": "10.0.40.100", "port": 3306},
    {"id": "win_rdp", "name": "Windows Server (Remote Desktop)", "ip": "192.168.29.17", "port": 3389},
    {"id": "pf_admin", "name": "PacketFence Web Admin", "ip": "192.168.29.91", "port": 1443},
    {"id": "wazuh_admin", "name": "Wazuh Security Dashboard", "ip": "192.168.29.103", "port": 443}
  ]
}
```

#### Bước 5: Frontend Hiển Thị
```javascript
// index.html
const data = await response.json();
document.getElementById('greeting').textContent = `Hello, ${data.username}`;

// Populate dropdown
resources.forEach(resource => {
    const option = document.createElement('option');
    option.value = resource.id;  // "linux_ssh"
    option.textContent = resource.name;  // "Linux Server (SSH)"
    select.appendChild(option);
});
```

---

### 3.4. API 2: Request OTP

**File:** `routers/jit.py`

**Endpoint:** `POST /api/jit/request-otp`

**Payload:**
```json
{
  "resource_id": "linux_ssh"
}
```

**Luồng:**

#### Bước 1: Validate IP và Profile
```python
client_ip = request.client.host
profile = get_profile_by_ip(client_ip)

if not profile:
    raise HTTPException(403, "Device not found")

if profile["risk_score"] > 30:
    raise HTTPException(403, "Risk score too high")
```

#### Bước 2: Kiểm tra Permission
```python
allowed_resources = ROLE_PERMISSIONS.get(profile["role"], [])

if payload.resource_id not in allowed_resources:
    raise HTTPException(403, "Access denied to this resource")
```

**Ví dụ:**
- User role = "IT" → allowed = ["linux_ssh", "linux_sql", ...]
- Request resource_id = "linux_ssh" → OK
- Request resource_id = "win_rdp" nhưng role = "accounting" → 403

#### Bước 3: Kiểm tra Telegram Chat ID
```python
if not profile["telegram_chat_id"]:
    raise HTTPException(400, "Telegram chat ID not configured for this user")
```

#### Bước 4: Sinh OTP 6 số
```python
otp_code = str(random.randint(100000, 999999))  # "482719"
```

#### Bước 5: Lưu OTP vào Cache
```python
otp_cache[client_ip] = {
    "otp": "482719",
    "resource_id": "linux_ssh",
    "expires_at": time.time() + 300,  # 5 phút
    "username": "LAB\\quochuy"
}
```

**Cấu trúc `otp_cache`:**
```python
{
  "10.0.20.10": {
    "otp": "482719",
    "resource_id": "linux_ssh",
    "expires_at": 1745068524.163,
    "username": "LAB\\quochuy"
  }
}
```

#### Bước 6: Gửi OTP qua Telegram
```python
await send_otp_telegram(
    chat_id="5372788511",
    username="LAB\\quochuy",
    resource_name="Linux Server (SSH)",
    otp_code="482719"
)
```

**File:** `services/telegram.py`

```python
async def send_otp_telegram(chat_id, username, resource_name, otp_code):
    message = f"""
🔐 **JIT Access Request**

User: {username}
Resource: {resource_name}
OTP Code: `{otp_code}`

⏱ Valid for 5 minutes
    """
    
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://api.telegram.org/bot12345:AAG9Bxasdjdfadf-o9NDK12kajdfaff/sendMessage",
            json={
                "chat_id": "5372788511",
                "text": message,
                "parse_mode": "Markdown"
            }
        )
```

**Kết quả:**
- User nhận tin nhắn Telegram với OTP code
- Frontend chuyển sang màn hình nhập OTP
- Countdown timer 5 phút bắt đầu

---

### 3.5. API 3: Grant Access (Verify OTP)

**File:** `routers/jit.py`

**Endpoint:** `POST /api/jit/grant-access`

**Payload:**
```json
{
  "resource_id": "linux_ssh",
  "otp_code": "482719",
  "duration_minutes": 30
}
```

**Luồng:**

#### Bước 1: Kiểm tra OTP Cache
```python
client_ip = request.client.host  # "10.0.20.10"

if client_ip not in otp_cache:
    raise HTTPException(400, "No OTP request found")

cached = otp_cache[client_ip]
```

#### Bước 2: Validate OTP
```python
# Kiểm tra hết hạn
if time.time() > cached["expires_at"]:
    del otp_cache[client_ip]
    raise HTTPException(400, "OTP expired")

# Kiểm tra mã OTP
if cached["otp"] != payload.otp_code:
    raise HTTPException(400, "Invalid OTP")

# Kiểm tra resource_id khớp
if cached["resource_id"] != payload.resource_id:
    raise HTTPException(400, "Resource mismatch")
```

#### Bước 3: Xóa OTP khỏi Cache
```python
del otp_cache[client_ip]
```

**Lý do:** OTP chỉ dùng 1 lần, sau khi verify thành công hoặc sai đều phải xóa

#### Bước 4: Validate lại Risk Score
```python
profile = get_profile_by_ip(client_ip)

if not profile or profile["risk_score"] > 30:
    raise HTTPException(403, "Risk score changed, access denied")
```

**Lý do:** Risk score có thể thay đổi trong 5 phút user nhập OTP (ví dụ: Wazuh phát hiện malware)

#### Bước 5: Lấy thông tin Resource
```python
resource = RESOURCES.get("linux_ssh")
# {
#   "name": "Linux Server (SSH)",
#   "ip": "10.0.40.100",
#   "port": 22
# }
```

#### Bước 6: Thêm Firewall Rule
```python
rule_id = await add_firewall_rule(
    source_ip="10.0.20.10",
    dest_ip="10.0.40.100",
    dest_port=22,
    username="LAB\\quochuy"
)
```

**File:** `services/vyos.py`

```python
async def add_firewall_rule(source_ip, dest_ip, dest_port, username):
    rule_id = str(uuid.uuid4())[:8]  # "a3f7c2d1"
    rule_number = 100 + hash(rule_id) % 900  # 100-999
    
    commands = [
        "configure",
        f"set firewall name JIT_ACCESS rule {rule_number} source address {source_ip}",
        f"set firewall name JIT_ACCESS rule {rule_number} destination address {dest_ip}",
        f"set firewall name JIT_ACCESS rule {rule_number} destination port {dest_port}",
        f"set firewall name JIT_ACCESS rule {rule_number} protocol tcp",
        f"set firewall name JIT_ACCESS rule {rule_number} action accept",
        f"set firewall name JIT_ACCESS rule {rule_number} description 'JIT-{username}-{rule_id}'",
        "commit",
        "save",
        "exit"
    ]
    
    if MOCK_MODE:
        print(f"\n[MOCK] Adding VyOS firewall rule {rule_id}:")
        for cmd in commands:
            print(f"  {cmd}")
        return rule_id
    
    # Production: Dùng netmiko SSH vào VyOS
    from netmiko import ConnectHandler
    connection = ConnectHandler(device_type="vyos", host="192.168.1.1", ...)
    for cmd in commands:
        connection.send_command(cmd)
    connection.disconnect()
    
    return rule_id
```

**Giải thích:**
- `rule_id`: UUID ngắn để tracking
- `rule_number`: 100-999, hash từ rule_id để tránh conflict
- VyOS commands: Tạo firewall rule cho phép traffic từ source_ip → dest_ip:dest_port
- `MOCK_MODE = True`: In ra console thay vì SSH thật (để debug)

#### Bước 7: Lưu Active Session
```python
session_id = "10.0.20.10_linux_ssh_1745068524"

active_sessions[session_id] = {
    "client_ip": "10.0.20.10",
    "resource_id": "linux_ssh",
    "rule_id": "a3f7c2d1",
    "granted_at": 1745068524.163,
    "expires_at": 1745070324.163  # +30 phút
}
```

#### Bước 8: Schedule Auto-Revoke
```python
async def revoke_access():
    await asyncio.sleep(30 * 60)  # Sleep 30 phút
    await remove_firewall_rule("a3f7c2d1")
    if session_id in active_sessions:
        del active_sessions[session_id]

threading.Thread(target=lambda: asyncio.run(revoke_access())).start()
```

**Giải thích:**
- Tạo background thread
- Sleep 30 phút
- Gọi `remove_firewall_rule()` để xóa rule khỏi VyOS
- Xóa session khỏi `active_sessions`

**File:** `services/vyos.py`

```python
async def remove_firewall_rule(rule_id):
    rule_number = 100 + hash(rule_id) % 900
    
    commands = [
        "configure",
        f"delete firewall name JIT_ACCESS rule {rule_number}",
        "commit",
        "save",
        "exit"
    ]
    
    if MOCK_MODE:
        print(f"\n[MOCK] Removing VyOS firewall rule {rule_id}:")
        for cmd in commands:
            print(f"  {cmd}")
        return
    
    # Production: SSH vào VyOS và xóa rule
```

#### Bước 9: Trả về Response
```python
return {
    "status": "success",
    "message": "Access granted for 30 minutes",
    "resource": "Linux Server (SSH)",
    "expires_in_minutes": 30
}
```

#### Bước 10: Frontend Hiển Thị
```javascript
// index.html
const data = await response.json();
showSuccess(`✅ ${data.message}`);
// "✅ Access granted for 30 minutes"
```

---

## 4. Data Structures

### 4.1. RESOURCES
```python
RESOURCES = {
    "linux_ssh": {
        "name": "Linux Server (SSH)",
        "ip": "10.0.40.100",
        "port": 22
    },
    "linux_sql": {
        "name": "Linux Server (SQL Database)",
        "ip": "10.0.40.100",
        "port": 3306
    },
    "win_rdp": {
        "name": "Windows Server (Remote Desktop)",
        "ip": "192.168.29.17",
        "port": 3389
    },
    "pf_admin": {
        "name": "PacketFence Web Admin",
        "ip": "192.168.29.91",
        "port": 1443
    },
    "wazuh_admin": {
        "name": "Wazuh Security Dashboard",
        "ip": "192.168.29.103",
        "port": 443
    }
}
```

### 4.2. ROLE_PERMISSIONS
```python
ROLE_PERMISSIONS = {
    "IT": ["linux_ssh", "linux_sql", "win_rdp", "pf_admin", "wazuh_admin"],
    "accounting": []  # Không có quyền JIT
}
```

### 4.3. USER_TELEGRAM_MAPPING
```python
USER_TELEGRAM_MAPPING = {
    "quochuy": "5372788511",
    "LAB\\quochuy": "5372788511"
}
```

### 4.4. otp_cache (In-memory)
```python
{
  "10.0.20.10": {
    "otp": "482719",
    "resource_id": "linux_ssh",
    "expires_at": 1745068524.163,
    "username": "LAB\\quochuy"
  }
}
```

### 4.5. active_sessions (In-memory)
```python
{
  "10.0.20.10_linux_ssh_1745068524": {
    "client_ip": "10.0.20.10",
    "resource_id": "linux_ssh",
    "rule_id": "a3f7c2d1",
    "granted_at": 1745068524.163,
    "expires_at": 1745070324.163
  }
}
```

---

## 5. Security Flow

### 5.1. Các Lớp Bảo Mật

#### Layer 1: IP-based Authentication
- Không có form login
- Nhận diện user qua `request.client.host`
- Tìm profile trong ProfileManager theo IP

#### Layer 2: Role-based Access Control (RBAC)
- Chỉ role "IT" có quyền truy cập JIT Portal
- Role "accounting" bị từ chối ngay từ API `/resources`

#### Layer 3: Risk Score Check
- Risk score > 30 → Từ chối
- Kiểm tra 2 lần: lúc request OTP và lúc grant access

#### Layer 4: OTP Verification
- OTP 6 số random
- Hết hạn sau 5 phút
- Chỉ dùng 1 lần (xóa sau khi verify)
- Gửi qua Telegram (out-of-band authentication)

#### Layer 5: Resource Permission Check
- Kiểm tra `resource_id` có trong `ROLE_PERMISSIONS[role]` không
- Ngăn chặn user request resource không được phép

#### Layer 6: Time-limited Access
- Firewall rule tự động xóa sau 30 phút
- Background task schedule revoke

---

## 6. Error Handling

### 6.1. Device Not Found (403)
```
Trigger: IP không có trong ProfileManager
Message: "Device not found in system"
```

### 6.2. Role Not Allowed (403)
```
Trigger: Role không phải "IT" hoặc không có trong ROLE_PERMISSIONS
Message: "Your role does not have JIT access permissions"
```

### 6.3. High Risk Score (403)
```
Trigger: risk_score > 30
Message: "Device has high risk score"
```

### 6.4. No Resources for Role (403)
```
Trigger: ROLE_PERMISSIONS[role] = []
Message: "Role 'accounting' has no JIT resources"
```

### 6.5. OTP Expired (400)
```
Trigger: time.time() > cached["expires_at"]
Message: "OTP expired"
```

### 6.6. Invalid OTP (400)
```
Trigger: cached["otp"] != payload.otp_code
Message: "Invalid OTP"
```

### 6.7. Telegram Not Configured (400)
```
Trigger: telegram_chat_id = None
Message: "Telegram chat ID not configured for this user"
```

---

## 7. Testing Scenarios

### 7.1. Happy Path (IT User)
1. User IP: 10.0.20.10, Role: IT, Risk Score: 10
2. Truy cập http://localhost:8003
3. Thấy 5 resources trong dropdown
4. Chọn "Linux Server (SSH)"
5. Click "Request Access"
6. Nhận OTP "482719" qua Telegram
7. Nhập OTP đúng
8. Firewall rule được tạo
9. Sau 30 phút rule tự động xóa

### 7.2. Accounting User (Denied)
1. User IP: 10.0.20.11, Role: accounting
2. Truy cập http://localhost:8003
3. Thấy lỗi: "Role 'accounting' has no JIT resources"

### 7.3. High Risk Score (Denied)
1. User IP: 10.0.20.10, Role: IT, Risk Score: 50
2. Truy cập http://localhost:8003
3. Thấy lỗi: "Device has high risk score"

### 7.4. OTP Expired
1. User request OTP
2. Đợi > 5 phút
3. Nhập OTP
4. Thấy lỗi: "OTP expired"

### 7.5. Wrong OTP
1. User request OTP "482719"
2. Nhập "123456"
3. Thấy lỗi: "Invalid OTP"

---

## 8. Integration Points

### 8.1. ProfileManager
```python
from shared.profile_manager import profile_manager

# Lấy tất cả profiles
profiles = profile_manager.list_profiles()

# Tìm profile theo IP
for mac, profile in profiles.items():
    if profile.ip_address == "10.0.20.10":
        username = profile.identity.get("username")
        role = profile.identity.get("current_role")
        risk_score = profile.risk_score.get("total_score")
```

### 8.2. Telegram Bot API
```python
POST https://api.telegram.org/bot<>/sendMessage
{
  "chat_id": "5372788511",
  "text": "OTP: 482719",
  "parse_mode": "Markdown"
}
```

### 8.3. VyOS Firewall (SSH)
```bash
# Add rule
configure
set firewall name JIT_ACCESS rule 234 source address 10.0.20.10
set firewall name JIT_ACCESS rule 234 destination address 10.0.40.100
set firewall name JIT_ACCESS rule 234 destination port 22
set firewall name JIT_ACCESS rule 234 protocol tcp
set firewall name JIT_ACCESS rule 234 action accept
set firewall name JIT_ACCESS rule 234 description 'JIT-quochuy-a3f7c2d1'
commit
save
exit

# Remove rule (sau 30 phút)
configure
delete firewall name JIT_ACCESS rule 234
commit
save
exit
```

---

## 9. Deployment

### 9.1. Cài đặt Dependencies
```bash
cd jit_portal
pip install -r requirements.txt
```

### 9.2. Cấu hình Environment
```bash
export TELEGRAM_BOT_TOKEN="token here"
```

### 9.3. Chạy Service
```bash
python main.py
# hoặc
uvicorn main:app --host 0.0.0.0 --port 8003 --reload
```

### 9.4. Truy cập
```
http://localhost:8003
```

---

## 10. Future Enhancements

### 10.1. Audit Log
- Ghi lại tất cả JIT access requests
- Lưu vào database: user, resource, timestamp, duration

### 10.2. Admin Dashboard
- Xem active sessions
- Revoke access thủ công
- Xem lịch sử access

### 10.3. Multi-factor Authentication
- Thêm TOTP (Google Authenticator)
- Biometric authentication

### 10.4. Dynamic Risk Score
- Tích hợp real-time với Wazuh
- Tự động revoke nếu risk score tăng đột ngột

### 10.5. Notification
- Gửi thông báo khi access được grant
- Gửi thông báo trước 5 phút khi access sắp hết hạn
