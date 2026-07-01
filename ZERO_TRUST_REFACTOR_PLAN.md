# Zero Trust Architecture Refactor Plan

## Mục tiêu

Cải tạo code hiện tại để thể hiện rõ kiến trúc Zero Trust Architecture (ZTA), đặc biệt tách rõ các thành phần:

| Thành phần ZTA | Vai trò | Mapping trong hệ thống |
|---|---|---|
| PIP | Nguồn thông tin ngữ cảnh | Wazuh, LDAP/AD, PacketFence, ProfileManager |
| PDP | Nơi ra quyết định | PDP Service |
| PE | Policy Engine, đánh giá policy | `policy_engine.py` |
| PA | Policy Administrator, tạo/chuyển action instruction | PDP dispatcher / `policy_admin.py` |
| PEP | Nơi thực thi thật | PacketFence, VyOS |
| PAP | Nơi định nghĩa policy | `policy_config.py` |
| Audit | Theo dõi quyết định và hành động | SQLite `audit_logs` + UI |

Hiện tại hệ thống đã chạy đúng hướng Zero Trust, nhưng policy còn rải ở nhiều nơi:

- PDP có risk/posture logic.
- JIT có role permission, resource, risk threshold.
- Action Service có LDAP group mapping và role/category mapping.
- PacketFence client có category mapping.
- VyOS ACL logic nằm riêng trong JIT.

Mục tiêu refactor là giữ nguyên behavior đang chạy, nhưng tổ chức lại code để dễ giải thích, dễ test, dễ demo khóa luận.

---

## Kiến trúc mục tiêu

```text
PacketFence / Wazuh / Proxy / UI
            |
            v
        Listener Service
            |
            v
+------------------------------+
|            PDP               |
|  +------------------------+  |
|  | PE - Policy Engine     |  |
|  +-----------+------------+  |
|              |               |
|  +-----------v------------+  |
|  | PA - Policy Admin      |  |
|  +-----------+------------+  |
+--------------|---------------+
               v
        Action Service / JIT
               |
               v
        PacketFence / VyOS
              PEP
```

PIP sources:

```text
Wazuh SCA / alerts / health status
LDAP / AD groups
PacketFence node/IP/MAC/session
ProfileManager device state
Netflow data
```

---

## Phase 1 — Gom policy config về một nơi

### Mục tiêu

Tạo PAP tĩnh cho PoC:

```text
orchestrator/shared/policy_config.py
```

### Nội dung cần gom

```python
GROUP_TO_ROLE = {
    "Accounting": "accounting",
    "IT": "IT",
}

ROLE_TO_CATEGORY_ID = {
    "default": 1,
    "guest": 2,
    "Machine": 6,
    "accounting": 9,
    "User": 13,
    "IT": 242,
    "restricted": 246,
}

RISK_LEVEL_SCORE_MAP = {
    7: 15,
    8: 20,
    9: 25,
    10: 35,
    11: 50,
    12: 100,
}

RISK_THRESHOLDS = {
    "jit_max": 30,
    "restrict": 60,
    "isolate": 80,
}

POSTURE_POLICY = {
    "sca_min_score": 70,
    "firewall_required": True,
    "antivirus_required": True,
}

JIT_ACCESS_DURATION_MINUTES = 5
JIT_OTP_TTL_SECONDS = 300
```

JIT resource policy:

```python
JIT_RESOURCES = {
    "linux_ssh": {"name": "Linux Server (SSH)", "ip": "10.0.40.100", "port": 22},
    "linux_sql": {"name": "Linux Server (SQL Database)", "ip": "10.0.40.100", "port": 3306},
    "win_rdp": {"name": "Windows Server (Remote Desktop)", "ip": "192.168.29.17", "port": 3389},
    "pf_admin": {"name": "PacketFence Web Admin", "ip": "192.168.29.91", "port": 1443},
    "wazuh_admin": {"name": "Wazuh Security Dashboard", "ip": "192.168.29.103", "port": 443},
}

JIT_ROLE_PERMISSIONS = {
    "IT": ["linux_ssh", "linux_sql", "win_rdp", "pf_admin", "wazuh_admin"],
    "accounting": [],
}
```

Lưu ý:

- Không đưa `vyos_ssh` vào resource được request.
- VyOS chỉ là PEP backend, không phải resource user xin quyền.

### Files tác động

- `orchestrator/shared/policy_config.py` tạo mới
- `orchestrator/pdp_service/risk_scoring.py`
- `orchestrator/action_service/services/action_service.py`
- `orchestrator/action_service/clients/packetfence_client.py`
- `jit_portal/routers/jit.py`

### Kết quả

- Policy không còn hardcode rải rác.
- PAP được thể hiện rõ trong code.

---

## Phase 2 — Tạo policy models

### Mục tiêu

Tạo model quyết định policy dùng chung:

```text
orchestrator/shared/policy_models.py
```

### Model đề xuất

```python
from dataclasses import dataclass
from typing import Optional, Dict, Any

@dataclass
class PolicyDecision:
    allowed: bool
    action: str
    reason: str
    target_role: Optional[str] = None
    risk_delta: int = 0
    risk_level: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
```

Action có thể là:

```text
allow_role
keep_uncheck
restrict
isolate
allow_jit
deny_jit
no_action
```

### Kết quả

- PE trả decision chuẩn.
- PA chỉ đọc decision để dispatch action.
- Audit dễ ghi thống nhất.

---

## Phase 3 — Tách Policy Engine (PE)

### Mục tiêu

Tạo:

```text
orchestrator/shared/policy_engine.py
```

PE chỉ evaluate, không gọi PacketFence, VyOS, LDAP API.

### Functions đề xuất

```python
def calculate_risk_penalty(rule_level: int, rule_id: str) -> int:
    ...

def calculate_risk_level(total_score: int) -> str:
    ...

def evaluate_posture_access(sca_score, firewall_enabled, antivirus_enabled, user_role):
    ...

def evaluate_alert_risk(current_score, rule_id, rule_level, rule_groups):
    ...

def evaluate_jit_access(profile, resource_id):
    ...

def resolve_role_from_groups(groups):
    ...

def resolve_category_id(role):
    ...
```

### Quy tắc

PE không được:

- gọi PacketFence
- gọi VyOS
- gọi HTTP API
- ghi DB
- mutate profile

PE chỉ nhận input và trả `PolicyDecision`.

### Kết quả

- PE thể hiện rõ trong ZTA.
- Có thể unit test dễ.

---

## Phase 4 — Tách Policy Administrator (PA)

### Mục tiêu

Tạo:

```text
orchestrator/pdp_service/policy_admin.py
```

PA nhận `PolicyDecision`, rồi dispatch action:

```python
async def dispatch_device_decision(decision, context):
    ...

async def dispatch_alert_decision(decision, context):
    ...
```

### Vai trò PA

- Nếu decision `allow_role`:
  - gọi Action Service change role.
- Nếu decision `restrict`:
  - gọi Action Service change role `restricted`.
- Nếu decision `isolate`:
  - gọi Action Service isolate.
- Nếu decision `no_action`:
  - chỉ log/audit.

### Kết quả

PDP service rõ cấu trúc:

```text
API route
-> collect context from PIP
-> PE evaluate
-> PA dispatch
-> audit decision
```

---

## Phase 5 — Làm Action Service thành PEP adapter rõ hơn

### Vấn đề hiện tại

Action Service đang làm hơi nhiều:

- query LDAP group
- map group sang role
- map role sang category ID
- call PacketFence

Theo ZTA sạch hơn:

- LDAP query = PIP adapter
- group -> role = PE/PAP policy
- role/category mapping = PEP adapter config
- PacketFence call = PEP adapter action

### Cải tạo từng bước

#### Step 5.1 — Chuyển mapping ra `policy_config.py`

- `GROUP_TO_ROLE`
- `ROLE_TO_CATEGORY_ID`

#### Step 5.2 — PDP quyết định target_role rõ ràng

Pre-connect flow sau refactor:

```text
Listener receives logon
-> PDP gets SCA/posture
-> PDP asks LDAP/PIP for groups or role
-> PE decides target_role
-> PA calls Action Service /change-role target_role
-> Action Service only calls PacketFence
```

#### Step 5.3 — Giữ LDAP ở Action tạm thời nếu cần

PoC có thể giữ endpoint:

```text
/actions/get-user-role
```

Nhưng PDP mới là nơi quyết định có dùng role đó hay không.

### Kết quả

Action Service trở thành:

```text
enforcement adapter / PEP adapter
```

Không còn tự ý quyết policy.

---

## Phase 6 — Refactor JIT theo policy engine

### Mục tiêu

JIT không hardcode policy nữa.

Trong `jit_portal/routers/jit.py`, thay:

```python
ROLE_PERMISSIONS
RESOURCES
risk_score > 30
duration_minutes hardcode
```

bằng import từ:

```python
from shared.policy_config import JIT_RESOURCES, JIT_ROLE_PERMISSIONS, JIT_ACCESS_DURATION_MINUTES
from shared.policy_engine import evaluate_jit_access
```

### Luồng mới

```text
GET /api/jit/resources
-> get profile by X-Forwarded-For
-> PE evaluate role/risk/resource visibility
-> return allowed resources
-> audit
```

```text
POST /api/jit/request-otp
-> PE evaluate_jit_access
-> if allow, send OTP
-> audit OTP requested/denied
```

```text
POST /api/jit/grant-access
-> validate OTP
-> PE re-check risk/resource
-> PA/JIT calls VyOS adapter
-> audit granted/revoked
```

### Kết quả

JIT cũng theo ZTA:

```text
PIP: ProfileManager
PE: evaluate_jit_access
PA: JIT router dispatch
PEP: VyOS
Audit: audit_logs
```

---

## Phase 7 — Safe VyOS ACL allocator

### Mục tiêu

JIT chỉ tạo forward rule tạm, không trùng static ACL.

### Rule policy

- Không cho request VyOS SSH.
- Không tạo `input` chain rule.
- Chỉ tạo `forward` chain rule.
- Rule number dùng `20-49`.
- Không dùng `50`, vì `acl_command.md` dùng rule 50 cho ICMP.
- Không đụng `100+`, vì static infrastructure rules nằm ở đó.

### Logic đề xuất

Trong `jit_portal/services/vyos.py`:

```python
JIT_RULE_START = 20
JIT_RULE_END = 49
RESERVED_FORWARD_RULES = {1, 2, 50}
```

Trước khi cấp rule:

```text
show configuration commands | match "firewall ipv4 forward filter rule"
```

Parse rule đang tồn tại, chọn rule đầu tiên trong `20-49` chưa được dùng.

### Temporary allow rule

Rule phải hẹp:

```text
source address = endpoint IP
destination address = resource IP
destination port = resource port
protocol = tcp
action = accept
```

### Kết quả

- Không overwrite static ACL.
- Không mở rộng quyền quá mức.
- User request resource vẫn hoạt động bình thường.

---

## Phase 8 — Pre-login SCA enrichment

### Vấn đề hiện tại

SCA thường được gọi khi user logon:

```text
Wazuh logon
-> Listener
-> PDP
-> Action get SCA
```

Nếu thiết bị mới phát hiện nhưng user chưa login, profile chưa có SCA.

### Cải tạo

Khi PacketFence `device-discovered`:

```text
Listener create profile
-> enrich PacketFence metadata
-> background call Action Service /actions/get-sca by IP
-> update profile posture_security.sca_score
-> add audit Pre-login SCA updated
```

### Nguyên tắc

- Không đổi role khi chưa có user.
- Không gọi change-role.
- Không promote device.
- Chỉ update posture context.
- Nếu Wazuh chưa có agent, retry nhẹ 3-6 lần.

### Kết quả

Profile có posture sớm hơn.
Pre-connect decision sau login nhanh và đầy đủ hơn.

---

## Phase 9 — Audit chuẩn hóa decision

### Mục tiêu

Mọi decision/action quan trọng đều có audit.

Audit sources:

```text
PDP
ACTION_SERVICE
JIT_PORTAL
WAZUH_ALERT
PACKETFENCE
SYSTEM
```

Audit events nên có:

```text
policy_name
decision
reason
target_role
risk_delta
resource
rule_id
```

Có thể giữ trong `reason` ở phase đầu, chưa cần schema mới.

### Events quan trọng

- `Policy evaluated`
- `Role change`
- `Manual isolate`
- `Manual release`
- `Risk score updated`
- `Pre-login SCA updated`
- `JIT OTP requested`
- `JIT access granted`
- `JIT access revoked`
- `JIT revoke failed`

### Kết quả

UI audit log thể hiện rõ workflow ZTA.
Demo dễ giải thích.

---

## Phase 10 — Unit tests cho PE

### Mục tiêu

Test decision logic không cần chạy external services.

Tạo:

```text
tests/test_policy_engine.py
```

### Test cases

Posture:

- SCA pass + firewall ON + antivirus ON -> allow role
- firewall OFF -> deny/restrict
- antivirus OFF -> deny/restrict
- SCA fail -> deny/restrict

Risk:

- rule level 7 -> risk delta 15
- rule `200110` target đúng endpoint source IP
- risk vượt restrict threshold -> restrict
- critical risk -> isolate

JIT:

- role IT + risk <= 30 + resource allowed -> allow
- role not allowed -> deny
- risk > 30 -> deny
- unknown resource -> deny

### Kết quả

Có bằng chứng khoa học cho khóa luận.
Refactor ít rủi ro hơn.

---

## Thứ tự triển khai khuyến nghị

Không làm một lần hết. Làm từng phase nhỏ:

1. `policy_config.py`
2. JIT dùng `policy_config.py`
3. Risk scoring dùng `policy_config.py`
4. `policy_models.py`
5. `policy_engine.py` cho JIT + risk trước
6. Refactor PDP alert risk dùng PE
7. Refactor pre-connect posture dùng PE
8. Tạo `policy_admin.py`
9. Làm Action Service thành adapter rõ hơn
10. Pre-login SCA enrichment
11. Tests cho PE

---

## Demo narrative sau refactor

```text
1. Endpoint được phát hiện bởi PacketFence.
2. Listener tạo profile và enrich posture từ Wazuh SCA.
3. Wazuh logon gửi user identity.
4. PDP nhận context từ PIP: profile, SCA, health, LDAP role, risk.
5. PE evaluate policy.
6. PA dispatch action instruction.
7. PacketFence/VyOS PEP enforce.
8. Audit log ghi lại toàn bộ decision và action.
9. JIT access dùng PE để kiểm tra role/risk/resource, rồi VyOS mở rule tạm thời.
10. Hết hạn, JIT revoke rule và audit.
```

---

## Kết luận

Hướng refactor này không phá kiến trúc hiện tại. Nó chỉ làm rõ ràng hơn:

```text
PDP = PE + PA
PEP = PacketFence + VyOS
PIP = Wazuh + LDAP + ProfileManager + PacketFence
PAP = policy_config.py
```

Phù hợp để triển khai từ từ và trình bày khoa học trong khóa luận tốt nghiệp.
