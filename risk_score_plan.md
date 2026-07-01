# Plan: Implement Risk Score System with Alert-Based Penalty

## Context

Hệ thống NAC hiện tại có risk_score field nhưng chưa được sử dụng đầy đủ. Mục tiêu là tính điểm risk từ Wazuh alerts để tự động xử lý theo ngưỡng.

**Yêu cầu đã chốt:**
- Mỗi device bắt đầu với `total_score = 0`
- Cộng điểm theo level 7-12:
  - Level 7 → +15
  - Level 8 → +20
  - Level 9 → +25
  - Level 10 → +35
  - Level 11 → +50
  - Level 12 → +100
- Ngưỡng hành động:
  - `> 60`: đổi role sang `restricted` (ACL trong PacketFence chặn 10.0.40.100)
  - `> 80`: isolate device
- Malware level 12 không bypass nữa: vẫn cộng điểm (+100) rồi đi qua threshold logic

## Design

### 1) Risk scoring module
**New file:** `orchestrator/pdp_service/risk_scoring.py`

- `LEVEL_SCORE_MAP` cho level 7..12
- `RULE_SCORE_OVERRIDE` để override theo rule_id khi cần
- `calculate_risk_penalty(rule_level, rule_id)`
- `calculate_risk_level(total_score)` trả về `UNKNOWN/LOW/MEDIUM/HIGH/CRITICAL`

### 2) PDP alert policy integration
**Modify:** `orchestrator/pdp_service/pdp_api.py` (`evaluate_alert`)

Flow mới:
1. Nếu level trong 7..12:
   - resolve profile theo `agent_ip`
   - tính `penalty`
   - `new_total = old_total + penalty`
   - update DB qua `profile_manager.update_risk_score(...)`
   - ghi audit qua `profile_manager.add_wazuh_alert(...)`
2. Đánh giá ngưỡng:
   - `new_total > 80` → `decision = isolate`
   - `new_total > 60` → `decision = change_role`, `target_role = restricted`
   - còn lại → `decision = none`
3. Nếu level < 7 → log-only, không cộng điểm

### 3) Listener forwarding update
**Modify:** `orchestrator/listener_service/listener_api.py`

- Bổ sung `rule_id` vào payload gửi `PDP_ALERT_URL`
- Với response PDP:
  - `isolate` → giữ luồng isolate hiện tại
  - `change_role` → gọi action service endpoint đổi role hiện có (`/actions/change-role`) với `target_role=restricted`

### 4) PacketFence setup (manual)
- Tạo role `restricted`
- Gán ACL chặn đích `10.0.40.100`
- Verify khi device vào `restricted` thì bị chặn; khi về role IT thì ACL tự được thay

## Files to Modify

### New
- `orchestrator/pdp_service/risk_scoring.py`

### Update
- `orchestrator/pdp_service/pdp_api.py`
- `orchestrator/listener_service/listener_api.py`

### External config (manual)
- PacketFence role/ACL: `restricted` block `10.0.40.100`

## Test Plan

1. **Brute force level 10 (rule 100051)**
   - Expected: `+35` điểm, ghi audit `event_id=100051`
2. **Threshold > 60**
   - Set score 55, bắn level 10 (`+35`) ⇒ 90
   - Expected: trigger isolate (vì >80)
3. **Threshold band 61..80**
   - Set score 40, bắn level 9 (`+25`) ⇒ 65
   - Expected: `change_role -> restricted`
4. **Malware level 12**
   - Expected: `+100` và isolate
5. **Low-level alert (<7)**
   - Expected: không đổi risk score
6. **PacketFence ACL behavior**
   - Device ở role `restricted` không truy cập được `10.0.40.100`
   - Promote lại role IT thì truy cập lại được

## Success Criteria

- Risk score tăng đúng theo bảng level
- Audit logs có `event_id`, `level`, và action risk penalty
- `>60` chuyển `restricted`, `>80` isolate
- Không làm hỏng flow logon/health/defender hiện tại
- ACL chặn Linux server được áp qua PacketFence role `restricted`

---
| testcase                       | tactic                | technique                                                                                 | rule id | level | action                                                                                                              | score | đối tượng action |
| ------------------------------ | --------------------- | ----------------------------------------------------------------------------------------- | ------- | ----- | ------------------------------------------------------------------------------------------------------------------- | ----- | ---------------- |
| tạo tài khoản Admin            | Persistence           | Create Account: Local Account (T1136.001)                                                 |         |       | net user hacker_acc 123456 /add<br>net localgroup administrators hacker_acc /add<br><br>net user hacker_acc /delete |       |                  |
| traffic tăng vượt mức quy định |                       |                                                                                           |         |       |                                                                                                                     |       |                  |
| truy cập vùng quản trị         |                       |                                                                                           |         |       |                                                                                                                     |       |                  |
| bruteforce web                 | Credential Access     | Bruteforce                                                                                | 100051  | 9     | truy cập vào trang brute force của dvwa đăng nhập sai 6 lần                                                         |       | data.srcip       |
| brutefore ssh                  | Credential Access     | Bruteforce                                                                                | 2502    | 10    | ssh vào linux server bị sai nhiều lần                                                                               |       | data.srcip               |
| scan port                      | Discovery             | Network Service Discovery (T1046)                                                         | 100081  | 9     | sử dụng nmap để quét linux server<br>nma -A -Pn 10.0.40.100                                                         |       | data.srcip       |
| UAC leo quyền admin            | Privileges Escalation | Valid Accounts: Local Accounts (T1078.003) hoặc Abuse Elevation Control Mechanism (T1548) | 100003  | 10    | mở cmd bằng quyền administrator và đănh nhập bằng tài khoản user                                                    |       | agent.ip         |
| sql injection                  | Initial Access        | Exploit Public-Facing Application (T1190)                                                 | 100091   | 12    | truy cập vào trang sql injection của dvwa nhập chuỗi<br>’ OR 1=1 #                                                  |       | data.srcip       |
| tắt fw/av                      | Defense Evasion       | Impair Defenses: Disable or Modify Tools (T1562.001)                                      | 100020  | 12    | tắt firewall và window security                                                                                     |       | agent.ip         |
| malware                        | Execution             | User execution                                                                            | 110094  | 12    | X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*                                                |       | agent.ip         |
| C2 connection                  |                       |                                                                                           |         |       |                                                                                                                     |       |                  |
| clear event log                | Defense Evasion       | Indicator Removal (T1070)                                                                 | 63104   | 9     | CMD: `wevtutil cl System` hoặc `cl Security`.                                                                       |       | agent.ip         |
