# Device Management UI Plan

## Context
Mục tiêu tiếp theo: xây dựng giao diện xem và quản lý thiết bị dựa trên dữ liệu hiện có trong hệ thống NAC.
Triển khai theo từng bước nhỏ để dễ test và rollback.

## Scope chính

### 0) Topology data foundation (backend trước UI)
- Mở rộng dữ liệu thiết bị để phục vụ sơ đồ mạng:
  - `operating_system`
  - `switch_ip` (từ PacketFence `last_switch`)
  - `switch_port` (từ PacketFence `last_ifDesc`)
  - `topology_last_seen_at`
  - `topology_source` (`packetfence` | `snmp`)
- Luồng enrich khi `device_discovered`:
  1. Nhận webhook phát hiện thiết bị mới.
  2. Query PacketFence `GET /api/v1/node/<mac>` một lần.
  3. Lấy `device_type` / fallback `dhcp_vendor` (`MSFT` -> `Windows`) cho OS.
  4. Lấy `last_switch`, `last_ifDesc` cho link-layer logic.
  5. Ghi vào profile/db theo kiểu best-effort (lỗi enrich không fail webhook).
- Giai đoạn sau thêm SNMP script làm fallback/verify khi PacketFence thiếu hoặc stale.

### 1) Device list UI (đọc từ DB `devices`)
- Hiển thị danh sách thiết bị từ bảng `devices`.
- Trường cơ bản:
  - `device_id` (MAC)
  - `ip_address`
  - `hostname`
  - `operating_system`
  - `switch_ip`, `switch_port`
  - `state`
  - `current_role`
  - `total_score`, `risk_level`
  - `profile_created_at`, `last_assessed_at`
- Filter/search cơ bản theo MAC, IP, username, state.
- Filter thêm theo switch/port để điều tra nhanh.

### 1.1) Network topology UI (new)
- Static nodes: Firewall, Switch, PacketFence, AD/Windows Server, Wazuh.
- Dynamic nodes: client devices từ `devices` table.
- Mapping node động vào switch theo `switch_ip` + `switch_port` (logical placement).
- Màu trạng thái theo `state`:
  - `COMPLIANT`: xanh
  - `NON_COMPLIANT`: vàng/cam
  - `ISOLATED`: đỏ
- Click device node mở detail drawer + action buttons.
- Nếu thiếu link-layer data: hiển thị ở vùng “Unknown segment”.

### 1.2) SNMP enhancement (defer)
- Script/worker query SNMP MAC table để xác thực port/switch.
- Chạy theo trigger:
  - thiếu `switch_port`
  - hoặc dữ liệu cũ quá TTL
- Cập nhật lại `switch_ip`, `switch_port`, `topology_last_seen_at`, `topology_source=snmp`.
- Ghi audit event `topology_updated` để trace thay đổi.

### 1.3) DB persistence note
- Block/unblock trạng thái cần persistence riêng (không chỉ bắn lệnh VyOS).
- Đề xuất bảng/field lưu trạng thái block theo device/IP để restart orchestrator vẫn biết trạng thái thực tế.
- UI đọc state này để hiển thị đúng nút `Block/Unblock`.

### 1.4) Restart safety
- Nếu orchestrator restart, UI vẫn đọc được state từ DB + external systems.
- Ưu tiên workflow action:
  1. Gọi external thành công.
  2. Persist state + audit vào DB.
  3. Trả success cho UI.
- Tránh lệch state khi tắt ngang.

### 1.5) Rollout strategy
- Làm topology read-only trước.
- Sau khi ổn định mới gắn actions trên topology nodes.
- Netflow overlay là phase sau.

### 1.6) API backend for topology
- `GET /devices` trả thêm `operating_system`, `switch_ip`, `switch_port`, `state`, `risk`.
- `GET /devices/{mac}/audit-logs`.
- `GET /topology` trả static nodes + edges + dynamic mapping (optional phase).
- `POST /devices/{mac}/refresh-topology` (optional manual refresh).

### 1.7) Acceptance criteria for topology MVP
- Device mới discovered hiển thị trên sơ đồ trong <= 5s.
- Nếu có `last_switch/last_ifDesc` thì node nằm đúng switch bucket.
- Nếu thiếu dữ liệu thì node vào “Unknown segment”, không fail render.
- Click node mở chi tiết + audit logs thành công.
- Không ảnh hưởng flow NAC hiện tại (logon/health/risk/action).

### 1.8) Risks & mitigations
- Risk: PacketFence không luôn có `last_ifDesc` ngay thời điểm discovered.
  - Mitigation: cho phép unknown placement + background refresh.
- Risk: Dữ liệu topology stale.
  - Mitigation: thêm `topology_last_seen_at` + TTL + SNMP fallback.
- Risk: UI quá tải khi nhiều node.
  - Mitigation: group theo switch, pagination/filter, lazy render.

### 1.9) Future extension map
- Netflow overlay theo 5 phút gần nhất trên mỗi node.
- Attack path highlight từ Wazuh alerts.
- Time slider replay trạng thái mạng.
- Multi-site topology view.

### 1.10) Data contract draft
- `operating_system`: string | null
- `switch_ip`: string | null
- `switch_port`: string | null
- `topology_source`: enum(`packetfence`,`snmp`) | null
- `topology_last_seen_at`: ISO-8601 string | null

### 1.11) Quick implementation checklist
- [ ] Add DB fields for topology.
- [ ] Extend profile mapping/update methods.
- [ ] Enrich `device_discovered` with OS + switch/port.
- [ ] Expose read APIs for devices/topology.
- [ ] Build topology read-only UI.
- [ ] Integrate actions (isolate/release/block/unblock).
- [ ] Add SNMP fallback worker.

### 1.12) Operational notes
- Luôn log `request_id` xuyên listener -> pdp -> action cho mọi topology refresh/action.
- Với action từ UI, thêm `initiated_by` (future) để audit người thao tác.
- Không expose credentials/infra endpoints ra frontend.

### 1.13) UI behavior details
- Device card hiển thị: MAC, IP, OS, role, risk, switch/port.
- Tooltip cho state transitions từ audit logs gần nhất.
- Batch filter: theo state + OS + switch + risk level.

### 1.14) Topology node actions matrix
- `COMPLIANT`: allow isolate, block
- `NON_COMPLIANT`: allow isolate, release, block/unblock
- `ISOLATED`: allow release
- Disabled buttons theo state để tránh thao tác sai

### 1.15) Observability for topology pipeline
- Metrics gợi ý:
  - `topology_enrich_success_total`
  - `topology_enrich_failed_total`
  - `topology_unknown_placement_total`
  - `topology_refresh_latency_ms`
- Log event chuẩn:
  - `topology_enrich_start`
  - `topology_enrich_updated`
  - `topology_enrich_failed`

### 1.16) Security & authorization (future)
- Action API từ UI cần authN/authZ theo role admin/operator/viewer.
- Read-only user không thấy nút action destructive.
- Log đầy đủ actor + action + target + result.

### 1.17) Backward compatibility
- Nếu DB cũ chưa có topology fields, cần migration hoặc recreate DB.
- UI phải handle null fields gracefully.

### 1.18) Testing outline for topology phase
- Unit test hàm map OS (`device_type` + `dhcp_vendor`).
- Integration test discovered -> enrich -> DB persisted.
- UI test render unknown/known placement.
- End-to-end test click node -> open detail -> run action.

### 1.19) Demo scenario (ngày mai)
1. Device join -> xuất hiện list + topology.
2. Logon -> state/risk update.
3. Health ON/ON -> recover role.
4. Click isolate/release -> thấy state đổi realtime.
5. Open audit panel -> đầy đủ lịch sử.

### 1.20) Definition of done
- Topology read-only + device actions hoạt động ổn định trên 2-3 máy test.
- Restart orchestrator không mất trạng thái quản trị quan trọng.
- Logs rõ ràng để trace toàn luồng.

### 2) Audit log UI
- Hiển thị lịch sử từ bảng `audit_logs` theo từng thiết bị.
- Trường hiển thị:
  - `changed_at`
  - `event_source`
  - `event_id`
  - `level`
  - `action`
  - `reason`
  - `role`
- Hỗ trợ filter theo thời gian và event source.

### 3) Action controls trên từng device
- **Isolate thiết bị**
  - Gọi API isolate hiện có.
- **Release (khôi phục actual role + reset risk + COMPLIANT)**
  - Nhúng API mới: `POST /actions/restore-actual-role`.
- **Block/Unblock IP trên VyOS**
  - Cần endpoint backend trung gian gọi VyOS service hiện có.
  - UI gồm 2 nút: block, unblock theo IP device.

### 4) Netflow button (để sau)
- Mỗi device có nút **Netflow**.
- Khi bấm: query Elasticsearch trên Wazuh lấy netflow 5 phút gần nhất.
- Feature này defer, triển khai ở phase sau khi core UI ổn định.

### 2) Audit log UI
- Hiển thị lịch sử từ bảng `audit_logs` theo từng thiết bị.
- Trường hiển thị:
  - `changed_at`
  - `event_source`
  - `event_id`
  - `level`
  - `action`
  - `reason`
  - `role`
- Hỗ trợ filter theo thời gian và event source.

### 3) Action controls trên từng device
- **Isolate thiết bị**
  - Gọi API isolate hiện có.
- **Release (khôi phục actual role + reset risk + COMPLIANT)**
  - Nhúng API mới: `POST /actions/restore-actual-role`.
- **Block/Unblock IP trên VyOS**
  - Cần endpoint backend trung gian gọi VyOS service hiện có.
  - UI gồm 2 nút: block, unblock theo IP device.

### 4) Netflow button (để sau)
- Mỗi device có nút **Netflow**.
- Khi bấm: query Elasticsearch trên Wazuh lấy netflow 5 phút gần nhất.
- Feature này defer, triển khai ở phase sau khi core UI ổn định.

## Đề xuất chia phase triển khai

### Phase 1 - Read-only UI
- Device list page.
- Device detail panel.
- Audit logs view.
- Không có action destructive ở phase này.

### Phase 2 - Device actions
- Isolate action.
- Release action (`restore-actual-role`).
- Block/Unblock VyOS.
- Thêm confirm modal + trạng thái loading/success/error.

### Phase 3 - Netflow
- Nút Netflow per-device.
- API backend query Wazuh/Elasticsearch last 5 minutes.
- UI bảng lưu lượng + summary nhanh.

## API mapping dự kiến

### Có sẵn
- `POST /actions/isolate`
- `POST /actions/restore-actual-role`

### Cần bổ sung
- Endpoint lấy danh sách devices từ DB.
- Endpoint lấy audit logs theo MAC.
- Endpoint block/unblock IP trên VyOS.
- (Phase 3) Endpoint query netflow 5p từ Wazuh Elasticsearch.

## Lưu ý triển khai
- Mọi action cần `request_id` để trace log.
- Action nút cần confirm trước khi gọi API (isolate/block).
- Không để UI gọi trực tiếp external systems; luôn đi qua backend service.
- Ưu tiên làm xong flow end-to-end nhỏ trước, rồi mở rộng.

## Ngày mai bắt đầu từ đâu
1. Chốt stack UI (web framework hiện dùng).
2. Làm API read-only: list devices + device audit logs.
3. Dựng UI danh sách + panel log trước.
4. Sau đó mới gắn action buttons.
