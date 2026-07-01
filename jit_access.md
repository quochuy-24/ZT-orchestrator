# Tài liệu Đặc tả Yêu cầu (SRS) - Tính năng JIT Access & Web Portal

## 1. Tổng quan Kiến trúc
Xây dựng một Cổng thông tin (Web Portal) tích hợp trực tiếp vào Backend **FastAPI** phục vụ tính năng **Just-In-Time (JIT) Access**.
- **Không có form Đăng nhập truyền thống:** Nhận diện người dùng tự động qua `client_ip` (Tầng Network).
- **Frontend:** HTML/JS cơ bản, được serve trực tiếp bởi FastAPI (dùng `Jinja2Templates` hoặc trả về file tĩnh).
- **Backend:** FastAPI xử lý API, tương tác Telegram Bot (gửi OTP) và VyOS (cấu hình Firewall/ACL).
- **Bảo mật:** Verify OTP + Kiểm tra điểm rủi ro (Risk Score) + Thu hồi quyền tự động (Background Task).

---

## 2. Đặc tả Giao diện Web Portal (Frontend)
Giao diện gồm 1 trang duy nhất (Single Page Application cơ bản) với 2 trạng thái màn hình (States):

### State 1: Màn hình Yêu cầu (Request Screen)
- **Hành vi khi load trang:** Tự động gọi API `GET /api/jit/resources`.
- **Logic:** - Nếu API báo lỗi (IP không có quyền): Hiển thị thông báo lỗi (màu đỏ) "Từ chối truy cập: Thiết bị không thuộc nhóm IT hoặc có rủi ro cao".
  - Nếu API thành công: Hiển thị lời chào "Xin chào, [Username]", và một Dropdown list (hoặc Radio buttons) danh sách các tài nguyên (Ví dụ: Linux Server - Port 22).
- **Action:** Nút "Yêu cầu Truy cập". Bấm vào sẽ gọi API `POST /api/jit/request-otp` và chuyển sang State 2.

### State 2: Màn hình Xác thực (Verify Screen)
- **UI:** Form nhập mã OTP (6 số) và một Countdown Timer (5 phút).
- **Action:** Nút "Xác nhận". Bấm vào sẽ gọi API `POST /api/jit/grant-access`.
- **Kết quả:** Nếu thành công, hiển thị thông báo xanh lá "✅ Đã mở Port. Quyền truy cập sẽ tự động đóng sau 30 phút".

---

## 3. Đặc tả API (Backend - FastAPI)

### 3.1. API Lấy danh sách tài nguyên
- **Endpoint:** `GET /api/jit/resources`
- **Logic:** 1. Lấy `request.client.host` (Client IP).
  2. Mock function: Tìm Profile thiết bị theo IP (Mock dữ liệu trả về `role: "IT"`, `risk_score: 10`, `username: "quochuy"`).
  3. Nếu `role != "IT"` hoặc `risk_score > 30`, return HTTP 403.
  4. Trả về JSON danh sách tài nguyên nội bộ.

### 3.2. API Yêu cầu OTP
- **Endpoint:** `POST /api/jit/request-otp`
- **Payload:** `{"resource_id": "string"}`
- **Logic:**
  1. Validate IP (giống API 1).
  2. Sinh OTP 6 số ngẫu nhiên.
  3. Lưu OTP vào In-memory dictionary `otp_cache[client_ip]` kèm thời gian hết hạn (5 phút).
  4. Gọi hàm Asynchronous gửi tin nhắn qua Telegram Bot cho Username tương ứng.
  5. Return HTTP 200.

### 3.3. API Cấp quyền & Thu hồi (Thực thi JIT)
- **Endpoint:** `POST /api/jit/grant-access`
- **Payload:** `{"resource_id": "string", "otp_code": "string", "duration_minutes": 30}`
- **Logic:**
  1. Kiểm tra OTP từ `otp_cache[client_ip]`. Xóa cache sau khi check.
  2. Validate lại IP Profile (đảm bảo Risk Score vẫn <= 30 lúc submit).
  3. **Enforce:** Gọi module `vyos_client` thực thi lệnh SSH qua `netmiko`: Mở ACL từ `client_ip` tới IP/Port của `resource_id`.
  4. **Revoke:** Thêm 1 `BackgroundTasks` (FastAPI) để `asyncio.sleep(duration_minutes * 60)`, sau đó gọi VyOS xóa chính cái ACL vừa tạo.
  5. Return HTTP 200.

---

## 4. Yêu cầu Code (Dành cho Developer/Claude)
1. **Tech Stack:** Python 3.10+, FastAPI, Uvicorn, httpx (cho Telegram API), netmiko (cho VyOS SSH).
2. **Cấu trúc File:** - `main.py` (Khởi tạo App & Mount HTML)
   - `routers/jit.py` (Chứa 3 API Endpoints)
   - `services/telegram.py` (Hàm gửi tin nhắn)
   - `services/vyos.py` (Hàm add/delete ACL)
   - `templates/index.html` (Code Frontend)
3. **Phong cách Code (Clean Code):**
   - Không comment giải thích những code hiển nhiên.
   - Bắt lỗi Try/Except gọn gàng cho phần SSH và HTTP call.
   - Code dễ đọc, modular. Tách biệt logic Router và Service.
   - Ở phần `vyos.py`, hãy viết logic mô phỏng (Print ra console câu lệnh VyOS) nếu không thể kết nối SSH thực tế lúc debug.

Hãy bắt đầu sinh code cho toàn bộ các file trên dựa theo đặc tả này.


Tài nguyên (IP),Dịch vụ (Port),Quyền của accounting,Quyền của IT
Linux Server (10.0.40.100),Nginx (80 / 443),✅ Standard,✅ Standard
,SQL (3306),❌ Blocked,🔐 JIT Access
,SSH (22),❌ Blocked,🔐 JIT Access
,DVWA (Ví dụ: 8080),💀 Honeypot Trap,💀 Honeypot Trap
Windows Server (192.168.29.17),"DNS / AD (53, 88...)",✅ Standard,✅ Standard
,RDP (3389),❌ Blocked,🔐 JIT Access
PacketFence (192.168.29.91),Web Admin (1443),❌ Blocked,🔐 JIT Access
Wazuh Server (192.168.29.103),Dashboard (443),❌ Blocked,🔐 JIT Access