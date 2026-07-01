Ái chà, tui xin lỗi bạn nha! Tui bị "ảo giác" một chút xíu, quên mất là khung chat này không vứt cái file đuôi `.md` trực tiếp cho bạn tải về được 😅. 

Tui gửi ngay nội dung chuẩn Markdown ở ngay bên dưới đây. Bạn chỉ cần copy toàn bộ đoạn trong khung đen và lưu thành file `vyos_acl_jit_config.md` để nhóm tham khảo và nạp cho Claude nhé!

```markdown
# Cấu Hình Firewall VyOS (Zero Trust - JIT Access)
**Phiên bản áp dụng:** VyOS 1.5/1.6 Rolling (từ 2026.02.x trở lên)
**Mô hình:** Zero Trust Network Access (Macro-segmentation kết hợp JIT Micro-segmentation)

---

## 1. Mục Tiêu Kiến Trúc (Defense in Depth)
- **Mở mặc định (Default Accept):** Cho phép các luồng truy cập tiêu chuẩn (Web HTTP/HTTPS, DNS) đi qua tự do để đảm bảo nghiệp vụ.
- **Khóa két sắt (Block High-Risk):** Chặn cứng toàn bộ các Port quản trị nhạy cảm (SSH, SQL, RDP, Web Admin) của các Server quan trọng.
- **Stateful Inspection:** Tự động cho phép các gói tin trả về của các kết nối hợp lệ.
- **JIT Provisioning (Dành riêng cho Python Backend):** Code Python sẽ chèn một Rule mở khóa tạm thời (Rule số `20`) để ưu tiên cho phép IP của nhân viên IT đi qua, và tự động xóa sau 30 phút.

---

## 2. Tập Lệnh Cấu Hình Lõi (Chạy 1 lần duy nhất lúc setup)

Truy cập vào VyOS và gõ lệnh `configure` để vào chế độ cấu hình, sau đó chạy tuần tự các khối lệnh sau:

### Khối 1: Cấu hình Stateful Firewall (Bộ nhớ kết nối)
*Giúp VyOS ghi nhớ trạng thái kết nối, không chặn nhầm các gói tin trả về hợp lệ.*

Filter traffic đi vào Firewall

```json
set firewall ipv4 input filter default-action drop
set firewall ipv4 input filter rule 1 action accept
set firewall ipv4 input filter rule 1 state established
set firewall ipv4 input filter rule 1 state related
set firewall ipv4 input filter rule 2 action drop
set firewall ipv4 input filter rule 2 state invalid

set firewall ipv4 input filter rule 5 description "Allow Loopback"
set firewall ipv4 input filter rule 5 inbound-interface name lo
set firewall ipv4 input filter rule 5 action accept
```

Cho phép ping 

```json
#allow ping to firewall
set firewall ipv4 input filter rule 30 description "Allow Ping to Router"
set firewall ipv4 input filter rule 30 protocol icmp
set firewall ipv4 input filter rule 30 action accept

#allow ping through firewall
set firewall ipv4 forward filter rule 50 protocol icmp
set firewall ipv4 forward filter rule 50 action accept
```

ACL cho phép PDP và máy macbook của tui ssh vào 

```json
set firewall group address-group ADMIN_IPS address 192.168.29.102
set firewall group address-group ADMIN_IPS address 192.168.29.79
set firewall group address-group ADMIN_IPS address 192.168.29.150
set firewall group address-group ADMIN_IPS address 192.168.29.6
set firewall group address-group ADMIN_IPS address 192.168.29.50

set firewall ipv4 input filter rule 10 description "Allow SSH from Admin Group"
set firewall ipv4 input filter rule 10 source group address-group ADMIN_IPS
set firewall ipv4 input filter rule 10 destination port 22
set firewall ipv4 input filter rule 10 protocol tcp
set firewall ipv4 input filter rule 10 action accept
```

Forward dữ liệu đi qua Firewall

```json
set firewall ipv4 forward filter default-action drop
set firewall ipv4 forward filter rule 1 action accept
set firewall ipv4 forward filter rule 1 state established
set firewall ipv4 forward filter rule 1 state related
set firewall ipv4 forward filter rule 2 action drop
set firewall ipv4 forward filter rule 2 state invalid
```

ACL cho hạ tầng chung (Nhóm A+)

```json
# cho phép DHCP relay 
set firewall ipv4 input filter rule 20 description "Allow DHCP Relay Input"
set firewall ipv4 input filter rule 20 inbound-interface name eth0.20
set firewall ipv4 input filter rule 20 protocol udp
set firewall ipv4 input filter rule 20 destination port 67
set firewall ipv4 input filter rule 20 action accept

# cho phép wazuh agent gửi dữ liệu về wazuh server
set firewall ipv4 forward filter rule 100 description "Allow Wazuh Agent to Server (TCP/UDP)"
set firewall ipv4 forward filter rule 100 destination address 192.168.29.103
set firewall ipv4 forward filter rule 100 destination port 1514,1515
set firewall ipv4 forward filter rule 100 protocol tcp_udp
set firewall ipv4 forward filter rule 100 action accept

# cho phép packetfence gọi xuống switch
set firewall ipv4 forward filter rule 101 description "Packetfence to Switch"
set firewall ipv4 forward filter rule 101 source address 192.168.29.91
set firewall ipv4 forward filter rule 101 destination address 10.0.10.0/24 
set firewall ipv4 forward filter rule 101 action accept

# cho phép switch giao tiếp với packetfence
set firewall ipv4 forward filter rule 102 description "Switch to Packetfence"
set firewall ipv4 forward filter rule 102 source address 10.0.10.0/24
set firewall ipv4 forward filter rule 102 destination address 192.168.29.91
set firewall ipv4 forward filter rule 102 action accept

# các dịch vụ cơ bản của Windows server
set firewall ipv4 forward filter rule 103 description "Allow DNS, Kerberos, LDAP, SMB"
set firewall ipv4 forward filter rule 103 destination address 192.168.29.17
set firewall ipv4 forward filter rule 103 protocol tcp_udp
set firewall ipv4 forward filter rule 103 destination port 53,88,389,445
set firewall ipv4 forward filter rule 103 action accept

# các dịch vụ cơ bản của Windows server
set firewall ipv4 forward filter rule 104 description "Allow DHCP and NTP"
set firewall ipv4 forward filter rule 104 destination address 192.168.29.17
set firewall ipv4 forward filter rule 104 protocol udp
set firewall ipv4 forward filter rule 104 destination port 67,68,123
set firewall ipv4 forward filter rule 104 action accept

# các dịch vụ cơ bản của Windows server
set firewall ipv4 forward filter rule 105 description "Allow RPC and Dynamic Ports"
set firewall ipv4 forward filter rule 105 destination address 192.168.29.17
set firewall ipv4 forward filter rule 105 protocol tcp
set firewall ipv4 forward filter rule 105 destination port 135,49152-65535
set firewall ipv4 forward filter rule 105 action accept

# cho phép truy cập vào dvwa
set firewall ipv4 forward filter rule 106 description "Allow web access DVWA"
set firewall ipv4 forward filter rule 106 destination address 10.0.40.100
set firewall ipv4 forward filter rule 106 protocol tcp
set firewall ipv4 forward filter rule 106 destination port 8081
set firewall ipv4 forward filter rule 106 action accept

# cho phép thiết bị truy cập trang web bên ngoài bình thường (fake internet bằng web host bởi máy 192.168.29.102)
set firewall ipv4 forward filter rule 107 description "http server"
set firewall ipv4 forward filter rule 107 destination address 192.168.29.102
set firewall ipv4 forward filter rule 107 protocol tcp
set firewall ipv4 forward filter rule 107 action accept

# cho phép thiết bị truy cập vào trang jit portal của PDP host lên
set firewall ipv4 forward filter rule 109 description "PDP"
set firewall ipv4 forward filter rule 109 destination address 192.168.29.50
set firewall ipv4 forward filter rule 109 protocol tcp
set firewall ipv4 forward filter rule 109 action accept

# 1. Cho phép Endpoint (VLAN 20) gửi request web đến Proxy
set firewall ipv4 forward filter rule 110 description "Allow Endpoint to DLP Proxy"
set firewall ipv4 forward filter rule 110 destination address 10.0.40.200
set firewall ipv4 forward filter rule 110 protocol tcp
set firewall ipv4 forward filter rule 110 destination port 3128
set firewall ipv4 forward filter rule 110 action accept

# 2. Cho phép Proxy Server ra Internet để lấy nội dung web
set firewall ipv4 forward filter rule 111 description "Allow DLP Proxy to Internet (HTTP/HTTPS)"
set firewall ipv4 forward filter rule 111 source address 10.0.40.200
set firewall ipv4 forward filter rule 111 protocol tcp
set firewall ipv4 forward filter rule 111 destination port 80,8081,443
set firewall ipv4 forward filter rule 111 action accept
```

---

## 3. Quy Ước Dành Cho Backend Developer (JIT Access)

Khi hệ thống JIT (FastAPI) cấp quyền, Code Python sẽ gửi lệnh chèn vào **Rule số 20** (hoặc bất kỳ số nào nhỏ hơn 100). Do VyOS đọc rule từ trên xuống, Rule 20 sẽ được thực thi và cho phép IP của nhân viên IT đi lọt trước khi chạm vào Rule Drop.

**Cú pháp đẩy qua Netmiko (Ví dụ mở SSH vào Linux Server):**
```python
cmds = [
    f"set firewall ipv4 forward filter rule 20 action accept",
    f"set firewall ipv4 forward filter rule 20 source address {client_ip}",
    f"set firewall ipv4 forward filter rule 20 destination address 10.0.40.100",
    f"set firewall ipv4 forward filter rule 20 destination port 22",
    f"set firewall ipv4 forward filter rule 20 protocol tcp",
    "commit"
]
```
*(Để xóa quyền khi hết giờ, Backend chỉ cần gửi lệnh: `delete firewall ipv4 forward filter rule 20` và `commit`)*.
```