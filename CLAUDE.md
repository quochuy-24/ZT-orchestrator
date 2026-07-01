# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NAC (Network Access Control) System with Zero Trust architecture integrating PacketFence, Wazuh, Active Directory, and VyOS. The system consists of 4 microservices that handle device discovery, policy evaluation, action execution, and just-in-time access.

## Architecture

The system follows a microservices pattern with these components:

- **Listener Service** (Port 8000): Receives webhooks from PacketFence and Wazuh
- **PDP Service** (Port 8001): Policy Decision Point - evaluates compliance and risk
- **Action Service** (Port 8002): Executes actions on PacketFence, Wazuh, and Active Directory
- **JIT Portal** (Port 8003): Just-In-Time access portal with OTP via Telegram

All services share a common `ProfileManager` that maintains device state in `orchestrator/profiles.json`.

## Development Commands

### Environment Setup
```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running Services

**All services together:**
```bash
python main.py
```

**Individual services for development:**
```bash
# Listener Service
cd orchestrator/listener_service
python -m uvicorn listener_api:app --host 0.0.0.0 --port 8000 --reload

# PDP Service  
cd orchestrator/pdp_service
python -m uvicorn pdp_api:app --host 0.0.0.0 --port 8001 --reload

# Action Service
cd orchestrator/action_service  
python -m uvicorn action_api:app --host 0.0.0.0 --port 8002 --reload

```bash
curl -X POST http://localhost:8000/webhook/device-discovered \
  -H "Content-Type: application/json" \
  -d '{"mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.20.100", "hostname": "test-device"}'
```

**Test Wazuh logon:**
```bash
curl -X POST http://localhost:8000/webhook/wazuh-alert/ \
  -H "Content-Type: application/json" \
  -d '{"rule": {"id": "100001"}, "agent": {"ip": "10.0.20.100"}, "data": {"win": {"eventdata": {"targetUserName": "testuser", "targetDomainName": "LAB"}}}}'
```

**Test JIT access:**
```bash
# Get available resources
curl http://localhost:8003/api/jit/resources

# Request OTP
curl -X POST http://localhost:8003/api/jit/request-otp \
  -H "Content-Type: application/json" \
  -d '{"resource_id": "linux_ssh"}'
```

## Key Components

### ProfileManager (`orchestrator/shared/profile_manager.py`)
Central state management for device profiles. Each device has:
- Device identity (MAC, IP, hostname)
- User identity (username, role, auth type)
- Security posture (SCA score, firewall, antivirus)
- Risk score calculation
- State tracking (EVALUATING, COMPLIANT, NON_COMPLIANT, ISOLATED, LOGGED_OFF)

### Service Communication
Services communicate via HTTP APIs:
- Listener → PDP: Device assessment requests
- PDP → Action: Execute policy decisions
- All services read/write to shared ProfileManager

### External Integrations
- **PacketFence**: Device management via REST API (`clients/packetfence_client.py`)
- **Wazuh**: Security monitoring via REST API (`clients/wazuh_client.py`)  
- **Active Directory**: User role lookup via LDAP (`clients/ldap_client.py`)
- **VyOS**: Firewall rule management via SSH (`jit_portal/services/vyos.py`)
- **Telegram**: OTP delivery via Bot API (`jit_portal/services/telegram.py`)

## Configuration

### Required Environment Variables
```bash
# Telegram Bot (for JIT Portal)
export TELEGRAM_BOT_TOKEN="your_bot_token"
```

### Service Configuration Files
- PacketFence credentials: `orchestrator/action_service/clients/packetfence_client.py`
- Wazuh credentials: `orchestrator/action_service/clients/wazuh_client.py`
- LDAP settings: `orchestrator/action_service/clients/ldap_client.py`
- VyOS SSH settings: `jit_portal/services/vyos.py`
- Telegram user mapping: `jit_portal/routers/jit.py`

## Workflow Patterns

### Device Join & User Login
1. PacketFence webhook → Listener creates profile (state: EVALUATING)
2. Wazuh logon event → Listener updates username → Forward to PDP
3. PDP gets SCA score + user role → Calculate risk → Forward to Action
4. Action changes role in PacketFence → Profile updated (state: COMPLIANT/NON_COMPLIANT)

### Security Alert Handling
1. Wazuh alert → Listener → PDP evaluation
2. PDP decides action based on rule level and groups
3. Critical threats (level ≥12 + malware groups) → Isolate device
4. Action service applies security event in PacketFence

### JIT Access Flow
1. User accesses web portal → IP-based authentication via ProfileManager
2. Role-based resource filtering → Request OTP → Telegram delivery
3. OTP verification → VyOS firewall rule creation → Auto-revoke after timeout

## Development Guidelines

### Code Organization
- Each service has its own directory with `requirements.txt`
- Shared utilities in `orchestrator/shared/`
- Client libraries in `orchestrator/action_service/clients/`
- All services use structured logging via `shared/logger.py`

### Profile State Management
- Always use ProfileManager for device state
- Call `profile_manager._save_profiles()` after updates
- Profile lookup by IP: `profile_manager.get_profile_by_ip(ip)`
- Profile lookup by MAC: `profile_manager.get_profile(mac)`

### Error Handling
- Use structured logging with request IDs for traceability
- HTTP exceptions with appropriate status codes
- Graceful degradation when external services are unavailable

### Testing Approach
- Use curl commands for API testing
- Mock external services during development
- Check profile state in `orchestrator/profiles.json` after operations

curl https://raw.githubusercontent.com/forrestchang/andrej-karpathy-skills/main/CLAUDE.md

