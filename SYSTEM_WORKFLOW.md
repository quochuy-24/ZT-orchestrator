# NAC Zero Trust System Workflow

## 1. System startup

`python main.py` starts four FastAPI services:

| Service | Port | Role |
| --- | ---: | --- |
| Listener Service | 8000 | Receives PacketFence and Wazuh events |
| PDP Service | 8001 | Evaluates policy decisions |
| Action Service | 8002 | Executes PacketFence, Wazuh, LDAP, and profile actions |
| JIT Portal | 8003 | Handles Just-In-Time access requests |

Shared state lives in `ProfileManager` and existing SQLite audit tables.

---

## 2. Device discovery phase

### Trigger

PacketFence detects a new endpoint and sends a device-discovered webhook to Listener Service.

### Flow

1. Listener receives MAC, IP, hostname, and PacketFence metadata.
2. Listener creates or updates device profile.
3. Device state becomes `EVALUATING` and current role starts as `Machine`.
4. Listener starts background enrichment:
   - operating system lookup
   - pre-login SCA lookup from Wazuh through Action Service
5. If SCA exists, profile posture is updated before user login.
6. Listener writes audit event:
   - `Pre-login SCA updated`, or
   - `Pre-login SCA unavailable`

### Result

Device exists in profile store before user authentication. System has early posture context and assigns only the pre-login `Machine` role, not the user's production role yet.

---

## 3. User login phase

### Trigger

Wazuh sends Windows logon alert, usually rule `100001`, to Listener Service.

### Flow

1. Listener receives Wazuh alert.
2. Listener extracts:
   - username
   - domain
   - agent IP
   - rule ID
   - rule level
3. Listener finds profile by endpoint IP.
4. Listener updates user identity in profile while preserving the current pre-decision role, usually `Machine`.
5. Listener sends device assessment request to PDP.

### Result

PDP receives enough context to decide whether endpoint should move from `Machine` or current role to the user's actual role, or be enforced into `uncheck` if posture is not compliant.

---

## 4. Posture evaluation phase

### PDP role

PDP contains:

- Policy Engine (PE): pure decision logic
- Policy Administrator (PA): dispatches approved actions

### Flow

1. PDP asks Action Service for current SCA score.
2. Action Service queries Wazuh.
3. PDP asks Action Service for LDAP groups.
4. Action Service queries LDAP and returns groups only.
5. PDP uses Policy Engine to map groups to role.
6. PDP evaluates posture:
   - SCA score must pass configured threshold
   - firewall must be enabled
   - antivirus must be enabled
   - user role must be resolvable
7. PDP writes audit event `Policy evaluated`.

### Decision outcomes

| Condition | PE action | Meaning |
| --- | --- | --- |
| SCA pass + firewall ON + antivirus ON + role resolved | `allow_role` | Endpoint may receive actual role |
| Any posture check fails | `keep_uncheck` | Endpoint is enforced into `uncheck` |

### Result

PDP has clear decision, but does not directly modify PacketFence.

---

## 5. Policy administration and enforcement phase

### Flow for `allow_role`

1. PA receives PE decision `allow_role`.
2. PA sends `/actions/change-role` to Action Service.
3. Action Service calls PacketFence API.
4. PacketFence changes node category/role.
5. Profile state becomes `COMPLIANT`.
6. Role-change audit is written.

### Flow for `keep_uncheck`

1. PA receives PE decision `keep_uncheck`.
2. PA sets target role to `uncheck`.
3. If current role is not already `uncheck`, PA sends a role-change request to Action Service.
4. Action Service calls PacketFence API to enforce `uncheck`.
5. Profile state becomes `NON_COMPLIANT`.
6. Audit records failed posture reason.

### Result

Action Service acts as enforcement adapter, not policy owner.

---

## 6. Health-status update phase

### Trigger

Wazuh health alerts report firewall or antivirus status, including rule `100020` and related Defender rules.

### Flow

1. Listener receives Wazuh health alert.
2. Listener extracts endpoint target IP.
3. Listener parses firewall and antivirus status.
4. If the status is bad (`ON -> OFF`), Listener forwards the alert to PDP before updating the stored posture so Policy Engine can detect the transition.
5. Listener updates profile posture fields:
   - firewall status
   - antivirus status
6. If the status is healthy and a logged-in user is waiting in `uncheck`, Listener can trigger a device posture re-evaluation.
7. PDP writes Wazuh alert audit and increases risk only when the event represents a bad transition.

### Result

Firewall/antivirus changes affect both access posture and risk scoring.

---

## 7. Security alert risk phase

### Trigger

Wazuh sends security alert unrelated to normal login posture.

### Flow

1. Listener receives the alert and resolves the endpoint target IP from rule-specific fields such as source IP, netflow source IP, or agent IP.
2. If profile lookup by IP fails, Listener can query PacketFence IP logs to reconcile IP to MAC and update the local profile.
3. Listener forwards the normalized alert to PDP.
4. PDP resolves the target endpoint and loads its profile.
5. Policy Engine calculates risk penalty from:
   - rule ID override, if configured
   - rule level map, otherwise
6. PDP updates profile risk score.
7. PDP calculates risk level.
8. PDP writes Wazuh audit entry.

### Risk outcomes

| Risk score | Risk level | Action |
| ---: | --- | --- |
| 0-59 | `MEDIUM` | no action / JIT denied |
| 60-79 | `HIGH` | restrict role |
| 80+ | `CRITICAL` | isolate device |

### Result

Risk score becomes continuous context for later decisions, including JIT.

---

## 8. Restriction phase

### Trigger

PDP decides action `restrict` because risk score crosses restriction threshold.

### Flow

1. PA sends role-change request to Action Service.
2. Action Service changes PacketFence role to `restricted`.
3. Profile state becomes `NON_COMPLIANT`.
4. Audit records risk-based restriction.

### Result

Device stays connected but loses normal access privileges.

---

## 9. Isolation phase

### Trigger

PDP decides action `isolate` because risk score crosses critical threshold.

### Flow

1. PA sends `/actions/isolate` to Action Service.
2. Action Service looks up MAC from PacketFence if needed.
3. Action Service applies PacketFence security event.
4. Profile state becomes `ISOLATED`.
5. Audit records isolation reason and security event ID.

### Result

Device is quarantined by PacketFence enforcement.

---

## 10. User logoff phase

### Trigger

Wazuh sends logoff alert, usually rule `100010`.

### Flow

1. Listener receives logoff event.
2. Listener finds profile by IP or user context.
3. Listener calls Action Service to revert PacketFence role to `uncheck`.
4. Profile identity/state is updated for logged-off user.
5. Audit records `user_logoff` decision.

### Result

Device returns to pre-authenticated state after user leaves.

---

## 11. JIT resource discovery phase

### Trigger

User opens JIT Portal through proxy.

### Flow

1. JIT Portal reads client IP from `X-Forwarded-For` only.
2. JIT Portal finds device profile by IP.
3. JIT Portal checks role and risk score with Policy Engine.
4. If allowed, portal returns resources permitted for role.
5. If denied, portal writes JIT audit event.

### Result

User sees only resources allowed by policy. VyOS itself is not requestable.

---

## 12. JIT OTP request phase

### Trigger

User selects resource and requests OTP.

### Flow

1. JIT Portal rechecks role, risk score, and selected resource.
2. If denied, audit records `JIT OTP denied`.
3. If allowed, portal generates OTP.
4. Portal sends OTP through Telegram.
5. If Telegram send succeeds, audit records `JIT OTP requested`.
6. If Telegram send fails, OTP is deleted and audit records `JIT OTP send failed`.

### Result

OTP exists only for allowed resource and expires after configured TTL.

---

## 13. JIT access grant phase

### Trigger

User submits OTP.

### Flow

1. JIT Portal validates OTP exists.
2. JIT Portal validates OTP not expired.
3. JIT Portal validates OTP value.
4. JIT Portal validates requested resource matches cached resource.
5. JIT Portal rechecks role and risk score with Policy Engine.
6. JIT Portal calls VyOS adapter to add temporary firewall rule.
7. If VyOS rule creation fails, JIT Portal keeps the OTP until it expires, writes `JIT access failed`, and returns an upstream enforcement error.
8. If VyOS rule creation succeeds, JIT Portal deletes the OTP.
9. Audit records `JIT access granted`.
10. Background timer starts for automatic revoke.

### VyOS enforcement

Temporary JIT rule is narrow:

- source IP = requesting endpoint IP
- destination IP = selected resource IP
- destination port = selected resource port
- protocol = TCP
- chain = `forward`

Dynamic rule allocation uses safe pool `20-49` and avoids static rules `1`, `2`, `50`, and `100+`.

### Result

User can access selected resource for configured short duration only.

---

## 14. JIT revoke phase

### Trigger

JIT duration expires.

### Flow

1. Background revoke task wakes up.
2. JIT Portal calls VyOS adapter to delete exact dynamic rule.
3. Audit records `JIT access revoked`.
4. If deletion fails, audit records `JIT revoke failed`.
5. Session is removed from active session memory.

### Result

Temporary access is removed without touching static firewall ACLs.

---

## 15. Restore from isolation phase

### Trigger

Admin or workflow requests restore after remediation.

### Flow

1. Action Service loads profile.
2. If user exists, Action Service resolves actual role from LDAP groups.
3. If no user exists, fallback role is `Machine` or stored actual role.
4. Action Service closes open PacketFence isolation security events.
5. Action Service changes PacketFence role back to actual role.
6. Risk score resets to `0`.
7. Profile state becomes `COMPLIANT`.
8. Audit records restore action and closed event IDs.

### Result

Endpoint exits isolation and returns to compliant access state.

---

## 16. Audit workflow

All important decisions write to existing audit logs.

### Sources

| Source | Meaning |
| --- | --- |
| `LISTENER` | Event ingestion and enrichment |
| `PDP` | Policy evaluation |
| `ACTION` / role change events | Enforcement results |
| `JIT_PORTAL` | JIT request, OTP, grant, revoke |

### Reason format

Audit reasons use structured fields:

```text
policy_name=... | decision=... | reason=... | key=value
```

### Result

Device drawer can show full lifecycle:

1. discovery with initial `Machine` role
2. pre-login SCA
3. login evaluation
4. role assignment or `uncheck` enforcement
5. risk updates
6. JIT access
7. restriction/isolation/restore

---

## 17. Zero Trust role separation

| ZTA component | Code responsibility |
| --- | --- |
| PAP | `shared/policy_config.py` stores static policy |
| PE | `shared/policy_engine.py` returns pure decisions |
| PA | `pdp_service/policy_admin.py` dispatches approved actions |
| PDP | `pdp_service/pdp_api.py` combines PE + PA |
| PIP | Wazuh, LDAP, PacketFence, ProfileManager adapters provide context |
| PEP | PacketFence and VyOS enforce access |
| Audit | ProfileManager writes existing audit logs |

### Final system behavior

System does not trust device, user, or network location by default. Every important access path depends on current identity, posture, risk, and policy decision before enforcement happens.
