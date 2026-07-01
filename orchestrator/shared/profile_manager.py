"""Device Profile Manager - SQLite storage"""

from typing import Dict, Optional, Any
from sqlalchemy import or_
from datetime import datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from shared.db_models import Base, Device, AuditLog


class DeviceProfile:
    """Device profile data structure"""

    def __init__(self, mac: str, ip: str, hostname: Optional[str] = None):
        self.device_id = mac
        self.ip_address = ip
        self.hostname = hostname
        self.operating_system = None
        self.topology = {
            "switch_ip": None,
            "switch_port": None,
            "last_seen_at": None,
            "source": None,
        }
        self.state = "EVALUATING"

        self.identity = {
            "username": None,
            "auth_type": None,
            "actual_role": None,
            "current_role": "Machine",
            "nas_ip": None,
            "switch_port": None,
        }

        self.posture_security = {
            "sca_score": None,
            "firewall_enabled": None,
            "antivirus_enabled": None,
            "critical_alerts_count": 0,
        }

        self.network_behavior = {
            "unique_dst_ports_1m": 0,
            "total_bytes_sent_1m": 0,
            "has_c2_connection": False,
        }

        self.risk_score = {
            "total_score": 0,
            "risk_level": "UNKNOWN",
        }

        self.role_history = []

        self.timestamps = {
            "profile_created_at": datetime.utcnow().isoformat(),
            "last_assessed_at": None,
        }


class ProfileManager:
    """Manage device profiles in SQLite"""

    def __init__(self, storage_path: Optional[str] = None):
        default_path = Path(__file__).resolve().parent.parent / "profiles.db"
        self.storage_path = Path(storage_path) if storage_path else default_path
        self.engine = create_engine(f"sqlite:///{self.storage_path}", connect_args={"check_same_thread": False})
        self.Session = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)
        with self.engine.connect() as conn:
            conn.exec_driver_sql("PRAGMA journal_mode=WAL")

    @staticmethod
    def _to_int_bool(value: Optional[bool]) -> Optional[int]:
        if value is None:
            return None
        return 1 if value else 0

    @staticmethod
    def _to_opt_bool(value: Optional[int]) -> Optional[bool]:
        if value is None:
            return None
        return bool(value)

    def _to_profile(self, device: Device, logs: list[AuditLog]) -> DeviceProfile:
        profile = DeviceProfile(device.device_id, device.ip_address, device.hostname)
        profile.state = device.state or "EVALUATING"
        profile.operating_system = device.operating_system
        profile.topology = {
            "switch_ip": device.topology_switch_ip,
            "switch_port": device.topology_switch_port,
            "last_seen_at": device.topology_last_seen_at,
            "source": device.topology_source,
        }

        profile.identity = {
            "username": device.username,
            "auth_type": device.auth_type,
            "actual_role": device.actual_role,
            "current_role": device.current_role or "Machine",
            "nas_ip": device.nas_ip,
            "switch_port": device.switch_port,
        }

        profile.posture_security = {
            "sca_score": device.sca_score,
            "firewall_enabled": self._to_opt_bool(device.firewall_enabled),
            "antivirus_enabled": self._to_opt_bool(device.antivirus_enabled),
            "critical_alerts_count": device.critical_alerts_count or 0,
        }

        profile.network_behavior = {
            "unique_dst_ports_1m": 0,
            "total_bytes_sent_1m": 0,
            "has_c2_connection": False,
        }

        profile.risk_score = {
            "total_score": device.total_score or 0,
            "risk_level": device.risk_level or "UNKNOWN",
        }

        profile.role_history = [
            {"role": log.role, "changed_at": log.changed_at, "reason": log.reason}
            for log in logs if log.role is not None
        ]

        profile.timestamps = {
            "profile_created_at": device.profile_created_at,
            "last_assessed_at": device.last_assessed_at,
        }
        return profile

    def create_profile(self, mac: str, ip: str, hostname: Optional[str] = None) -> DeviceProfile:
        session = self.Session()
        try:
            existing = session.query(Device).filter_by(device_id=mac).first()
            if existing:
                existing.ip_address = ip
                existing.hostname = hostname
                session.commit()
                logs = session.query(AuditLog).filter_by(device_id=mac).order_by(AuditLog.changed_at).all()
                return self._to_profile(existing, logs)

            profile = Device(
                device_id=mac,
                ip_address=ip,
                hostname=hostname,
                state="EVALUATING",
                current_role="Machine",
                critical_alerts_count=0,
                total_score=0,
                risk_level="UNKNOWN",
                profile_created_at=datetime.utcnow().isoformat(),
            )
            session.add(profile)
            session.commit()
            return self._to_profile(profile, [])
        finally:
            session.close()

    def get_profile(self, mac: str) -> Optional[DeviceProfile]:
        session = self.Session()
        try:
            device = session.query(Device).filter_by(device_id=mac).first()
            if not device:
                return None
            logs = session.query(AuditLog).filter_by(device_id=mac).order_by(AuditLog.changed_at).all()
            return self._to_profile(device, logs)
        finally:
            session.close()

    def update_discovery_metadata(
        self,
        mac: str,
        operating_system: Optional[str] = None,
        hostname: Optional[str] = None,
        switch_ip: Optional[str] = None,
        switch_port: Optional[str] = None,
        topology_source: Optional[str] = None,
    ) -> Optional[DeviceProfile]:
        session = self.Session()
        try:
            device = session.query(Device).filter_by(device_id=mac).first()
            if not device:
                return None

            if operating_system is not None:
                device.operating_system = operating_system
            if hostname is not None and hostname.strip():
                device.hostname = hostname.strip()
            if switch_ip is not None:
                device.topology_switch_ip = switch_ip
            if switch_port is not None:
                device.topology_switch_port = switch_port
            if topology_source is not None:
                device.topology_source = topology_source

            if any(v is not None for v in (switch_ip, switch_port, topology_source)):
                device.topology_last_seen_at = datetime.utcnow().isoformat()

            session.commit()
            logs = session.query(AuditLog).filter_by(device_id=mac).order_by(AuditLog.changed_at).all()
            return self._to_profile(device, logs)
        finally:
            session.close()

    def update_operating_system(self, mac: str, operating_system: str) -> Optional[DeviceProfile]:
        return self.update_discovery_metadata(mac=mac, operating_system=operating_system)

    def update_actual_role(self, mac: str, actual_role: str) -> Optional[DeviceProfile]:
        session = self.Session()
        try:
            device = session.query(Device).filter_by(device_id=mac).first()
            if not device:
                return None
            device.actual_role = actual_role
            session.commit()
            logs = session.query(AuditLog).filter_by(device_id=mac).order_by(AuditLog.changed_at).all()
            return self._to_profile(device, logs)
        finally:
            session.close()

    def update_user_info(self, mac: str, username: str, auth_type: str = "802.1x-User", current_role: str = "uncheck") -> Optional[DeviceProfile]:
        session = self.Session()
        try:
            device = session.query(Device).filter_by(device_id=mac).first()
            if not device:
                return None
            device.username = username
            device.auth_type = auth_type
            device.current_role = current_role
            session.commit()
            logs = session.query(AuditLog).filter_by(device_id=mac).order_by(AuditLog.changed_at).all()
            return self._to_profile(device, logs)
        finally:
            session.close()

    def update_posture_security(self, mac: str, sca_score: Optional[int] = None, firewall_enabled: Optional[bool] = None, antivirus_enabled: Optional[bool] = None, critical_alerts_count: int = 0) -> Optional[DeviceProfile]:
        session = self.Session()
        try:
            device = session.query(Device).filter_by(device_id=mac).first()
            if not device:
                return None
            if sca_score is not None:
                device.sca_score = sca_score
            if firewall_enabled is not None:
                device.firewall_enabled = self._to_int_bool(firewall_enabled)
            if antivirus_enabled is not None:
                device.antivirus_enabled = self._to_int_bool(antivirus_enabled)
            device.critical_alerts_count = critical_alerts_count
            session.commit()
            logs = session.query(AuditLog).filter_by(device_id=mac).order_by(AuditLog.changed_at).all()
            return self._to_profile(device, logs)
        finally:
            session.close()

    def update_network_behavior(self, mac: str, unique_dst_ports: int = 0, total_bytes_sent: int = 0, has_c2_connection: bool = False) -> Optional[DeviceProfile]:
        return self.get_profile(mac)

    def update_risk_score(self, mac: str, total_score: int, risk_level: str) -> Optional[DeviceProfile]:
        session = self.Session()
        try:
            device = session.query(Device).filter_by(device_id=mac).first()
            if not device:
                return None
            device.total_score = total_score
            device.risk_level = risk_level
            device.last_assessed_at = datetime.utcnow().isoformat()
            session.commit()
            logs = session.query(AuditLog).filter_by(device_id=mac).order_by(AuditLog.changed_at).all()
            return self._to_profile(device, logs)
        finally:
            session.close()

    def update_state(self, mac: str, state: str) -> Optional[DeviceProfile]:
        session = self.Session()
        try:
            device = session.query(Device).filter_by(device_id=mac).first()
            if not device:
                return None
            device.state = state
            session.commit()
            logs = session.query(AuditLog).filter_by(device_id=mac).order_by(AuditLog.changed_at).all()
            return self._to_profile(device, logs)
        finally:
            session.close()

    def add_role_change(self, mac: str, new_role: str, reason: str) -> Optional[DeviceProfile]:
        session = self.Session()
        try:
            device = session.query(Device).filter_by(device_id=mac).first()
            if not device:
                return None

            device.current_role = new_role
            log = AuditLog(
                device_id=mac,
                event_source="SYSTEM",
                event_id=None,
                level=None,
                action="Role change",
                changed_at=datetime.utcnow().isoformat(),
                reason=reason,
                role=new_role,
            )
            session.add(log)
            session.commit()
            logs = session.query(AuditLog).filter_by(device_id=mac).order_by(AuditLog.changed_at).all()
            return self._to_profile(device, logs)
        finally:
            session.close()

    def add_system_event(
        self,
        mac: str,
        action: str,
        reason: str,
        role: Optional[str] = None,
        event_id: Optional[str] = None,
        level: Optional[int] = None,
        event_source: str = "SYSTEM",
    ) -> Optional[DeviceProfile]:
        session = self.Session()
        try:
            device = session.query(Device).filter_by(device_id=mac).first()
            if not device:
                return None
            log = AuditLog(
                device_id=mac,
                event_source=event_source,
                event_id=event_id,
                level=level,
                action=action,
                changed_at=datetime.utcnow().isoformat(),
                reason=reason,
                role=role,
            )
            session.add(log)
            session.commit()
            logs = session.query(AuditLog).filter_by(device_id=mac).order_by(AuditLog.changed_at).all()
            return self._to_profile(device, logs)
        finally:
            session.close()

    def add_wazuh_alert(self, mac: str, event_id: str, level: int, action: str, reason: Optional[str] = None) -> Optional[DeviceProfile]:
        session = self.Session()
        try:
            device = session.query(Device).filter_by(device_id=mac).first()
            if not device:
                return None
            log = AuditLog(
                device_id=mac,
                event_source="WAZUH_ALERT",
                event_id=event_id,
                level=level,
                action=action,
                changed_at=datetime.utcnow().isoformat(),
                reason=reason or f"Wazuh rule {event_id} (level {level})",
                role=None,
            )
            session.add(log)
            session.commit()
            logs = session.query(AuditLog).filter_by(device_id=mac).order_by(AuditLog.changed_at).all()
            return self._to_profile(device, logs)
        finally:
            session.close()

    def get_profile_by_ip(self, ip: str) -> Optional[DeviceProfile]:
        session = self.Session()
        try:
            device = session.query(Device).filter_by(ip_address=ip).first()
            if not device:
                return None
            logs = session.query(AuditLog).filter_by(device_id=device.device_id).order_by(AuditLog.changed_at).all()
            return self._to_profile(device, logs)
        finally:
            session.close()

    def list_profiles(self) -> Dict[str, DeviceProfile]:
        session = self.Session()
        try:
            result: Dict[str, DeviceProfile] = {}
            devices = session.query(Device).all()
            for device in devices:
                logs = session.query(AuditLog).filter_by(device_id=device.device_id).order_by(AuditLog.changed_at).all()
                result[device.device_id] = self._to_profile(device, logs)
            return result
        finally:
            session.close()

    def list_devices_paginated(self, q: Optional[str] = None, state: Optional[str] = None, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        session = self.Session()
        try:
            query = session.query(Device)

            if state:
                query = query.filter(Device.state == state)

            if q:
                q_like = f"%{q}%"
                query = query.filter(
                    or_(
                        Device.device_id.ilike(q_like),
                        Device.ip_address.ilike(q_like),
                        Device.username.ilike(q_like),
                        Device.hostname.ilike(q_like),
                    )
                )

            total = query.count()
            devices = (
                query.order_by(Device.profile_created_at.desc())
                .offset(max(0, offset))
                .limit(max(1, min(limit, 500)))
                .all()
            )

            items = []
            for device in devices:
                items.append(
                    {
                        "device_id": device.device_id,
                        "ip_address": device.ip_address,
                        "hostname": device.hostname,
                        "operating_system": device.operating_system,
                        "switch_ip": device.topology_switch_ip,
                        "switch_port": device.topology_switch_port,
                        "topology_last_seen_at": device.topology_last_seen_at,
                        "topology_source": device.topology_source,
                        "state": device.state,
                        "username": device.username,
                        "auth_type": device.auth_type,
                        "actual_role": device.actual_role,
                        "current_role": device.current_role,
                        "sca_score": device.sca_score,
                        "firewall_enabled": self._to_opt_bool(device.firewall_enabled),
                        "antivirus_enabled": self._to_opt_bool(device.antivirus_enabled),
                        "critical_alerts_count": device.critical_alerts_count,
                        "total_score": device.total_score,
                        "risk_level": device.risk_level,
                        "profile_created_at": device.profile_created_at,
                        "last_assessed_at": device.last_assessed_at,
                    }
                )

            return {"items": items, "total": total, "limit": limit, "offset": offset}
        finally:
            session.close()

    def get_audit_logs_paginated(self, mac: str, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        session = self.Session()
        try:
            base = session.query(AuditLog).filter_by(device_id=mac)
            total = base.count()
            rows = (
                base.order_by(AuditLog.changed_at.desc())
                .offset(max(0, offset))
                .limit(max(1, min(limit, 1000)))
                .all()
            )

            items = [
                {
                    "id": row.id,
                    "device_id": row.device_id,
                    "event_source": row.event_source,
                    "event_id": row.event_id,
                    "level": row.level,
                    "action": row.action,
                    "changed_at": row.changed_at,
                    "reason": row.reason,
                    "role": row.role,
                }
                for row in rows
            ]

            return {"items": items, "total": total, "limit": limit, "offset": offset}
        finally:
            session.close()


profile_manager = ProfileManager()
