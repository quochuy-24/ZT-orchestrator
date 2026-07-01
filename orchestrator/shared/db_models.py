from sqlalchemy import Column, Integer, String, Text, ForeignKey, Index
from sqlalchemy.orm import declarative_base, relationship


Base = declarative_base()


class Device(Base):
    __tablename__ = "devices"

    device_id = Column(String(50), primary_key=True)
    ip_address = Column(String(50), index=True)
    hostname = Column(String(100))
    operating_system = Column(String(100))
    topology_switch_ip = Column(String(50))
    topology_switch_port = Column(String(100))
    topology_last_seen_at = Column(Text)
    topology_source = Column(String(20))
    state = Column(String(50), default="EVALUATING")
    username = Column(String(100), index=True)
    auth_type = Column(String(50))
    actual_role = Column(String(50))
    current_role = Column(String(50), default="Machine")
    nas_ip = Column(String(50))
    switch_port = Column(String(50))

    sca_score = Column(Integer)
    firewall_enabled = Column(Integer)
    antivirus_enabled = Column(Integer)
    critical_alerts_count = Column(Integer, default=0)

    total_score = Column(Integer, default=0)
    risk_level = Column(String(20), default="UNKNOWN")

    profile_created_at = Column(Text, nullable=False)
    last_assessed_at = Column(Text)

    audit_logs = relationship("AuditLog", back_populates="device", cascade="all, delete-orphan")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(50), ForeignKey("devices.device_id"), nullable=False)
    event_source = Column(String(50), nullable=False)
    event_id = Column(String(50))
    level = Column(Integer)
    action = Column(Text, nullable=False)
    changed_at = Column(Text, nullable=False)
    reason = Column(Text)
    role = Column(String(50))

    device = relationship("Device", back_populates="audit_logs")

    __table_args__ = (
        Index("idx_audit_device_time", "device_id", "changed_at"),
        Index("idx_audit_event_id", "event_id", "changed_at"),
    )
