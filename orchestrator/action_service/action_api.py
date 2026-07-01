"""Action Service API - Port 8002"""

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, Dict, Any
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.logger import get_logger, setup_logging
from action_service.services import action_service

setup_logging("INFO", service_name="action")
logger = get_logger(__name__)

app = FastAPI(
    title="Action Service API",
    version="1.0.0",
    description="Execute actions on devices - isolate, change role, get SCA"
)


class IsolateRequest(BaseModel):
    agent_ip: str
    security_event_id: str
    reason: str
    request_id: Optional[str] = None


class ChangeRoleRequest(BaseModel):
    mac: str
    target_role: str
    reason: str
    request_id: Optional[str] = None


class GetSCARequest(BaseModel):
    ip: str
    request_id: Optional[str] = None


class GetNetflowRequest(BaseModel):
    ip: str
    minutes: int = 5
    request_id: Optional[str] = None


class GetUserRoleRequest(BaseModel):
    username: str


class RevertToUncheckRequest(BaseModel):
    mac: str
    reason: str
    request_id: Optional[str] = None


class RestoreActualRoleRequest(BaseModel):
    mac: str
    reason: str
    request_id: Optional[str] = None


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "action-api"}


@app.post("/actions/isolate")
async def isolate_device(request: IsolateRequest):
    """Isolate device by applying security event"""
    import uuid
    request_id = request.request_id or str(uuid.uuid4())

    logger.info("isolate_api_called",
                request_id=request_id,
                agent_ip=request.agent_ip)

    result = await action_service.isolate_device(
        request.agent_ip,
        request.security_event_id,
        request.reason,
        request_id
    )

    return result


@app.post("/actions/change-role")
async def change_role(request: ChangeRoleRequest):
    """Change device role in PacketFence"""
    import uuid
    request_id = request.request_id or str(uuid.uuid4())

    logger.info("change_role_api_called",
                request_id=request_id,
                mac=request.mac,
                target_role=request.target_role)

    result = await action_service.change_device_role(
        request.mac,
        request.target_role,
        request.reason,
        request_id
    )

    return result


@app.post("/actions/get-sca")
async def get_sca(request: GetSCARequest):
    """Get Wazuh agent info and SCA score"""
    import uuid
    request_id = request.request_id or str(uuid.uuid4())

    logger.info("get_sca_api_called",
                request_id=request_id,
                ip=request.ip)

    result = await action_service.get_device_sca(request.ip, request_id)

    return result


@app.post("/actions/get-netflow")
async def get_netflow(request: GetNetflowRequest):
    """Get recent netflow connections for device IP."""
    import uuid
    request_id = request.request_id or str(uuid.uuid4())

    logger.info("get_netflow_api_called",
                request_id=request_id,
                ip=request.ip,
                minutes=request.minutes)

    result = await action_service.get_device_netflow(request.ip, request.minutes, request_id)

    return result


@app.post("/actions/get-user-role")
async def get_user_role(request: GetUserRoleRequest):
    """Get user role from AD groups."""
    import uuid
    request_id = str(uuid.uuid4())

    logger.info("get_user_role_api_called",
                request_id=request_id,
                username=request.username)

    result = await action_service.get_user_role(request.username, request_id)

    return result


@app.post("/actions/get-user-groups")
async def get_user_groups(request: GetUserRoleRequest):
    """Get user groups from LDAP without resolving access role."""
    import uuid
    request_id = str(uuid.uuid4())

    logger.info("get_user_groups_api_called",
                request_id=request_id,
                username=request.username)

    result = await action_service.get_user_groups(request.username, request_id)

    return result


@app.post("/actions/revert-to-uncheck")
async def revert_to_uncheck(request: RevertToUncheckRequest):
    """Revert device to uncheck state (for logoff)"""
    import uuid
    request_id = request.request_id or str(uuid.uuid4())

    logger.info("revert_to_uncheck_api_called",
                request_id=request_id,
                mac=request.mac)

    result = await action_service.revert_device_to_uncheck(
        request.mac,
        request.reason,
        request_id
    )

    return result


@app.post("/actions/restore-actual-role")
async def restore_actual_role(request: RestoreActualRoleRequest):
    """Restore device to actual role and reset risk/state."""
    import uuid
    request_id = request.request_id or str(uuid.uuid4())

    logger.info("restore_actual_role_api_called",
                request_id=request_id,
                mac=request.mac)

    result = await action_service.restore_device_to_actual_role(
        request.mac,
        request.reason,
        request_id
    )

    return result


if __name__ == "__main__":
    import uvicorn
    logger.info("Starting Action Service API on port 8002")
    uvicorn.run("action_api:app", host="0.0.0.0", port=8002, reload=True)
