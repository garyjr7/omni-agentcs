"""Administrative API for the NEXUS AI Directory control plane."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from nexus_api.auth.deps import (
    ensure_tenant_access,
    require_admin,
    require_system_admin,
)
from nexus_api.config import NEXUS_DB_PATH
from nexus_core.kernel.directory import DirectoryRepository
from nexus_core.kernel.models import AgentDefinition, RiskLevel, ToolDefinition
from nexus_core.kernel.store_factory import get_control_store

router = APIRouter(
    prefix="/directory",
    tags=["Directory"],
    dependencies=[Depends(require_admin)],
)
store = get_control_store(NEXUS_DB_PATH)
directory = DirectoryRepository(store)


class TenantCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    tenant_id: str | None = Field(default=None, min_length=2, max_length=120)


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)


class AgentCreate(BaseModel):
    tenant_id: str
    name: str = Field(min_length=2, max_length=120)
    version: str = "1.0.0"
    description: str = ""
    capabilities: list[str] = []
    tool_ids: list[str] = []
    model_route: str = "default"


class ToolCreate(BaseModel):
    tenant_id: str
    name: str = Field(min_length=2, max_length=120)
    version: str = "1.0.0"
    description: str = ""
    input_schema: dict = {}
    risk: RiskLevel = RiskLevel.READ_ONLY
    required_permissions: list[str] = []


class EnvironmentCreate(BaseModel):
    tenant_id: str
    name: str
    classification: str = "internal"


class GroupCreate(BaseModel):
    tenant_id: str
    name: str = Field(min_length=2, max_length=120)


class DepartmentCreate(BaseModel):
    tenant_id: str
    name: str = Field(min_length=2, max_length=120)


class CapabilityCreate(BaseModel):
    tenant_id: str
    name: str = Field(min_length=2, max_length=120)
    description: str = ""


class CapabilityAssignment(BaseModel):
    tenant_id: str
    capability_id: str


class ToolResourceBinding(BaseModel):
    tenant_id: str
    resource_id: str
    scopes: list[str]


class GroupMemberCreate(BaseModel):
    tenant_id: str
    subject_type: str
    subject_id: str


class ServiceAccountCreate(BaseModel):
    tenant_id: str
    name: str = Field(min_length=2, max_length=120)
    roles: list[str] = ["viewer"]
    expires_at: str | None = None


class ResourceCreate(BaseModel):
    tenant_id: str
    kind: str
    name: str
    classification: str = "internal"
    environment_id: str | None = None
    owner_id: str | None = None
    attributes: dict[str, str] = {}


@router.get("/tenants")
def list_tenants(_: dict = Depends(require_system_admin)):
    return {"items": store.list_tenants()}


@router.get("/organizations")
async def list_organizations(_: dict = Depends(require_system_admin)):
    return {"items": store.list_organizations()}


@router.post("/organizations", status_code=status.HTTP_201_CREATED)
async def create_organization(body: OrganizationCreate,
                              _: dict = Depends(require_system_admin)):
    return store.create_organization(body.name)


@router.post("/tenants", status_code=status.HTTP_201_CREATED)
async def create_tenant(body: TenantCreate, _: dict = Depends(require_system_admin)):
    try:
        return store.create_tenant(body.name, body.tenant_id)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/agents")
async def list_agents(tenant_id: str, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, tenant_id)
    return {"items": store.list_definitions("kernel_agents", tenant_id)}


@router.post("/agents", status_code=status.HTTP_201_CREATED)
async def create_agent(body: AgentCreate, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    definition = AgentDefinition(**body.model_dump()).to_dict()
    return store.put_definition("kernel_agents", definition)


@router.get("/tools")
def list_tools(tenant_id: str, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, tenant_id)
    return {"items": store.list_definitions("kernel_tools", tenant_id)}


@router.post("/tools", status_code=status.HTTP_201_CREATED)
def create_tool(body: ToolCreate, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    definition = ToolDefinition(**body.model_dump()).to_dict()
    return store.put_definition("kernel_tools", definition)


@router.get("/environments")
def list_environments(tenant_id: str, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, tenant_id)
    return {"items": directory.list_kind("kernel_environments", tenant_id)}


@router.post("/environments", status_code=201)
def create_environment(body: EnvironmentCreate, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    return directory.create_environment(**body.model_dump())


@router.get("/groups")
def list_groups(tenant_id: str, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, tenant_id)
    return {"items": directory.list_kind("kernel_groups", tenant_id)}


@router.post("/groups", status_code=201)
def create_group(body: GroupCreate, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    return directory.create_group(body.tenant_id, body.name)


@router.get("/departments")
async def list_departments(tenant_id: str, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, tenant_id)
    return {"items": directory.list_kind("kernel_departments", tenant_id)}


@router.post("/departments", status_code=201)
async def create_department(body: DepartmentCreate, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    return directory.create_department(body.tenant_id, body.name)


@router.get("/capabilities")
async def list_capabilities(tenant_id: str, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, tenant_id)
    return {"items": directory.list_kind("kernel_capabilities", tenant_id)}


@router.post("/capabilities", status_code=201)
async def create_capability(body: CapabilityCreate, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    return directory.create_capability(**body.model_dump())


@router.post("/agents/{agent_id}/capabilities", status_code=204)
async def assign_capability(agent_id: str, body: CapabilityAssignment,
                            user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    directory.assign_agent_capability(body.tenant_id, agent_id, body.capability_id)


@router.post("/tools/{tool_id}/resources", status_code=204)
async def bind_tool_resource(tool_id: str, body: ToolResourceBinding,
                             user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    directory.bind_tool_resource(body.tenant_id, tool_id, body.resource_id, body.scopes)


@router.post("/groups/{group_id}/members", status_code=201)
def add_group_member(group_id: str, body: GroupMemberCreate,
                     user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    member_id = directory.add_member(
        body.tenant_id, group_id, body.subject_type, body.subject_id
    )
    return {"id": member_id}


@router.get("/service-accounts")
def list_service_accounts(tenant_id: str, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, tenant_id)
    return {"items": directory.list_kind("kernel_service_accounts", tenant_id)}


@router.post("/service-accounts", status_code=201)
def create_service_account(body: ServiceAccountCreate, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    return directory.create_service_account(**body.model_dump())


@router.get("/resources")
def list_resources(tenant_id: str, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, tenant_id)
    return {"items": directory.list_kind("kernel_resources", tenant_id)}


@router.post("/resources", status_code=201)
def create_resource(body: ResourceCreate, user: dict = Depends(require_admin)):
    ensure_tenant_access(user, body.tenant_id)
    return directory.create_resource(**body.model_dump())
