from fastapi import APIRouter, Depends, HTTPException
from typing import List

from app.crud import agent_template as template_crud
from app.crud import agent_workflow as agent_workflow_crud
from app.schemas.agent_template import AgentTemplateSchema
from app.schemas.agent_workflow import AgentWorkflowSchema, AgentWorkflowCreateSchema, AgentWorkflowUpdateSchema
from .auth import FourkitesStatelessOrBearerOrKeycloakJWTAuthentication  

authentication = FourkitesStatelessOrBearerOrKeycloakJWTAuthentication()

router = APIRouter()

# ------------------- Template Endpoints ------------------- #

@router.get("/get_template", response_model=AgentTemplateSchema, summary="Get Agent Template")

# Uncomment the line below to enable authorization using authentication dependency

#async def get_template(agent: str, user: dict = Depends(authentication)):
async def get_template(agent: str):
    """
    Retrieve agent template based on the agent's name.

    - **agent**: The agent name (e.g., tracy)
    """
    template = await template_crud.get_agent_template(agent)
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return template

@router.post("/get_template", response_model=AgentTemplateSchema, status_code=201, summary="Create Agent Template")

# Uncomment the line below to enable authorization using authentication dependency

#async def create_template(template: AgentTemplateSchema, user: dict = Depends(authentication)):
async def create_template(template: AgentTemplateSchema):
    """
    Create a new agent template.

    - **template**: Agent template data to be created
    """
    result = await template_crud.save_agent_template(template)
    if not result:
        raise HTTPException(status_code=500, detail="Template could not be created")
    return result

# ------------------- Agent Workflow Endpoints ------------------- #

@router.post("/agent-workflow/{shipper_id}", response_model=AgentWorkflowCreateSchema, status_code=201, summary="Create Agent Workflow")

# Uncomment the line below to enable authorization using authentication dependency

#async def create_agent_workflow(shipper_id: str, workflow: AgentWorkflowSchema, user: dict = Depends(authentication)):
async def create_agent_workflow(shipper_id: str, workflow: AgentWorkflowSchema):
    
    """
    Create a tenant-specific agent workflow.

    - **shipper_id**: Shipper ID for the tenant
    - **workflow**: Agent workflow data to be created
    """
    user = {"userId": "test_user"}
    result = await agent_workflow_crud.save_agent_workflow(shipper_id, workflow.dict(), user)

    if not result:
        raise HTTPException(status_code=500, detail="Agent workflow could not be created")
    return result


@router.put("/agent-workflow/{shipper_id}", response_model=AgentWorkflowUpdateSchema, status_code=200, summary="Update Agent Workflow")

# Uncomment the line below to enable authorization using authentication dependency

#async def update_agent_workflow(shipper_id: str, workflow: AgentWorkflowSchema, user: dict = Depends(authentication)):
async def update_agent_workflow(shipper_id: str, workflow: AgentWorkflowSchema):
    """
    Update a tenant-specific agent workflow.

    - **shipper_id**: Shipper ID for the tenant
    - **workflow**: Agent workflow data to be updated
    """
    user = {"userId": "test_user"}
    result = await agent_workflow_crud.update_agent_workflow(shipper_id, workflow.dict(), user)
    
    if not result:
        raise HTTPException(status_code=404, detail="Agent workflow not found or could not be updated")
    
    return result
