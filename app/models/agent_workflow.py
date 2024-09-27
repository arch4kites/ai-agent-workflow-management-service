from pydantic import BaseModel
from typing import List, Dict, Optional, Any

class AgentWorkflowSchema(BaseModel):
    agent_name: str
    data_set_access: Dict[str, str]
    workflows: List[Dict[str, Any]]

class AgentWorkflowCreateSchema(AgentWorkflowSchema):
    shipper_id: str
    status: str
    created_by: str
    created_at: str

class AgentWorkflowUpdateSchema(BaseModel):
    agent_name: Optional[str]
    workflows: Optional[List[Dict[str, Any]]]
    data_set_access: Optional[Dict[str, str]]
    status: Optional[str]
    updated_by: str
    updated_at: str

