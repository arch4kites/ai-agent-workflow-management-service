from pydantic import BaseModel
from typing import List, Dict
from typing import Any

class AgentTemplateSchema(BaseModel):
    agent_id: str
    agent_name: str
    role: str
    data_set_access: Dict[str, str]
    workflows: List[Dict[str, Any]]
