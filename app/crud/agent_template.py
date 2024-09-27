from app.db.database import template_collection
from app.schemas.agent_template import AgentTemplateSchema

async def get_agent_template(agent_name: str):
    template = await template_collection.find_one({"agent_name": agent_name})
    if template:
        template.pop("_id", None)
    return template

async def save_agent_template(template: AgentTemplateSchema):
    result = await template_collection.insert_one(template.dict())
    inserted_template = await template_collection.find_one({"_id": result.inserted_id})
    if inserted_template:
        inserted_template.pop("_id", None)
    return inserted_template
