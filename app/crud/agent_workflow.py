import uuid
import logging
from datetime import datetime, timezone
from app.db.database import agent_workflow_collection, agent_workflow_history_collection
from app.crud.agent_template import get_agent_template

logging.basicConfig(level=logging.INFO)

async def save_agent_workflow(shipper_id: str, workflow: dict, user: dict):
    agent= workflow.get("agent_name")
    template = await get_agent_template(agent)
    if not template:
        logging.error(f"No template found for agent: {agent}")
        return None
    else:
        logging.info(f"Template found for agent: {agent}")

    workflow = template  
    workflow["agent_id"] = str(uuid.uuid4())  
    workflow["status"] = workflow.get("status", "active")
    workflow["shipper_id"] = shipper_id
    workflow["created_at"] = datetime.now(timezone.utc).isoformat()
    workflow["created_by"] = user["userId"]
    

    existing_workflow = await agent_workflow_collection.find_one({"shipper_id": shipper_id})
    if existing_workflow:
        logging.warning(f"Workflow already exists for shipper_id: {shipper_id}")
        return None

    try:
        result = await agent_workflow_collection.insert_one(workflow)
        logging.info(f"Workflow successfully inserted with ID: {result.inserted_id}")
        
        inserted_workflow = await agent_workflow_collection.find_one({"_id": result.inserted_id})
        return inserted_workflow  
    except Exception as e:
        logging.error(f"Error inserting workflow: {e}")
        return None


async def update_agent_workflow(shipper_id: str, workflow: dict, user: dict):
    logging.info(f"Attempting to update workflow for shipper_id: {shipper_id}, workflow: {workflow}, user: {user}")

    existing_workflow = await agent_workflow_collection.find_one({"shipper_id": shipper_id})
    
    if not existing_workflow:
        logging.error(f"No existing workflow found for shipper_id: {shipper_id}")
        return None


    workflow_history = existing_workflow.copy()
    workflow_history.pop('_id', None)  
    workflow_history["updated_at"] = datetime.now(timezone.utc).isoformat()
    workflow_history["updated_by"] = user["userId"]
    
    await agent_workflow_history_collection.insert_one(workflow_history)
    logging.info(f"Inserted workflow history for shipper_id: {shipper_id}")

    try:
        result = await agent_workflow_collection.update_one(
            {"shipper_id": shipper_id},
            {
                "$set": {
                    "agent_name": workflow.get("agent_name", existing_workflow["agent_name"]),
                    "workflows": workflow.get("workflows", existing_workflow["workflows"]),
                    "data_set_access": workflow.get("data_set_access", existing_workflow["data_set_access"]),
                    "status": workflow.get("status", existing_workflow["status"]),
                    "updated_by": user["userId"],
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
            }
        )

        if result.modified_count > 0:
            logging.info(f"Successfully updated workflow for shipper_id: {shipper_id}")
            updated_workflow = await agent_workflow_collection.find_one({"shipper_id": shipper_id})
            return updated_workflow
        else:
            logging.warning(f"No modifications made for shipper_id: {shipper_id}")
            return None

    except Exception as e:
        logging.error(f"Error updating workflow for shipper_id: {shipper_id}, error: {e}")
        return None
