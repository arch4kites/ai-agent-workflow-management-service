from motor.motor_asyncio import AsyncIOMotorClient

MONGO_URL = "mongodb://localhost:27017"
DATABASE_NAME = "AgentWorkflowManagement"

client = AsyncIOMotorClient(MONGO_URL)
db = client[DATABASE_NAME]

template_collection = db["agent_workflow_templates"]
agent_workflow_collection = db["agent_workflows"]
agent_workflow_history_collection = db["agent_workflows_history"]
