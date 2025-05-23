import os
import json
from contextlib import asynccontextmanager
from typing import Optional

import posthog
from fastapi import FastAPI, Request, Depends
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from database import init_db
from config import STATIC_DIR, ASSETS_DIR, POSTHOG_API_KEY, POSTHOG_HOST, redis_client, redis_pool
from dependencies import UserSession, optional_auth
from routers.auth_router import auth_router
from routers.user_router import user_router
from routers.workspace_router import workspace_router
from routers.pad_router import pad_router
from routers.template_pad_router import template_pad_router
from database.service import TemplatePadService
from database.database import async_session, run_migrations_with_lock

# Initialize PostHog if API key is available
if POSTHOG_API_KEY:
    posthog.project_api_key = POSTHOG_API_KEY
    posthog.host = POSTHOG_HOST

async def load_templates():
    """
    Load all templates from the templates directory into the database if they don't exist.
    
    This function reads all JSON files in the templates directory, extracts the display name
    from the "appState.pad.displayName" field, uses the filename as the name, and stores
    the entire JSON as the data.
    """
    try:
        # Get a session and template service
        async with async_session() as session:
            template_service = TemplatePadService(session)
            
            # Get the templates directory path
            templates_dir = os.path.join(os.path.dirname(__file__), "templates")
            
            # Iterate through all JSON files in the templates directory
            for filename in os.listdir(templates_dir):
                if filename.endswith(".json"):
                    # Use the filename without extension as the name
                    name = os.path.splitext(filename)[0]
                    
                    # Check if template already exists
                    existing_template = await template_service.get_template_by_name(name)

                    if not existing_template:

                        file_path = os.path.join(templates_dir, filename)
                        
                        # Read the JSON file
                        with open(file_path, 'r') as f:
                            template_data = json.load(f)
                        
                        # Extract the display name from the JSON
                        display_name = template_data.get("appState", {}).get("pad", {}).get("displayName", "Untitled")
                        
                        # Create the template if it doesn't exist
                        await template_service.create_template(
                            name=name,
                            display_name=display_name,
                            data=template_data
                        )
                        print(f"Added template: {name} ({display_name})")
                    else:
                        print(f"Template already in database: '{name}'")
            
    except Exception as e:
        print(f"Error loading templates: {str(e)}")

@asynccontextmanager
async def lifespan(_: FastAPI):
    # Initialize database
    await init_db()
    print("Database connection established successfully")
    
    # Run database migrations with Redis lock
    # All workers will wait for the migration to complete before proceeding
    try:
        migration_success = await run_migrations_with_lock(
            redis_client=redis_client,
            lock_timeout=120,  # 2 minutes timeout for the lock
            max_wait_time=300  # 5 minutes maximum wait time
        )
        
        if migration_success:
            print("Database migrations completed successfully or already done")
        else:
            print("Warning: Migrations failed or timed out - proceeding with caution")
    except Exception as e:
        print(f"Warning: Failed to run migrations: {str(e)}")
    
    # Check Redis connection
    try:
        redis_client.ping()
        print("Redis connection established successfully")
    except Exception as e:
        print(f"Warning: Redis connection failed: {str(e)}")
    
    # Load all templates from the templates directory
    await load_templates()
    print("Templates loaded successfully")
    
    yield
    
    # Clean up connections when shutting down
    try:
        redis_pool.disconnect()
        print("Redis connections closed")
    except Exception as e:
        print(f"Error closing Redis connections: {str(e)}")

app = FastAPI(lifespan=lifespan)

# CORS middleware setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="assets")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
async def read_root(request: Request, auth: Optional[UserSession] = Depends(optional_auth)):
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

# Include routers in the main app with the /api prefix
app.include_router(auth_router, prefix="/auth")
app.include_router(user_router, prefix="/api/users")
app.include_router(workspace_router, prefix="/api/workspace")
app.include_router(pad_router, prefix="/api/pad")
app.include_router(template_pad_router, prefix="/api/templates")
    
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
