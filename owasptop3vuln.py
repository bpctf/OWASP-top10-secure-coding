import os
import importlib.util
import urllib.request
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
import sys

app = FastAPI()

# Fake database example.
# Never put plain-text passwords in your database. This is purely for the sake of this exercise.
DB = {
    1: {"id": 1, "username": "alice", "role": "user", "pass": "123"},
    2: {"id": 2, "username": "bob", "role": "admin", "pass": "admin123"}
}

@app.get("/api/user-profile")
def get_user_profile(
    user_id: int, 
    plugin_url: str = "", 
    debug_mode: str = "true"
):
    try:
        if plugin_url:
            local_plugin = "temp_plugin.py"
            urllib.request.urlretrieve(plugin_url, local_plugin)
            
            spec = importlib.util.spec_from_file_location("plugin", local_plugin)
            plugin = importlib.util.module_from_spec(spec)
            sys.modules["plugin"] = plugin
            spec.loader.exec_module(plugin)

        user_data = DB.get(user_id)
        if not user_data:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        return {
            "status": "success",
            "data": user_data
        }

    except Exception as e:
        if debug_mode.lower() == "true":
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": str(e),
                    "traceback": repr(e),
                    "environment_variables": dict(os.environ),
                    "server_info": "FastAPI/Uvicorn running on Debug Mode"
                }
            )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal Server Error")


