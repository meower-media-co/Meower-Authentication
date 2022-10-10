from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from dotenv import load_dotenv
import os
import requests

# Load environment variables
load_dotenv()

if "MAIN_API" in os.environ:
    main_api_req = requests.get(f"{os.environ['MAIN_API']}/")
    if main_api_req.status_code == 200:
        # Initialize API object
        app = FastAPI()

        # Import and attatch middleware
        from routers.middleware import middleware_dispatch
        app.add_middleware(BaseHTTPMiddleware, dispatch=middleware_dispatch)

        # Import and attatch routers
        from routers import authenticate, email
        app.include_router(authenticate.router)
        app.include_router(email.router)
    else:
        print(f"Failed to contact main API (staus code: {str(main_api_req.status_code)})!\nNot registering API until main API can respond to requests.")
else:
    print("API address environment variable not set!\nPlease add 'MAIN_API' environment variable.\nNot registering API until set.")