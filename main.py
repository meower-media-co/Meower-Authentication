from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from dotenv import load_dotenv
import os
import requests

# Load JWT private key
with open("jwt.pem", "r") as f:
    os.environ["JWT_PRIVATE"] = f.read()

# Load JWT public key
with open("jwt.pem.pub", "r") as f:
    os.environ["JWT_PUBLIC"] = f.read()

# Load environment variables
load_dotenv()

if "MAIN_API" in os.environ:
    main_api_req = requests.get(f"{os.environ['MAIN_API']}/auth/test")
    if main_api_req.status_code == 200:
        # Initialize API object
        app = FastAPI()

        # Import and attatch middleware
        from routers.middleware import process_time_header
        app.add_middleware(BaseHTTPMiddleware, dispatch=process_time_header)

        # Import and attatch routers
        from routers import authenticate, email
        app.include_router(authenticate.router)
        app.include_router(email.router)
    else:
        print(f"Failed to contact main API (staus code: {str(main_api_req.status_code)})!\nNot registering API until main API can respond to requests.")
else:
    print("API address environment variable not set!\nPlease add 'MAIN_API' environment variable.\nNot registering API until set.")