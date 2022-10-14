from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from dotenv import load_dotenv


if __name__ == "__main__":
    # Load environment variables
    load_dotenv()

    # Initialize API object
    app = FastAPI()

    # Import and attatch middleware
    from routers.middleware import middleware_dispatch
    app.add_middleware(BaseHTTPMiddleware, dispatch=middleware_dispatch)

    # Import and attatch routers
    from routers import authenticate, email
    app.include_router(authenticate.router)
    app.include_router(email.router)
