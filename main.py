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
    from routers import authenticate, email, current_session, internal
    app.include_router(authenticate.router)
    app.include_router(email.router)
    app.include_router(current_session.router)
    app.include_router(internal.router)

    from routers.account import authentication, sessions
    app.include_router(authentication.router)
    app.include_router(sessions.router)