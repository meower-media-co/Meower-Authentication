from util.ratelimits import auto_ratelimit
from fastapi import Request, HTTPException
import time
import json
import os


async def middleware_dispatch(request:Request, call_next):
    # Initialize start time and client info object
    req_start_time = time.time()
    request.client.info = {}

    # Get client info from header
    client_info_header = request.headers.get("X-Client-Info")
    if client_info_header is not None:
        try:
            request.client.info = json.loads(client_info_header)
        except:
            raise HTTPException(status_code=400, detail="Unable to parse client info header")

    # Add user agent and IP address to client info
    request.client.info["ua"] = request.headers.get("User-Agent")
    if (os.getenv("TRUST_CF").lower() == "true") and (request.headers.get("CF-Connecting-IP") is not None):
        request.client.info["ip"] = request.headers.get("CF-Connecting-IP")
    elif (os.getenv("TRUST_PROXY").lower() == "true") and (request.headers.get("X-Forwarded-For") is not None):
        request.client.info["ip"] = request.headers.get("X-Forwarded-For")
    else:
        request.client.info["ip"] = request.client.host

    # Check ratelimit
    auto_ratelimit("global", request.client.info["ip"], 30, 60)

    # Finish request
    resp = await call_next(request)

    # Add processing time header to response
    resp.headers["X-Process-Time"] = str(time.time() - req_start_time)

    # Return response payload
    return resp
