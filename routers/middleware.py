from fastapi import Request
import time

async def process_time_header(req: Request, call_next):
    start_time = time.time()
    resp = await call_next(req)
    resp.headers["X-Process-Time"] = str(time.time() - start_time)
    return resp