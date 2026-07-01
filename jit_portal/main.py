"""JIT Access Portal - Main Application"""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn

from routers import jit

app = FastAPI(
    title="JIT Access Portal",
    version="1.0.0",
    description="Just-In-Time Access Management for Critical Resources"
)

app.include_router(jit.router, prefix="/api/jit", tags=["JIT Access"])

templates = Jinja2Templates(directory="templates")

@app.get("/")
async def root():
    return templates.TemplateResponse("index.html", {"request": {}})

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "jit-portal"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8003, reload=True)
