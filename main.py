import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import os

from app.api import router as api_router
from app.database import init_db

app = FastAPI(
    title="SENTINEL-X 2.0 | AI Security Operations Center",
    description="Real-Time Network Telemetry, Scapy Sniffing, and Deep Learning Anomaly Detection Platform",
    version="2.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Router
app.include_router(api_router)

# Mount Static Frontend Files
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/css", StaticFiles(directory=os.path.join(frontend_dir, "css")), name="css")
    app.mount("/js", StaticFiles(directory=os.path.join(frontend_dir, "js")), name="js")

@app.get("/")
@app.get("/login")
@app.get("/dashboard")
@app.get("/events")
@app.get("/incidents")
@app.get("/devices")
@app.get("/alerts")
@app.get("/audit")
@app.get("/models")
@app.get("/datasets")
@app.get("/reports")
@app.get("/settings")
@app.get("/help")
def read_root():
    index_path = os.path.join(frontend_dir, "index.html")
    return FileResponse(index_path)

if __name__ == "__main__":
    init_db()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    print("\n" + "="*70)
    print(" [*] SENTINEL-X 2.0 | AI SECURITY OPERATIONS CENTER WEB PLATFORM")
    print(f" [>] Web Application Server starting at: http://{host}:{port}")
    print("="*70 + "\n")
    uvicorn.run("main:app", host=host, port=port, reload=False)
