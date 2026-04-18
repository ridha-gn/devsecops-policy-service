import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from api.routes import router

app = FastAPI(
    title="DevSecOps Policy Service",
    description="Analyzes infrastructure code and enforces security policies",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

@app.get("/")
async def dashboard():
    return FileResponse("dashboard.html")

if __name__ == "__main__":
    print("Starting DevSecOps Policy Service...")
    print("Dashboard: http://localhost:8000")
    print("API Docs:  http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
