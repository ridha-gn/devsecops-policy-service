import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from api.routes import router
from api.users import router as users_router

app = FastAPI(
    title="DevSecOps Policy Service",
    description=(
        "Analyzes infrastructure code and enforces security policies. "
        "Protected by Role-Based Access Control (RBAC).\n\n"
        "**Roles:** Developer · DevOps Engineer · Security Officer · Super Admin"
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(router)


app.include_router(users_router)


@app.get("/", include_in_schema=False)
async def dashboard():
    return FileResponse("dashboard.html")


if __name__ == "__main__":
    print("=" * 60)
    print("  DevSecOps Policy Service v2.0  --  RBAC Enabled")
    print("=" * 60)
    print("  Dashboard : http://localhost:8000")
    print("  API Docs  : http://localhost:8000/docs")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000)
