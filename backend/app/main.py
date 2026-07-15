from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import analytics, breaches, companies, match_queue

app = FastAPI(
    title="Breach Intelligence API",
    description="Unified breach intelligence ingestion & correlation platform",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your frontend's origin in production
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.include_router(breaches.router)
app.include_router(companies.router)
app.include_router(analytics.router)
app.include_router(match_queue.router)


@app.get("/health")
async def health():
    return {"status": "ok"}
