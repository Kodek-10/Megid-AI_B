
from fastapi import APIRouter
router = APIRouter(prefix="/community", tags=["Communauté"])

@router.get("/stats")
async def get_stats():
    return {"total_reports": 0, "threats_blocked_today": 0, "active_users": 0}
