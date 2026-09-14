# API routes module
from .devices import router as devices_router
from .logs import router as logs_router
from .views import router as views_router

__all__ = ["devices_router", "logs_router", "views_router"]
