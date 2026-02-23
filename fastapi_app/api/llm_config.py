"""
LLM Configuration API - Admin only.
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from ..db.database import get_db
from ..models.llm_config import LLMConfig, LLMProvider
from ..models.user import User
from ..core.permissions import require_role
from ..core.auth import get_current_user
from ..services.ai.client import ai_client

logger = logging.getLogger(__name__)

router = APIRouter(tags=["llm_config"])
templates = Jinja2Templates(directory="fastapi_app/templates")


def _base_context(request: Request) -> dict:
    ctx = {"request": request}
    user = getattr(request.state, "current_user", None)
    ctx["current_user"] = user
    return ctx


def _render(template_name: str, request: Request, context: dict = None):
    ctx = _base_context(request)
    if context:
        ctx.update(context)
    return templates.TemplateResponse(template_name, ctx)


# ============================================================
# Pydantic Schemas
# ============================================================

class LLMConfigCreate(BaseModel):
    provider: LLMProvider
    model_name: str = Field(..., min_length=1, max_length=100)
    api_key: Optional[str] = None
    api_base_url: Optional[str] = None
    max_tokens: int = Field(default=2048, ge=100, le=8192)
    temperature: int = Field(default=0, ge=0, le=100)  # 0-100


class LLMConfigUpdate(BaseModel):
    provider: Optional[LLMProvider] = None
    model_name: Optional[str] = Field(None, min_length=1, max_length=100)
    api_key: Optional[str] = None
    api_base_url: Optional[str] = None
    max_tokens: Optional[int] = Field(None, ge=100, le=8192)
    temperature: Optional[int] = Field(None, ge=0, le=100)
    is_active: Optional[bool] = None


class LLMConfigResponse(BaseModel):
    id: int
    provider: str
    model_name: str
    api_key_set: bool
    api_base_url: Optional[str]
    is_active: bool
    max_tokens: int
    temperature: int

    class Config:
        from_attributes = True


class TestAIRequest(BaseModel):
    test_prompt: str = "Explain what a port scan is in one sentence."


# ============================================================
# UI Routes
# ============================================================

@router.get("/system/ai-settings/", response_class=HTMLResponse, name="llm_config_page",
            dependencies=[Depends(require_role("ADMIN"))])
async def llm_config_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """LLM Configuration page (Admin only)."""
    # Get existing configs
    result = await db.execute(select(LLMConfig).order_by(LLMConfig.id.desc()))
    configs = result.scalars().all()

    # Provider options with model suggestions
    provider_models = {
        "claude": [
            "claude-sonnet-4-5-20250929",
            "claude-opus-4-6-20250820",
            "claude-haiku-4-5-20251001",
        ],
        "openai": [
            "gpt-4",
            "gpt-4-turbo",
            "gpt-4o",
            "gpt-3.5-turbo",
        ],
        "ollama": [
            "llama3.2:8b",
            "llama3.2:3b",
            "mixtral:8x7b",
            "codellama:13b",
            "mistral:7b",
        ],
        "gemini": [
            "gemini-1.5-pro",
            "gemini-1.5-flash",
            "gemini-pro",
        ],
        "azure_openai": [
            "gpt-4",
            "gpt-35-turbo",
        ],
    }

    return _render("llm_config.html", request, {
        "configs": configs,
        "provider_models": provider_models,
    })


# ============================================================
# API Routes
# ============================================================

@router.get("/api/llm-config/", name="api_llm_config_list",
            dependencies=[Depends(require_role("ADMIN"))])
async def list_llm_configs(db: AsyncSession = Depends(get_db)):
    """Get all LLM configurations."""
    result = await db.execute(select(LLMConfig).order_by(LLMConfig.id.desc()))
    configs = result.scalars().all()

    return [
        LLMConfigResponse(
            id=c.id,
            provider=c.provider.value,
            model_name=c.model_name,
            api_key_set=bool(c.api_key),
            api_base_url=c.api_base_url,
            is_active=c.is_active,
            max_tokens=c.max_tokens,
            temperature=c.temperature,
        )
        for c in configs
    ]


@router.post("/api/llm-config/", name="api_llm_config_create",
             dependencies=[Depends(require_role("ADMIN"))])
async def create_llm_config(
    config_data: LLMConfigCreate,
    db: AsyncSession = Depends(get_db),
):
    """Create a new LLM configuration."""
    # If this config should be active, deactivate all others
    if True:  # New configs are active by default
        await db.execute(
            update(LLMConfig).values(is_active=False)
        )
        await db.commit()

    # Create new config
    new_config = LLMConfig(
        provider=config_data.provider,
        model_name=config_data.model_name,
        api_key=config_data.api_key,
        api_base_url=config_data.api_base_url,
        max_tokens=config_data.max_tokens,
        temperature=config_data.temperature,
        is_active=True,
    )

    db.add(new_config)
    await db.commit()
    await db.refresh(new_config)

    # Clear cached config in AI client
    ai_client._config = None

    logger.info(f"Created LLM config: {new_config.provider.value}/{new_config.model_name}")

    return LLMConfigResponse(
        id=new_config.id,
        provider=new_config.provider.value,
        model_name=new_config.model_name,
        api_key_set=bool(new_config.api_key),
        api_base_url=new_config.api_base_url,
        is_active=new_config.is_active,
        max_tokens=new_config.max_tokens,
        temperature=new_config.temperature,
    )


@router.put("/api/llm-config/{config_id}/", name="api_llm_config_update",
            dependencies=[Depends(require_role("ADMIN"))])
async def update_llm_config(
    config_id: int,
    config_data: LLMConfigUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update an existing LLM configuration."""
    result = await db.execute(select(LLMConfig).where(LLMConfig.id == config_id))
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="LLM config not found")

    # If activating this config, deactivate all others
    if config_data.is_active is True and not config.is_active:
        await db.execute(
            update(LLMConfig).where(LLMConfig.id != config_id).values(is_active=False)
        )

    # Update fields
    if config_data.provider is not None:
        config.provider = config_data.provider
    if config_data.model_name is not None:
        config.model_name = config_data.model_name
    if config_data.api_key is not None:
        config.api_key = config_data.api_key
    if config_data.api_base_url is not None:
        config.api_base_url = config_data.api_base_url
    if config_data.max_tokens is not None:
        config.max_tokens = config_data.max_tokens
    if config_data.temperature is not None:
        config.temperature = config_data.temperature
    if config_data.is_active is not None:
        config.is_active = config_data.is_active

    await db.commit()
    await db.refresh(config)

    # Clear cached config
    ai_client._config = None

    logger.info(f"Updated LLM config {config_id}")

    return LLMConfigResponse(
        id=config.id,
        provider=config.provider.value,
        model_name=config.model_name,
        api_key_set=bool(config.api_key),
        api_base_url=config.api_base_url,
        is_active=config.is_active,
        max_tokens=config.max_tokens,
        temperature=config.temperature,
    )


@router.delete("/api/llm-config/{config_id}/", name="api_llm_config_delete",
               dependencies=[Depends(require_role("ADMIN"))])
async def delete_llm_config(
    config_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Delete an LLM configuration."""
    result = await db.execute(select(LLMConfig).where(LLMConfig.id == config_id))
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="LLM config not found")

    await db.delete(config)
    await db.commit()

    # Clear cached config
    ai_client._config = None

    logger.info(f"Deleted LLM config {config_id}")

    return {"status": "deleted", "id": config_id}


@router.post("/api/llm-config/activate/{config_id}/", name="api_llm_config_activate",
             dependencies=[Depends(require_role("ADMIN"))])
async def activate_llm_config(
    config_id: int,
    db: AsyncSession = Depends(get_db),
):
    """Activate a specific LLM configuration (deactivates all others)."""
    result = await db.execute(select(LLMConfig).where(LLMConfig.id == config_id))
    config = result.scalar_one_or_none()

    if not config:
        raise HTTPException(status_code=404, detail="LLM config not found")

    # Deactivate all others
    await db.execute(update(LLMConfig).where(LLMConfig.id != config_id).values(is_active=False))

    # Activate this one
    config.is_active = True
    await db.commit()
    await db.refresh(config)

    # Clear cached config
    ai_client._config = None

    logger.info(f"Activated LLM config {config_id}")

    return {"status": "activated", "id": config_id}


@router.post("/api/llm-config/test/", name="api_llm_config_test",
             dependencies=[Depends(require_role("ADMIN"))])
async def test_llm_config(
    test_data: TestAIRequest,
    db: AsyncSession = Depends(get_db),
):
    """Test the active LLM configuration with a sample prompt."""
    try:
        if not await ai_client.is_configured():
            raise HTTPException(status_code=400, detail="No active LLM configuration found")

        response = await ai_client.complete(test_data.test_prompt)

        return {
            "status": "success",
            "response": response,
            "prompt": test_data.test_prompt,
        }
    except Exception as e:
        logger.error(f"LLM test failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Test failed: {str(e)}")
