"""
LLM Configuration model for AI features.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Enum as SQLEnum
import enum

from ..db.database import Base


class LLMProvider(str, enum.Enum):
    """Supported LLM providers."""
    CLAUDE = "claude"
    OPENAI = "openai"
    OLLAMA = "ollama"
    GEMINI = "gemini"
    AZURE_OPENAI = "azure_openai"


class LLMConfig(Base):
    """
    LLM configuration for AI features.
    Only one active config allowed at a time.
    """
    __tablename__ = "llm_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    provider = Column(SQLEnum(LLMProvider), nullable=False)
    model_name = Column(String(100), nullable=False)  # e.g., claude-sonnet-4-5, gpt-4, llama3.2
    api_key = Column(Text, nullable=True)  # Encrypted in production
    api_base_url = Column(String(500), nullable=True)  # For Ollama or Azure
    is_active = Column(Boolean, default=True, nullable=False)
    max_tokens = Column(Integer, default=2048)
    temperature = Column(Integer, default=0)  # 0-100, convert to 0.0-1.0

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self):
        return f"<LLMConfig(provider='{self.provider}', model='{self.model_name}', active={self.is_active})>"
