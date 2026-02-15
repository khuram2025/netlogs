"""
Pydantic schemas for Address Objects.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class AddressObjectCreate(BaseModel):
    """Schema for creating an address object."""
    name: str = Field(..., min_length=1, max_length=255)
    obj_type: str = Field(..., max_length=20)
    value: str = Field(..., min_length=1, max_length=500)
    description: Optional[str] = None
    source: Optional[str] = Field(None, max_length=50)
    members: Optional[str] = None

    @field_validator('obj_type')
    @classmethod
    def validate_type(cls, v: str) -> str:
        v = v.lower().strip()
        valid = ['host', 'subnet', 'range', 'fqdn', 'group']
        if v not in valid:
            raise ValueError(f'Type must be one of: {", ".join(valid)}')
        return v

    @field_validator('source')
    @classmethod
    def validate_source(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.lower().strip()
        valid = ['fortigate', 'paloalto', 'cisco', 'csv', 'manual']
        if v not in valid:
            raise ValueError(f'Source must be one of: {", ".join(valid)}')
        return v


class AddressObjectResponse(BaseModel):
    """Schema for address object response."""
    id: int
    name: str
    obj_type: str
    value: str
    description: Optional[str]
    source: Optional[str]
    members: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
