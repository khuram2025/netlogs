"""
Pydantic schemas for Project and Communication Matrix.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator
import re


class CommunicationMatrixEntryCreate(BaseModel):
    """Schema for creating a communication matrix entry."""
    source_ip: str = Field(..., min_length=1, max_length=45)
    source_hostname: Optional[str] = Field(None, max_length=255)
    destination_ip: str = Field(..., min_length=1, max_length=45)
    destination_hostname: Optional[str] = Field(None, max_length=255)
    destination_port: str = Field(..., min_length=1, max_length=100)
    protocol: str = Field(default="TCP", max_length=20)
    connection_type: str = Field(default="PERMANENT", max_length=20)
    description: Optional[str] = None
    is_active: bool = True

    @field_validator('source_ip', 'destination_ip')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IP address or CIDR notation."""
        v = v.strip()
        # Allow CIDR notation, IP ranges, or 'any'
        if v.lower() == 'any':
            return 'any'
        # Basic validation for IP or CIDR
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$'
        if not re.match(ip_pattern, v):
            # Allow hostname-style entries too
            if not re.match(r'^[\w\.\-]+$', v):
                raise ValueError('Invalid IP address or hostname format')
        return v

    @field_validator('destination_port')
    @classmethod
    def validate_port(cls, v: str) -> str:
        """Validate port number or range."""
        v = v.strip()
        if v.lower() == 'any':
            return 'any'
        # Allow single port, range (80-443), or comma-separated
        port_pattern = r'^(\d{1,5}(-\d{1,5})?(,\s*\d{1,5}(-\d{1,5})?)*)$'
        if not re.match(port_pattern, v):
            raise ValueError('Invalid port format. Use single port, range (80-443), or comma-separated')
        return v

    @field_validator('protocol')
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        """Validate protocol."""
        v = v.upper().strip()
        valid_protocols = ['TCP', 'UDP', 'ICMP', 'ANY', 'TCP/UDP']
        if v not in valid_protocols:
            raise ValueError(f'Protocol must be one of: {", ".join(valid_protocols)}')
        return v


class CommunicationMatrixEntryUpdate(BaseModel):
    """Schema for updating a communication matrix entry."""
    source_ip: Optional[str] = Field(None, max_length=45)
    source_hostname: Optional[str] = Field(None, max_length=255)
    destination_ip: Optional[str] = Field(None, max_length=45)
    destination_hostname: Optional[str] = Field(None, max_length=255)
    destination_port: Optional[str] = Field(None, max_length=100)
    protocol: Optional[str] = Field(None, max_length=20)
    connection_type: Optional[str] = Field(None, max_length=20)
    description: Optional[str] = None
    is_active: Optional[bool] = None


class CommunicationMatrixEntryResponse(BaseModel):
    """Schema for communication matrix entry response."""
    id: int
    project_id: int
    source_ip: str
    source_hostname: Optional[str]
    destination_ip: str
    destination_hostname: Optional[str]
    destination_port: str
    protocol: str
    connection_type: str
    connection_type_display: str
    description: Optional[str]
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ProjectCreate(BaseModel):
    """Schema for creating a project."""
    name: str = Field(..., min_length=1, max_length=255)
    owner: str = Field(..., min_length=1, max_length=255)
    resources: Optional[str] = None
    location: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    status: str = Field(default="OTHER", max_length=20)

    @field_validator('status')
    @classmethod
    def validate_status(cls, v: str) -> str:
        """Validate project status."""
        v = v.upper().strip()
        valid_statuses = ['ACTIVE', 'INACTIVE', 'ARCHIVED', 'OTHER']
        if v not in valid_statuses:
            raise ValueError(f'Status must be one of: {", ".join(valid_statuses)}')
        return v


class ProjectUpdate(BaseModel):
    """Schema for updating a project."""
    name: Optional[str] = Field(None, max_length=255)
    owner: Optional[str] = Field(None, max_length=255)
    resources: Optional[str] = None
    location: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = Field(None, max_length=20)


class ProjectResponse(BaseModel):
    """Schema for project response."""
    id: int
    name: str
    owner: str
    resources: Optional[str]
    location: Optional[str]
    description: Optional[str]
    status: str
    status_display: str
    entry_count: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ProjectDetailResponse(ProjectResponse):
    """Schema for detailed project response with communication entries."""
    communication_entries: List[CommunicationMatrixEntryResponse]

    class Config:
        from_attributes = True
