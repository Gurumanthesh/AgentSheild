from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class LinkModel(BaseModel):
    text: str | None = None
    url: str | None = None

    @field_validator("text", "url")
    @classmethod
    def clean_string(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return value.strip()[:2000]


class AnalyzeRequest(BaseModel):
    url: str = Field(default="", max_length=2000)
    text: str = Field(default="", max_length=12000)
    links: list[LinkModel] = Field(default_factory=list)

    @field_validator("links")
    @classmethod
    def validate_links(cls, value: list[LinkModel]) -> list[LinkModel]:
        if len(value) > 20:
            raise ValueError("links cannot exceed 20 items")
        return value

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            return value
        if len(value) > 2000:
            raise ValueError("url is too long")
        return value


class AnalysisResponse(BaseModel):
    status: str
    risk_score: int
    risk_level: str
    summary: str
    indicators: list[dict[str, Any]]
    recommendations: list[str]
    analyzed_at: str
    engine: str
