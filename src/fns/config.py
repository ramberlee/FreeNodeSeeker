from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator


# --- Sources ---

class GithubSourceConfig(BaseModel):
    enabled: bool = True
    search_queries: list[str] = Field(default_factory=lambda: [
        "free v2ray subscription",
        "v2ray config",
        "clash node free",
        "vless free",
    ])
    max_results: int = 30
    token: str | None = None


class WebScrapeSourceConfig(BaseModel):
    enabled: bool = True
    urls: list[str] = Field(default_factory=list)
    request_delay: float = 1.0
    proxy: str | None = None


class ApiSourceConfig(BaseModel):
    enabled: bool = True
    urls: list[str] = Field(default_factory=list)


class SourcesConfig(BaseModel):
    github: GithubSourceConfig = Field(default_factory=GithubSourceConfig)
    web_scrape: WebScrapeSourceConfig = Field(default_factory=WebScrapeSourceConfig)
    api: ApiSourceConfig = Field(default_factory=ApiSourceConfig)


# --- Validator ---

class ValidatorConfig(BaseModel):
    concurrency: int = 50
    timeout: float = 5.0
    retries: int = 1
    test_url: str = "http://www.google.com/"

    @field_validator("concurrency")
    @classmethod
    def concurrency_range(cls, v: int) -> int:
        return max(1, min(v, 200))


# --- Output ---

class ClashOutputConfig(BaseModel):
    port: int = 7890
    socks_port: int = 7891
    allow_lan: bool = False
    mode: str = "Rule"
    log_level: str = "info"


class OutputConfig(BaseModel):
    formats: list[str] = Field(default_factory=lambda: ["clash", "base64"])
    clash: ClashOutputConfig = Field(default_factory=ClashOutputConfig)
    dir: str = "./output"


# --- Scheduler ---

class SchedulerConfig(BaseModel):
    interval_hours: int = 6


# --- Logging ---

class LoggingConfig(BaseModel):
    level: str = "INFO"
    file: str | None = None


# --- Top-level ---

class FnsConfig(BaseModel):
    sources: SourcesConfig = Field(default_factory=SourcesConfig)
    validator: ValidatorConfig = Field(default_factory=ValidatorConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    scheduler: SchedulerConfig = Field(default_factory=SchedulerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    max_alive_nodes: int = 0  # 0 = no limit


# --- Config I/O ---

DEFAULT_CONFIG_PATHS = [
    Path.cwd() / "fns.yaml",
    Path.cwd() / "config.yaml",
    Path(os.path.expanduser("~/.fns/config.yaml")),
]


def find_config() -> Path | None:
    for p in DEFAULT_CONFIG_PATHS:
        if p.exists():
            return p
    return None


def load_config(path: Path | None = None) -> FnsConfig:
    if path is None:
        path = find_config()
    if path is None or not path.exists():
        return FnsConfig()
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return FnsConfig(**data)


def write_example_config(path: Path) -> None:
    example = FnsConfig()
    data = example.model_dump()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
