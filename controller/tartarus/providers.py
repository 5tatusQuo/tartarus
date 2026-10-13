from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol


class CodexProvider(Protocol):
    """Supplies Codex process authentication without exposing credentials to callers."""

    def prepare(self, command: list[str]) -> tuple[list[str], dict[str, str] | None]: ...


@dataclass(frozen=True)
class CliCodexProvider:
    def prepare(self, command: list[str]) -> tuple[list[str], dict[str, str] | None]:
        return command, None


@dataclass(frozen=True)
class ChatGPTCodexProvider:
    access_token: Callable[[], str]

    def prepare(self, command: list[str]) -> tuple[list[str], dict[str, str] | None]:
        environment = os.environ.copy()
        environment["TARTARUS_CHATGPT_ACCESS_TOKEN"] = self.access_token()
        provider = [
            "--config",
            'model_provider="openai_chatgpt_plan"',
            "--config",
            'model_providers.openai_chatgpt_plan.name="ChatGPT plan"',
            "--config",
            'model_providers.openai_chatgpt_plan.base_url="https://api.openai.com/v1"',
            "--config",
            'model_providers.openai_chatgpt_plan.env_key="TARTARUS_CHATGPT_ACCESS_TOKEN"',
            "--config",
            'model_providers.openai_chatgpt_plan.wire_api="responses"',
            "--config",
            "model_providers.openai_chatgpt_plan.requires_openai_auth=false",
            "--config",
            "model_providers.openai_chatgpt_plan.supports_websockets=false",
        ]
        return [*command[:-1], *provider, command[-1]], environment

    def app_server_command(self, executable: str = "codex") -> list[str]:
        """Return the documented app-server transport for interactive clients."""
        return [
            executable,
            "app-server",
            "--listen",
            "stdio://",
            "-c",
            'model_provider="openai_chatgpt_plan"',
            "-c",
            'model_providers.openai_chatgpt_plan.name="ChatGPT plan"',
            "-c",
            'model_providers.openai_chatgpt_plan.base_url="https://api.openai.com/v1"',
            "-c",
            'model_providers.openai_chatgpt_plan.env_key="TARTARUS_CHATGPT_ACCESS_TOKEN"',
            "-c",
            'model_providers.openai_chatgpt_plan.wire_api="responses"',
            "-c",
            "model_providers.openai_chatgpt_plan.requires_openai_auth=false",
            "-c",
            "model_providers.openai_chatgpt_plan.supports_websockets=false",
        ]
