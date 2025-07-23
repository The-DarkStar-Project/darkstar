"""
openvas_connector.py

A simple async HTTP connector for the OpenVAS FastAPI service.
Provides methods to create/list targets, create/start/list tasks, and fetch reports.

Usage:
    from openvas_connector import OpenVASAPIClient
    client = OpenVASAPIClient()
    await client.create_target("example", ["192.168.1.1"])
"""

import os
from typing import List, Dict, Any, Optional

import httpx

# Base URL of the FastAPI OpenVAS service
BASE_URL = os.getenv("OPENVAS_API_URL", "http://openvas-api:8008")


class OpenVASAPIClient:
    """
    Async client to interact with the OpenVAS FastAPI HTTP API.
    """

    def __init__(self, base_url: str = None):
        self.base_url = base_url or BASE_URL
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "OpenVASAPIClient":
        self._client = httpx.AsyncClient(base_url=self.base_url)
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self._client.aclose()

    async def create_target(
        self,
        name: str,
        hosts: List[str],
        port_range: str = "1-65535",
        port_list_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload = {"name": name, "hosts": hosts, "port_range": port_range}
        if port_list_id:
            payload["port_list_id"] = port_list_id
        resp = await self._client.post("/targets", json=payload)
        resp.raise_for_status()
        return resp.json()

    async def list_targets(self) -> List[Dict[str, Any]]:
        resp = await self._client.get("/targets")
        resp.raise_for_status()
        return resp.json()

    async def create_task(self, name: str, target_id: str) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"name": name, "target_id": target_id}
        resp = await self._client.post("/tasks", json=payload)
        resp.raise_for_status()
        return resp.json()

    async def list_tasks(self) -> List[Dict[str, Any]]:
        resp = await self._client.get("/tasks")
        resp.raise_for_status()
        return resp.json()

    async def start_task(self, task_id: str) -> Dict[str, Any]:
        resp = await self._client.post(f"/tasks/{task_id}/start")
        resp.raise_for_status()
        return resp.json()

    async def get_task_status(self, task_id: str) -> Dict[str, Any]:
        resp = await self._client.get(f"/tasks/{task_id}/status")
        resp.raise_for_status()
        return resp.json()

    async def get_report(self, report_id: str) -> str:
        url = f"/reports/{report_id}"
        resp = await self._client.get(url)
        resp.raise_for_status()
        return resp.text


# Convenience functions for one-off use without context manager
async def create_target(name: str, hosts: List[str], **kwargs) -> Dict[str, Any]:
    async with OpenVASAPIClient() as client:
        return await client.create_target(name, hosts, **kwargs)


async def list_targets() -> List[Dict[str, Any]]:
    async with OpenVASAPIClient() as client:
        return await client.list_targets()


async def create_task(name: str, target_id: str, **kwargs) -> Dict[str, Any]:
    async with OpenVASAPIClient() as client:
        return await client.create_task(name, target_id, **kwargs)


async def list_tasks() -> List[Dict[str, Any]]:
    async with OpenVASAPIClient() as client:
        return await client.list_tasks()


async def start_task(task_id: str) -> Dict[str, Any]:
    async with OpenVASAPIClient() as client:
        return await client.start_task(task_id)


async def get_task_status(task_id: str) -> Dict[str, Any]:
    async with OpenVASAPIClient() as client:
        return await client.get_task_status(task_id)


async def get_report(report_id: str) -> str:
    async with OpenVASAPIClient() as client:
        return await client.get_report(report_id)
