from typing import Dict
from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self._connections: Dict[str, WebSocket] = {}

    async def connect(self, thread_id: str, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections[thread_id] = websocket
        print(f"[ws] Client connected: {thread_id}")

    def disconnect(self, thread_id: str) -> None:
        self._connections.pop(thread_id, None)
        print(f"[ws] Client disconnected: {thread_id}")

    async def send(self, thread_id: str, data: dict) -> bool:
        ws = self._connections.get(thread_id)
        if not ws:
            return False
        try:
            await ws.send_json(data)
            return True
        except Exception as e:
            print(f"[ws] Send error for {thread_id}: {e}")
            self.disconnect(thread_id)
            return False

    def is_connected(self, thread_id: str) -> bool:
        return thread_id in self._connections


ws_manager = ConnectionManager()