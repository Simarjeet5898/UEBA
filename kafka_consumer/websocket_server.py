# websocket_server.py
import asyncio
import json
import redis.asyncio as redis
from fastapi import FastAPI, WebSocket
from fastapi.websockets import WebSocketDisconnect
from typing import List

app = FastAPI()
redis_client = redis.Redis()

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()

@app.websocket("/ws/anomalies")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(0.1)
    except WebSocketDisconnect:
        manager.disconnect(websocket)

async def redis_subscriber():
    pubsub = redis_client.pubsub()
    await pubsub.subscribe('anomaly_channel')
    async for message in pubsub.listen():
        if message['type'] == 'message':
            await manager.broadcast(message['data'].decode())

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(redis_subscriber())
