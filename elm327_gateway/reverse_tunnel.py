"""
Reverse WebSocket Tunnel - Gateway connects outbound to server.

The gateway app connects TO our server (outbound HTTPS WebSocket),
so no firewall ports need to be open on either side.

Protocol:
    Gateway → Server: {"type": "register", "shop_id": "xxx", "api_key": "xxx"}
    Server → Gateway: {"type": "request", "id": "uuid", "method": "POST", "path": "/connect", "body": {...}}
    Gateway → Server: {"type": "response", "id": "uuid", "status": 200, "body": {...}}

The server keeps a registry of connected gateways by shop_id.
When the Open WebUI tool needs to talk to a gateway, it sends a request
through the server's proxy, which forwards it over the WebSocket.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Callable, Dict, Optional

try:
    import aiohttp
except ImportError:
    aiohttp = None

logger = logging.getLogger(__name__)


class GatewayTunnel:
    """
    WebSocket tunnel client that connects the gateway to the server.
    
    Receives commands from the server, executes them against
    the local gateway HTTP API, and sends results back.
    """
    
    def __init__(
        self,
        server_url: str,
        shop_id: str,
        api_key: str,
        local_gateway_port: int = 8327,
        on_status_change: Callable[[str], None] = None,
    ):
        """
        Args:
            server_url: Server WebSocket URL (wss://automotive.aurora-sentient.net)
            shop_id: Unique shop identifier
            api_key: API key for authentication
            local_gateway_port: Port where the local gateway server runs
            on_status_change: Callback when connection status changes
        """
        # Normalize URL
        if server_url.startswith("http://"):
            ws_url = server_url.replace("http://", "ws://")
        elif server_url.startswith("https://"):
            ws_url = server_url.replace("https://", "wss://")
        elif server_url.startswith(("ws://", "wss://")):
            ws_url = server_url
        else:
            ws_url = f"wss://{server_url}"
        
        self.ws_url = f"{ws_url.rstrip('/')}/api/scan_tool/gateway/tunnel"
        self.shop_id = shop_id
        self.api_key = api_key
        self.local_url = f"http://localhost:{local_gateway_port}"
        self._on_status_change = on_status_change
        
        self._ws = None
        self._session = None
        self._running = False
        self._connected = False
        self._reconnect_delay = 5  # seconds
        self._max_reconnect_delay = 60
    
    @property
    def connected(self) -> bool:
        return self._connected
    
    def _status(self, msg: str):
        """Report status change."""
        logger.info(msg)
        if self._on_status_change:
            try:
                self._on_status_change(msg)
            except:
                pass
    
    async def _get_session(self):
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def _forward_to_local(self, method: str, path: str, body: dict = None) -> dict:
        """Forward a request to the local gateway server."""
        session = await self._get_session()
        url = f"{self.local_url}{path}"
        
        try:
            if method.upper() == "GET":
                async with session.get(url, params=body) as resp:
                    return {"status": resp.status, "body": await resp.json()}
            elif method.upper() == "POST":
                async with session.post(url, json=body) as resp:
                    return {"status": resp.status, "body": await resp.json()}
            else:
                return {"status": 405, "body": {"detail": f"Unsupported method: {method}"}}
        except aiohttp.ClientConnectorError:
            return {"status": 503, "body": {"detail": "Local gateway not running"}}
        except Exception as e:
            return {"status": 500, "body": {"detail": str(e)}}
    
    async def _handle_request_background(self, request_id: str, method: str, path: str, body: dict):
        """Handle a forwarded request in a background task (non-blocking)."""
        try:
            result = await self._forward_to_local(method, path, body)

            response = {
                "type": "response",
                "id": request_id,
                "status": result["status"],
                "body": result["body"],
            }

            if self._ws and not self._ws.closed:
                await self._ws.send_str(json.dumps(response))
                logger.info(f"→ Response {request_id}: {result['status']}")
            else:
                logger.warning(f"Cannot send response {request_id}: WebSocket closed")
        except Exception as e:
            logger.error(f"Background request {request_id} failed: {e}")

    async def _handle_message(self, msg_data: str):
        """Handle an incoming message from the server."""
        try:
            msg = json.loads(msg_data)
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON from server: {msg_data[:100]}")
            return
        
        msg_type = msg.get("type")
        
        if msg_type == "request":
            # Server is forwarding a tool request to us
            request_id = msg.get("id")
            method = msg.get("method", "GET")
            path = msg.get("path", "/")
            body = msg.get("body")
            
            logger.info(f"← Request {request_id}: {method} {path}")
            
            # Run in background so the message loop keeps processing
            # pings/heartbeats while long operations (module scan) run
            asyncio.create_task(
                self._handle_request_background(request_id, method, path, body)
            )
        
        elif msg_type == "ping":
            # Server keepalive
            if self._ws and not self._ws.closed:
                await self._ws.send_str(json.dumps({"type": "pong"}))
        
        elif msg_type == "error":
            logger.error(f"Server error: {msg.get('message')}")
        
        elif msg_type == "registered":
            self._status(f"[OK] Registered as shop '{self.shop_id}'")
        
        else:
            logger.debug(f"Unknown message type: {msg_type}")
    
    async def _connect_once(self) -> bool:
        """Attempt one WebSocket connection."""
        if aiohttp is None:
            raise ImportError("aiohttp required: pip install aiohttp")
        
        session = await self._get_session()
        
        try:
            self._status(f"Connecting to {self.ws_url}...")
            
            self._ws = await session.ws_connect(
                self.ws_url,
                heartbeat=60,
                timeout=aiohttp.ClientTimeout(total=30),
            )
            
            # Register with the server
            await self._ws.send_str(json.dumps({
                "type": "register",
                "shop_id": self.shop_id,
                "api_key": self.api_key,
                "version": "1.0.0",
            }))
            
            self._connected = True
            self._status("[OK] Connected to server")
            self._reconnect_delay = 5  # Reset backoff
            
            # Message loop
            async for msg in self._ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    await self._handle_message(msg.data)
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {self._ws.exception()}")
                    break
                elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED):
                    break
            
            return True
            
        except aiohttp.ClientConnectorError as e:
            self._status(f"[ERR] Cannot reach server: {e}")
            return False
        except Exception as e:
            self._status(f"[ERR] Connection error: {e}")
            return False
        finally:
            self._connected = False
            if self._ws and not self._ws.closed:
                await self._ws.close()
                self._ws = None
    
    async def run(self):
        """
        Run the tunnel with automatic reconnection.
        
        Call this as an asyncio task - it runs forever.
        """
        self._running = True
        
        while self._running:
            await self._connect_once()
            
            if not self._running:
                break
            
            self._status(f"Reconnecting in {self._reconnect_delay}s...")
            await asyncio.sleep(self._reconnect_delay)
            
            # Exponential backoff
            self._reconnect_delay = min(
                self._reconnect_delay * 1.5,
                self._max_reconnect_delay
            )
        
        self._status("Tunnel stopped")
    
    async def stop(self):
        """Stop the tunnel."""
        self._running = False
        if self._ws and not self._ws.closed:
            await self._ws.close()
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
