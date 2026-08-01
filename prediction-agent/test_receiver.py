import logging
from typing import List, Dict
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Development-only alert receiver")

logger = logging.getLogger("test_receiver")
logging.basicConfig(level=logging.INFO)

received_alerts: List[Dict] = []


class AlertPayload(BaseModel):
    event_id: str
    server_name: str | None = None
    timestamp: str | None = None
    prediction: str | None = None
    confidence: float | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    flow_duration: float | None = None
    model_version: str | None = None


@app.post("/alerts")
async def receive_alert(payload: AlertPayload):
    received_alerts.append(payload.model_dump())
    logger.info("Received alert: %s", payload.model_dump())
    return {"status": "accepted"}


@app.get("/alerts")
async def get_alerts():
    return received_alerts


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8001)
