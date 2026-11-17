"""ASGI entry point: `uvicorn guardrail.asgi:app --port 8100`."""
from .service import create_app

app = create_app()
