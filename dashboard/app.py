"""Dashboard backend: serves the prioritisation results."""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

_STATIC = Path(__file__).parent / "static"
app = FastAPI(title="Triage Dashboard")


def _load() -> dict:
    path = os.environ.get("TRIAGE_RESULTS", "triage_results.json")
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {"meta": {}, "summary": {}, "results": [], "error": f"not found: {path}"}


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (_STATIC / "index.html").read_text(encoding="utf-8")


@app.get("/api/data")
async def data() -> JSONResponse:
    return JSONResponse(_load())


app.mount("/static", StaticFiles(directory=str(_STATIC)), name="static")
