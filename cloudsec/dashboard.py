"""Optional local-only FastAPI dashboard that serves a previously generated JSON report."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from cloudsec.report import to_html


def create_app(report_path: str) -> FastAPI:
    app = FastAPI(title="AI Cloud Security Engine")

    def load():
        return json.loads(Path(report_path).read_text())

    @app.get("/", response_class=HTMLResponse)
    def index():
        return to_html(load())

    @app.get("/api/report")
    def report():
        return load()

    return app


def serve(report_path: str, port: int = 8000):
    import uvicorn

    uvicorn.run(create_app(report_path), host="127.0.0.1", port=port)
