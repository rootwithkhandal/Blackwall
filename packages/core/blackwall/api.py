import threading
import uvicorn
import os
import json
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from blackwall.firewall import Firewall

def start_api_server(fw: Firewall, port: int = 8000):
    """
    Spawns a FastAPI application in a background daemon thread.
    Exposes firewall rules, banned IPs, stats, and the ledger.
    """
    app = FastAPI(
        title="BlackWall SOC API",
        description="REST API for automated SOC integrations (n8n, Tines, Slack).",
        version="2.1.0"
    )

    docs_dir = os.path.join(os.getcwd(), "docs")
    if os.path.exists(docs_dir):
        app.mount("/docs", StaticFiles(directory=docs_dir, html=True), name="docs")

    @app.get("/rules", tags=["Firewall"])
    def get_rules():
        """Get all active firewall rules."""
        return {"rules": fw.get_rules()}

    @app.get("/banned", tags=["Firewall"])
    def get_banned():
        """Get the current list of auto-banned IP addresses."""
        return {"banned_ips": sorted(list(fw.banned_ips))}

    @app.get("/stats", tags=["Metrics"])
    def get_stats():
        """Get live firewall traffic and enforcement statistics."""
        return fw.get_stats()

    @app.get("/ledger", tags=["Logging"])
    def get_ledger(limit: int = 50):
        """Get the most recent lines from the ledger."""
        lines = []
        ledger_path = os.path.join(os.getcwd(), "data", "ledger.jsonl")
        total = 0
        if os.path.exists(ledger_path):
            with open(ledger_path, "r") as f:
                all_lines = f.readlines()
                total = len(all_lines)
                for line in all_lines[-limit:]:
                    try:
                        lines.append(json.loads(line))
                    except:
                        pass
        return {
            "total_logs": total,
            "limit": limit,
            "logs": lines
        }

    def _run():
        try:
            with open("api_error.log", "a") as f:
                f.write(f"[api] Starting SOC REST API on 0.0.0.0:{port} ...\n")
            import asyncio
            config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="warning")
            server = uvicorn.Server(config)
            asyncio.run(server.serve())
            with open("api_error.log", "a") as f:
                f.write("[api] Server stopped.\n")
        except Exception as e:
            with open("api_error.log", "a") as f:
                import traceback
                f.write(f"[api] Fatal Uvicorn Error: {e}\n{traceback.format_exc()}\n")

    t = threading.Thread(target=_run, daemon=True, name="FastAPI_Thread")
    t.start()
