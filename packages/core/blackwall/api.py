import threading
import uvicorn
from fastapi import FastAPI
from blackwall.firewall import Firewall
from blackwall.blockchain import Blockchain

def start_api_server(fw: Firewall, ledger: Blockchain, port: int = 8000):
    """
    Spawns a FastAPI application in a background daemon thread.
    Exposes firewall rules, banned IPs, stats, and the blockchain ledger.
    """
    app = FastAPI(
        title="BlackWall SOC API",
        description="REST API for automated SOC integrations (n8n, Tines, Slack).",
        version="2.1.0"
    )

    @app.get("/rules", tags=["Firewall"])
    def get_rules():
        """Get all active firewall rules."""
        return {"rules": fw.get_rules()}

    @app.get("/banned", tags=["Firewall"])
    def get_banned():
        """Get the current list of auto-banned IP addresses."""
        # Using sorted list for deterministic JSON
        return {"banned_ips": sorted(list(fw.banned_ips))}

    @app.get("/stats", tags=["Metrics"])
    def get_stats():
        """Get live firewall traffic and enforcement statistics."""
        return fw.get_stats()

    @app.get("/ledger", tags=["Blockchain"])
    def get_ledger(limit: int = 50):
        """Get the most recent blocks from the immutable ledger."""
        chain = [b.to_dict() for b in ledger.chain[-limit:]]
        return {
            "total_blocks": len(ledger.chain),
            "limit": limit,
            "blocks": chain
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
