"""
run.py — Convenience script to start the development server

Usage:
    python run.py

Then open: http://localhost:8000/docs
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,   # auto-restart on file changes (dev mode)
    )
