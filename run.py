"""
Cyber Sentinel - Platform Entrypoint & Launcher
Checks ML model availability, initializes SQLite database, and runs Uvicorn ASGI server.
"""

import os
import sys
import uvicorn

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.config import URL_MODEL_PATH, TEXT_MODEL_PATH
from backend.database import init_db


def check_and_train_models():
    """Verify that serialized models exist, or trigger the training pipeline."""
    if not os.path.exists(URL_MODEL_PATH) or not os.path.exists(TEXT_MODEL_PATH):
        print("\n" + "="*60)
        print("[*] Trained models not found. Running training pipeline...")
        print("="*60)
        from ml.training.train_models import run_pipeline
        run_pipeline()
    else:
        print("[*] Trained ML models verified in ml/trained_models/.")


def main():
    print("="*60)
    print("      CYBER SENTINEL - AI THREAT DETECTION PLATFORM      ")
    print("="*60)
    
    # 1. Initialize SQLite schema
    init_db()
    print("[*] Database schema initialized.")
    
    # 2. Verify ML models
    check_and_train_models()
    
    # 3. Start Uvicorn Server
    print("\n[*] Starting Cyber Sentinel Web Server at: http://127.0.0.1:8000")
    print("[*] OpenAPI Documentation: http://127.0.0.1:8000/docs")
    print("="*60 + "\n")
    
    uvicorn.run(
        "backend.app:app",
        host="127.0.0.1",
        port=8000,
        reload=False
    )


if __name__ == "__main__":
    main()
