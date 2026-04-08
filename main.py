import uvicorn
import os
from dotenv import load_dotenv

# Load environment variables from .env for local development
load_dotenv()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print(f"[*] Starting SIEM Dashboard on port {port}...")
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=True)
