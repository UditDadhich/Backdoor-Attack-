import sys
import subprocess
import time
import webbrowser
from threading import Thread

def install_dependencies():
    print("Checking and installing web server dependencies (fastapi, uvicorn)...")
    try:
        import fastapi
        import uvicorn
        import pydantic
        print("All dependencies already installed.")
    except ImportError:
        print("Installing missing packages...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "fastapi", "uvicorn", "pydantic"])
        print("Dependencies successfully installed!")

def start_server():
    import uvicorn
    # Start the server on port 8000
    uvicorn.run("aegis_llm.api:app", host="127.0.0.1", port=8000, log_level="info")

if __name__ == "__main__":
    install_dependencies()
    
    print("\nStarting Aegis-LLM Security API Server...")
    # Start the server in a separate background thread
    server_thread = Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # Give the server a moment to bind to the port
    time.sleep(2.0)
    
    dashboard_url = "http://127.0.0.1:8000/dashboard"
    print(f"\nOpening dashboard in your web browser: {dashboard_url}")
    webbrowser.open(dashboard_url)
    
    print("\n" + "="*80)
    print(" Aegis-LLM is running active protection in the background.")
    print(" You can interact with the sandbox webpage now.")
    print(" To stop the server, press Ctrl+C in this terminal window.")
    print("="*80 + "\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down security gateway...")
        sys.exit(0)
