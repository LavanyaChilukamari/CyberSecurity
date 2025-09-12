# Ransomware Detection Lab (full)

1. Setup venv (recommended)
   python3 -m venv venv
   source venv/bin/activate       # macOS / Linux
   .\venv\Scripts\Activate.ps1    # Windows PowerShell

2. Install deps
   pip install -r requirements.txt

3. Run app
   python ransomware_detection_tool.py

4. Open in browser:
   http://127.0.0.1:5000

Demo users:
- analyst / password123
- admin / adminpass

API:
- POST /api/detect  (JSON body: {"filename":"...","process":"...","action":"..."})
- GET  /api/logs    (optional query: ?status=Suspicious&limit=200&offset=0)
- GET  /api/logs/<id>
