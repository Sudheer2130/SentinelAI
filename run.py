import uvicorn
import sys
import os

BANNER = r"""
  ____             _   _            _    ___ 
 / ___|  ___ _ __ | |_(_)_ __   ___| |  / _ \
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ | | | | |
  ___) |  __/ | | | |_| | | | |  __/ | | |_| |
 |____/ \___|_| |_|\__|_|_| |_|\___|_|  \___/ 
                                             
   SentinelAI Autonomous SOC Analyst & Threat Hunter
   Real-Time SIEM Log Correlation | Threat Intel | MITRE ATT&CK
   ============================================================
"""

def main():
    print(BANNER)
    print(" [*] Initializing SentinelAI Platform...")
    print(" [*] Web Dashboard: http://127.0.0.1:8000")
    print(" [*] API Documentation: http://127.0.0.1:8000/docs")
    print(" [*] Press Ctrl+C to stop.\n")
    
    # Run uvicorn server
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)

if __name__ == "__main__":
    main()
