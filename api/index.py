import sys
import os

# Add the project root directory to sys.path so 'app' module can be imported in Vercel Serverless environment
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from app.main import app

# Export the ASGI application for Vercel's Python runtime
handler = app
