import os
from typing import Optional
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    PROJECT_NAME: str = "SentinelAI - Autonomous SOC Analyst & Threat Hunter"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Server configuration
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Threat Intelligence API Keys (Optional, fallback to high-fidelity offline engine if absent)
    ABUSEIPDB_API_KEY: Optional[str] = os.getenv("ABUSEIPDB_API_KEY", "")
    VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY", "")
    
    # LLM Providers (Free / Local options prioritized)
    GEMINI_API_KEY: Optional[str] = os.getenv("GEMINI_API_KEY", "")
    GROQ_API_KEY: Optional[str] = os.getenv("GROQ_API_KEY", "")
    OPENAI_API_KEY: Optional[str] = os.getenv("OPENAI_API_KEY", "")
    OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3")
    
    # Provider selection: "auto", "gemini", "groq", "ollama", "openai", "heuristic"
    LLM_PROVIDER: str = os.getenv("LLM_PROVIDER", "auto")
    
    # Threat Intel Cache Expiration (seconds)
    CACHE_TTL: int = 86400  # 24 hours

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
