"""
core/security.py
All security policy enforcement.
"""
from urllib.parse import urlparse
from config import Settings


   
def is_allowed_url(url: str) -> bool:

    netloc = urlparse(url).netloc
    return netloc in Settings.ALLOWED_HOSTS
    
def is_allowed_domain(domain:str) -> bool:
    """ 
    Check if a domain is allowed based on security policy.
    """
def sanitize_headers(headers:dict) -> dict:
    """
    Sanitize headers based on security policy.
    """

    return {
        k: "[REDACTED]" if k.lower() in Settings.SENSITIVE_KEYS else v
        for k, v in headers.items()
    }
