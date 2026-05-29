from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import requests

load_dotenv()
KEY = os.getenv("ABUSEIPDB_KEY")

def call_abuseipdb(ip):
    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90
            },
            timeout=3
        )
        data = response.json()["data"]
        return {
            "score": data["abuseConfidenceScore"],
            "reports": data["totalReports"],
            "country": data["countryCode"]
        }
    except Exception:
        return None
    
cache = {}

def get_abuse_score(ip):
    now = datetime.now()
    if ip in cache:
        cached_result, cached_time = cache[ip]
        if now - cached_time < timedelta(hours=1):
            return cached_result
        
    result = call_abuseipdb(ip)      
    cache[ip] = (result, now)    
    return result