from collections import defaultdict
from datetime import timedelta


failed = defaultdict(list)
alert = {}

def brute_force(event):
    if event["Event type"] != "failed_password":
        return None
    now = event["Timestamp"]
    ip = event["IP"]
    user = event["Username"]
    failed[ip].append(now)
    failed[ip] = [timestamp for timestamp in failed[ip] if now - timestamp < timedelta(seconds=30)]

    if len(failed[ip]) > 5:
        if alert.get(ip) is None or now - alert.get(ip) > timedelta(seconds=20):
            alert[ip] = now
            return {
            "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
            "SEVERITY": "High",
            "TYPE": "Brute Force",
            "MITRE ATT&CK": "T1110.001",
            "Description": f"Attack from {ip} - 5+ incorrect password for {user}!"
            }
        
def login_root(event):
    if event["Event type"] != "accepted_password" or event["Username"] != "root":
        return None
    now = event["Timestamp"]
    ip = event["IP"]
    return {
            "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
            "SEVERITY": "High",
            "TYPE": "Root login",
            "MITRE ATT&CK": "T1078.003",
            "Description": f"Login as root from: {ip}"
            }
    
    

        


    