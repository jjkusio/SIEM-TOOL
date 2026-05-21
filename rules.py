from collections import defaultdict
from datetime import timedelta


failed = defaultdict(list)
alert = {}
failed_ips        = defaultdict(list)  
cred_stuff        = defaultdict(set)   
sudo_fails        = defaultdict(list) 

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
    
def not_in_sudoers(event):
    if event["Event type"] != "user_not_in_sudoers":
        return None
    now = event["Timestamp"]
    user = event["Username"]
    return {
            "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
            "SEVERITY": "HIGH",
            "TYPE": "User not in sudoers",
            "MITRE ATT&CK": "T1548.003",
            "Description": f"{user} not in sudoers"
            }

def invalid_user(event):
    if event["Event type"] != "invalid_user_attempt":
        return None
    user = event["Username"]
    now = event["Timestamp"]
    return {
        "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
        "SEVERITY": "HIGH",
        "TYPE": "User does not exist",
        "MITRE ATT&CK": "T1087.001",
        "Description": f"User {user} does not exist"
    }

def failed_sudo(event):
    if event["Event type"] != "failed_sudo":
        return None
    user=event["Username"]
    now = event["Timestamp"]
    return{
        "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
        "SEVERITY": "MEDIUM",
        "TYPE": "Failed sudo command",
        "MITRE ATT&CK": "T1548.003",
        "Description": f"{user} failed a sudo command"
    }
    

def new_user(event):
    if event["Event type"] != "new_user":
        return None
    user=event["Username"]
    now = event["Timestamp"]
    return{
        "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
        "SEVERITY": "MEDIUM",
        "TYPE": "New user added",
        "MITRE ATT&CK": "T1136.001",
        "Description": f"new User ({user}) added"
    }

def del_user(event):
    if event["Event type"] != "del_user":
        return None
    user=event["Username"]
    now = event["Timestamp"]
    return{
        "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
        "SEVERITY": "MEDIUM",
        "TYPE": "User deleted",
        "MITRE ATT&CK": "T1531",
        "Description": f"User ({user}) deleted"
    }


def pass_change(event):
    if event["Event type"] != "password_changed":
        return None
    user=event["Username"]
    now = event["Timestamp"]
    return{
        "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
        "SEVERITY": "MEDIUM",
        "TYPE": "Password changed",
        "MITRE ATT&CK": "T1098",
        "Description": f"Password changed for user  ({user})"
    }

def new_group(event):
    if event["Event type"] != "new_group":
        return None
    now = event["Timestamp"]
    group = event["Group"]
    return{
        "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
        "SEVERITY": "MEDIUM",
        "TYPE": "New group",
        "MITRE ATT&CK": "T1136",
        "Description": f"Group '{group}' added"
    }

def accepted_publickey(event):
    if event["Event type"] != "accepted_publickey" or event["Username"] !="root":
        return None
    now = event["Timestamp"]
    return{
        "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
        "SEVERITY": "High",
        "TYPE": "Root login",
        "MITRE ATT&CK": "T1078.003",
        "Description": f"Successful login for root"
    }

