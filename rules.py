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
            "SEVERITY": "HIGH",
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
            "SEVERITY": "HIGH",
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
        "SEVERITY": "HIGH",
        "TYPE": "Root login",
        "MITRE ATT&CK": "T1078.003",
        "Description": f"Successful login for root"
    }

password_spray_state = defaultdict(list)
password_spray_alert = {}
def password_spray(event):
    if event["Event type"] != "failed_password":
        return None
    now = event["Timestamp"] 
    ip = event["IP"]
    user = event["Username"]
    password_spray_state[ip].append((user, now))

    password_spray_state[ip] = [
        (u, t) for u, t in password_spray_state[ip]
        if now - t < timedelta(seconds=40)
    ]

    users = set(u for u, t in password_spray_state[ip])
    if len(users) >= 5:
        if password_spray_alert.get(ip) is None or now - password_spray_alert[ip] > timedelta(seconds=60):
            password_spray_alert[ip] = now
            return {
                "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
                "SEVERITY": "HIGH",
                "TYPE": "Password Spray",
                "MITRE ATT&CK": "T1110.003",
                "Description": f"Password spraying from {ip} against users: {', '.join(users)}"
            }

bf_state = defaultdict(list)
bf_alert = {}

def successful_after_bruteforce(event):
    ip = event["IP"]
    now = event["Timestamp"]

    if event["Event type"] == "failed_password":
        bf_state[ip].append(now)
        bf_state[ip] = [
            t for t in bf_state[ip]
            if now - t < timedelta(minutes=2)
        ]

    if event["Event type"] == "accepted_password":
        if len(bf_state[ip]) >= 5:
            if bf_alert.get(ip) is None or now - bf_alert[ip] > timedelta(minutes=3):
                bf_alert[ip] = now
                return {
                    "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
                    "SEVERITY": "CRITICAL",
                    "TYPE": "Brute Force Success",
                    "MITRE ATT&CK": "T1110",
                    "Description": f"Successful login after brute force from {ip}"
                }
                
                
offhours_alert = {}

def off_hours_login(event):
    if event["Event type"] not in ["accepted_password", "accepted_publickey"]:
        return None

    now = event["Timestamp"]
    ip = event["IP"]
    user = event["Username"]

    if now.hour < 5 or now.hour >= 22:
        key = f"{user}-{ip}"

        if offhours_alert.get(key) is None or now - offhours_alert[key] > timedelta(hours=1):
            offhours_alert[key] = now
            return {
                "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
                "SEVERITY": "MEDIUM",
                "TYPE": "Off Hours Login",
                "MITRE ATT&CK": "T1078",
                "Description": f"{user} login from {ip} off-hours"
            }

sudo_state = defaultdict(list)
sudo_alert = {}

def multiple_failed_sudo(event):
    if event["Event type"] != "failed_sudo":
        return None

    now = event["Timestamp"]
    user = event["Username"]

    sudo_state[user].append(now)
    sudo_state[user] = [
        t for t in sudo_state[user]
        if now - t < timedelta(minutes=2)
    ]

    if len(sudo_state[user]) >= 3:
        if sudo_alert.get(user) is None or now - sudo_alert[user] > timedelta(minutes=5):
            sudo_alert[user] = now
            return {
                "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
                "SEVERITY": "MEDIUM",
                "TYPE": "Failed sudo",
                "MITRE ATT&CK": "T1548.003",
                "Description": f"{user} multiple sudo failures"
            }
        
privesc_state = defaultdict(list)
privesc_alert = {}

def privilege_escalation_chain(event):
    user = event["Username"]
    now = event["Timestamp"]

    if event["Event type"] in ["accepted_password", "sudo_command", "session_opened"]:
        privesc_state[user].append((event["Event type"], now))

    privesc_state[user] = [
        (e, t) for e, t in privesc_state[user]
        if now - t < timedelta(minutes=3)
    ]

    events = [e for e, t in privesc_state[user]]

    if "accepted_password" in events and "sudo_command" in events:
        if privesc_alert.get(user) is None or now - privesc_alert[user] > timedelta(minutes=10):
            privesc_alert[user] = now
            return {
                "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
                "SEVERITY": "HIGH",
                "TYPE": "Privilege Escalation Chain",
                "MITRE ATT&CK": "T1548",
                "Description": f"Privilege escalation suspected for {user}"
            }
        
newuser_state = defaultdict(list)
newuser_alert = {}

def new_user_sudo(event):
    user = event["Username"]
    now = event["Timestamp"]

    if event["Event type"] in ["new_user", "sudo_command"]:
        newuser_state[user].append((event["Event type"], now))

    newuser_state[user] = [
        (e, t) for e, t in newuser_state[user]
        if now - t < timedelta(minutes=10)
    ]

    events = [e for e, t in newuser_state[user]]

    if "new_user" in events and "sudo_command" in events:
        if newuser_alert.get(user) is None or now - newuser_alert[user] > timedelta(minutes=20):
            newuser_alert[user] = now
            return {
                "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
                "SEVERITY": "HIGH",
                "TYPE": "New User Privilege Abuse",
                "MITRE ATT&CK": "T1136",
                "Description": f"{user} new user + sudo activity"
            }
        
root_ip_alert = {}

def root_publickey_new_ip(event):
    if event["Event type"] != "accepted_publickey":
        return None

    if event["Username"] != "root":
        return None

    now = event["Timestamp"]
    ip = event["IP"]

    if root_ip_alert.get(ip) is None:
        root_ip_alert[ip] = now
        return {
            "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
            "SEVERITY": "HIGH",
            "TYPE": "Root SSH Key Login",
            "MITRE ATT&CK": "T1078",
            "Description": f"Root login via SSH key from {ip}"
        }
    

enum_state = defaultdict(list)
enum_alert = {}

def username_enumeration(event):
    if event["Event type"] != "invalid_user_attempt":
        return None

    now = event["Timestamp"]
    ip = event["IP"]
    user = event["Username"]

    enum_state[ip].append((user, now))

    enum_state[ip] = [
        (u, t) for u, t in enum_state[ip]
        if now - t < timedelta(minutes=2)
    ]

    users = set(u for u, t in enum_state[ip])

    if len(users) >= 6:
        if enum_alert.get(ip) is None or now - enum_alert[ip] > timedelta(minutes=5):
            enum_alert[ip] = now
            return {
                "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
                "SEVERITY": "MEDIUM",
                "TYPE": "Username Enumeration",
                "MITRE ATT&CK": "T1087.001",
                "Description": f"Username enumeration from {ip}"
            }
        
session_state = defaultdict(list)
session_alert = {}

def session_flood(event):
    if event["Event type"] != "session_opened":
        return None

    now = event["Timestamp"]
    user = event["Username"]

    session_state[user].append(now)

    session_state[user] = [
        t for t in session_state[user]
        if now - t < timedelta(seconds=60)
    ]

    if len(session_state[user]) >= 10:
        if session_alert.get(user) is None or now - session_alert[user] > timedelta(minutes=5):
            session_alert[user] = now
            return {
                "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
                "SEVERITY": "MEDIUM",
                "TYPE": "Session Flood",
                "MITRE ATT&CK": "T1078",
                "Description": f"Too many sessions for {user}"
            }
        
external_alert = {}

def external_ip_login(event):
    if event["Event type"] not in ["accepted_password", "accepted_publickey"]:
        return None

    now = event["Timestamp"]
    ip = event["IP"]
    user = event["Username"]

    trusted = ["192.168.", "10.", "172.16.", "127."]

    if not any(ip.startswith(t) for t in trusted):
        key = f"{user}-{ip}"

        if external_alert.get(key) is None or now - external_alert[key] > timedelta(hours=1):
            external_alert[key] = now
            return {
                "TIME": now.strftime("%Y-%m-%d %H:%M:%S"),
                "SEVERITY": "MEDIUM",
                "TYPE": "External Login",
                "MITRE ATT&CK": "T1078",
                "Description": f"{user} login from external IP {ip}"
            }