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

def brute_force_success(event):
    ip  = event.get("IP")
    now = event.get("Timestamp")
    if not ip or not now:
        return None

    if event["Event type"] == "failed_password":
        failed_ips[ip].append(now)
        failed_ips[ip] = [t for t in failed_ips[ip]
                          if now - t < timedelta(minutes=5)]

    if event["Event type"] == "accepted_password":
        recent = [t for t in failed_ips.get(ip, [])
                  if now - t < timedelta(minutes=5)]
        if recent:
            failed_ips[ip].clear()
            return {
                "TIME":        now.strftime("%Y-%m-%d %H:%M:%S"),
                "SEVERITY":    "Critical",
                "TYPE":        "Brute force – udany atak",
                "MITRE ATT&CK": "T1110.001",
                "Description": f"IP {ip} odgadło hasło użytkownika "
                               f"{event.get('Username')} po {len(recent)} próbach"
            }


def credential_stuffing(event):
    if event["Event type"] != "invalid_user_attempt":
        return None
    ip   = event.get("IP")
    user = event.get("Username")
    now  = event.get("Timestamp")
    if not ip or not user or not now:
        return None

    cred_stuff[ip].add(user)

    if len(cred_stuff[ip]) >= 4:
        count = len(cred_stuff[ip])
        cred_stuff[ip].clear()
        return {
            "TIME":        now.strftime("%Y-%m-%d %H:%M:%S"),
            "SEVERITY":    "High",
            "TYPE":        "Credential stuffing",
            "MITRE ATT&CK": "T1110.004",
            "Description": f"IP {ip} próbowało {count} różnych nieistniejących loginów"
        }


def ssh_scan(event):
    if event["Event type"] != "maxstartups_throttle_start":
        return None
    now = event.get("Timestamp")
    return {
        "TIME":        now.strftime("%Y-%m-%d %H:%M:%S"),
        "SEVERITY":    "Medium",
        "TYPE":        "Skanowanie SSH",
        "MITRE ATT&CK": "T1046",
        "Description": "sshd osiągnął MaxStartups – zbyt wiele równoczesnych połączeń"
    }


def repeated_sudo_fail(event):
    if event["Event type"] != "failed_sudo":
        return None
    user = event.get("Username")
    now  = event.get("Timestamp")
    if not user or not now:
        return None

    sudo_fails[user].append(now)
    sudo_fails[user] = [t for t in sudo_fails[user]
                        if now - t < timedelta(minutes=10)]

    if len(sudo_fails[user]) >= 3:
        sudo_fails[user].clear()
        return {
            "TIME":        now.strftime("%Y-%m-%d %H:%M:%S"),
            "SEVERITY":    "High",
            "TYPE":        "Wielokrotny błąd sudo",
            "MITRE ATT&CK": "T1548.003",
            "Description": f"{user} 3+ razy podał błędne hasło przy sudo w ciągu 10 minut"
        }


def del_group(event):
    if event["Event type"] != "del_group":
        return None
    now   = event.get("Timestamp")
    group = event.get("Group")
    return {
        "TIME":        now.strftime("%Y-%m-%d %H:%M:%S"),
        "SEVERITY":    "Medium",
        "TYPE":        "Usunięcie grupy",
        "MITRE ATT&CK": "T1531",
        "Description": f"Grupa '{group}' została usunięta"
    }


def user_add_failed(event):
    if event["Event type"] != "user_add_failed":
        return None
    now  = event.get("Timestamp")
    user = event.get("Username")
    return {
        "TIME":        now.strftime("%Y-%m-%d %H:%M:%S"),
        "SEVERITY":    "Medium",
        "TYPE":        "Nieudane dodanie użytkownika",
        "MITRE ATT&CK": "T1136.001",
        "Description": f"Nieudana próba dodania użytkownika '{user}'"
    }


def off_hours_login(event):
    if event["Event type"] not in ("accepted_password", "accepted_publickey"):
        return None
    now  = event.get("Timestamp")
    user = event.get("Username")
    ip   = event.get("IP")
    if not now:
        return None

    hour    = now.hour
    weekday = now.weekday()  # 0=pon, 6=nie
    is_work_hours = (weekday < 5) and (8 <= hour < 18)

    if not is_work_hours:
        return {
            "TIME":        now.strftime("%Y-%m-%d %H:%M:%S"),
            "SEVERITY":    "Medium",
            "TYPE":        "Logowanie poza godzinami",
            "MITRE ATT&CK": "T1078",
            "Description": f"Użytkownik {user} zalogował się z {ip} "
                           f"o {now.strftime('%H:%M')} "
                           f"({'weekend' if weekday >= 5 else 'poza godz. pracy'})"
        }


def root_session_opened(event):
    if event["Event type"] != "new_session":
        return None
    if event.get("Username") != "root":
        return None
    now = event.get("Timestamp")
    return {
        "TIME":        now.strftime("%Y-%m-%d %H:%M:%S"),
        "SEVERITY":    "High",
        "TYPE":        "Sesja roota (systemd)",
        "MITRE ATT&CK": "T1078.003",
        "Description": "systemd-logind zarejestrował nową sesję dla użytkownika root"
    }


def password_update_failed(event):
    if event["Event type"] != "update_login_failed":
        return None
    now  = event.get("Timestamp")
    user = event.get("Username")
    return {
        "TIME":        now.strftime("%Y-%m-%d %H:%M:%S"),
        "SEVERITY":    "Low",
        "TYPE":        "Błąd aktualizacji keyring",
        "MITRE ATT&CK": "T1556",
        "Description": f"Nie udało się zsynchronizować hasła keyringa dla {user}"
    }


def cant_view_passwd(event):
    if event["Event type"] != "cant_view_or_modify_passwd":
        return None
    now  = event.get("Timestamp")
    user = event.get("Username")
    return {
        "TIME":        now.strftime("%Y-%m-%d %H:%M:%S"),
        "SEVERITY":    "Medium",
        "TYPE":        "Próba dostępu do /etc/passwd",
        "MITRE ATT&CK": "T1087.001",
        "Description": f"{user} próbował wyświetlić lub zmodyfikować /etc/passwd bez uprawnień"
    }