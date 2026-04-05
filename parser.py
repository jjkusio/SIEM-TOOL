import paramiko
import re 
from datetime import datetime
event_types = [
    ("failed password",               "failed_password"),
    ("accepted password",             "accepted_password"),
    ("new session",                   "new_session"),
    ("session opened",                "session_opened"),
    ("logged out",                    "session_logout"),
    ("session closed",                "session_closed"),
    ("removed session",               "session_removed"),
    ("authentication failure",        "authentication_failure"),
    ("failed su",                     "failed_sudo"),
    ("connection closed by invalid",  "invalid_user"),
    ("connection closed by",          "connection_closed_preauth"),
    ("password information for root", "passwd_root"),
    ("add '",                         "group_add"),
    ("delete '",                      "group_delete"),
    ("not in sudoers",                "user_not_in_sudoers"),
    ("command=",                      "sudo_command"),
    ("received disconnect",           "received_disconnect"),
    ("disconnected from user",        "user_disconnected"),
    ("invalid user",                  "invalid_user_attempt"),
    ("check pass",                    "check_pass"),
    ("accepted publickey",            "accepted_publickey"),
    ("connection reset by",           "connection_reset"),
    ("unable to negotiate",           "unable_to_negotiate"),
    ("new group",                     "new_group"),
    ("group added",                   "new_group"),
    ("removed shadow group",          "removed_user_group"),
    ("removed group",                 "del_group"),
    ("group '",                       "del_group"),
    ("password changed",              "password_changed"),
    ("new user",                      "new_user"),
    ("delete user",                   "del_user"),
    ("failed adding user",            "user_add_failed"),
    ("xcouldn't update the login keyring password", "update_login_failed")

    ]

ssh_client = paramiko.SSHClient()

hname = input("Enter hostname: ")
uname = input("Enter username: ")
passw = input ("Enter password: ")
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh_client.connect(hostname=hname, port=22, username=uname, password=passw)
stdin, stdout, stderr = ssh_client.exec_command("tail -f /var/log/auth.log")


def base_parser(line):
    time = re.search(r"\d{1,2}:\d{1,2}:\d{1,2}", line)
    date = re.search(r"\d{1,4}-\d{1,2}-\d{1,2}", line)
    times= (date.group() if date is not None else "") + " " + (time.group() if time is not None else "")
    timestamp = datetime.strptime(times, "%Y-%m-%d %H:%M:%S")
    parts = line.split()
    hostname = parts[1] if len(parts) > 1 else ""
    if len(parts) > 2 and parts[2].startswith("("):
        proc_name = re.search(r"(?<= \()[\w-]+", line)
    else:
        proc_name = re.search(r"[\w-]+(?=\[)", line)
    pid = re.search(r"(?<=\[)\w+", line)
    dic ={
        "Timestamp": timestamp,
        "Hostname": hostname,
        "Process name": proc_name.group() if proc_name is not None else None,
        "PID": pid.group() if pid is not None else None
    }
    return dic

def parser_auth(line):
    if ("pam_unix" in line.lower() and "su:auth" in line.lower()) or "authentication failure" in line.lower():
        username = re.search(r"(?<=user=)\w+", line)
    elif "password changed" in line.lower():
        username = re.search(r"(?<=for )\w+", line)
    elif "pam_unix" in line.lower() or "invalid user" in line.lower() or "preauth" in line.lower() or "systemd-logind" in line.lower():
        username = re.search(r"(?<=user )\w+", line)
    elif "delete user" in line.lower() or "failed adding user" in line.lower():
        username = re.search(r"(?<=user ')\w+", line)
    elif "FAILED SU" in line:
        username = re.search(r"(?<=[)] )\w+", line)
    elif "usermod" in line:
        username = re.search(r"(?<=')\w+", line)
    elif "COMMAND=" in line:
        username=re.search(r"sudo:\s+(\w+)", line)
    elif "disconnected from user" in line.lower():
        username = re.search(r"(?<=from user )\w+", line)
    elif "removed group" in line.lower():
        username = re.search(r"(?<=owned by ')\w+", line)
    elif "new user" in line.lower():
        username=re.search(r"(?<=name=)\w+", line)
    else:
        username = re.search(r"(?<=for )\w+", line)
    if ("name=" in line.lower() and "new group" in line.lower()) or "group added to" in line.lower():
        group = re.search(r"(?<=name=)\w+", line)
    else:
        group = re.search(r"(?<=group ')\w+", line)
    ip = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
    port = re.search(r"(?<=port )\w+", line)
    dic ={
        "Source ip": ip.group() if ip else None,
        "Username": username.group() if username else None,
        "Port": port.group() if port else None,
        "Group": group.group() if group else None,
        "Event type": None
    }
    if "COMMAND=" in line:
        match = re.search(r"sudo:\s+(\w+)", line)
        dic["Username"] = match.group(1) if match is not None else None
    for phrase, event in event_types:
        if phrase in line.lower():
            dic["Event type"] = event
            break
    return dic

events= []
for line in stdout:
    a = base_parser(line)
    b = parser_auth(line)
    c = a | b
    events.append(c)
    print(c)
    print(line)

  

