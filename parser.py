import paramiko
import re 
from datetime import datetime
from rules import brute_force, login_root, not_in_sudoers, invalid_user
import streamlit as st
import pandas as pd
import threading
import queue
from streamlit_autorefresh import st_autorefresh


def base_parser(line):
    message = re.search(r"(?<=\):).+\w+", line)
    if message is None:
        message = re.search(r"(?<=\]:).+\w+", line)
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
    if proc_name == None:
        proc_name = re.search(r"\w+(?=:)", parts[2])
    pid = re.search(r"(?<=\[)\w+", line)
    port = re.search(r"(?<=port )\w+", line)
    dic ={
        "Timestamp": timestamp,
        "Hostname": hostname,
        "Process name": proc_name.group() if proc_name is not None else None,
        "Port": port.group() if port else None,
        "PID": pid.group() if pid is not None else None,
        "Message": message.group() if message else None
    }
    return dic


def base_dic():
    return {
        "Username": None,
        "IP": None,
        "Event type": None,
        "Group": None
    }

def sshd_parser(line):
    linel = line.lower()
    events = [
    ("failed password",               "failed_password"),
    ("accepted password",             "accepted_password"),
    ("connection closed by invalid",  "invalid_user"),
    ("connection closed by",          "connection_closed_preauth"),
    ("received disconnect",           "received_disconnect"),
    ("disconnected from user",        "user_disconnected"),
    ("invalid user",                  "invalid_user_attempt"),
    ("check pass",                    "check_pass"),
    ("accepted publickey",            "accepted_publickey"),
    ("connection reset by",           "connection_reset"),
    ("unable to negotiate",           "unable_to_negotiate"),
    ("session opened",                "session_opened"),  
    ("session closed",                "session_closed"),
    ("authentication failure",        "authentication_failure"),
    ("ignoring max retries",          "max_retries_ignore"),
    ("exited maxstartups",            "maxstartups_exit"),
    ("beginning maxstartups",         "maxstartups_throttle_start"),
    ]
    if "invalid user" in linel:
        username = re.search(r"(?<=invalid user )\w+", linel)
    elif "authentication failure" in linel:
        username = re.search(r"(?<=user=)\w+", line)
    elif "session opened" in linel or "session closed" in linel or "disconnected from" in linel or "check pass" in linel:
        username = re.search(r"(?<=user )\w+", line)
    else:
        username = re.search(r"(?<=for )\w+", line)
    ip = re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
    event_type = None
    for phrase, event in events:
        if phrase in linel:
            event_type = event
            break
    dic = base_dic()
    dic["Username"] = username.group() if username else None
    dic["IP"] = ip.group() if ip else None
    dic["Event type"] = event_type
    return dic

def sudo_parser(line):
    linel = line.lower()
    dic = base_dic()
    event_type = None
    events=[
        ("failed su",                     "failed_sudo"),
        ("not in sudoers",                "user_not_in_sudoers"),
        ("command=",                      "sudo_command"),
        ("session opened",                "session_opened"),
        ("session closed",                "session_closed"),
        ("authentication failure",        "authentication_failure"),
    ]
    username = None
    if "failed su" in linel:
        username = re.search(r"(?<=\) )\w+", line)
    elif "session opened" in linel or "session closed" in linel:
        username = re.search(r"(?<=by )\w+", line)
    elif "authentication failure" in linel:
        username = re.search(r"(?<=user=)\w+", line)
    for phrase, event in events:
        if phrase in linel:
            event_type = event
            break
    dic["Event type"] = event_type
    dic["Username"] = username.group() if username else None
    if "COMMAND=" in line or "not in sudoers" in linel:
        match = re.search(r"sudo:\s+(\w+)", line)
        dic["Username"] = match.group(1) if match is not None else None
    return dic

def passwd_parser(line):
    linel = line.lower()
    dic = base_dic()
    event_type = None
    events =[
         ("couldn't update the login keyring password", "update_login_failed"),
         ("password changed",              "password_changed"),
         ("can't view or modify",          "cant_view_or_modify_passwd")
    ]
    for phrase, event in events:
        if phrase in linel:
            event_type = event
            break
    username = None
    username = re.search(r"(?<=for )\w+", line)
    dic['Username'] = username.group() if username else None
    dic["Event type"] = event_type
    return dic

def useradd_parser(line):
    linel = line.lower()
    dic = base_dic()
    event_type = None
    events =[
         ("new group",                     "new_group"),
         ("new user",                      "new_user"),
         ("failed adding user",            "user_add_failed"),
    ]
    if ("name=" in line.lower() and "new group" in line.lower()) or "group added to" in line.lower():
        group = re.search(r"(?<=name=)\w+", line)
    else:
        group = re.search(r"(?<=group ')\w+", line)
    for phrase, event in events:
        if phrase in linel:
            event_type = event
            break
    if "failed adding user" in linel:
        username = re.search(r"(?<=user ')\w+", line)
    else:
        username = re.search(r"(?<=name=)\w+", line)
    dic['Username'] = username.group() if username else None
    dic["Event type"] = event_type
    dic["Group"] = group.group() if group else None
    return dic

def userdel_parser(line):
    linel = line.lower()
    dic = base_dic()
    event_type = None
    events = [
    ("removed shadow group",          "removed_user_group"),
    ("removed group",                 "del_group"),
    ("delete user",                   "del_user"),
    ]
    for phrase, event in events:
        if phrase in linel:
            event_type = event
            break
    if ("name=" in line.lower() and "new group" in line.lower()) or "group added to" in line.lower():
        group = re.search(r"(?<=name=)\w+", line)
    else:
        group = re.search(r"(?<=group ')\w+", line)
    if "delete user" in linel:
        username = re.search(r"(?<=user ')\w+", line)
    else:
        username=re.search(r"(?<=by ')\w+",line)
    dic['Username'] = username.group() if username else None
    dic["Event type"] = event_type
    dic["Group"] = group.group() if group else None
    return dic

def groupadd_parser(line):
    linel = line.lower()
    dic = base_dic()
    event_type = None
    events = [
    ("new group",                     "new_group"),
    ("group added",                   "new_group"),
    ]
    for phrase, event in events:
        if phrase in linel:
            event_type = event
            break
    if ("name=" in line.lower() and "new group" in line.lower()) or "group added to" in line.lower():
        group = re.search(r"(?<=name=)\w+", line)
    else:
        group = re.search(r"(?<=group ')\w+", line)
    dic["Event type"] = event_type
    dic["Group"] = group.group() if group else None
    return dic

def groupdel_parser(line):
    linel = line.lower()
    dic = base_dic()
    event_type = None
    events = [
    ("removed group",                 "del_group"),
    ]
    for phrase, event in events:
        if phrase in linel:
            event_type = event
            break
    group = re.search(r"(?<=group ')\w+", line)
    dic["Event type"] = event_type
    dic["Group"] = group.group() if group else None
    return dic

def systemd_parser(line):
    linel = line.lower()
    dic = base_dic()
    event_type = None
    events = [
    ("new session",                   "new_session"),
    ("removed session",               "session_removed"),
    ("logged out",                    "session_logout")
    ]
    username = None
    for phrase, event in events:
        if phrase in linel:
            event_type = event
            break
    username = re.search(r"(?<=user )\w+", line)
    dic["Event type"] = event_type
    dic["Username"] = username.group() if username else None
    return dic

processes = {
    "sshd": sshd_parser,
    "systemd-logind": systemd_parser,
    "groupadd": groupadd_parser,
    "groupdel": groupdel_parser,
    "useradd": useradd_parser,
    "userdel": userdel_parser,
    "passwd": passwd_parser,
    "sudo": sudo_parser,
    "su": sudo_parser,
}

st.set_page_config(layout="wide")
alerts = [brute_force, login_root, not_in_sudoers, invalid_user]

if "Q"not in st.session_state:
    st.session_state.Q = queue.Queue()
if "Q_alert" not in st.session_state:
    st.session_state.Q_alert = queue.Queue()
if "logs_df" not in st.session_state:
    st.session_state.logs_df = pd.DataFrame(
        columns=["Timestamp", "Message"]
    )
if "alert_list" not in st.session_state:
    st.session_state.alert_list = []

if "connected" not in st.session_state:
    st.session_state.connected = False


st_autorefresh(interval=3000, key="autorefresh")


st.markdown("# :red[SIEM] Tool")
def read_alerts_que():
    alert_list = []
    while True:
        try:
                alert = st.session_state.Q_alert.get_nowait()
                alert_list.append(alert)
        except queue.Empty:
            break
    return alert_list


def read_log(stdout, q_logs, q_alerts):
    for line in iter(stdout.readline, ""):
        try:
            base = base_parser(line)
            if base["Process name"] is None or base["Process name"] not in processes:
                continue
            # logi
            if base["Message"] is not None:
                q_logs.put(base)
            # alerty
            not_base = processes[base["Process name"]](line)
            final = base | not_base
            for event in alerts:
                result = event(final)
                if result:
                    q_alerts.put(result)
        except Exception as e:
            continue

def read_que():
    rows = []
    while True:
        try:
            alert = st.session_state.Q.get_nowait()
            rows.append(alert)
        except:
            break
    return rows

rows = read_que()
alert_data  = read_alerts_que()

if alert_data:
    for alert in alert_data:
        st.session_state.alert_list.append(alert)



if rows:
    new_df = pd.DataFrame(rows, columns=["Timestamp", "Message"])
    st.session_state.logs_df = pd.concat(
        [st.session_state.logs_df, new_df], ignore_index=True
    )

col_logs, col_alerts = st.columns([2, 1])

with col_logs:
    st.markdown("# Logs")
    st.dataframe(st.session_state.logs_df)
with col_alerts:
    st.markdown("# :red[Alerts]")
    if not st.session_state.alert_list:
        st.info("No alerts...")
    else:
        for alert in reversed(st.session_state.alert_list):
            with st.container(border=True):
                st.caption(f"{alert['TIME']}")
                st.error(f"Severity: {alert['SEVERITY']}")
                st.error(f"Alert type: {alert['TYPE']}")
                with st.expander("More info..."):
                    st.warning(f"MITTRE: {alert['MITRE ATT&CK']}")
                    st.warning(f"Description: {alert['Description']}")



with st.sidebar:
    st.text_input("Enter hostname/IP: ", key="hname")
    st.text_input("Enter username: ", key="uname")
    st.text_input("Enter password: ", type="password", key="passw")
    if st.button("Connect"):
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(hostname=st.session_state.hname, port=22, username=st.session_state.uname, password=st.session_state.passw, timeout=5)
            stdin, stdout, stderr = ssh_client.exec_command(f"sudo -S tail -f /var/log/auth.log", get_pty=True)
            stdin.write(st.session_state.passw + "\n")
            stdin.flush()
            st.session_state.Q = queue.Queue()
            st.session_state.Q_alert = queue.Queue()
            t = threading.Thread(target=read_log, args=(stdout, st.session_state.Q, st.session_state.Q_alert), daemon=True)
            t.start()
            st.session_state.connected = True
        except Exception as s:
            st.exception(s)
            st.session_state.connected = False
        if st.session_state.connected:
            st.success("Connected!")
        else:
            st.error("Unable to connect.")
            

         

            

