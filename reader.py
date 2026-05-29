import queue
import streamlit as st
import time
from parsers import processes, base_parser
from AbuseIPDB import get_abuse_score
from rules import brute_force, login_root, not_in_sudoers, invalid_user, failed_sudo, new_user, del_user, pass_change, new_group, accepted_publickey, password_spray, successful_after_bruteforce, off_hours_login, multiple_failed_sudo, privilege_escalation_chain, new_user_sudo, root_publickey_new_ip, username_enumeration, session_flood, external_ip_login

alerts = [brute_force, login_root, not_in_sudoers, invalid_user, failed_sudo, new_user, del_user, pass_change, new_group, accepted_publickey, password_spray, successful_after_bruteforce, off_hours_login, multiple_failed_sudo,
          privilege_escalation_chain, new_user_sudo, root_publickey_new_ip, username_enumeration, session_flood, external_ip_login]

def read_alerts_que():
    alert_list = []
    while True:
        try:
                alert = st.session_state.Q_alert.get_nowait()
                alert_list.append(alert)
        except queue.Empty:
            break
    return alert_list

def read_events_que():
    event_list=[]
    while True:
        try:
            event = st.session_state.Q_event.get_nowait()
            event_list.append(event)
        except queue.Empty:
            break
    return event_list


def read_log(stdout, q_logs, q_alerts, q_events, demo_mode=False):
    for line in iter(stdout.readline, ""):
        try:
            base = base_parser(line)
            if base["Process name"] is None or base["Process name"] not in processes:
                continue
            # logi
            q_logs.put(base)
            # alerty
            not_base = processes[base["Process name"]](line)
            final = base | not_base
            q_events.put(final)
            for event in alerts:
                result = event(final)
                if result:
                    ip = final.get("IP")
                    if ip:
                        result["IP"] = ip
                        abuse = get_abuse_score(ip)
                        if abuse:
                            result["AbuseScore"] = abuse["score"]
                            result["AbuseReports"] = abuse["reports"]
                            result["Country"] = abuse["country"]
                    q_alerts.put(result)
            if demo_mode:
                time.sleep(0.2)
        except Exception as e:
            print(f"ERROR: {e} | LINE: {line}")
            continue

def read_que():
    rows = []
    while True:
        try:
            log= st.session_state.Q.get_nowait()
            rows.append(log)
        except queue.Empty:
            break
    return rows