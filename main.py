import paramiko
from AbuseIPDB import get_abuse_score
import re 
from datetime import datetime
import streamlit as st
import pandas as pd
import threading
import queue
from streamlit_autorefresh import st_autorefresh
from parsers import processes
from reader import read_log, read_que, read_alerts_que, read_events_que

MITRE_TACTICS = {
    "T1110": "Credential Access", "T1110.001": "Credential Access", "T1110.003": "Credential Access",
    "T1078": "Initial Access", "T1078.003": "Initial Access",
    "T1548": "Privilege Escalation", "T1548.003": "Privilege Escalation",
    "T1087.001": "Discovery",
    "T1136": "Persistence", "T1136.001": "Persistence", "T1098": "Persistence",
    "T1531": "Impact", "T1053.003": "Persistence"
}
MITRE_NAMES = {
    "T1110": "Brute Force", "T1110.001": "Password Guessing", "T1110.003": "Password Spraying",
    "T1078": "Valid Accounts", "T1078.003": "Local Accounts",
    "T1548": "Abuse Elevation Control", "T1548.003": "Sudo and Sudo Caching",
    "T1087.001": "Account Discovery: Local Account",
    "T1136": "Create Account", "T1136.001": "Create Account: Local Account",
    "T1098": "Account Manipulation", "T1531": "Account Access Removal", "T1053.003": "Scheduled Task/Job: Cron"
}

st.set_page_config(layout="wide")


if "Q"not in st.session_state:
    st.session_state.Q = queue.Queue()
if "Q_alert" not in st.session_state:
    st.session_state.Q_alert = queue.Queue()
if "Q_event" not in st.session_state:
    st.session_state.Q_event = queue.Queue()
if "logs_df" not in st.session_state:
    st.session_state.logs_df = pd.DataFrame(
        columns=["Timestamp", "Message"]
    )
if "alert_list" not in st.session_state:
    st.session_state.alert_list = []

if "event_list" not in st.session_state:
    st.session_state.event_list = []

if "connected" not in st.session_state:
    st.session_state.connected = False

st_autorefresh(interval=3000, key="autorefresh")
st.markdown("# :red[SIEM] Tool")
rows = read_que()
alert_data  = read_alerts_que()
event_data = read_events_que()

if event_data:
    for event in event_data:
        st.session_state.event_list.append(event)


if alert_data:
    for alert in alert_data:
        st.session_state.alert_list.append(alert)

if rows:
    new_df = pd.DataFrame(rows, columns=["Timestamp", "Message"])
    st.session_state.logs_df = pd.concat(
        [st.session_state.logs_df, new_df], ignore_index=True
    )

col_logs, col_alerts = st.columns([2.0, 2.0])

with col_logs:
    st.markdown("# Logs")
    st.dataframe(st.session_state.logs_df.tail(1000), height=800, column_config={
        "Timestamp": st.column_config.DatetimeColumn(width="small"),
        "Message": st.column_config.TextColumn(width="large")
    })


with col_alerts:
    st.markdown("# :red[Alerts]")
    with st.container(border=True, height=800):
        if not st.session_state.alert_list:
            st.caption("No alerts...")
        else:
            for alert in reversed(st.session_state.alert_list):
                with st.container(border=True, height=420):
                    st.caption(f"{alert['TIME']}")
                    st.error(f"Severity: {alert['SEVERITY']}")
                    st.error(f"Alert type: {alert['TYPE']}")
                    with st.expander("More info..."):
                        mitre = alert['MITRE ATT&CK']
                        url = "https://attack.mitre.org/techniques/" + mitre.replace(".", "/") + "/"
                        st.warning(f"MITRE: [{mitre}]({url})")
                        st.warning(f"Description: {alert['Description']}")
                        if "AbuseScore" in alert:
                            st.info(f"Country: {alert['Country']}")
                            st.info(f"Abuse score: {alert['AbuseScore']}/100")
                            st.info(f"Total reports: {alert['AbuseReports']}")
st.divider()
st.markdown("# :blue[Overview]")

if not st.session_state.event_list:
    st.info("Waiting for data to analyze...")
else:
    df_e = pd.DataFrame(st.session_state.event_list)
    time_col = "TIME" if "TIME" in df_e.columns else "Timestamp"

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Number of Events", len(df_e))
    kpi2.metric("Number of Alerts", len(st.session_state.alert_list))
    failed_ips_count = df_e[df_e["Event type"] == "failed_password"]["IP"].nunique()
    kpi3.metric("Unique IP addresses", failed_ips_count)
    high_alerts = len([a for a in st.session_state.alert_list if a['SEVERITY'] == 'HIGH'])
    kpi4.metric("Critical Alerts", high_alerts, delta_color="inverse")

    st.divider()


    c_charts1, c_charts2 = st.columns([1, 1])
    
    with c_charts1:
        st.subheader("Top Attacking IPs")
        failed_df = df_e[df_e["Event type"] == "failed_password"]
        if not failed_df.empty:
            st.bar_chart(failed_df["IP"].value_counts().head(7))
        else:
            st.caption("No failed login attempts yet.")

    with c_charts2:
        st.subheader("Event Distribution")
        st.bar_chart(df_e["Event type"].value_counts().head(7))

    st.divider()
st.markdown("# :blue[TTP Table]")

if not st.session_state.alert_list:
        st.caption("No alerts to map yet.")
else:
        ttp_rows = []
        for a in st.session_state.alert_list:
            mitre = a["MITRE ATT&CK"]
            ip = a.get("IP", "-")
            name = MITRE_NAMES.get(mitre, "")
            ttp_rows.append({
                "IP": ip,
                "Technique": f"{mitre} - {name}" if name else mitre,
                "Tactic": MITRE_TACTICS.get(mitre, "-"),
                "Procedure": a["Description"],
                "IoC": f"https://www.virustotal.com/gui/ip-address/{ip}" if ip != "-" else None,
            })
        ttp_df = pd.DataFrame(ttp_rows)

        st.dataframe(
            ttp_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "IoC": st.column_config.LinkColumn("IoC", display_text="VirusTotal"),
            },
        )
        st.download_button(
            "Export CSV",
            ttp_df.to_csv(index=False),
            "ttp_report.csv",
            "text/csv",
        )

with st.sidebar:
    st.header("Connect by SSH:")
    st.text_input("Enter hostname/IP: ", key="hname")
    st.text_input("Enter username: ", key="uname")
    st.text_input("Path to private key:", value="C:/Users/Janek/.ssh/id_ed25519", key="keypath")
    if st.button("Connect"):
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.load_system_host_keys()
            ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
            ssh_client.connect(hostname=st.session_state.hname, port=22, username=st.session_state.uname, key_filename=st.session_state.keypath, timeout=5)
            stdin, stdout, stderr = ssh_client.exec_command(f"sudo  tail -f /var/log/auth.log /var/log/syslog", get_pty=True)
            st.session_state.Q = queue.Queue()
            st.session_state.Q_alert = queue.Queue()
            t = threading.Thread(target=read_log, args=(stdout, st.session_state.Q, st.session_state.Q_alert, st.session_state.Q_event), daemon=True)
            t.start()
            st.session_state.connected = True
        except Exception as s:
            st.exception(s)
            st.session_state.connected = False
        if st.session_state.connected:
            st.success("Connected!")
        else:
            st.error("Unable to connect.")
    if st.button("Run demo"):
        st.session_state.Q = queue.Queue()
        st.session_state.Q_alert = queue.Queue()
        st.session_state.Q_event = queue.Queue()
        f = open("demo_auth.log")
        t = threading.Thread(
            target=read_log,
            args=(f, st.session_state.Q, st.session_state.Q_alert, st.session_state.Q_event, True),
            daemon=True,
        )
        t.start()
            

         

            

