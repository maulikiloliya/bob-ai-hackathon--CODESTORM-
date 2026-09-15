from datetime import datetime, timedelta

# --- MITRE ATT&CK REFERENCE MAP ---
MITRE_MATRIX = {
    "T1110": {"tactic": "Credential Access", "name": "Brute Force"},
    "T1046": {"tactic": "Discovery", "name": "Network Service Scanning"},
    "T1566": {"tactic": "Initial Access", "name": "Phishing"}
}

class ThreatIntelligenceAssistant:
    def __init__(self, time_window_minutes=15):  # Fixed double underscores
        self.time_window = timedelta(minutes=time_window_minutes)
        self.master_incidents = {}

    def parse_timestamp(self, ts_str):
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")  # Fixed %Y specifier

    def process_and_correlate(self, cyber_data, sat_data):
        for log in cyber_data:
            ip = log["target_ip"]
            if ip not in self.master_incidents:
                self.master_incidents[ip] = []
            self.master_incidents[ip].append({
                "time": self.parse_timestamp(log["timestamp"]),
                "source": log["source"],
                "event": log["event"],
                "technique": log["technique"],
                "type": "Cyber"
            })

        for log in sat_data:
            ip = log["associated_asset_ip"]
            if ip not in self.master_incidents:
                self.master_incidents[ip] = []
            self.master_incidents[ip].append({
                "time": self.parse_timestamp(log["timestamp"]),
                "source": log["source"],
                "event": log["event"],
                "technique": log.get("technique", "Unknown"),
                "type": "Satellite"
            })

        return self.evaluate_threats()

    def evaluate_threats(self):
        prioritised_threats = []

        for ip, events in self.master_incidents.items():
            if len(events) < 2:
                continue
            
            events.sort(key=lambda x: x["time"])
            
            has_cyber = any(e["type"] == "Cyber" for e in events)
            has_sat = any(e["type"] == "Satellite" for e in events)
            time_span = events[-1]["time"] - events[0]["time"]

            if has_cyber and has_sat and time_span <= self.time_window:
                priority = "CRITICAL (Cross-Domain Attack Vector)"
            else:
                priority = "HIGH (Multi-Alert Cluster)"

            prioritised_threats.append({
                "target_asset": ip,
                "priority": priority,
                "event_count": len(events),
                "timeline": events
            })
            
        prioritised_threats.sort(key=lambda x: "CRITICAL" in x["priority"], reverse=True)
        return prioritised_threats

    def generate_bluf_summary(self, threat_cluster):
        ip = threat_cluster["target_asset"]
        priority = threat_cluster["priority"]
        
        tactics_observed = []
        for e in threat_cluster["timeline"]:
            tech = e["technique"]
            if tech in MITRE_MATRIX:
                tactics_observed.append(f"{MITRE_MATRIX[tech]['tactic']} ({MITRE_MATRIX[tech]['name']})")
        
        tactics_str = ", ".join(set(tactics_observed)) if tactics_observed else "Unknown / Cross-Domain Disruption"

        bluf = f"==================================================\n"
        bluf += f"THREAT ASSESSMENT BRIEF: ASSET {ip}\n"
        bluf += f"PRIORITY LEVEL: {priority}\n"
        bluf += f"==================================================\n"
        bluf += f"BLUF (BOTTOM LINE UP FRONT):\n"
        bluf += f"  Immediate action required on Asset {ip}. Simultaneous network exploitation\n"
        bluf += f"  and physical satellite telemetry degradation detected within a tight window.\n"
        bluf += f"  High probability of coordinated multi-domain hostile operations.\n\n"
        bluf += f"MITRE ATT&CK TACTICS OBSERVED:\n"
        bluf += f"  - {tactics_str}\n\n"
        bluf += f"CHRONOLOGICAL EVENT TIMELINE:\n"
        
        for idx, e in enumerate(threat_cluster["timeline"], 1):
            bluf += f"  [{idx}] {e['time'].strftime('%H:%M:%S')} | [{e['type']}] From {e['source']}: {e['event']}\n"
        bluf += "==================================================\n"
        return bluf

# --- SAMPLE DATA INPUTS & EXECUTION ---
cyber_feed = [
    {"target_ip": "192.168.1.50", "timestamp": "2026-09-14T10:00:00Z", "source": "Firewall", "event": "SSH Brute Force", "technique": "T1110"}
]

satellite_feed = [
    {"associated_asset_ip": "192.168.1.50", "timestamp": "2026-09-14T10:05:00Z", "source": "Telemetry", "event": "Signal Jamming", "technique": "Unknown"}
]

assistant = ThreatIntelligenceAssistant(time_window_minutes=15)
evaluated_incidents = assistant.process_and_correlate(cyber_feed, satellite_feed)

for incident in evaluated_incidents:
    print(assistant.generate_bluf_summary(incident))