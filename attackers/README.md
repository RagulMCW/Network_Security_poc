# ⚔️ Attack Simulators

This directory contains various containers designed to simulate different types of cyber attacks against the network monitor. These are used to test the detection capabilities of the Zeek monitor and the AI Agent.

---

## 📂 **Available Attackers**

| Attacker | IP Address | Type | Description |
|----------|------------|------|-------------|
| **DoS Attacker** | `192.168.6.132` | Volumetric | Floods the network with SYN packets to test DoS detection. |
| **Malware Attacker** | `192.168.6.200` | Signature | Uploads known malware files (EICAR, etc.) to test hash detection. |
| **SSH Attacker** | `192.168.6.133` | Brute Force | Attempts to guess SSH passwords using a wordlist. |
| **Endpoint Behavior** | `192.168.6.201` | Behavioral | Simulates complex patterns like C2 beacons, DGA, and exfiltration. |

---

## 🔄 **General Workflow**

```mermaid
graph LR
    User[User/Dashboard] -->|Starts| Container[Attack Container]
    Container -->|Generates| Traffic[Malicious Traffic]
    Traffic -->|Targets| Monitor[Network Monitor (192.168.6.131)]
    Monitor -->|Captures| Zeek[Zeek Logs]
```

---

## 🚀 **How to Manage**

You can manage these attackers individually from their respective directories or via the **Dashboard**.

### **Start All Attackers**
(Not recommended to start all at once for clear analysis)
```bash
# Use the dashboard for individual control
```

### **Stop All Attackers**
```bash
docker stop dos-attacker malware-attacker ssh-attacker endpoint-behavior-attacker
```
