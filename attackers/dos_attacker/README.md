# 🌊 DoS Attacker Simulator

Simulates a Denial of Service (DoS) attack by flooding the target with high-volume network traffic.

---

## ⚙️ **Technical Details**

- **IP Address:** `192.168.6.132`
- **Tool Used:** `hping3`
- **Attack Type:** TCP SYN Flood
- **Target:** `192.168.6.131` (Network Monitor) on port 5000

---

## 🔄 **Attack Flow**

```mermaid
graph TD
    Attacker[DoS Attacker] -->|SYN Packets (100+/sec)| Network[Docker Network]
    Network -->|Floods| Target[Monitor Server]
    Target -->|Overwhelmed| Service[Service Degradation]
    
    subgraph Detection
    Zeek[Zeek Monitor] -->|Counts| ConnLog[conn.log]
    ConnLog -->|High Connection Rate| Alert[AI Detection]
    end
```

---

## 🚀 **Usage**

### **Start Attack**
```bash
./hping3_sender.sh
```

### **Stop Attack**
```bash
./stop_attacker.sh
```

### **Clean Up**
```bash
./cleanup_iptables.sh
```
