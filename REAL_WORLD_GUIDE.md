# AI Intrusion Detection System - Deployment & Real-World Guide

## 🚀 Project Overview

This is a **production-ready, modern Intrusion Detection System (IDS)** using:
- ✅ Real-time network packet capture (pcap)
- ✅ ML-based threat detection (Random Forest + Deep Learning)
- ✅ FastAPI production server
- ✅ Real-time alerts (Email, Slack, Webhook, PagerDuty, Teams)
- ✅ Docker containerization
- ✅ PostgreSQL database for threat logging
- ✅ Prometheus + Grafana monitoring
- ✅ Streamlit dashboard for visualization

---

## 📋 System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Network Traffic                           │
└──────────────────────┬──────────────────────────────────────┘
                       │
                ┌──────▼──────┐
                │   Sniffer   │ (real_time_sniffer.py)
                │  Packet     │
                │  Capture    │
                └──────┬──────┘
                       │
            ┌──────────▼──────────┐
            │  Feature Engineering │
            │  & Preprocessing    │
            └──────────┬──────────┘
                       │
            ┌──────────▼──────────┐
            │   ML Model Layer   │
            │ - Random Forest    │
            │ - Logistic Reg.    │
            │ - LSTM (future)    │
            └──────────┬──────────┘
                       │
       ┌───────────────▼───────────────┐
       │   Alert & Notification Layer   │
       │ - Email  - Slack - Webhook    │
       │ - Teams  - PagerDuty          │
       └───────────────┬───────────────┘
       ┌───────────────▼───────────────┐
       │   Data Persistence Layer      │
       │ - PostgreSQL Database         │
       │ - Redis Cache                 │
       └───────────────┬───────────────┘
       ┌───────────────▼───────────────┐
       │   API & Dashboard Layer       │
       │ - FastAPI (8000)              │
       │ - Streamlit (8501)            │
       │ - Grafana (3000)              │
       └───────────────────────────────┘
```

---

## 🔧 Installation & Setup

### Option 1: Docker Compose (Recommended)

```bash
# Clone/Navigate to project
cd "d:\6th SEM PROJECT\Intrusion Detection System"

# Build and start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f ids-api
```

**Services will be available at:**
- 🔵 FastAPI: http://localhost:8000
- 🟣 Streamlit: http://localhost:8501
- 📊 Grafana: http://localhost:3000 (admin/admin123)
- 📈 Prometheus: http://localhost:9090
- 🗄️ PostgreSQL: localhost:5432

### Option 2: Local Installation

```bash
# Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Install additional system requirements
pip install scapy pyshark

# Train model (if needed)
python src/data_preprocessing.py
python src/train_models.py

# Start API server
python -m uvicorn src.ids_api_server:app --host 0.0.0.0 --port 8000

# In another terminal, start Streamlit
streamlit run streamlit_app/app.py
```

---

## 🌐 Real-World Usage Scenarios

### Scenario 1: Network Monitor (Corporate Network)

```bash
# Run packet capture on network interface
python src/network_sniffer.py --interface eth0 --limit 10000

# Process captured packets through model
python -m src.threat_detector --source network --enable-alerts
```

### Scenario 2: SIEM Integration (Splunk/ELK)

```bash
# Start API server
python -m uvicorn src.ids_api_server:app --host 0.0.0.0 --port 8000
```

**Send logs to API:**
```bash
curl -X POST http://localhost:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d '{
    "src_ip": "192.168.1.100",
    "dst_ip": "8.8.8.8",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "TCP",
    "packet_length": 1500,
    "pkt_count": 5,
    "bytes": 75000,
    "duration": 30.5,
    "rate": 0.16
  }'
```

### Scenario 3: Alert to Multiple Channels

```python
from src.alert_notifications import NotificationManager, Alert, AlertSeverity
from datetime import datetime

# Initialize manager
manager = NotificationManager()

# Add notification channels
manager.add_slack("https://hooks.slack.com/services/YOUR/WEBHOOK/URL")
manager.add_email("smtp.gmail.com", 587, "your@gmail.com", "password")
manager.add_webhook("https://your-siem.com/api/alerts")
manager.add_pagerduty("api_key", "service_key")
manager.add_teams("https://outlook.webhook.office.com/...")

# Create alert
alert = Alert(
    alert_id="alert_001",
    severity=AlertSeverity.CRITICAL,
    attack_type="DDoS",
    description="Massive DDoS attack detected",
    source_ip="203.0.113.45",
    dest_ip="192.168.1.50",
    packet_count=50000,
    confidence=0.98,
    timestamp=datetime.now().isoformat()
)

# Send to all channels
results = manager.send_alert(alert, ["security@company.com"])
print(results)  # {'slack': True, 'email': True, 'webhook': True, ...}
```

### Scenario 4: Batch Predictions for Log Analysis

```bash
# Generate threats dataset
python src/threat_generator.py --output-file data/threats.csv

# Run batch predictions
curl -X POST http://localhost:8000/api/v1/predict/batch \
  -H "Content-Type: application/json" \
  -d @- << 'EOF'
{
  "packets": [
    {
      "src_ip": "192.168.1.100",
      "dst_ip": "8.8.8.8",
      "src_port": 54321,
      "dst_port": 443,
      "protocol": "TCP",
      "packet_length": 1500,
      "pkt_count": 5,
      "bytes": 75000,
      "duration": 30.5,
      "rate": 0.16
    }
  ],
  "return_probabilities": true
}
EOF
```

---

## 📊 Real-world Attack Scenarios Supported

### 1. **Port Scanning Detection**
- Detects sequential port scans
- Identifies service enumeration
- Flags suspicious port combinations

### 2. **DDoS Attack Detection**
- Multiple source IP tracking
- High-volume packet rate detection
- Targeted port identification

### 3. **Botnet Traffic Detection**
- Periodic beaconing patterns
- C2 communication channels
- Command & control server identification

### 4. **Brute Force Attacks**
- SSH/RDP credential stuffing
- Repeated login attempts
- Slow/fast bruteforce variants

### 5. **Data Exfiltration**
- Large data transfer detection
- Unusual protocol usage
- External destination flagging

### 6. **Privilege Escalation**
- Exploit-related port patterns
- System service scanning
- Unusual port combinations

---

## 🔐 Configuration for Production

### Environment Variables (`.env`)

```bash
# Database
DATABASE_URL=postgresql://ids_user:password@postgres-db:5432/ids_database

# API Security
API_KEY=your-secret-api-key
ALLOWED_NETWORKS=10.0.0.0/8,172.16.0.0/12

# Alerts
SLACK_WEBHOOK=https://hooks.slack.com/services/xxx
PAGERDUTY_API_KEY=xxxxx
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=user@gmail.com
SMTP_PASSWORD=xxxxx

# Monitoring
ENABLE_PROMETHEUS=true
LOG_LEVEL=INFO
```

### Network Interface Configuration

**Linux (requires root):**
```bash
# Capture on specific interface
python src/network_sniffer.py --interface eth0

# Capture on all interfaces
python src/network_sniffer.py --interface all
```

**Windows (requires admin):**
```powershell
# Run PowerShell as Administrator
python src/network_sniffer.py --interface Ethernet

# List available interfaces
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

---

## 📈 Monitoring & Analytics

### Prometheus Metrics

```
ids_predictions_total - Total predictions made
ids_threats_detected_total - Threats detected
ids_api_latency_ms - API response time
ids_model_confidence - Prediction confidence
ids_alerts_sent_total - Alerts sent
```

### Grafana Dashboards

Pre-configured dashboards for:
- 📊 Real-time threat timeline
- 🔴 Critical alerts heatmap
- 📍 Threat geolocation
- 📈 Attack trends

Access at: http://localhost:3000

---

## 🚨 Alert Configuration Examples

### Slack Integration

```python
from src.alert_notifications import SlackNotifier, Alert, AlertSeverity

notifier = SlackNotifier("https://hooks.slack.com/services/YOUR/WEBHOOK")
alert = Alert(...)
notifier.send(alert)
```

### Email Integration

```python
from src.alert_notifications import EmailNotifier

notifier = EmailNotifier(
    smtp_server="smtp.gmail.com",
    smtp_port=587,
    sender_email="ids@company.com",
    sender_password="app_password"
)
notifier.send(alert, ["security@company.com"])
```

### PagerDuty Integration

```python
from src.alert_notifications import PagerDutyNotifier

notifier = PagerDutyNotifier(
    api_key="your_api_key",
    service_key="integration_key"
)
notifier.send(alert)
```

---

## 🔄 Database Maintenance

### Backup Database

```bash
docker exec ids-postgres pg_dump -U ids_user ids_database > backup.sql
```

### Restore Database

```bash
docker exec -i ids-postgres psql -U ids_user ids_database < backup.sql
```

### Cleanup Old Threats

```sql
-- Keep only last 90 days
SELECT cleanup_old_threats(90);

-- View daily summary
SELECT * FROM daily_threat_summary;

-- Get top attacking IPs
SELECT * FROM top_attacking_ips LIMIT 20;
```

---

## 🧪 Testing & Validation

### Unit Tests

```bash
python -m pytest tests/ -v
```

### Load Testing

```bash
# Generate 1000 predictions
python -c "
from src.threat_generator import ThreatScenarioGenerator
import requests

gen = ThreatScenarioGenerator()
threats = gen.generate_mixed_dataset(1000)

for _, threat in threats.iterrows():
    requests.post('http://localhost:8000/api/v1/predict', json=threat.to_dict())
"
```

---

## 📝 Logging & Debugging

### View Application Logs

```bash
docker-compose logs -f ids-api
docker-compose logs -f ids-dashboard
```

### Enable Debug Mode

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

---

## 🛡️ Security Best Practices

1. **API Security**
   - Use VPN/Private networks for API access
   - Implement API key authentication
   - Enable HTTPS/TLS

2. **Database Security**
   - Change default PostgreSQL password
   - Use network policies
   - Enable encryption at rest

3. **Alert Security**
   - Use encrypted channels (HTTPS webhooks)
   - Rotate API keys regularly
   - Implement rate limiting

4. **Network Security**
   - Capture traffic from trusted interfaces only
   - Use firewall rules
   - Monitor API access logs

---

## 🔗 API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/predict` | POST | Single prediction |
| `/api/v1/predict/batch` | POST | Batch predictions |
| `/api/v1/health` | GET | Health check |
| `/api/v1/alerts` | GET | Get alerts |
| `/api/v1/alerts/critical` | GET | Critical alerts only |
| `/api/v1/stats` | GET | System stats |
| `/ws/monitor` | WebSocket | Real-time monitoring |

---

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Streamlit Documentation](https://docs.streamlit.io/)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)

---

## 🆘 Troubleshooting

### Model Not Loading
```bash
# Check model exists
ls -la models/final_ids_model.pkl

# Retrain if needed
python src/train_models.py
```

### Network Capture Not Working
```bash
# Check interfaces
python -c "from scapy.all import get_if_list; print(get_if_list())"

# Run with sudo (Linux)
sudo python src/network_sniffer.py
```

### Docker Issues
```bash
# Rebuild images
docker-compose down -v
docker-compose up --build

# Clean up
docker system prune -a
```

---

## 📞 Support & Contact

For issues, questions, or contributions:
- 📧 Email: security@ids-system.local
- 🐛 Report bugs: GitHub Issues
- 🔄 Pull requests welcome!

---

**Last Updated:** 2024
**Version:** 1.0.0
**Status:** Production Ready ✅
