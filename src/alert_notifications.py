"""
Alert Notification System
Send alerts via Email, Slack, Webhooks, and other channels
"""

import logging
import json
import requests
from typing import List, Dict, Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class Alert:
    """Alert data structure"""
    alert_id: str
    severity: AlertSeverity
    attack_type: str
    description: str
    source_ip: str
    dest_ip: str
    packet_count: int
    confidence: float
    timestamp: str
    additional_data: Optional[Dict] = None


class SlackNotifier:
    """Send alerts to Slack channel"""
    
    SEVERITY_COLORS = {
        AlertSeverity.INFO: "#36a64f",      # Green
        AlertSeverity.WARNING: "#ff9900",   # Orange
        AlertSeverity.CRITICAL: "#ff0000"   # Red
    }
    
    def __init__(self, webhook_url: str):
        """
        Initialize Slack notifier
        
        Args:
            webhook_url: Slack incoming webhook URL
        """
        self.webhook_url = webhook_url
    
    def send(self, alert: Alert) -> bool:
        """Send alert to Slack"""
        try:
            payload = {
                "attachments": [
                    {
                        "color": self.SEVERITY_COLORS.get(alert.severity, "#cccccc"),
                        "title": f"🚨 {alert.severity.value} - {alert.attack_type}",
                        "text": alert.description,
                        "fields": [
                            {"title": "Alert ID", "value": alert.alert_id, "short": True},
                            {"title": "Severity", "value": alert.severity.value, "short": True},
                            {"title": "Source IP", "value": alert.source_ip, "short": True},
                            {"title": "Destination IP", "value": alert.dest_ip, "short": True},
                            {"title": "Packet Count", "value": str(alert.packet_count), "short": True},
                            {"title": "Confidence", "value": f"{alert.confidence*100:.2f}%", "short": True},
                            {"title": "Timestamp", "value": alert.timestamp, "short": False},
                        ],
                        "footer": "AI Intrusion Detection System",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info(f"✅ Alert sent to Slack: {alert.alert_id}")
                return True
            else:
                logger.error(f"❌ Failed to send Slack alert: {response.text}")
                return False
        
        except Exception as e:
            logger.error(f"❌ Slack notification error: {e}")
            return False


class EmailNotifier:
    """Send alerts via email"""
    
    def __init__(self, smtp_server: str, smtp_port: int, sender_email: str, sender_password: str):
        """
        Initialize Email notifier
        
        Args:
            smtp_server: SMTP server address
            smtp_port: SMTP port
            sender_email: Sender email address
            sender_password: Sender email password
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender_email = sender_email
        self.sender_password = sender_password
    
    def send(self, alert: Alert, recipient_emails: List[str]) -> bool:
        """Send alert via email"""
        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[{alert.severity.value}] Security Alert: {alert.attack_type}"
            msg["From"] = self.sender_email
            msg["To"] = ", ".join(recipient_emails)
            
            # HTML template
            html = f"""
            <html>
                <body style="font-family: Arial, sans-serif;">
                    <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px;">
                        <h2 style="color: #d9534f;">🚨 Security Alert</h2>
                        <p><strong>Alert ID:</strong> {alert.alert_id}</p>
                        <p><strong>Severity:</strong> <span style="color: red; font-weight: bold;">{alert.severity.value}</span></p>
                        <p><strong>Attack Type:</strong> {alert.attack_type}</p>
                        <p><strong>Description:</strong> {alert.description}</p>
                        <hr>
                        <h3>Alert Details</h3>
                        <ul>
                            <li><strong>Source IP:</strong> {alert.source_ip}</li>
                            <li><strong>Destination IP:</strong> {alert.dest_ip}</li>
                            <li><strong>Packet Count:</strong> {alert.packet_count}</li>
                            <li><strong>Confidence:</strong> {alert.confidence*100:.2f}%</li>
                            <li><strong>Timestamp:</strong> {alert.timestamp}</li>
                        </ul>
                        <hr>
                        <p style="font-size: 12px; color: #999;">
                            Generated by AI Intrusion Detection System
                        </p>
                    </div>
                </body>
            </html>
            """
            
            msg.attach(MIMEText(html, "html"))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.smtp_port == 587:
                    server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.sendmail(self.sender_email, recipient_emails, msg.as_string())
            
            logger.info(f"✅ Alert sent via email: {alert.alert_id}")
            return True
        
        except Exception as e:
            logger.error(f"❌ Email notification error: {e}")
            return False


class WebhookNotifier:
    """Send alerts to custom webhooks"""
    
    def __init__(self, webhook_url: str):
        """
        Initialize Webhook notifier
        
        Args:
            webhook_url: Custom webhook URL
        """
        self.webhook_url = webhook_url
    
    def send(self, alert: Alert) -> bool:
        """Send alert to webhook"""
        try:
            payload = {
                "alert_id": alert.alert_id,
                "severity": alert.severity.value,
                "attack_type": alert.attack_type,
                "description": alert.description,
                "source_ip": alert.source_ip,
                "dest_ip": alert.dest_ip,
                "packet_count": alert.packet_count,
                "confidence": float(alert.confidence),
                "timestamp": alert.timestamp,
                "additional_data": alert.additional_data or {}
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=5,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code in [200, 201, 202]:
                logger.info(f"✅ Alert sent to webhook: {alert.alert_id}")
                return True
            else:
                logger.error(f"❌ Webhook failed: {response.status_code} - {response.text}")
                return False
        
        except Exception as e:
            logger.error(f"❌ Webhook notification error: {e}")
            return False


class PagerDutyNotifier:
    """Integration with PagerDuty"""
    
    def __init__(self, api_key: str, service_key: str):
        """
        Initialize PagerDuty notifier
        
        Args:
            api_key: PagerDuty API key
            service_key: PagerDuty service integration key
        """
        self.api_key = api_key
        self.service_key = service_key
        self.events_endpoint = "https://events.pagerduty.com/v2/enqueue"
    
    def send(self, alert: Alert) -> bool:
        """Send incident to PagerDuty"""
        try:
            payload = {
                "routing_key": self.service_key,
                "event_action": "trigger" if alert.severity == AlertSeverity.CRITICAL else "resolve",
                "client": "AI IDS",
                "client_url": "https://ids.internal",
                "payload": {
                    "summary": f"{alert.severity.value}: {alert.attack_type}",
                    "severity": self._map_severity_to_pagerduty(alert.severity),
                    "source": alert.source_ip,
                    "custom_details": {
                        "alert_id": alert.alert_id,
                        "description": alert.description,
                        "dest_ip": alert.dest_ip,
                        "confidence": f"{alert.confidence*100:.2f}%"
                    }
                }
            }
            
            response = requests.post(
                self.events_endpoint,
                json=payload,
                timeout=5
            )
            
            if response.status_code == 202:
                logger.info(f"✅ Incident created in PagerDuty: {alert.alert_id}")
                return True
            else:
                logger.error(f"❌ PagerDuty failed: {response.text}")
                return False
        
        except Exception as e:
            logger.error(f"❌ PagerDuty error: {e}")
            return False
    
    @staticmethod
    def _map_severity_to_pagerduty(severity: AlertSeverity) -> str:
        """Map alert severity to PagerDuty severity"""
        mapping = {
            AlertSeverity.INFO: "info",
            AlertSeverity.WARNING: "warning",
            AlertSeverity.CRITICAL: "critical"
        }
        return mapping.get(severity, "info")


class TeamsNotifier:
    """Send alerts to Microsoft Teams"""

    def __init__(self, webhook_url: str):
        """
        Initialize Teams notifier
        
        Args:
            webhook_url: Teams incoming webhook URL
        """
        self.webhook_url = webhook_url
    
    def send(self, alert: Alert) -> bool:
        """Send alert to Microsoft Teams"""
        try:
            color = "#FF0000" if alert.severity == AlertSeverity.CRITICAL else "#FFA500"
            
            payload = {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "themeColor": color,
                "summary": f"{alert.severity.value}: {alert.attack_type}",
                "sections": [
                    {
                        "activityTitle": f"🚨 {alert.severity.value} - {alert.attack_type}",
                        "activitySubtitle": alert.description,
                        "facts": [
                            {"name": "Alert ID", "value": alert.alert_id},
                            {"name": "Source IP", "value": alert.source_ip},
                            {"name": "Destination IP", "value": alert.dest_ip},
                            {"name": "Packet Count", "value": str(alert.packet_count)},
                            {"name": "Confidence", "value": f"{alert.confidence*100:.2f}%"},
                            {"name": "Timestamp", "value": alert.timestamp},
                        ],
                        "markdown": True
                    }
                ]
            }
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info(f"✅ Alert sent to Teams: {alert.alert_id}")
                return True
            else:
                logger.error(f"❌ Teams failed: {response.text}")
                return False
        
        except Exception as e:
            logger.error(f"❌ Teams notification error: {e}")
            return False


class NotificationManager:
    """Unified notification manager for multiple channels"""
    
    def __init__(self):
        self.notifiers = []
    
    def add_slack(self, webhook_url: str):
        """Add Slack notifier"""
        self.notifiers.append(("slack", SlackNotifier(webhook_url)))
        logger.info("✅ Slack notifier added")
    
    def add_email(self, smtp_server: str, smtp_port: int, sender_email: str, sender_password: str):
        """Add Email notifier"""
        self.notifiers.append(("email", EmailNotifier(smtp_server, smtp_port, sender_email, sender_password)))
        logger.info("✅ Email notifier added")
    
    def add_webhook(self, webhook_url: str):
        """Add custom webhook notifier"""
        self.notifiers.append(("webhook", WebhookNotifier(webhook_url)))
        logger.info("✅ Webhook notifier added")
    
    def add_pagerduty(self, api_key: str, service_key: str):
        """Add PagerDuty notifier"""
        self.notifiers.append(("pagerduty", PagerDutyNotifier(api_key, service_key)))
        logger.info("✅ PagerDuty notifier added")
    
    def add_teams(self, webhook_url: str):
        """Add Microsoft Teams notifier"""
        self.notifiers.append(("teams", TeamsNotifier(webhook_url)))
        logger.info("✅ Teams notifier added")
    
    def send_alert(self, alert: Alert, recipient_emails: List[str] = None) -> Dict[str, bool]:
        """Send alert to all configured channels"""
        results = {}
        
        for channel_name, notifier in self.notifiers:
            if channel_name == "email" and recipient_emails:
                results[channel_name] = notifier.send(alert, recipient_emails)
            else:
                results[channel_name] = notifier.send(alert)
        
        return results


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    # Create alert
    alert = Alert(
        alert_id="alert_demo_001",
        severity=AlertSeverity.CRITICAL,
        attack_type="DDoS Attack",
        description="Multiple packets from suspicious source IPs detected",
        source_ip="203.0.113.45",
        dest_ip="192.168.1.50",
        packet_count=5000,
        confidence=0.98,
        timestamp=datetime.now().isoformat(),
        additional_data={"attack_vector": "Port 80", "duration": "300 seconds"}
    )
    
    # Initialize notification manager
    manager = NotificationManager()
    
    # Add your channels here (replace with real URLs/credentials)
    # manager.add_slack("https://hooks.slack.com/services/YOUR/WEBHOOK/URL")
    # manager.add_webhook("https://your-api.com/alerts")
    
    print("📧 Alert Notification System configured")
    print(f"Alert: {alert.alert_id}")
    print(f"Type: {alert.attack_type}")
    print(f"Severity: {alert.severity.value}")
