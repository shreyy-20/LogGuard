import smtplib
import threading
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from src.config import NotificationConfig

logger = logging.getLogger("LogGuard.Alerter")

# Try importing desktop notification library
try:
    from plyer import notification
    DESKTOP_SUPPORTED = True
except ImportError:
    DESKTOP_SUPPORTED = False

class AlertDispatcher:
    """Dispatches alerts via desktop notifications and email in a non-blocking manner."""
    def __init__(self, config: NotificationConfig):
        self.config = config

    def dispatch(self, alert_entry: dict):
        """Dispatches an alert based on enabled notification channels."""
        # 1. Desktop Notification
        if self.config.desktop_enabled:
            self._send_desktop_notification(alert_entry)

        # 2. Email Notification
        if self.config.email_enabled:
            # Send email in a background thread to prevent latency blocking the log monitor
            email_thread = threading.Thread(
                target=self._send_email_notification,
                args=(alert_entry,),
                name="EmailAlertThread",
                daemon=True
            )
            email_thread.start()

    def _send_desktop_notification(self, alert: dict):
        """Triggers local desktop notification bubble."""
        if not DESKTOP_SUPPORTED:
            logger.debug("Desktop notifications disabled: plyer library not installed.")
            return

        title = f"LogGuard Alert [{alert['severity']}]"
        # Truncate message if it's too long for a system bubble
        message = alert["message"]
        if len(message) > 200:
            message = message[:197] + "..."

        def _notify():
            try:
                notification.notify(
                    title=title,
                    message=message,
                    app_name="LogGuard",
                    timeout=self.config.desktop_timeout
                )
            except Exception as e:
                logger.debug(f"Failed to trigger desktop notification (expected in headless environment): {e}")

        # Run notification in separate thread to prevent blocking
        t = threading.Thread(target=_notify, daemon=True)
        t.start()

    def _send_email_notification(self, alert: dict):
        """Connects to SMTP host and sends structured HTML/Plain-text email."""
        c = self.config
        if not all([c.smtp_host, c.smtp_port, c.smtp_username, c.smtp_password, c.from_email, c.to_email]):
            logger.error("Email alerting is enabled but SMTP settings are incomplete in config.yaml")
            return

        subject = f"[{alert['severity']}] LogGuard Alert - {alert['alert_type']}"

        # Email body structure
        plain_body = (
            f"LogGuard Alert Triggered!\n\n"
            f"Severity: {alert['severity']}\n"
            f"Event Type: {alert['alert_type']}\n"
            f"Timestamp: {alert['timestamp']}\n\n"
            f"Message:\n{alert['message']}\n\n"
            f"This is an automated security email from your LogGuard Monitoring System.\n"
        )

        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #f4f6f9; padding: 20px; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; border: 1px solid #ddd; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                <div style="background-color: {'#d9534f' if alert['severity'] == 'CRITICAL' else '#f0ad4e'}; color: white; padding: 15px; text-align: center; font-size: 20px; font-weight: bold;">
                    LogGuard Alert: {alert['severity']}
                </div>
                <div style="padding: 20px;">
                    <p style="font-size: 16px;">An alert rule has been triggered by the log monitoring system:</p>
                    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
                        <tr style="background-color: #f9f9f9;">
                            <td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #eee;">Alert Type:</td>
                            <td style="padding: 8px; border-bottom: 1px solid #eee;">{alert['alert_type']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #eee;">Timestamp:</td>
                            <td style="padding: 8px; border-bottom: 1px solid #eee;">{alert['timestamp']}</td>
                        </tr>
                        <tr style="background-color: #f9f9f9;">
                            <td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #eee;">Severity:</td>
                            <td style="padding: 8px; color: {'red' if alert['severity'] == 'CRITICAL' else 'orange'}; font-weight: bold; border-bottom: 1px solid #eee;">{alert['severity']}</td>
                        </tr>
                    </table>
                    <div style="background-color: #f8f9fa; border-left: 4px solid #d9534f; padding: 15px; margin: 15px 0; font-family: monospace; font-size: 14px; white-space: pre-wrap;">
                        {alert['message']}
                    </div>
                </div>
                <div style="background-color: #f1f1f1; padding: 10px; text-align: center; font-size: 12px; color: #777;">
                    This is an automated alert from your self-hosted LogGuard daemon.
                </div>
            </div>
        </body>
        </html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = c.from_email
        msg["To"] = c.to_email

        part1 = MIMEText(plain_body, "plain")
        part2 = MIMEText(html_body, "html")
        msg.attach(part1)
        msg.attach(part2)

        try:
            with smtplib.SMTP(c.smtp_host, c.smtp_port, timeout=10) as server:
                server.starttls()
                server.login(c.smtp_username, c.smtp_password)
                server.sendmail(c.from_email, c.to_email, msg.as_string())
            logger.info(f"Email alert dispatched successfully to {c.to_email}")
        except Exception as e:
            logger.error(f"Failed to dispatch email alert: {e}")
