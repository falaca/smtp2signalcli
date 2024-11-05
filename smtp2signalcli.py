#!/usr/bin/env python3
import email
import base64
import io
import json
import yaml
import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage
from aiosmtpd.smtp import AuthResult, LoginPassword
from email.message import EmailMessage
import requests
import logging

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

SIGNAL_CLI_API_URL = config["SIGNAL_CLI_API_URL"]
SIGNAL_RECIPIENT = config["SIGNAL_RECIPIENT"]
SIGNAL_ACCOUNT = config["SIGNAL_ACCOUNT"]
SMTP_PORT = config["SMTP_PORT"]

# This provides no security, since we are not using TLS.
# However, the Reolink doorbell refuses to send emails
# if the SMTP server doesn't support authentication.
USER_CREDENTIALS = {
    'doorbell': '12345',
}

class SignalHandler(AsyncMessage):
    async def handle_message(self, message):
        sender = message["from"]
        recipients = message["to"]
        subject = message["subject"]
        body = self.get_body(message)
        base64_attachments = self.get_base64_attachments(message)

        # Construct JSON payload for signal-cli REST API
        payload = {
            "message": f"{body}",
            "number": SIGNAL_ACCOUNT,
            "recipients": [SIGNAL_RECIPIENT],
            "base64_attachments": base64_attachments,
            "notify_self": False,
            "text_mode": "normal"
        }

        #print("Payload:", json.dumps(payload, indent=2))

        # Send the message to signal-cli REST API
        try:
            response = requests.post(SIGNAL_CLI_API_URL, json=payload)
            response.raise_for_status()
            print("Message sent to Signal successfully.")
        except requests.exceptions.RequestException as e:
            print("Error sending message to Signal:", e)

    def get_body(self, msg):
        """Extracts the body of an email."""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition"))

                if content_type == "text/plain" and "attachment" not in disposition:
                    return part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8")
        else:
            return msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8")

    def get_base64_attachments(self, msg):
        """Extracts JPEG attachments, encodes them in base64, and formats them for signal-cli."""
        base64_attachments = []
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition"))

            if content_type == "image/jpeg" and "attachment" in disposition:
                # Read the attachment content and encode it to base64
                attachment_data = part.get_payload(decode=True)
                base64_data = base64.b64encode(attachment_data).decode("utf-8")
                
                # Format as per the required `base64_attachments` structure
                base64_attachments.append(f"data:{content_type};base64,{base64_data}")
                print("Attachment added as base64.")
        
        return base64_attachments

class Authenticator:
    def __call__(self, server, session, envelope, mechanism, auth_data):
        login = auth_data.login.decode('utf-8')
        password = auth_data.password.decode('utf-8')
        if login in USER_CREDENTIALS and USER_CREDENTIALS[login] == password:
            return AuthResult(success=True)
        return AuthResult(success=False)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    handler = SignalHandler()
    auth = Authenticator()
    controller = Controller(handler, hostname="0.0.0.0", port=SMTP_PORT, authenticator=auth, auth_required=True, auth_require_tls=False)
    controller.start()
    print(f"SMTP server running on port {SMTP_PORT}. Waiting for emails...")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        print("SMTP server shutting down.")
        controller.stop()
