#!/usr/bin/env python3
import asyncio
import base64
import email
import io
import json
import logging
import os
import re
import requests
import ssl
import yaml

from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage
from aiosmtpd.smtp import AuthResult, LoginPassword
from email.message import EmailMessage
from OpenSSL import crypto

with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

SIGNAL_CLI_API_URL = config["SIGNAL_CLI_API_URL"]
SIGNAL_ACCOUNT = config["SIGNAL_ACCOUNT"]
SMTP_PORT = config["SMTP_PORT"]

# To increase compatibility with old devices, TLS can be made optional.
# But without TLS, passwords are sent in the clear, providing no security.
# Reolink cameras require authentication and support TLS but do not
# perform certificate validation, offering little benefit over plain SMTP.
REQUIRE_TLS = config["REQUIRE_TLS"]
USER_CREDENTIALS = config.get("USER_CREDENTIALS", {})

RECIPIENT_MAP = config.get("RECIPIENT_MAP", {})

CERT_FILE = "smtp_cert.pem"
KEY_FILE = "smtp_key.pem"

# Generate a self-signed certificate if one doesn't exist
def generate_self_signed_cert(cert_file, key_file):
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        print("Generating self-signed certificate...")
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.get_subject().CN = "smtp2signal"
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)  # 10 years
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, "sha256")

        with open(cert_file, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_file, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        print("Self-signed certificate generated.")
    else:
        print("Using existing certificate.")


class SignalHandler(AsyncMessage):
    async def handle_message(self, message):
        sender = message["from"]
        recipients = message["to"]
        subject = message["subject"]
        body = self.get_body(message)
        base64_attachments = self.get_base64_attachments(message)

        # Extract valid Signal recipients from recipient email addresses
        signal_recipients = self.extract_signal_recipients(recipients)
        if not signal_recipients:
            print("No valid phone number or group ID found in recipient email addresses.")
            return

        # Construct JSON payload for signal-cli REST API
        payload = {
            "message": f"{body}",
            "number": SIGNAL_ACCOUNT,
            "recipients": signal_recipients,
            "base64_attachments": base64_attachments,
            "notify_self": False,
            "text_mode": "normal"
        }

        logging.debug("Payload: %s", json.dumps(payload, indent=2))

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

    def extract_signal_recipients(self, recipients):
        """Extracts valid Signal recipients from recipient email addresses."""
        signal_recipients = []
        for recipient in recipients.split(","):
            recipient = recipient.strip().lstrip("<").rstrip(">").split('@')[0]  # Ignore domain

            # Check for a phone number in format +12345678901 or 12345678901
            phone_match = re.search(r"\+?(\d{10,15})", recipient)
            if phone_match:
                phone_number = phone_match.group(1)
                if not phone_number.startswith("+"):
                    phone_number = f"+{phone_number}"
                signal_recipients.append(phone_number)
                continue

            # Check for a group ID in the format "group.<base64ID>"
            # But some email clients don't allow / or = characters
            group_match = re.match(r"group\.([A-Za-z0-9+/=]+)", recipient)
            if group_match:
                group_id = group_match.group(0)
                signal_recipients.append(group_id)
                continue

            # Check if recipient is in the RECIPIENT_MAP
            mapped_recipient = RECIPIENT_MAP.get(recipient)
            if mapped_recipient:
                signal_recipients.append(mapped_recipient)
                continue

            print(f"Ignoring invalid recipient address: {recipient}")

        return signal_recipients if signal_recipients else None

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

    generate_self_signed_cert(CERT_FILE, KEY_FILE)
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    controller = Controller(
            handler,
            hostname="0.0.0.0",
            port=SMTP_PORT,
            authenticator=auth,
            auth_required=True,
            auth_require_tls=REQUIRE_TLS,
            require_starttls=REQUIRE_TLS,
            tls_context=ssl_context)
    controller.start()
    print(f"SMTP server running on port {SMTP_PORT}. Waiting for emails...")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        print("SMTP server shutting down.")
        controller.stop()
