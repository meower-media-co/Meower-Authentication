from jinja2 import Template
from threading import Thread
import os
import requests


TEMPLATES = {
    "verify_email": {
        "subject": "Verify your email address",
        "file": "verify_email.html",
        "fields": ["username"],
        "link": True
    },
    "verify_child": {
        "subject": "Verify your child's Meower account",
        "file": "verify_child.html",
        "fields": ["username"],
        "link": True
    },
    "reset_password": {
        "subject": "Reset your Meower password",
        "file": "reset_password.html",
        "fields": ["username"],
        "link": True
    }
}


def send_email(email:str, template:str, fields:dict, token:str = None):
    if email is None:
        return

    # Make sure template exists
    if template not in TEMPLATES:
        raise FileNotFoundError

    # Get template information
    template = TEMPLATES[template]
    
    # Make sure all fields are set
    if set(fields.keys()) != set(template["fields"]):
        raise ValueError

    # Create link
    if template["link"]:
        fields["link"] = (os.getenv("EMAIL_CALLBACK", "https://meower.org/email-action") + "?token=" + token)

    # Render template
    body = Template(template["file"]).render(fields)

    # Send email
    mail_provider = os.getenv("EMAIL_PROVIDER", "mailchannels")
    if mail_provider == "mailchannels":
        # Create and start thread for worker request
        Thread(target=requests.post,
            args=(
                os.getenv("EMAIL_WORKER_URL", "email-worker.meower.org"),
            ),
            kwargs={
                "headers": {
                    "X-Auth-Token": os.getenv("EMAIL_WORKER_TOKEN")
                },
                "json": {
                    "email": email,
                    "name": fields.get("username", email.split("@")[0]),
                    "subject": template["subject"],
                    "body": body
                }
            }
        ).start()
    elif mail_provider == "smtp":
        pass # TODO: Add SMTP support
