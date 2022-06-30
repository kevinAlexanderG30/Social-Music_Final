import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

message = Mail(
    from_email='tkxk3vin@gmail.com',
    to_emails='tkxk3vin@gmail.com',
    subject='Sending with Twilio SendGrid is Fun',
    html_content='Confirmation email <a href="http://localhost:5000">Ok</a>')
try:
    sg = SendGridAPIClient("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")
    response = sg.send(message)
    print(response.status_code)
    print(response.body)
    print(response.headers)
except Exception as e:
    print(str(e))