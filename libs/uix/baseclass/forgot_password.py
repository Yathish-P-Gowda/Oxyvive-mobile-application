import re
import smtplib
from email.message import EmailMessage
import anvil
from anvil.tables import app_tables
from kivy import platform
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from kivy.utils import dp
from kivymd.app import MDApp
from kivymd.uix.dialog import MDDialog
from kivymd.uix.screen import MDScreen
from twilio.rest import Client
from server import Server
import base64
import json
import os
from server import Server

import bcrypt
import random
import smtplib

from io import BytesIO
from kivy.core.window import Window
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivymd.uix.screen import MDScreen
from kivy.properties import BooleanProperty, StringProperty
from kivy.uix.label import Label
from kivy.uix.popup import Popup
from twilio.rest import Client
from anvil.tables import app_tables

from server import Server

# Your Twilio credentials
account_sid = "AC64ab0fed3c9135f8011fb5e50f969cbe"
auth_token = "2c450c5297067c3a88b338397d95beaf"
verify_sid = "VA8937ab1f8c09c4e3842e4b32f72c8dc7"
verified_number = "+919108340960"

# Initialize Twilio client
try:
    client = Client(account_sid, auth_token)
except Exception as e:
    print(f"Error: {e}")


class ForgotPassword(MDScreen):
    def __init__(self, **kwargs):
        super(ForgotPassword, self).__init__(**kwargs)
        Window.bind(on_keyboard=self.on_keyboard)
        self.server = Server()

    def on_keyboard(self, instance, key, scancode, codepoint, modifier):
        if key == 27:  # Keycode for the back button on Android
            self.on_back_button()
            return True
        return False

    def on_back_button(self):
        self.manager.push_replacement("login","right")

    def show_validation_dialog(self, message):
        # Create the dialog asynchronously
        Clock.schedule_once(lambda dt: self._create_dialog(message), 0)

    def _create_dialog(self, message):
        dialog = MDDialog(
            text=f"{message}",
            elevation=0,
        )
        dialog.open()

    def validate_password(self, password):
        # Check if the password is not empty
        if not password:
            return False, ""
        # Check if the password has at least 8 characters
        if len(password) < 6:
            return False, "Password must have at least 6 characters"
        # Check if the password contains both uppercase and lowercase letters
        if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
            return False, "Password must contain uppercase, lowercase"
        # Check if the password contains at least one digit
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
        # Check if the password contains at least one special character
        special_characters = r"[!@#$%^&*(),.?\":{}|<>]"
        if not re.search(special_characters, password):
            return False, "Password must contain a special character"
        # All checks passed; the password is valid
        return True, "Password is valid"

    def change_password(self):
        email_phone = self.ids.phone_email.text
        new_password = self.ids.new_password.text.strip()

        is_valid_password, password_error_message = self.validate_password(new_password)
        self.ids.change_password.disabled = False

        if self.server.is_connected():
            if "@" in email_phone:
                record = app_tables.oxi_users.get(oxi_email=email_phone)
            else:
                record = app_tables.oxi_users.get(oxi_phone=email_phone)

            if not is_valid_password:
                self.ids.new_password.error = True
                self.ids.new_password.helper_text = password_error_message
            else:
                if record:
                    # Verify the old password if you're implementing a change-password feature
                    # Assuming there's a field for the old password and method to get it
                    hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                    record.update(oxi_password=hashed_new_password.decode('utf-8'))
                    self.manager.push_replacement("login")
                    print("Password changed successfully.")

                else:
                    print("User record not found.")

    def show_popup(self, message, on_ok=None):
        popup_content = BoxLayout(orientation='vertical', padding=10, spacing=10)

        message_label = Label(
            font_size=25,
            text=message,
            text_size=(0.8 * Window.width, None),
            halign='center',
            valign='middle',
            color=(0, 0, 0, 1)  # RGB Black
        )
        message_label.bind(size=message_label.setter('text_size'))

        ok_button = Button(
            text="OK",
            font_size=dp(25),
            size_hint=(None, None),
            size=(dp(100), dp(40)),
            pos_hint={'center_x': 0.5},
            background_normal='',
            background_color=(1, 0, 0, 1),  # Red color
            color=(1, 1, 1, 1),  # White text color
            on_release=lambda x: (popup.dismiss(), on_ok() if on_ok else None)
        )

        popup_content.add_widget(message_label)
        popup_content.add_widget(ok_button)

        popup = Popup(
            title='Info',
            title_color='black',
            content=popup_content,
            size_hint=(0.8, 0.3),
            background='white',
            auto_dismiss=False  # Prevent dismissal without pressing OK
        )
        popup.open()

    import smtplib
    from email.message import EmailMessage

    def send_email_otp(self, email):
        self.n = str(random.randint(100000, 999999))
        try:
            from_mail = "oxivive@gmail.com"
            password = "bqrt soih plhy dnix"  # Consider using environment variables for sensitive info
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(from_mail, password)
            msg = EmailMessage()
            msg['Subject'] = "OTP Verification"
            msg['From'] = from_mail
            msg['To'] = email
            msg.set_content(f"Your OTP is: {self.n}")
            server.send_message(msg)
            server.quit()
            self.show_popup(
                f"OTP sent via email {email}",
                on_ok=lambda: self.update_ui_on_otp_sent(email)
            )
        except Exception as e:
            print(f"Error: {e}")
            self.show_popup("Failed to send email, try again!")

    def send_sms_otp(self, user_input):
        try:
            self.n = str(random.randint(100000, 999999))
            self.client.messages.create(
                to=user_input,
                from_="1234",
                body=f"Your OTP is: {self.n}"
            )
            self.show_popup(
                f"OTP sent via SMS {user_input}",
                on_ok=lambda: self.update_ui_on_otp_sent(user_input)
            )
        except Exception as e:
            self.show_popup("Failed to send SMS, try again!")

    #
    def sent_otp(self):
        if platform == 'android':
            from android.permissions import request_permissions, Permission
            request_permissions([Permission.SEND_SMS, Permission.RECEIVE_SMS])
        user_input = self.ids.phone_email.text
        if self.server.is_connected():
            # Fetch user from Anvil's database
            if "@" in user_input:
                user_anvil = app_tables.oxi_users.get(oxi_email=user_input)
                if user_anvil:
                    self.send_email_otp(user_input)
            else:
                try:
                    user_input = int(user_input)
                    user_anvil = app_tables.oxi_users.get(oxi_phone=user_input)
                    if user_anvil:
                        self.send_sms_otp(user_input)
                except ValueError:
                    self.show_popup("Invalid phone number format")
                    return

    def handle_invalid_phone(self):
        self.ids.phone_email.helper_text = "Invalid Email or Phone number (10 digits required)"

    def update_ui_on_otp_sent(self, phone_number):
        print(f"OTP sent to {phone_number}")
        self.ids.sent_otp.text = "Sent"
        self.ids.sent_otp.color = (0, 1, 0, 1)
        self.ids.otp.disabled = False
        self.ids.verify_otp.disabled = False

    def handle_otp_sending_error(self, e):
        self.show_validation_dialog(f"{e}")

    #
    def verify_otp(self):
        email_phone = self.ids.phone_email.text
        user_entered_otp = self.ids.otp.text
        if "@" in email_phone:
            if user_entered_otp ==self.n:
                self.update_ui_on_otp_verified()
            else:
                self.handle_invalid_phone()
        else:
            if user_entered_otp ==self.n:
                self.update_ui_on_otp_verified()
            else:
                self.handle_invalid_phone()

        # try:
        #     # Verify OTP via Twilio
        #     verification_check = client.verify.v2.services(verify_sid) \
        #         .verification_checks \
        #         .create(to=phone_number, code=user_entered_otp)
        #     if verification_check.status == 'approved':
        #         self.update_ui_on_otp_verified()
        #     else:
        #         self.handle_invalid_otp()
        # except Exception as e:
        #     self.handle_otp_verification_error(e)

    def update_ui_on_otp_verified(self):
        print("OTP verified")
        self.ids.verify_otp.text = "Verified"
        self.ids.verify_otp.color = (0, 1, 0, 1)
        self.ids.new_password.disabled = False
        self.change_password()

    def handle_invalid_otp(self):
        self.show_validation_dialog("Invalid OTP")

    def handle_otp_verification_error(self, e):
        self.show_validation_dialog("Error Occurred")
        print(e)
