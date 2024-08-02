import json
import math
import os
import random
import smtplib
import string
import time
import webbrowser
from datetime import datetime
from email.message import EmailMessage
from http.server import SimpleHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import urlparse, parse_qs
import requests
from anvil.tables import app_tables
from kivy.clock import Clock
from kivy.core.window import Window
from kivymd.uix.button import MDFlatButton
from kivymd.uix.dialog import MDDialog
from kivymd.uix.screen import MDScreen
from server import Server
from kivymd.uix.button import MDRaisedButton


class Payment(MDScreen):
    servicer_id = None
    date = None
    time_left = None
    api_key = "AIzaSyA8GzhJLPK0Hfryi5zHbg3RMDSMCukmQCw"
    origin = None

    def __init__(self, **kwargs):
        super(Payment, self).__init__(**kwargs)
        self.amt = None
        self.service_type = None
        self.razorpay_payment_id = None
        self.dialog = None
        self.tax = None
        self.data_stored = False  # Flag to prevent storing data multiple times
        self.dialog_opened = False  # Flag to prevent showing dialog multiple times
        Window.bind(on_keyboard=self.on_keyboard)
        self.server = Server()

    def on_pre_enter(self):
        self.change()
        self.servicer_details()
        self.user_details()
        self.data_stored = False
        self.dialog_opened = False

    def on_keyboard(self, instance, key, scancode, codepoint, modifier):
        if key == 27:  # Keycode for the back button on Android
            self.on_back_button()
            return True
        return False

    def on_back_button(self):
        self.manager.push("slot_booking", "right")

    def change(self):
        pass

    def store_booked_data(self):
        if self.data_stored:
            return
        self.data_stored = True  # Set the flag to indicate data is stored

        with open('booking_data.json', 'r') as file:
            booking_data = json.load(file)
        oxi_id = booking_data.get('user_id', '')
        servicer_id = booking_data.get('servicer_id', '')
        book_date = booking_data.get('book_date', '')
        book_time = booking_data.get('book_time', '')
        self.date_time = booking_data.get('date_time', '')
        username = booking_data.get('username', '')

        script_dir = os.path.dirname(os.path.abspath(__file__))
        json_user_file_path = os.path.join(script_dir, "user_data.json")
        # Fetch email from user_data.json
        with open(json_user_file_path, 'r') as file:
            user_data = json.load(file)
        oxi_email = user_data.get('email', '')
        print(oxi_email)

        try:
            if self.server.is_connected():
                slot_id = self.generate_random_code()
                date_object = datetime.strptime(book_date, '%Y-%m-%d').date()
                app_tables.oxi_book_slot.add_row(
                    oxi_book_id=slot_id,
                    oxi_servicer_id=servicer_id,
                    oxi_id=oxi_id,
                    oxi_book_date=date_object,
                    oxi_book_time=book_time,
                    oxi_date_time=self.date_time,
                    oxi_payment_id=self.razorpay_payment_id,
                    oxi_username=username,
                    oxi_service_type=self.service_type
                )
                self.show_validation_dialog(
                    "Your slot is successfully booked. You will receive an instant response from Oxivive.",
                    self.on_payment_success
                )

                # Sending email after successful booking
                email_subject = "Booking Confirmation From Oxivive"
                email_message = (f"Dear {username},\n\nYour slot is successfully booked on {self.date_time} for "
                                 f"{self.service_type}.\n\nThank you for choosing our service at OXIVIVE.")
                self.send_email(oxi_email, email_subject, email_message)
                Clock.schedule_once(self.sending_notification)
                self.manager.push_replacement('client_services')
            else:
                self.show_validation_dialog("No internet connection")
        except Exception as e:
            print(e)
            self.show_validation_dialog("Error processing user data")


    def show_validation_dialog(self, message, callback=None):
        if self.dialog_opened:
            return
        self.dialog_opened = True  # Set the flag to indicate dialog is shown
        Clock.schedule_once(lambda dt: self._create_dialog(message, callback), 0)

    def _create_dialog(self, message, callback):
        dialog = MDDialog(
            text=f"{message}",
            elevation=0,
            buttons=[MDRaisedButton(text="OK", on_release=lambda x: self._close_dialog(dialog, callback))],
        )
        dialog.open()

    def _close_dialog(self, dialog, callback):
        dialog.dismiss()
        self.dialog_opened = False  # Reset the flag after closing dialog
        if callback:
            callback()

    def on_payment_success(self):
        self.manager.push_replacement('client_services')

    def servicer_details(self):
        details = app_tables.oxiclinics.get(oxiclinics_id=self.servicer_id)
        if not details:
            details = app_tables.oxiwheels.get(oxiwheels_id=self.servicer_id)
            if not details:
                details = app_tables.oxigyms.get(oxigyms_id=self.servicer_id)
        if not details:
            print("Service ID not found in any table")
            return
        details = dict(details)
        print(details)
        if 'oxiclinics_address' in details:
            self.ids.service_name.text = details.get('oxiclinics_Name', 'N/A')
            self.service_type = 'OxiClinic'
            self.ids.service_type.text = 'OxiClinic'
            self.ids.service_address.text = details.get('oxiclinics_address', 'N/A')
            self.ids.c_fee.text = f"₹{details.get('oxiclinics_fees', 'N/A')}"
            self.amt = details.get('oxiclinics_fees', 'N/A')
            oxiclinics_profile = details['oxiclinics_image']
            if oxiclinics_profile:
                current_dir = os.getcwd()
                image_path = os.path.join(current_dir, 'servicer_profile_image.png')
                with open(image_path, 'wb') as img_file:
                    img_file.write(oxiclinics_profile.get_bytes())

                if 's_image' in self.ids:
                    self.ids.s_image.source = image_path
                    self.ids.s_image.reload()
                else:
                    print("Profile image ID not found")
            else:
                if 's_image' in self.ids:
                    self.ids.s_image.source = 'images/profile.jpg'

            self.destination = details['oxiclinics_address']
            print('origin', self.origin)
            print('destination', self.destination)
            self.fetch_and_calculate_distance()

        elif 'oxiwheels_address' in details:
            self.ids.service_name.text = details.get('oxiwheels_Name', 'N/A')
            self.service_type = 'OxiWheel'
            self.ids.service_type.text = 'OxiWheel'
            self.ids.service_address.text = details.get('oxiwheels_address', 'N/A')
            self.ids.c_fee.text = f"₹{details.get('oxiwheels_fees', 'N/A')}"
            self.amt = details.get('oxiwheels_fees', 'N/A')
            oxiwheels_profile = details['oxiwheels_image']
            if oxiwheels_profile:
                current_dir = os.getcwd()
                image_path = os.path.join(current_dir, 'servicer_profile_image.png')
                with open(image_path, 'wb') as img_file:
                    img_file.write(oxiwheels_profile.get_bytes())

                if 's_image' in self.ids:
                    self.ids.s_image.source = image_path
                    self.ids.s_image.reload()
                else:
                    print("Profile image ID not found")
            else:
                if 's_image' in self.ids:
                    self.ids.s_image.source = 'images/profile.jpg'

            self.destination = details['oxiwheels_address']

            print('origin', self.origin)
            print('destination', self.destination)
            self.fetch_and_calculate_distance()



        elif 'oxigyms_address' in details:
            self.ids.service_name.text = details.get('oxigyms_Name', 'N/A')
            self.service_type = 'OxiGym'
            self.ids.service_type.text = 'OxiGym'
            self.ids.service_address.text = details.get('oxigyms_address', 'N/A')
            self.ids.c_fee.text = f"₹{details.get('oxigyms_fees', 'N/A')}"
            self.amt = details.get('oxigyms_fees', 'N/A')
            oxigyms_profile = details['oxigyms_image']
            if oxigyms_profile:
                current_dir = os.getcwd()
                image_path = os.path.join(current_dir, 'servicer_profile_image.png')
                with open(image_path, 'wb') as img_file:
                    img_file.write(oxigyms_profile.get_bytes())

                if 's_image' in self.ids:
                    self.ids.s_image.source = image_path
                    self.ids.s_image.reload()
                else:
                    print("Profile image ID not found")
            else:
                if 's_image' in self.ids:
                    self.ids.s_image.source = 'images/profile.jpg'

            self.destination = details['oxigyms_address']

            print('origin', self.origin)
            print('destination', self.destination)
            self.fetch_and_calculate_distance()
        else:
            self.ids.service_address.text = 'N/A'

    def view_bill(self):
        scroll_view = self.ids.scroll_view
        bill_card = self.ids.bill
        scroll_view.scroll_to(bill_card)

    def generate_random_code(self):
        prefix = "BI"
        random_numbers = ''.join(random.choices(string.digits, k=5))
        code = prefix + random_numbers
        return code

    def initiate_payment(self):
        print("Initiating payment...")
        amount = int(self.amt)  # Amount in INR (sub-units, e.g., 100 INR = 10000 paisa)
        api_key = 'rzp_test_41ch2lqayiGZ9X'
        api_secret = 'CPEd7kVR1d215BH12bIoJb63'

        try:
            response = requests.post(
                'https://api.razorpay.com/v1/orders',
                auth=(api_key, api_secret),
                data=json.dumps({
                    'amount': amount * 100,  # Amount in paisa
                    'currency': 'INR',
                    'receipt': 'order_rcptid_12',
                    'payment_capture': '1'
                }),
                headers={'Content-Type': 'application/json'}
            )
            response.raise_for_status()
            order_data = response.json()
            print(f"Order created successfully. Order ID: {order_data['id']}")
            order_id = order_data['id']
            self.update_html_file(order_id, amount * 100)
            self.serve_and_open_html()
        except requests.exceptions.HTTPError as http_err:
            print(f"HTTP error occurred: {http_err}")
        except Exception as err:
            print(f"Other error occurred: {err}")

    def update_html_file(self, order_id, amount):
        print(f"Updating HTML file with order ID: {order_id} and amount: {amount}")
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Razorpay Checkout</title>
            <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
        </head>
        <body>
        <script>
            var options = {{
                "key": "rzp_test_41ch2lqayiGZ9X",
                "amount": "{amount}",
                "currency": "INR",
                "name": "Oxivive",
                "description": "Test Transaction",
                "order_id": "{order_id}",
                "handler": function (response) {{
                    var xhr = new XMLHttpRequest();
                    xhr.open('GET', 'http://localhost:9000/success?payment_id=' + response.razorpay_payment_id, true);
                    xhr.send();
                    alert("Payment successful! Payment ID: " + response.razorpay_payment_id);
                    window.location.href = "http://localhost:9000/success";
                }},
                "prefill": {{
                    "name": "Your Name",
                    "email": "your.email@example.com",
                    "contact": "9999999999"
                }},
                "theme": {{
                    "color": "#3399cc"
                }}
            }};
            var rzp1 = new Razorpay(options);
            rzp1.on('payment.failed', function (response) {{
                alert("Payment failed! Error: " + response.error.reason);
            }});
            rzp1.open();
        </script>
        </body>
        </html>
        """
        with open("checkout.html", "w") as file:
            file.write(html_content)
        print("HTML file updated successfully.")

    def serve_and_open_html(self):
        def serve(app):
            class CustomHandler(SimpleHTTPRequestHandler):
                def __init__(self, *args, **kwargs):
                    self.app = app
                    super().__init__(*args, **kwargs)

                def do_GET(self):
                    if self.path.startswith('/success'):
                        parsed_url = urlparse(self.path)
                        query_params = parse_qs(parsed_url.query)
                        payment_id = query_params.get('payment_id', [''])[0]
                        if payment_id:
                            print(f"Payment successful! Payment ID: {payment_id}")
                            self.app.razorpay_payment_id = payment_id
                        print("Success page requested.")
                        self.send_response(200)
                        self.send_header("Content-type", "text/html")
                        self.end_headers()
                        self.wfile.write(b"""
                            <!DOCTYPE html>
                                <html lang="en">
                                    <head>
                                        <meta charset="UTF-8">
                                        <title>Oxivive Payment Success</title>
                                    </head>
                                    <body>
                                        <h1>Payment Successful!</h1>
                                    </body>
                                </html>
                            """)
                        print("Sending response to success page request.")
                        print("Shutting down the server and switching to success screen.")
                        shutdown_thread = Thread(target=self.app.shutdown_and_switch)
                        shutdown_thread.start()
                    else:
                        print(f"Serving file: {self.path}")
                        super().do_GET()

            httpd = HTTPServer(('localhost', 9000), CustomHandler)
            print("Local server started. Serving at http://localhost:9000/checkout.html")
            httpd.serve_forever()

        server_thread = Thread(target=serve, args=(self,))
        server_thread.daemon = True
        server_thread.start()
        print("Opening Razorpay checkout page...")
        webbrowser.open("http://localhost:9000/checkout.html")
        # webview.create_window('Razorpay Checkout', url="http://localhost:9000/checkout.html", width=800, height=600,
        # resizable=True, js_api=True)
        # webview.start()

    def shutdown_and_switch(self):
        time.sleep(1)
        print("Server shutdown initiated.")
        self.switch_to_success_screen()

    def switch_to_success_screen(self):
        self.store_booked_data()


    def sending_notification(self, *args):
        self.appointment_time = self.convert_datetime(self.date_time)
        print(self.appointment_time)
        message = f"Your appointment is booked for {self.appointment_time.strftime('%Y-%m-%d %H:%M')}"
        self.manager.load_screen('menu_notification')
        self.manager.get_screen('menu_notification').schedule_notifications(self.appointment_time)
        self.manager.get_screen('menu_notification').show_notification("Appointment Booked", message)

        print("Switched to success screen.")

    def convert_datetime(self, original_str):
        # Define the format of the original datetime string (without year)
        original_format = "%a, %d %b %I:%M %p"
        # Parse the original datetime string
        try:
            dt = datetime.strptime(original_str, original_format)
        except ValueError as e:
            print(f"Error parsing datetime: {e}")
            return None
        # Replace the year with the current year
        current_year = datetime.now().year
        dt = dt.replace(year=current_year)

        return dt

    def get_distance(self, api_key, origin, destination):
        url = "https://maps.googleapis.com/maps/api/distancematrix/json"
        params = {
            "origins": origin,
            "destinations": destination,
            "key": api_key
        }

        response = requests.get(url, params=params)
        data = response.json()

        if data['status'] == 'OK':
            elements = data['rows'][0]['elements'][0]
            if elements['status'] == 'OK':
                distance = elements['distance']['text']
                duration = elements['duration']['text']
                return distance, duration
            else:
                return "Error: " + elements['status']
        else:
            return "Error: " + data['status']

    def fetch_coordinates(self, address):
        url = "https://maps.googleapis.com/maps/api/geocode/json"
        params = {
            "address": address,
            "key": self.api_key
        }

        response = requests.get(url, params=params)
        data = response.json()

        if data['status'] == 'OK':
            location = data['results'][0]['geometry']['location']
            return location['lat'], location['lng']
        else:
            raise ValueError(f"Error fetching coordinates: {data['status']}")

    def fetch_and_calculate_distance(self):
        try:
            origin_coords = self.fetch_coordinates(self.origin)
            destination_coords = self.fetch_coordinates(self.destination)

            lat1, lon1 = origin_coords
            lat2, lon2 = destination_coords

            distance = self.haversine(lat1, lon1, lat2, lon2)
            result_text = f"Distance: {distance:.2f} km"
        except ValueError as e:
            result_text = str(e)

        self.ids.distance_from.text = f'[color=#6200EA]Distance between [/color] - {result_text}'

    def haversine(self, lat1, lon1, lat2, lon2):
        R = 6371  # Earth radius in kilometers

        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(
            dlon / 2) ** 2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        distance = R * c
        return distance

    def send_email(self, email, subject, message):
        try:
            from_mail = "oxivive@gmail.com"
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(from_mail, "bqrt soih plhy dnix")

            msg = EmailMessage()
            msg['Subject'] = subject
            msg['From'] = from_mail
            msg['To'] = email
            msg.set_content(message)
            server.send_message(msg)
            server.quit()
            print(f"Email sent successfully to {email}")
        except Exception as e:
            print(f"Failed to send email: {e}")

    def user_details(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        json_user_file_path = os.path.join(script_dir, "user_data.json")
        with open(json_user_file_path, 'r') as file:
            user_info = json.load(file)

            self.ids.username.text = f"{user_info.get('username')}"