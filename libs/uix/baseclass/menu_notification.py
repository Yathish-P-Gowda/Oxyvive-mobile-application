import json
import logging
import os
from datetime import datetime, timedelta

import anvil
from anvil.tables import app_tables
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.uix.floatlayout import FloatLayout
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.button import MDRaisedButton
from kivymd.uix.card import MDCard
from kivymd.uix.label import MDLabel, MDIcon
from kivymd.uix.screen import MDScreen
from plyer import notification
from plyer.utils import platform

if platform == 'android':
    from jnius import autoclass, cast

    PythonActivity = autoclass('org.kivy.android.PythonActivity')
    Context = autoclass('android.content.Context')
    Intent = autoclass('android.content.Intent')
    PendingIntent = autoclass('android.app.PendingIntent')
    NotificationManager = autoclass('android.app.NotificationManager')
    NotificationChannel = autoclass('android.app.NotificationChannel')
    NotificationBuilder = autoclass('android.app.Notification$Builder')


class NoNotification(MDBoxLayout):
    pass


class Notification(MDScreen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        Window.bind(on_keyboard=self.on_keyboard)
        self.notifications = []
        script_dir = os.path.dirname(os.path.abspath(__file__))
        json_user_file_path = os.path.join(script_dir, "user_data.json")
        with open(json_user_file_path, 'r') as file:
            user_info = json.load(file)
            self.user_id = user_info['id']
        self.load_notifications()

    def save_notification(self, title, message):
        """Save a new notification to the Anvil database."""
        app_tables.oxi_notifications.add_row(oxi_id=self.user_id, oxi_notification_title=title,
                                             oxi_notification=message)

    def load_notifications(self):
        """Load notifications from the Anvil database."""
        notifications = app_tables.oxi_notifications.search(oxi_id=self.user_id)
        notifications_list = list(notifications)
        if not notifications_list:
            self.show_no_notifications_message()
        else:
            self.notifications = [notif['message'] for notif in notifications]
            self.update_notification_list()

    def show_no_notifications_message(self):
        """Show a message indicating there are no notifications."""
        notification_list = self.ids.notification_list
        notification_list.clear_widgets()

        # Create a layout to center the message and icon
        layout = MDBoxLayout(orientation='vertical', size_hint_y=None, height=self.height)
        layout.add_widget(MDIcon(icon='bell-outline', size_hint=(None, None), size=('96dp', '96dp'),
                                 pos_hint={'center_x': 0.5, 'center_y': 0.6}))
        layout.add_widget(MDLabel(text='No notifications', halign='center', font_style='H5',
                                  pos_hint={'center_x': 0.5, 'center_y': 0.4}))

        notification_list.add_widget(layout)

    def delete_notification(self, message):
        """Delete a notification from the Anvil database."""
        row = app_tables.oxi_notifications.get(oxi_id=self.user_id, oxi_notification=message)
        if row:
            row.delete()

    def on_keyboard(self, instance, key, scancode, codepoint, modifier):
        if key == 27:  # Keycode for the back button on Android
            self.notification_back()
            return True
        return False

    def notification_back(self):
        self.manager.current = 'client_services'  # Changed from push_replacement

    def show_notification(self, title, message):
        self.notifications.append(message)
        self.save_notification(title, message)
        self.update_notification_list()
        self.push_device_notification(title, message)

    def update_notification_list(self):
        notification_list = self.ids.notification_list
        notification_list.clear_widgets()
        for notification in self.notifications:
            card = MDCard(orientation='vertical', size_hint_y=None, height="130dp", padding='20dp',
                          pos_hint={'center_x': 0.5, 'center_y': 0.5}, elevation=2)
            card.add_widget(MDLabel(text=notification, halign="center"))
            card.add_widget(MDRaisedButton(text="Mark as Read", on_release=self.mark_as_read))
            notification_list.add_widget(card)

    def mark_as_read(self, instance):
        card = instance.parent
        message = card.children[1].text
        self.notifications.remove(message)
        self.delete_notification(message)
        card.parent.remove_widget(card)

    def push_device_notification(self, title, message):
        if platform == 'android':
            self.push_android_notification(title, message)
        elif platform == 'win':
            self.push_windows_notification(title, message)

    # Function to send Android notification
    def push_android_notification(self, title, message):
        logging.info(f"Pushing Android notification: {title} - {message}")
        try:
            context = cast('android.content.Context', PythonActivity.mActivity)

            # Create an intent to launch the app
            intent = Intent(context, PythonActivity)
            intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP)

            # Create a pending intent to wrap the intent
            pending_intent = PendingIntent.getActivity(
                context, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE
            )

            # Notification channel ID and name
            channel_id = "my_channel_id"
            channel_name = "My Channel"

            # Get the NotificationManager system service
            notification_manager = context.getSystemService(Context.NOTIFICATION_SERVICE)

            # Create the NotificationChannel (if required)
            importance = NotificationManager.IMPORTANCE_DEFAULT
            notification_channel = NotificationChannel(channel_id, channel_name, importance)
            notification_channel.setDescription("Channel Description")
            notification_manager.createNotificationChannel(notification_channel)

            # Build the notification
            builder = NotificationBuilder(context, channel_id)
            builder.setSmallIcon(autoclass('android.R$drawable').ic_dialog_info)
            builder.setContentTitle(title)
            builder.setContentText(message)
            builder.setAutoCancel(True)
            builder.setContentIntent(pending_intent)  # Set the pending intent

            # Show the notification
            notification = builder.build()
            notification_manager.notify(1, notification)
        except Exception as e:
            logging.error(f"Failed to send Android notification: {e}")

    # Function to send Windows notification
    def push_windows_notification(self, title, message):
        logging.info(f"Pushing Windows notification: {title} - {message}")
        try:
            notification.notify(
                title=title,
                message=message,
                app_name="Oxivive",
                timeout=10
            )
        except Exception as e:
            logging.error(f"Failed to send Windows notification: {e}")

    def schedule_notifications(self, appointment_time):
        now = datetime.now()
        day_before = appointment_time - timedelta(days=1)
        two_hours_before = appointment_time - timedelta(hours=2)

        if day_before > now:
            delay = (day_before - now).total_seconds()
            Clock.schedule_once(lambda dt: self.show_notification("Reminder",
                                                                  "Your appointment is tomorrow at " + appointment_time.strftime(
                                                                      "%Y-%m-%d %H:%M")), delay)

        if two_hours_before > now:
            delay = (two_hours_before - now).total_seconds()
            Clock.schedule_once(lambda dt: self.show_notification("Reminder",
                                                                  "Your appointment is in 2 hours at " + appointment_time.strftime(
                                                                      "%Y-%m-%d %H:%M")), delay)
