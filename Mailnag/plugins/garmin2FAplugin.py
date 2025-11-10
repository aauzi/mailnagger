# Copyright 2025 André Auzi <aauzi@free.fr>
# Copyright 2013 - 2020 Patrick Ulbrich <zulu99@gmx.net>
# Copyright 2020 Dan Christensen <jdc@uwo.ca>
# Copyright 2020 Denis Anuschewski
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
#

import gi

gi.require_version('Notify', '0.7')
gi.require_version('GLib', '2.0')
gi.require_version('Gtk', '3.0')

import os
import dbus
import threading
import logging
import re
from html.parser import HTMLParser

from gi.repository import Notify, Gio, Gtk
from Mailnag.common.plugins import Plugin, HookTypes
from Mailnag.common.i18n import _
from Mailnag.common.subproc import start_subprocess
from Mailnag.common.exceptions import InvalidOperationException
from Mailnag.common.utils import dbgindent


class HTML2FAParser(HTMLParser):
        def __init__(self):
                super().__init__()

                self._in_strong = False
                self._data = ''

        def handle_starttag(self, tag, attrs):
                if tag == 'strong':
                        self._in_strong = True
        def handle_endtag(self, tag):
                if tag == 'strong':
                        self._in_strong = False
        def handle_data(self, data):
                if not self._in_strong:
                        return
                self._data += data
        def get_passcode(self, text):
                self.feed(text)
                self.close()

                if not self._data:
                        return None

                return self._data


class Garmin2FAPlugin(Plugin):
        def __init__(self):
                # dict that tracks all notifications that need to be closed
                self._notifications = {}
                self._initialized = False
                self._lock = threading.Lock()
                self._notification_server_wait_event = threading.Event()
                self._notification_server_ready = False
                self._is_gnome = False
                self._mails_added_hook = None
                self._mails_removed_hook = None


        def enable(self):
                self._notification_server_wait_event.clear()
                self._notification_server_ready = False
                self._notifications = {}

                # initialize Notification
                if not self._initialized:
                        Notify.init("Mailnag")
                        self._is_gnome = self._is_gnome_environment(('XDG_CURRENT_DESKTOP', 'GDMSESSION'))
                        self._initialized = True

                def mails_added_hook(new_mails, all_mails):
                        self._notify_async(new_mails, all_mails)

                self._mails_added_hook = mails_added_hook

                def mails_removed_hook(remaining_mails):
                        self._notify_async([], remaining_mails)

                self._mails_removed_hook = mails_removed_hook

                controller = self.get_mailnag_controller()
                hooks = controller.get_hooks()

                hooks.register_hook_func(HookTypes.MAILS_ADDED,
                        self._mails_added_hook)

                hooks.register_hook_func(HookTypes.MAILS_REMOVED,
                        self._mails_removed_hook)

        def disable(self):
                controller = self.get_mailnag_controller()
                hooks = controller.get_hooks()

                if self._mails_added_hook != None:
                        hooks.unregister_hook_func(HookTypes.MAILS_ADDED,
                                self._mails_added_hook)
                        self._mails_added_hook = None

                if self._mails_removed_hook != None:
                        hooks.unregister_hook_func(HookTypes.MAILS_REMOVED,
                                self._mails_removed_hook)
                        self._mails_removed_hook = None

                # Abort possible notification server wait
                self._notification_server_wait_event.set()
                # Close all open notifications
                # (must be called after _notification_server_wait_event.set()
                # to prevent a possible deadlock)
                self._close_notifications()


        def get_manifest(self):
                return (_("Garmin 2FA LibNotify Notifications"),
                        _("Shows a popup when Garmin 2FA mails arrive."),
                        "0.1",
                        "André Auzi <aauzi@free.fr>")


        def get_default_config(self):
                return {}


        def has_config_ui(self):
                return False


        def get_config_ui(self):
                return None


        def load_ui_from_config(self, config_ui):
                pass


        def save_ui_to_config(self, config_ui):
                pass


        def _notify_async(self, new_mails, all_mails):
                def thread():
                        with self._lock:
                                # The desktop session may have started Mailnag
                                # before the libnotify dbus daemon.
                                if not self._notification_server_ready:
                                        if not self._wait_for_notification_server():
                                                return
                                        self._notification_server_ready = True

                                self._notify_2FA(new_mails, all_mails)

                t = threading.Thread(target = thread)
                t.start()


        def _get_2FA_passcode(self, mail):
                _parser = HTML2FAParser()
                return _parser.get_passcode(mail)


        def _notify_2FA(self, new_mails, all_mails):
                # Remove notifications for messages not in all_mails:
                for k, n in list(self._notifications.items()):
                        if hasattr(n, 'mail') and not (n.mail in all_mails):
                                # The user may have closed the notification:
                                try_close(n)
                                del self._notifications[k]

                # In single notification mode new mails are
                # added to the *bottom* of the notification list.
                new_mails.sort(key = lambda m: m.datetime, reverse = False)

                for mail in new_mails:
                        sender = self._get_sender(mail)
                        uid = mail.flags['uid']
                        backend = mail.flags['backend']
                        body = backend.fetch_text(uid)
                        logging.debug("garmin2FA: sender=%s, subject=%s, body:\n%s",
                                      sender, mail.subject,
                                      dbgindent(body))
                        
                        if (sender != 'Garmin' or
                            (mail.subject != 'Your Security Passcode' and
                             mail.subject != _('Your Security Passcode'))):
                                continue

                        code = self._get_2FA_passcode(body)
                        if code is None:
                                continue

                        logging.info("garmin2FA: passcode=%s", code)

                        n = self._get_notification(self._get_sender(mail),
                                                   '{0}: {1}'.format(mail.subject, code), "mail-unread")
                        # Remember the associated message, so we know when to remove the notification:
                        n.mail = mail
                        notification_id = str(id(n))
                        if self._is_gnome:
                                n.set_timeout(Notify.EXPIRES_NEVER)
                                n.set_urgency(Notify.Urgency.CRITICAL)
                                n.add_action("copy-code", _("📋 Code: {0}").format(code),
                                        self._notification_action_handler, (mail, notification_id, code))
                        n.show()
                        self._notifications[notification_id] = n


        def _close_notifications(self):
                with self._lock:
                        for n in self._notifications.values():
                                try_close(n)
                        self._notifications = {}


        def _get_notification(self, summary, body, icon):
                n = Notify.Notification.new(summary, body, icon)
                n.set_category("email")
                n.set_hint_string("desktop-entry", "mailnag")

                if self._is_gnome:
                        n.add_action("default", "default", self._notification_action_handler, None)

                return n


        def _wait_for_notification_server(self):
                bus = dbus.SessionBus()
                while not bus.name_has_owner('org.freedesktop.Notifications'):
                        self._notification_server_wait_event.wait(5)
                        if self._notification_server_wait_event.is_set():
                                return False
                return True


        def _notification_action_handler(self, n, action, user_data):
                with self._lock:
                        if action == "default":
                                mailclient = get_default_mail_reader()
                                if mailclient != None:
                                        start_subprocess(mailclient)

                                # clicking the notification bubble has closed all notifications
                                # so clear the reference array as well.
                                self._notifications = {}
                        elif action == "copy-code":
                                controller = self.get_mailnag_controller()
                                try:
                                        try:
                                                import subprocess

                                                code = user_data[2]
                                                p = subprocess.Popen(['xclip', '-selection', 'c'],
                                                                     stdin=subprocess.PIPE,
                                                                     close_fds=True)
                                                p.communicate(input=code.encode('utf-8'))

                                                logging.debug('xclip set text: %s', code)
                                        except Exception as ex:
                                                logging.error('xclip set text failed (%s)', str(ex))

                                        controller.mark_mail_as_read(user_data[0].id)
                                except InvalidOperationException:
                                        pass

                                # clicking the action has closed the notification
                                # so remove its reference.
                                del self._notifications[user_data[1]]


        def _get_sender(self, mail):
                name, addr = mail.sender
                if len(name) > 0: return name
                else: return addr


        def _prepend_new_mails(self, new_mails, all_mails):
                # The mail list (all_mails) is sorted by date (mails with most recent
                # date on top). New mails with no date or older mails that come in
                # delayed won't be listed on top. So if a mail with no or an older date
                # arrives, it gives the impression that the top most mail (i.e. the mail
                # with the most recent date) is re-notified.
                # To fix that, simply put new mails on top explicitly.
                return new_mails + [m for m in all_mails if m not in new_mails]


        def _is_gnome_environment(self, env_vars):
                for var in env_vars:
                        if 'gnome' in os.environ.get(var, '').lower().split(':'):
                                return True
                return False


def get_default_mail_reader():
        mail_reader = None
        app_info = Gio.AppInfo.get_default_for_type ("x-scheme-handler/mailto", False)

        if app_info != None:
                executable = Gio.AppInfo.get_executable(app_info)

                if (executable != None) and (len(executable) > 0):
                        mail_reader = executable

        return mail_reader


# If the user has closed the notification, an exception is raised.
def try_close(notification):
        try:
                notification.close()
        except:
                pass
