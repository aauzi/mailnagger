# Copyright 2025 André Auzi <aauzi@free.fr>
# Copyright 2024 Timo Kankare <timo.kankare@iki.fi>
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
import re
from subprocess import Popen, PIPE
import logging
from collections.abc import Callable
from typing import Any, Optional
from gi.repository import Notify, Gio, Gtk
from Mailnag.common.plugins import Plugin, HookTypes
from Mailnag.common.i18n import _
from Mailnag.common.subproc import start_subprocess
from Mailnag.common.exceptions import InvalidOperationException
from Mailnag.daemon.mails import Mail
from Mailnag.common.utils import dbgindent

NOTIFICATION_MODE_COUNT = '0'
NOTIFICATION_MODE_SHORT_SUMMARY = '3'
NOTIFICATION_MODE_SUMMARY = '1'
NOTIFICATION_MODE_SINGLE = '2'

DESKTOP_ENV_VARS_FOR_SUPPORT_TEST = ('XDG_CURRENT_DESKTOP', 'GDMSESSION')
SUPPORTED_DESKTOP_ENVIRONMENTS = ("gnome", "cinnamon")

plugin_defaults = {
	'notification_mode' : NOTIFICATION_MODE_SHORT_SUMMARY,
	'max_visible_mails' : '10',
	'2FA_notifications' : True,
	'2FA_providers': [
		# sender, subject, body text re
		('Garmin', 'Your Security Passcode',	r'<strong[^>]*>(?P<code>\d+)</strong>'),
		('Garmin', _('Your Security Passcode'), r'<strong[^>]*>(?P<code>\d+)</strong>'),
	],
}


class LibNotifyPlugin(Plugin):
	def __init__(self) -> None:
		# dict that tracks all notifications that need to be closed
		self._notifications: dict[str, Notify.Notification] = {}
		self._initialized = False
		self._lock = threading.Lock()
		self._notification_server_wait_event = threading.Event()
		self._notification_server_ready = False
		self._is_supported_env = False
		self._mails_added_hook: Optional[Callable[[list[Mail], list[Mail]], None]] = None


	def enable(self) -> None:
		self._max_mails = int(self.get_config()['max_visible_mails'])
		self._notification_server_wait_event.clear()
		self._notification_server_ready = False
		self._notifications = {}

		# initialize Notification
		if not self._initialized:
			Notify.init("Mailnagger")
			self._is_supported_env = self._is_supported_environment()
			self._initialized = True

		def mails_added_hook(new_mails: list[Mail], all_mails: list[Mail]) -> None:
			self._notify_async(new_mails, all_mails)

		self._mails_added_hook = mails_added_hook

		def mails_removed_hook(remaining_mails: list[Mail]) -> None:
			self._notify_async([], remaining_mails)

		self._mails_removed_hook: Optional[Callable[[list[Mail]], None]] = mails_removed_hook

		controller = self.get_mailnag_controller()
		hooks = controller.get_hooks()

		hooks.register_hook_func(HookTypes.MAILS_ADDED,
			self._mails_added_hook)

		hooks.register_hook_func(HookTypes.MAILS_REMOVED,
			self._mails_removed_hook)

	def disable(self) -> None:
		controller = self.get_mailnag_controller()
		hooks = controller.get_hooks()

		if self._mails_added_hook is not None:
			hooks.unregister_hook_func(HookTypes.MAILS_ADDED,
				self._mails_added_hook)
			self._mails_added_hook = None

		if self._mails_removed_hook is not None:
			hooks.unregister_hook_func(HookTypes.MAILS_REMOVED,
				self._mails_removed_hook)
			self._mails_removed_hook = None

		# Abort possible notification server wait
		self._notification_server_wait_event.set()
		# Close all open notifications
		# (must be called after _notification_server_wait_event.set()
		# to prevent a possible deadlock)
		self._close_notifications()


	def get_manifest(self) -> tuple[str, str, str, str]:
		return (_("LibNotify Notifications"),
				_("Shows a popup when new mails arrive."),
				"2.1",
				"Patrick Ulbrich <zulu99@gmx.net>")


	def get_default_config(self) -> dict[str, Any]:
		return plugin_defaults


	def has_config_ui(self) -> bool:
		return True


	def get_config_ui(self) -> Gtk.Box:
		radio_mapping = [
			(NOTIFICATION_MODE_COUNT,				Gtk.RadioButton(label = _('Count of new mails'))),
			(NOTIFICATION_MODE_SHORT_SUMMARY,			Gtk.RadioButton(label = _('Short summary of new mails'))),
			(NOTIFICATION_MODE_SUMMARY,				Gtk.RadioButton(label = _('Detailed summary of new mails'))),
			(NOTIFICATION_MODE_SINGLE,				Gtk.RadioButton(label = _('One notification per new mail')))
		]

		box = Gtk.Box()
		box.set_spacing(12)
		box.set_orientation(Gtk.Orientation.VERTICAL)

		label = Gtk.Label()
		label.set_markup('<b>%s</b>' % _('Notification mode:'))
		label.set_alignment(0.0, 0.0)
		box.pack_start(label, False, False, 0)

		inner_box = Gtk.Box()
		inner_box.set_spacing(6)
		inner_box.set_orientation(Gtk.Orientation.VERTICAL)

		last_radio = None
		for m, r in radio_mapping:
			if last_radio != None:
				r.join_group(last_radio)
			inner_box.pack_start(r, False, False, 0)
			last_radio = r

		alignment = Gtk.Alignment()
		alignment.set_padding(0, 6, 18, 0)
		alignment.add(inner_box)
		box.pack_start(alignment, False, False, 0)

		self._radio_mapping = radio_mapping

		return box


	def load_ui_from_config(self, config_ui: Gtk.Widget) -> None:
		config = self.get_config()
		radio = [r for m, r in self._radio_mapping if m == config['notification_mode']][0]
		radio.set_active(True)


	def save_ui_to_config(self, config_ui: Gtk.Widget) -> None:
		config = self.get_config()
		mode = [m for m, r in self._radio_mapping if r.get_active()][0]
		config['notification_mode'] = mode


	def _notify_async(self, new_mails: list[Mail], all_mails: list[Mail]) -> None:
		def thread() -> None:
			with self._lock:
				# The desktop session may have started Mailnag
				# before the libnotify dbus daemon.
				if not self._notification_server_ready:
					if not self._wait_for_notification_server():
						return
					self._notification_server_ready = True

				config = self.get_config()

				if config['notification_mode'] == NOTIFICATION_MODE_SINGLE:
					self._notify_single(new_mails, all_mails)
				else:
					self._notify_2FA_attempts(new_mails, all_mails)
					if len(all_mails) == 0:
						if '0' in self._notifications:
							# The user may have closed the notification:
							try_close(self._notifications['0'])
							del self._notifications['0']
					elif len(new_mails) > 0:
						if config['notification_mode'] == NOTIFICATION_MODE_COUNT:
							self._notify_count(len(all_mails))
						elif config['notification_mode'] == NOTIFICATION_MODE_SHORT_SUMMARY:
							self._notify_short_summary(new_mails, all_mails)
						elif config['notification_mode'] == NOTIFICATION_MODE_SUMMARY:
							self._notify_summary(new_mails, all_mails)

		t = threading.Thread(target = thread)
		t.start()


	def _notify_short_summary(self, new_mails: list[Mail], all_mails: list[Mail]) -> None:
		summary = ""
		body = ""
		lst = []
		mails = self._prepend_new_mails(new_mails, all_mails)
		mail_count = len(mails)

		if '0' not in self._notifications:
			self._notifications['0'] = self._get_notification(" ", None, None) # empty string will emit a gtk warning

		i = 0
		n = 0
		while (n < 3) and (i < mail_count):
			s = self._get_sender(mails[i])
			if s not in lst:
				lst.append(s)
				n += 1
			i += 1

		if self._is_supported_env:
			senders = "<i>%s</i>" % ", ".join(lst)
		else:
			senders = ", ".join(lst)

		if mail_count > 1:
			summary = _("{0} new mails").format(str(mail_count))
			if (mail_count - i) > 1:
				body = _("from {0} and others.").format(senders)
			else:
				body = _("from {0}.").format(senders)
		else:
			summary = _("New mail")
			body = _("from {0}.").format(senders)

		self._notifications['0'].update(summary, body, "mail-unread")
		self._notifications['0'].show()


	def _notify_summary(self, new_mails: list[Mail], all_mails: list[Mail]) -> None:
		summary = ""
		body = ""
		mails = self._prepend_new_mails(new_mails, all_mails)

		if '0' not in self._notifications:
			self._notifications['0'] = self._get_notification(" ", None, None) # empty string will emit a gtk warning

		ubound = len(mails) if len(mails) <= self._max_mails else self._max_mails

		for i in range(ubound):
			if self._is_supported_env:
				body += "%s:\n<i>%s</i>\n\n" % (self._get_sender(mails[i]), mails[i].subject)
			else:
				body += "%s  -	%s\n" % (ellipsize(self._get_sender(mails[i]), 20), ellipsize(mails[i].subject, 20))

		if len(mails) > self._max_mails:
			if self._is_supported_env:
				body += "<i>%s</i>" % _("(and {0} more)").format(str(len(mails) - self._max_mails))
			else:
				body += _("(and {0} more)").format(str(len(mails) - self._max_mails))

		if len(mails) > 1: # multiple new emails
			summary = _("{0} new mails").format(str(len(mails)))
		else:
			summary = _("New mail")

		self._notifications['0'].update(summary, body, "mail-unread")
		self._notifications['0'].show()


	def _notify_2FA_attempts(self, new_mails, all_mails) -> None:
		self._cleanup_notifications_not_in(all_mails)

		# In single notification mode new mails are
		# added to the *bottom* of the notification list.
		new_mails.sort(key = lambda m: m.datetime, reverse = False)

		config = self.get_config()

		if not config['2FA_notifications']:
			      return

		providers = config['2FA_providers']
		if not len(providers):
			return

		for mail in new_mails:
			self._notify_2FA_attempt(mail, providers)


	def _notify_2FA_attempt(self, mail, providers) -> bool:
		sender = self._get_sender(mail)
		subject = mail.subject
		body = None

		for p in providers:
			if (sender == p[0] and subject == p[1]):
				logging.debug("2FA pre-matched : sender=%s, subject=%s",
					      sender, subject)

				# fetch the body text only when send and subject match
				# but only once (different regexps may work)
				if body is None:
					body = mail.fetch_text()
				#pipe = Popen(['grep', '-C', '4', '-e', '<strong'],
				#	     stdin=PIPE, stdout=PIPE)
				#text, _ = pipe.communicate(input=body.encode('utf-8'))
				#logging.debug('grep:\n%s', text.decode('utf-8'))
				m = re.search(p[2], body)
				if m:
					code = m.group('code')
					logging.debug("2FA matched code %s: sender=%s, subject=%s, body:\n%s",
						      code,
						      sender, subject,
						      dbgindent(body))
					break
		else:
			logging.debug("2FA not matched : sender=%s, subject=%s, body:\n%s",
				      sender, subject,
				      dbgindent(body))

			return False

		n = self._get_notification(sender, f'{subject}: {code}', "mail-unread")
		n.set_timeout(Notify.EXPIRES_NEVER)
		n.set_urgency(Notify.Urgency.CRITICAL)

		notification_id = str(id(n))
		if self._is_supported_env:
			n.add_action("copy-code", _("📋 Code: {0}").format(code),
				     self._notification_action_handler, (mail, notification_id, code))
		n.show()
		self._record_mail_notification(mail, n)
		return True


	def _record_mail_notification(self, mail: Mail, n: Notify.Notification) -> None:
		# Remember the associated message, so we know when to remove the notification:
		n.mail = mail
		notification_id = str(id(n))
		self._notifications[notification_id] = n


	def _cleanup_notifications_not_in(self, all_mails) -> None:
		# Remove notifications for messages not in all_mails:
		for k, n in list(self._notifications.items()):
			if hasattr(n, 'mail') and not (n.mail in all_mails):
				# The user may have closed the notification:
				try_close(n)
				del self._notifications[k]


	def _notify_single(self, new_mails, all_mails):
		self._cleanup_notifications_not_in(all_mails)

		# In single notification mode new mails are
		# added to the *bottom* of the notification list.
		new_mails.sort(key = lambda m: m.datetime, reverse = False)

		config = self.get_config()
		providers = None

		if config['2FA_notifications']:
			providers = config['2FA_providers']

		for mail in new_mails:
			if (providers is not None and
			    self._notify_2FA_attempt(mail, providers)):
				continue

			n = self._get_notification(self._get_sender(mail), mail.subject, "mail-unread")
			notification_id = str(id(n))
			if self._is_supported_env:
				n.add_action("mark-as-read", _("Mark as read"),
					self._notification_action_handler, (mail, notification_id))
			n.show()
			self._record_mail_notification(mail, n)


	def _notify_count(self, count: int) -> None:
		if '0' not in self._notifications:
			self._notifications['0'] = self._get_notification(" ", None, None) # empty string will emit a gtk warning

		if count > 1: # multiple new emails
			summary = _("{0} new mails").format(str(count))
		else:
			summary = _("New mail")

		self._notifications['0'].update(summary, None, "mail-unread")
		self._notifications['0'].show()


	def _close_notifications(self) -> None:
		with self._lock:
			for n in self._notifications.values():
				try_close(n)
			self._notifications = {}


	def _get_notification(
		self,
		summary: str,
		body: Optional[str],
		icon: Optional[str]
	) -> Notify.Notification:
		n = Notify.Notification.new(summary, body, icon)
		n.set_category("email")
		n.set_hint_string("desktop-entry", "mailnagger")

		if self._is_supported_env:
			n.add_action("default", "default", self._notification_action_handler, None)

		return n


	def _wait_for_notification_server(self) -> bool:
		bus = dbus.SessionBus()
		while not bus.name_has_owner('org.freedesktop.Notifications'):
			self._notification_server_wait_event.wait(5)
			if self._notification_server_wait_event.is_set():
				return False
		return True


	def _notification_action_handler(
		self,
		n: Notify.Notification,
		action: str,
		user_data: tuple[Mail, str]
	) -> None:
		with self._lock:
			if action == "default":
				mailclient = Gio.AppInfo.get_default_for_type("x-scheme-handler/mailto", False)
				if mailclient is not None:
					Gio.AppInfo.launch(mailclient)

				# clicking the notification bubble has closed all notifications
				# so clear the reference array as well.
				self._notifications = {}
			elif action == "mark-as-read":
				controller = self.get_mailnag_controller()
				try:
					controller.mark_mail_as_read(user_data[0].id)
				except InvalidOperationException:
					pass

				# clicking the action has closed the notification
				# so remove its reference.
				del self._notifications[user_data[1]]
			elif action == "copy-code":
				controller = self.get_mailnag_controller()
				try:
					code = user_data[2]
					try:
						pipe = Popen(['xclip', '-selection', 'c'],
							     stdin=PIPE,
							     close_fds=True)
						pipe.communicate(input=code.encode('utf-8'))
						logging.debug('xclip set text:%s', code)
					except:
						logging.exception('xclip set text failed.')

					controller.mark_mail_as_read(user_data[0].id)
				except InvalidOperationException:
					pass

				# clicking the action has closed the notification
				# so remove its reference.
				del self._notifications[user_data[1]]

	@staticmethod
	def _get_sender(mail: Mail) -> str:
		name, addr = mail.sender
		if len(name) > 0: return name
		else: return addr

	@staticmethod
	def _prepend_new_mails(new_mails: list[Mail], all_mails: list[Mail]) -> list[Mail]:
		# The mail list (all_mails) is sorted by date (mails with most recent
		# date on top). New mails with no date or older mails that come in
		# delayed won't be listed on top. So if a mail with no or an older date
		# arrives, it gives the impression that the top most mail (i.e. the mail
		# with the most recent date) is re-notified.
		# To fix that, simply put new mails on top explicitly.
		return new_mails + [m for m in all_mails if m not in new_mails]

	@staticmethod
	def _is_supported_environment() -> bool:
		for var in DESKTOP_ENV_VARS_FOR_SUPPORT_TEST:
			desktop_env = os.environ.get(var, '').lower().split(':')
			for env in SUPPORTED_DESKTOP_ENVIRONMENTS:
				if env in desktop_env:
					return True
		return False


def ellipsize(str: str, max_len: int) -> str:
	if max_len < 3: max_len = 3
	if len(str) <= max_len:
		return str
	else:
		return str[0:max_len - 3] + '...'


# If the user has closed the notification, an exception is raised.
def try_close(notification: Notify.Notification) -> None:
	try:
		notification.close()
	except:
		pass
