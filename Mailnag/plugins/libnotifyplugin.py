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
from subprocess import Popen, PIPE, TimeoutExpired
import logging
import csv
import copy
from collections.abc import Callable
from typing import Any, Optional
from gi.repository import Notify, Gio, Gtk, Gdk, GLib
from Mailnag.common.dist_cfg import PACKAGE_NAME
from Mailnag.common.plugins import Plugin, HookTypes
from Mailnag.common.i18n import _
from Mailnag.common.subproc import start_subprocess
from Mailnag.common.exceptions import InvalidOperationException
from Mailnag.daemon.mails import Mail
from Mailnag.common.utils import dbgindent
from Mailnag.common.config import cfg_folder
from mailnagger.resources import get_resource_text
import Mailnag.plugins

NOTIFICATION_MODE_COUNT = '0'
NOTIFICATION_MODE_SHORT_SUMMARY = '3'
NOTIFICATION_MODE_SUMMARY = '1'
NOTIFICATION_MODE_SINGLE = '2'
NOTIFICATION_MODE_SILENT = '4'

_LOGGER = logging.getLogger(__name__)

DESKTOP_ENV_VARS_FOR_SUPPORT_TEST = ('XDG_CURRENT_DESKTOP', 'GDMSESSION')
SUPPORTED_DESKTOP_ENVIRONMENTS = ("gnome", "cinnamon")

RE_CODE = r'\b(?P<code>\d{4,8})\b'

cfg_2fa_providers_file = os.path.join(cfg_folder, '2fa_providers.tsv')

plugin_defaults = {
	'notification_mode' : NOTIFICATION_MODE_SHORT_SUMMARY,
	'max_visible_mails' : '10',
	'2fa_notifications' : True,
}

_2fa_providers_keys = ('enabled', 'provider', 'subject', 'text_re')
default_2fa_providers = [
	(True, 'Garmin', 'Your Security Passcode',    r'Use this one-time code for your account\n{code}\n'),
	(True, 'Garmin', _('Your Security Passcode'), r'voici votre code de sécurité.\n{code}\n'),
]

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
		self._copy_commands = [ # wl-copy (Wayland), xsel (X11 alternatif), xclip (X11 standard)
			['wl-copy'],
			['xclip', '-selection', 'c'],
			['xsel', '--clipboard', '--input']
		]


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
		libnotifyplugin_ui = get_resource_text(
			Mailnag.plugins,
			"libnotifyplugin.ui"
		)
		builder = Gtk.Builder()
		builder.set_translation_domain(PACKAGE_NAME)

		builder.add_from_string(libnotifyplugin_ui)

		radio_id_mapping = {
			NOTIFICATION_MODE_COUNT:		'notification_mode_count',
			NOTIFICATION_MODE_SHORT_SUMMARY:	'notification_mode_short_summary',
			NOTIFICATION_MODE_SUMMARY:		'notification_mode_summary',
			NOTIFICATION_MODE_SINGLE:		'notification_mode_single',
			NOTIFICATION_MODE_SILENT:		'notification_2FA_only',
		}

		radio_mapping = []

		for mode in [NOTIFICATION_MODE_COUNT,
			     NOTIFICATION_MODE_SHORT_SUMMARY,
			     NOTIFICATION_MODE_SUMMARY,
			     NOTIFICATION_MODE_SINGLE,
			     NOTIFICATION_MODE_SILENT,
			     ]:
			radio_btn = builder.get_object(radio_id_mapping[mode])
			radio_mapping.append((mode, radio_btn))

		label = builder.get_object('notification_modes')
		label.set_markup(f'<b>{_('Notification mode:')}</b>')
		label = builder.get_object('2fa_providers')
		label.set_markup(f'<b>{_('2FA providers')}</b>')

		builder.connect_signals({
			'close':			self._on_close,
			'btn_cancel_clicked':		self._on_btn_cancel_clicked,
			'btn_ok_clicked':		self._on_btn_ok_clicked,
			'btn_add_provider_clicked':	self._on_btn_add_provider_clicked,
			'btn_remove_provider_clicked':	self._on_btn_remove_provider_clicked,
			'btn_edit_provider_clicked':	self._on_btn_edit_provider_clicked,
			'provider_toggled':		self._on_provider_toggled,
			'provider_row_activated':	self._on_provider_row_activated,
			'provider_sel_changed':		self._on_provider_sel_changed,
			'expander_2fa_providers_expanded': self._on_expander_2fa_providers_expanded,
			'info_response':		self._on_info_response,
		})

		self._builder = builder
		self._radio_mapping = radio_mapping
		self._dialog = builder.get_object('edit_2FA_provider_dialog')
		self._switch_2FA_notifications = builder.get_object('switch_2FA_notifications')
		self._liststore_2FA_providers = builder.get_object('liststore_2FA_providers')
		self._treeview_2FA_providers = builder.get_object('treeview_2FA_providers')
		self._infobar_info = builder.get_object('info')
		self._label_info = builder.get_object('label_info')

		self._scrolled_window = builder.get_object('scrolledwindow1')
		self._scrolled_window.set_min_content_height(120)
		self._scrolled_window.set_min_content_width(348)
		self._scrolled_window.set_propagate_natural_height(True)
		self._scrolled_window.set_propagate_natural_width(True)
		self._scrolled_window.set_max_content_height(348)

		return builder.get_object('box1')


	@staticmethod
	def _eval_2fa_providers(providers: list|str) -> list:
		assert isinstance(providers,list), f'Oops! config still have invalid providers (type={type(providers).__name__})'
		return providers

	def _check_2fa_provider_pattern(self, sender: str, subject: str, pattern: str) -> bool:
		if not '{code}' in subject and not '{code}' in pattern:

			_LOGGER.debug('Missing "code" group pattern: {code}...\n'
				      'sender: %s, subject: %s\npattern:\n%s',
				      sender, subject,
				      pattern)
			self._alert_message(_('Missing "code" group pattern: {code}'),
					    msg_type=Gtk.MessageType.ERROR, duration_s=5)
			return False

		def check_regexp(name: str, msg_name: str, regexp_p: str) -> bool:
			if '{code}' not in regexp_p:
				return True
			try:
				compiled_re = regexp_p.replace('{code}', RE_CODE).strip()
				_cre = re.compile(compiled_re)
				return True
			except (re.error, AttributeError) as e:
				posi = ''
				pos = getattr(e, 'pos', None)
				if pos is not None:
					posi = "\n" + (" " * pos) + "^"
				_LOGGER.exception('%s is incorrect regexp: %s\nregex: %s\n%s%s',
						  name, str(e), regexp_p,
						  compiled_re, posi)
				self._alert_message(_('%s is incorrect regexp'), msg_name,
						    msg_type=Gtk.MessageType.ERROR, duration_s=5)
			return False

		if not check_regexp('subject', _('Subject'), re.escape(subject)):
			return False

		if not check_regexp('pattern', _('Pattern'), pattern):
			return False

		return True

	def get_config(self):
		config = super().get_config()
		config['2fa_providers'] = self._load_2fa_providers_from_config()
		return config

	def _load_2fa_providers_from_config(self):
		def check_regexp(name: str, regexp_p: str) -> bool:
			if '{code}' not in regexp_p:
				return True
			try:
				compiled_re = regexp_p.replace('{code}', RE_CODE).strip()
				_cre = re.compile(compiled_re)
				return True
			except (re.error, AttributeError) as e:
				posi = ''
				pos = getattr(e, 'pos', None)
				if pos is not None:
					posi = "\n" + (" " * pos) + "^"
				_LOGGER.exception('%s is incorrect regexp: %s\nregex: %s\n%s%s',
						  name, str(e), regexp_p,
						  compiled_re, posi)
			return False


		lv = None
		try:
			with open(cfg_2fa_providers_file, 'r', encoding='utf-8') as fin:
				next(fin)
				lv = list(csv.DictReader(fin, fieldnames=_2fa_providers_keys, delimiter='\t'))
		except (FileNotFoundError, StopIteration):
			pass
		except Exception as e:
			_LOGGER.exception('Failed to read 2FA providers file: %s\n%s',
					  os.path.basename(cfg_2fa_providers_file),
					  str(e))

		if lv is not None:
			providers = []
			for l, v in enumerate(lv, start=2):
				if not isinstance(v, dict):
					_LOGGER.debug('Line %d invalid in: %s',
						      os.path.basename(cfg_2fa_providers_file))
					continue

				values = []
				regexps_invalid = []
				is_enabled = str(v.get('enabled', '')).lower() in ('y', 'yes', 'true', 'on')

				for k in _2fa_providers_keys:
					if k == 'enabled':
						continue

					val = v.get(k, "")
					if val:
						if k == 'subject':
							if not check_regexp(k, re.escape(v[k])):
								regexps_invalid.append(f'line: {l}, field: {k}, value: {v[k]}')
						elif k =='text_re':
							if not check_regexp(k, v[k]):
								regexps_invalid.append(f'line: {l}, field: {k}, value: {v[k]}')
					values.append(val)

				if regexps_invalid:
					_LOGGER.debug('Regexp invalid in: %s\n	%s',
						      os.path.basename(cfg_2fa_providers_file),
						      '\n  '.join(regexps_invalid))

				values.insert(0, is_enabled and not bool(regexps_invalid))

				providers.append(values)
			return providers

		return copy.deepcopy(default_2fa_providers)

	def load_ui_from_config(self, config_ui: Gtk.Widget) -> None:
		config = self.get_config()
		radio = [r for m, r in self._radio_mapping if m == config['notification_mode']][0]
		radio.set_active(True)
		self._switch_2FA_notifications.set_active(config['2fa_notifications'])
		providers = config['2fa_providers']
		for (_enabled, _sender, _subject, _pattern) in providers:
			if _enabled and not self._check_2fa_provider_pattern(_sender, _subject, _pattern):
				_enabled = False
			self._liststore_2FA_providers.append([_enabled, _sender, _subject, _pattern])

	def _save_2fa_providers_to_config(self, providers):
		named_providers = []
		for v in providers:
			nv = dict()
			for i in range(len(_2fa_providers_keys)):
				k = _2fa_providers_keys[i]
				nv[k] = v[i]
			named_providers.append(nv)
		with open(cfg_2fa_providers_file, 'wt', encoding='utf-8') as fout:
			w = csv.DictWriter(fout, fieldnames=_2fa_providers_keys, delimiter='\t')
			w.writeheader()
			w.writerows(named_providers)


	def save_ui_to_config(self, config_ui: Gtk.Widget) -> None:
		config = self.get_config()
		mode = [m for m, r in self._radio_mapping if r.get_active()][0]
		config['notification_mode'] = mode
		config['2fa_notifications'] = self._switch_2FA_notifications.get_active()
		providers = []
		for row in self._liststore_2FA_providers:
			providers.append(tuple(row))
		self._save_2fa_providers_to_config(providers)
		if '2fa_providers' in config:
			del config['2fa_providers']


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

				if config['notification_mode'] == NOTIFICATION_MODE_SILENT:
					self._notify_2FA_attempts(new_mails, all_mails)
				elif config['notification_mode'] == NOTIFICATION_MODE_SINGLE:
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

		senders = ', '.join(lst)
		if self._is_supported_env:
			senders = f'<i>{senders}</i>'

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
			m = mails[i]
			sender = self._get_sender(m)
			subject = m.subject
			if self._is_supported_env:
				body += f'{sender}:\n<i>{subject}</i>\n\n'
			else:
				body += f'{ellipsize(sender, 20)}  -	{ellipsize(subject, 20)}\n'

		if len(mails) > self._max_mails:
			fragment = _("(and {0} more)").format(str(len(mails) - self._max_mails))
			if self._is_supported_env:
				body += f'<i>{fragment}</i>'

		if len(mails) > 1: # multiple new emails
			summary = _("{0} new mails").format(str(len(mails)))
		else:
			summary = _("New mail")

		self._notifications['0'].update(summary, body, "mail-unread")
		self._notifications['0'].show()


	def _notify_2FA_attempts(self, new_mails: List[Mail], all_mails: List[Mail]) -> None:
		self._cleanup_notifications_not_in(all_mails)

		# In single notification mode new mails are
		# added to the *bottom* of the notification list.
		new_mails.sort(key = lambda m: m.datetime, reverse = False)

		config = self.get_config()

		if not config['2fa_notifications']:
			      return

		providers = self._eval_2fa_providers(config['2fa_providers'])
		if not len(providers):
			return

		for mail in new_mails:
			self._notify_2FA_attempt(mail, providers)


	def _notify_2FA_attempt(self, mail, providers) -> bool:
		sender = self._get_sender(mail)
		subject = mail.subject
		body = None
		code = None

		for (_enabled, _sender, _subject, _text_re) in providers:
			if not _enabled or sender != _sender:
				continue

			if '{code}' in _subject:
				_pattern = re.escape(_subject).replace(r'\{code\}', RE_CODE).strip()
				m = re.match(_pattern, subject)

				if m:
					code = m.group('code')
					_LOGGER.debug("2FA matched code %s: sender=%s, subject=%s",
						      code,
						      sender, subject)
					break
				else:
					continue
			else:
				if subject != _subject:
					continue

			_LOGGER.debug("2FA pre-matched : sender=%s, subject=%s",
				      sender, subject)

			# fetch the body text only when sender and subject match
			# but only once (different patterns may need to be tested)
			if body is None:
				body = mail.fetch_text()

			if body is None:
				_LOGGER.warning("2FA match not achievable: sender=%s, subject=%s\nBody not available.",
						sender, subject)
				return False

			m = re.search(_text_re.replace('{code}', RE_CODE).strip(), body)
			if m:
				code = m.group('code')
				_LOGGER.debug("2FA matched code %s: sender=%s, subject=%s, body:\n%s",
					      code,
					      sender, subject,
					      dbgindent(body))
				break
		else:
			_LOGGER.debug("2FA not matched : sender=%s, subject=%s, body:\n%s",
				      sender, subject,
				      #dbgindent(body))
				      '	 '+'\n	'.join(str(body).splitlines()))

			return False

		assert code is not None

		_summary = f"🔑 {code} — {sender}"
		_body = f'\t\t<i>{subject}</i>' if self._is_supported_env else f'\t\t{subject}'

		n = self._get_notification(_summary,
					   _body,
					   "security-medium")

		n.set_timeout(Notify.EXPIRES_NEVER)
		n.set_urgency(Notify.Urgency.CRITICAL)

		notification_id = str(id(n))
		if self._is_supported_env:
			n.add_action("copy-code", f'📋 {_("Copy code:")} {code}',
				     self._notification_action_handler, (mail, notification_id, code))
		n.show()
		self._record_mail_notification(mail, n)
		return True


	def _record_mail_notification(self, mail: Mail, n: Notify.Notification) -> None:
		# Remember the associated message, so we know when to remove the notification:
		n.mail = mail
		notification_id = str(id(n))
		self._notifications[notification_id] = n


	def _cleanup_notifications_not_in(self, all_mails: List[Mail]) -> None:
		# Remove notifications for messages not in all_mails:
		for k, n in list(self._notifications.items()):
			if hasattr(n, 'mail') and not (n.mail in all_mails):
				# The user may have closed the notification:
				try_close(n)
				del self._notifications[k]


	def _notify_single(self, new_mails: List[Mail], all_mails: List[Mail]) -> None:
		self._cleanup_notifications_not_in(all_mails)

		# In single notification mode new mails are
		# added to the *bottom* of the notification list.
		new_mails.sort(key = lambda m: m.datetime, reverse = False)

		config = self.get_config()
		providers = None

		if config['2fa_notifications']:
			providers = self._eval_2fa_providers(config['2fa_providers'])

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

	def _copy_to_clipboard(self, text: str) -> None:
		"""Copie le texte dans le presse-papier en supportant Wayland et X11."""
		# On encode le texte une seule fois
		encoded_text = text.encode('utf-8')

		for i, cmd in enumerate(list(self._copy_commands)):
			try:
				# On tente d'exécuter la commande
				pipe = Popen(cmd, stdin=PIPE, close_fds=True)
				pipe.communicate(input=encoded_text, timeout=2)

				if pipe.returncode == 0:
					_LOGGER.debug("Code copy succeeded with %s", cmd[0])
					successful_cmd = self._copy_commands.pop(i)
					self._copy_commands.insert(0, successful_cmd)
					break
			except TimeoutExpired:
				_LOGGER.warning("Timeout expired with %s.", cmd[0])
				if pipe:
					pipe.kill() # Important : kill the blocking process
					pipe.wait()
			except Exception as e:
				_LOGGER.error("Copy failed with %s: %s", cmd[0], str(e))

		else:
			_LOGGER.error("Copy to clipboard failed (install wl-clipboard or xclip).")

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
					self._copy_to_clipboard(code)
					controller.mark_mail_as_read(user_data[0].id)
				except InvalidOperationException:
					pass

				# clicking the action has closed the notification
				# so remove its reference.
				if user_data[1] in self._notifications:
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


	def _on_close(self, widget: Gtk.Dialog) -> None:
		_LOGGER.debug('on_close')
		self._dialog.hide()
		self._dialog.response(Gtk.ResponseType.CLOSE)


	def _on_btn_cancel_clicked(self, widget: Gtk.Button) -> None:
		_LOGGER.debug('on_btn_cancel_clicked')
		self._dialog.hide()
		self._dialog.response(Gtk.ResponseType.CANCEL)


	def _on_btn_ok_clicked(self, widget: Gtk.Button) -> None:
		_LOGGER.debug('on_btn_ok_clicked')
		self._dialog.hide()
		self._dialog.response(Gtk.ResponseType.OK)


	def _on_btn_add_provider_clicked(self, widget: Gtk.ToolButton) -> None:
		_LOGGER.debug('on_btn_add_provider_clicked')
		b = self._builder
		d = self._dialog

		b.get_object('enable').set_active(False)
		b.get_object('sender').set_text('')
		b.get_object('subject').set_text('')
		b.get_object('pattern_text_buffer').set_text('')

		if d.run() != Gtk.ResponseType.OK:
			return

		_enable = b.get_object('enable').get_active()
		_sender = b.get_object('sender').get_text()
		_subject = b.get_object('subject').get_text()
		start = b.get_object('pattern_text_buffer').get_start_iter()
		end = b.get_object('pattern_text_buffer').get_end_iter()
		_pattern = b.get_object('pattern_text_buffer').get_text(start, end, False)

		if not self._check_2fa_provider_pattern(_sender, _subject, _pattern) and _enable:
			_enable = False

		row = [_enable, _sender, _subject, _pattern]

		iter = self._liststore_2FA_providers.append(row)
		model = self._treeview_2FA_providers.get_model()
		path = model.get_path(iter)
		self._treeview_2FA_providers.set_cursor(path, None, False)
		self._treeview_2FA_providers.grab_focus()


	def _show_confirmation_dialog(self, text: str) -> None:
		message = Gtk.MessageDialog(None, Gtk.DialogFlags.MODAL,
			Gtk.MessageType.QUESTION, Gtk.ButtonsType.YES_NO, text)
		resp = message.run()
		message.destroy()
		if resp == Gtk.ResponseType.YES: return True
		else: return False


	def _on_btn_remove_provider_clicked(self, widget: Gtk.ToolButton) -> None:
		_LOGGER.debug('on_btn_remove_provider_clicked')

		treeselection = self._treeview_2FA_providers.get_selection()
		model, iter = treeselection.get_selected()

		if iter is None:
			return

		_sender = model.get_value(iter, 1)
		_subject = model.get_value(iter, 2)
		_pattern = model.get_value(iter, 3)

		if not self._show_confirmation_dialog(
			    _('Delete this provider:') + '\n' +
				'\n  ' + _("Sender:") + _sender +
				'\n  ' + _("Subject:") + _subject +
				'\n  ' + _("Pattern:") +
				'\n    ' + _pattern):
			return

		# select prev/next account
		p = model.get_path(iter)
		if not p.prev():
			p.next()

		treeselection = self._treeview_2FA_providers.get_selection()
		treeselection.select_path(p)
		self._treeview_2FA_providers.grab_focus()

		# remove from treeview
		model.remove(iter)


	def _edit_provider(self, model, iter) -> None:
		if iter is None:
			return

		_enabled = model.get_value(iter, 0)
		_sender = model.get_value(iter, 1)
		_subject = model.get_value(iter, 2)
		_pattern = model.get_value(iter, 3)

		b = self._builder
		d = self._dialog

		b.get_object('enable').set_active(_enabled)
		b.get_object('sender').set_text(_sender)
		b.get_object('subject').set_text(_subject)
		b.get_object('pattern_text_buffer').set_text(_pattern)

		if d.run() != Gtk.ResponseType.OK:
			return

		_enabled = b.get_object('enable').get_active()
		_sender = b.get_object('sender').get_text()
		_subject = b.get_object('subject').get_text()
		start = b.get_object('pattern_text_buffer').get_start_iter()
		end = b.get_object('pattern_text_buffer').get_end_iter()
		_pattern = b.get_object('pattern_text_buffer').get_text(start, end, False)

		if not self._check_2fa_provider_pattern(_sender, _subject, _pattern) and _enabled:
			_enabled = False

		model.set_value(iter, 0, _enabled)
		model.set_value(iter, 1, _sender)
		model.set_value(iter, 2, _subject)
		model.set_value(iter, 3, _pattern)


	def _on_btn_edit_provider_clicked(self, widget: Gtk.ToolButton) -> None:
		_LOGGER.debug('on_btn_edit_provider_clicked')
		treeselection = self._treeview_2FA_providers.get_selection()
		model, iter = treeselection.get_selected()

		self._edit_provider(model, iter)


	def _on_provider_toggled(self, cell: Gtk.CellRendererToggle, path: Gtk.TreePath) -> None:
		_LOGGER.debug('on_provider_toggled')
		model = self._liststore_2FA_providers
		iter = model.get_iter(path)

		_enabled = not model.get_value(iter, 0)
		_sender = model.get_value(iter, 1)
		_subject = model.get_value(iter, 2)
		_pattern = model.get_value(iter, 3)

		if _enabled and not self._check_2fa_provider_pattern(_sender, _subject, _pattern):
			return

		self._liststore_2FA_providers.set_value(iter, 0, _enabled)


	def _on_provider_row_activated(self, view: Gtk.TreeView, path: Gtk.TreePath, column: Gtk.TreeViewColumn) -> None:
		_LOGGER.debug('on_provider_row_activated')

		event = Gtk.get_current_event()

		_LOGGER.debug('event.type = %s', event.type.value_name)

		if column.get_name() != 'col_enabled':
			model = view.get_model()
			iter = model.get_iter(path)
			self._edit_provider(model, iter)


	def _on_expander_2fa_providers_expanded(self, expander, pspec) -> None:
		wnd = expander.get_toplevel()

		w = wnd.get_size().width
		wnd.resize(w, 1)


	def _on_provider_sel_changed(self, selection: Gtk.TreeSelection) -> None:
		model, iter = selection.get_selected()
		sensitive = (iter is not None)
		for  id in ('btn_remove_2FA_provider', 'btn_edit_2FA_provider'):
			self._builder.get_object(id).set_sensitive(sensitive)

	@staticmethod
	def _stop_infobar_timeout(infobar: Gtk.InfoBar) -> None:
		timeout_id = getattr(infobar, "timeout_id", None)
		if timeout_id is not None:
			GLib.source_remove(timeout_id)
			infobar.timeout_id = None

	@staticmethod
	def _start_infobar_timeout(infobar: Gtk.InfoBar, duration_s: int) -> None:
		LibNotifyPlugin._stop_infobar_timeout(infobar)

		def timeout_reached():
			infobar.hide()
			infobar.timeout_id = None
			return False

		infobar.timeout_id = GLib.timeout_add(duration_s*1000, timeout_reached)


	def _alert_message(self, msg_format:str, *args, msg_type: Gtk.MessageType = Gtk.MessageType.INFO, duration_s:int = None) -> None:
		self._stop_infobar_timeout(self._infobar_info)

		# 1. Formatage sécurisé du message
		try:
			msg = msg_format % args if args else msg_format
		except TypeError as e:
			msg = msg_format
			log_msg = f"Erreur de formatage message: {msg_format} (args: {args})"
			_LOGGER.exception("Format Error: %s\n%s", str(e), log_msg)

		# 2. Correspondance Logging et Affichage
		# On définit le niveau de log en fonction du type GTK passé
		if msg_type == Gtk.MessageType.ERROR:
			_LOGGER.error(msg)
		elif msg_type == Gtk.MessageType.WARNING:
			_LOGGER.warning(msg)
		elif msg_type == Gtk.MessageType.QUESTION:
			_LOGGER.info("QUESTION: %s", msg)
		else: # INFO ou OTHER
			_LOGGER.info(msg)

		self._label_info.set_text(msg)
		self._infobar_info.set_message_type(msg_type)
		self._infobar_info.show()

		if duration_s is not None:
			self._start_infobar_timeout(self._infobar_info, duration_s)

	def _on_info_response(self, infobar: Gtk.InfoBar, response_id: int) -> None:
		if response_id in (Gtk.ResponseType.CLOSE, Gtk.ResponseType.OK):
			self._stop_infobar_timeout(infobar)
			infobar.hide()


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
