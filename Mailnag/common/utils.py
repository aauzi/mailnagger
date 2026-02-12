# Copyright 2025 André Auzi <aauzi@free.fr>
# Copyright 2024 Timo Kankare <timo.kankare@iki.fi>
# Copyright 2011 - 2019 Patrick Ulbrich <zulu99@gmx.net>
# Copyright 2007 Marco Ferragina <marco.ferragina@gmail.com>
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

import sys
import time
import dbus
import logging
import logging.config
import logging.handlers
from collections.abc import Callable
from typing import TypeVar

import gi
gi.require_version('Goa', '1.0')
from gi.repository import Goa

from Mailnag.common.config import read_cfg
from Mailnag.common.dist_cfg import DBUS_BUS_NAME, DBUS_OBJ_PATH

LOG_FORMAT = '%(levelname)s (%(asctime)s): %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

_LOGGER = logging.getLogger(__name__)

def init_logging(
	enable_stdout: bool = True,
	enable_syslog: bool = True,
	log_level: int = logging.DEBUG
) -> None:
	logging.basicConfig(
		format = LOG_FORMAT,
		datefmt = LOG_DATE_FORMAT,
		level = log_level)

	logger = logging.getLogger('')

	if not enable_stdout:
		stdout_handler = logger.handlers[0]
		logger.removeHandler(stdout_handler)

	if enable_syslog:
		syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
		syslog_handler.setLevel(log_level)
		syslog_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))

		logger.addHandler(syslog_handler)

	configure_logging()

def configure_logging() -> None:
	VALID_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}

	config = {
		"version": 1,
		"disable_existing_loggers": False,
		"incremental": True,
		"root": {
			"level": logging.getLevelName(logging.getLogger().getEffectiveLevel())
		},
		"loggers": {},
	}

	cfg = read_cfg()

	if not 'logger_levels' in cfg:
		return

	raw_levels = dict(cfg.items('logger_levels'))
	for name, level in raw_levels.items():
		clean_level = str(level).upper().strip()

		if clean_level not in VALID_LEVELS:
			continue

		if name == "root":
			config["root"]["level"] = clean_level
		else:
			config["loggers"][name] = {
				"level": clean_level,
				"propagate": True
			}

	logging.config.dictConfig(config)


def splitstr(strn: str, delimeter: str) -> list[str]:
	return [s.strip() for s in strn.split(delimeter) if s.strip()]


def set_procname(newname: str) -> None:
	from ctypes import cdll, byref, create_string_buffer
	libc = cdll.LoadLibrary('libc.so.6')
	buff = create_string_buffer(len(newname)+1)
	buff.value = newname.encode('utf-8')
	libc.prctl(15, byref(buff), 0, 0, 0)


T = TypeVar("T")


def try_call(f: Callable[[], T], err_retval: T) -> T:
	try:
		return f()
	except:
		_LOGGER.exception('Caught an exception.')
		return err_retval


def shutdown_existing_instance(wait_for_completion: bool = True) -> None:
	bus = dbus.SessionBus()

	if bus.name_has_owner(DBUS_BUS_NAME):
		sys.stdout.write('Shutting down existing Mailnagger process...')
		sys.stdout.flush()

		try:
			proxy = bus.get_object(DBUS_BUS_NAME, DBUS_OBJ_PATH)
			shutdown = proxy.get_dbus_method('Shutdown', DBUS_BUS_NAME)

			shutdown()

			if wait_for_completion:
				while bus.name_has_owner(DBUS_BUS_NAME):
					time.sleep(2)

			print('OK')
		except:
			print('FAILED')


def get_goa_account_id(name, user):
	_LOGGER.debug("Get GOA account: name: %s, user: %s", name, user)

	client = Goa.Client.new_sync(None)
	goa_accounts = client.get_accounts()

	for obj in goa_accounts:
		account = obj.get_account()
		if account is None or account.props.mail_disabled:
			continue
		mail = obj.get_mail()
		if mail is None or not mail.props.imap_supported:
			continue

		_LOGGER.debug("	 account: name: %s, user: %s",
			      mail.props.email_address,
			      mail.props.imap_user_name)
		if (name == mail.props.email_address
		    and user == mail.props.imap_user_name):
			identity = account.get_property('id')
			_LOGGER.debug("	 account: name: %s, user: %s, id: %s",
				      mail.props.email_address,
				      mail.props.imap_user_name,
				      identity)
			return identity
	return None


def refresh_goa_token(account_id):
	client = Goa.Client.new_sync(None)
	obj = client.lookup_by_id(account_id)
	if obj is None:
		return None

	oauth2_based = obj.get_oauth2_based()
	if oauth2_based is None:
		return None

	return oauth2_based.call_get_access_token_sync(None)


def strlimit(txt: str) -> str:
	txt = str(txt)
	return txt[:min(80, len(txt))] + '...'


def dbgindent(txt: str) -> str:
	txt = strlimit(str(txt).strip())
	return '    ' + '\n    '.join(txt.splitlines())
