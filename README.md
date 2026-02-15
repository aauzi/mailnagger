![Mailnagger](https://github.com/tikank/mailnagger/blob/22f00f270c616dc94e9bee301146ff117d00b3a4/data/icons/hicolor/256x256/apps/mailnag.png)

## An extensible mail notification daemon

Mailnagger is a daemon program that checks POP3 and IMAP servers for new mail.
On mail arrival it performs various actions provided by plugins.
Mailnagger comes with a set of desktop-independent default plugins for
visual/sound notifications, script execution etc. and can be extended
with additional plugins easily.

Mailnagger is a fork of [Mailnag](https://github.com/pulb/mailnag).

__This project needs your support!__

If you like Mailnagger, please help to keep it going by [contributing code](https://github.com/tikank/mailnagger),
[reporting/fixing bugs](https://github.com/tikank/mailnagger/issues),
[translating strings into your native language](https://github.com/tikank/mailnagger/tree/master/po),
or [writing docs](https://github.com/tikank/mailnagger/tree/master/docs).


## 🚀 Advanced Features (This Fork)

This version of Mailnagger introduces several high-productivity enhancements and core engine improvements:

### 🔑 Intelligent 2FA Detection & Power Summary
* **Automatic Extraction**: The `libnotify` plugin scans incoming emails to detect Two-Factor Authentication (2FA) codes using customizable regex patterns.
* **HTML Body Parsing**: Smart extraction of plain text from HTML emails to ensure 2FA patterns are matched accurately even in complex layouts.
* **Urgency Handling**: 2FA notifications are treated with higher priority, ensuring they stay visible while the code is valid.
* **Instant Visibility**: Extracted codes are injected directly into the notification title (e.g., `🔑 123456 — Garmin`).
* **One-Click Copy**: A "Copy code" button is integrated into the notification, supporting **Wayland** (`wl-copy`) and **X11** (`xclip`, `xsel`).
* **On-Demand Fetching**: Uses the new `fetch_text()` backend method to retrieve only the necessary data for parsing, saving bandwidth.
* **Independent Notifications**: Each incoming mail generates a unique notification instance. Copying a 2FA code from one specific notification won't interfere with others, even during simultaneous bursts.
* **Non-Blocking Fetch**: The 2FA extraction engine works asynchronously. Slow network responses from one mail server won't delay notifications from other accounts.
* **Clipboard Persistence**: Copy actions are delegated to system-level utilities, ensuring codes remain available in your clipboard even after notifications are dismissed.

### 🛡️ Robust GOA & OAuth2 Management
* **Native GNOME Integration**: Deeply integrated with **GNOME Online Accounts (GOA)**.
* **Automatic Token Refresh**: Implements `refresh_goa_token` to handle OAuth2 access token updates in the background, preventing connection drops for Gmail/Outlook.

### 📊 Professional Logging System
* **Granular Control**: Define log levels per module via the `[logger_levels]` section in `mailnag.cfg`.
* **Safe Configuration**: Uses `dictConfig` with predefined `VALID_LEVELS` to ensure system stability even with custom log settings.

---

## ⚙️ Configuration

### 1. Granular Logging Control (`mailnag.cfg`)

You can now define the logging verbosity per module by adding a `[logger_levels]` section to your `~/.config/mailnag/mailnag.cfg`.

```ini
[logger_levels]
# Set the global log level (DEBUG, INFO, WARNING, ERROR, or CRITICAL)
root = INFO

# Specific level for the 2FA extraction and GOA utilities
Mailnag.common.utils = DEBUG

# Specific level for the libnotify plugin (useful for regex debugging)
Mailnag.plugins.libnotifyplugin = DEBUG

```

* **Dynamic Loading**: The daemon validates these levels against a predefined list (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) and applies them using `dictConfig`.
* **Dual Output**: Logs are automatically routed to both standard output and the system journal via `/dev/log`.

---

### 2. 2FA Providers (`2fa_providers.tsv`)

The extraction of security codes from incoming emails is managed via a Tab-Separated Values (TSV) file located at `~/.config/mailnag/2fa_providers.tsv`.

| Column | Description |
| --- | --- |
| **enabled** | `True` or `False` to toggle detection for this service. |
| **provider** | The display name of the service (e.g., Garmin, Microsoft). |
| **subject** | The email subject pattern to match (supports the `{code}` placeholder). |
| **text_re** | The Regex used to find the code in the email body (use `{code}` for the target). |

---

### 3. GNOME Online Accounts (GOA) Integration

This fork provides deep integration with GNOME Online Accounts for robust authentication.

* **Account Linking**: The system automatically maps your email and username to the corresponding GOA identity using `get_goa_account_id`.
* **Automatic OAuth2 Refresh**: If a connection fails due to an expired session, `refresh_goa_token` silently fetches a new access token from the system, preventing manual re-authentication prompts.

---

## 🛠️ Developers &  "Under the Hood"

* **Architecture**: Transitioned to **Abstract Base Classes (ABC)** for backends, ensuring a strict and stable interface.
* **Reliability**: All backends now support **UID-based tracking** and the `fetch_text()` method.
* **Standards**: Configuration management now follows **XDG Base Directory** specifications using `pathlib`.
* **Resilience**: Improved socket error handling and auto-retry logic for IMAP/POP3 connections.
* **Code Style**: Unified codebase using `_LOGGER` and strict **tab-indentation** (optimized for `tabsize 8`).

If you are developing custom plugins or backends, please note the following core changes:

* **Backend Interface**: The `list_messages()` method has been updated to yield a 4-tuple including the message **UID**: `(folder, message, uid, flags)`.
* **Mandatory Method**: All backends must now implement `fetch_text()` to allow on-demand retrieval of the email body.

## 🏗️ Build & Setup Improvements
* **Robust Localization**: Improved `BuildData` class with explicit error handling and logging during translation compilation.
* **Asset Integrity**: Fixed missing UI resources in the distribution package, ensuring `libnotifyplugin.ui` is correctly installed.
* **Modern Packaging**: Updated `setup.py` to support high-resolution icons and standardized XDG desktop file locations.

---

## ⚠️ Technical Incompatibilities

**Important:** This fork modifies the Mailnagger core. Its `libnotify` is **not compatible** with backends from the original `titank` repository due to the following changes:

* **`fetch_text()` Method**: All mail backends now require a mandatory `fetch_text()` function.
* **Modified Signatures**: Backend methods like `list_messages` now return additional data (such as UIDs), making them incompatible with older core versions.

---

## 🔄 Migration Note (Standard Compliance)

This fork now follows the **XDG Base Directory Specification**. 
Config files have moved from `~/.mailnag` to `~/.config/mailnag`.

If you are upgrading from an older version, you can migrate your settings manually:

```bash
mkdir -p ~/.config/mailnag
cp ~/.mailnag/mailnag.cfg ~/.config/mailnag/
# Optional: Move your custom rules/scripts if you have any
```
## 📋 Requirements & Installation

### Core Dependencies
* **Python** (>= 3.10) - *Mandatory for modern type syntax.*
* **pyxdg** - *Mandatory for XDG directory support.*
* **PyGObject / GLib / gir-notify** - *For system notifications and UI.*
* **dbus-python** - *For communication with GOA and desktop services.*

### Optional (Feature-Specific)
* **2FA Clipboard**: `wl-clipboard` (Wayland) or `xclip/xsel` (X11).
* **Secure Storage**: `libsecret` / `gir1.2-secret-1`.
* **Translations**: `gettext` (only for building from source).

### Installation
```bash
pipx install mailnagger
```

## Configuration 

Run `mailnagger-config` to setup Mailnagger.

Closing the configuration window will start Mailnagger automatically.

> **Note:**
> Mailnagger uses same configuration files and secret storage as Mailnag.
> They are currently compatible, but there will be someday some kind of
> migration to Mailnagger's own configuration files.


### Default Mail Client

Clicking a mail notification popup will open the default mail client specified in `GNOME Control Center -> Details -> Default Applications`.
If you're a webmail (e.g. gmail) user and want your account to be launched in a browser, please install a tool like [gnome-gmail](http://gnome-gmail.sourceforge.net).


### Desktop Integration

By default, Mailnagger emits libnotify notifications, which work fine on
most desktop environments but are visible for a few seconds only.
If you like to have a tighter desktop integration (e.g. a permanently visible indicator in your top panel) you have to install an appropriate
extension/plugin for your desktop shell.

Mailnag has following desktop extensions:

* GNOME-Shell ([GNOME-Shell extension](https://github.com/pulb/mailnag-gnome-shell)) 
* KDE ([Plasma 5 applet by driglu4it](https://store.kde.org/p/1420222/))
* Cinnamon ([Applet by hyOzd](https://bitbucket.org/hyOzd/mailnagapplet))
* Elementary Pantheon ([MessagingMenu plugin](https://github.com/pulb/mailnag-messagingmenu-plugin))
* XFCE ([MessagingMenu plugin](https://github.com/pulb/mailnag-messagingmenu-plugin))

Since Mailnagger is essentially same as Mailnag, those extensions should/might
work with Mailnagger.

Furthermore, GNOME users can also install the [GOA plugin](https://github.com/pulb/mailnag-goa-plugin),
which makes Mailnagger aware of email accounts specified in GNOME Online Accounts.


### Troubleshooting

__Gmail doesn't work__

If Mailnagger is unable to connect to your Gmail account, please try the following solutions:
* Install the [GOA plugin](https://github.com/pulb/mailnag-goa-plugin) to connect via GNOME online accounts
* Have a look at the [FAQ](https://github.com/pulb/mailnag/wiki/FAQ)
* Try to apply [this](https://github.com/pulb/mailnag/issues/190) workaround

__Other issues__

If Mailnagger doesn't work properly for you, either examine the system log
for errors (`journalctl -b _COMM=mailnagger`)
or run `mailnagger` in a terminal and observe the output.

