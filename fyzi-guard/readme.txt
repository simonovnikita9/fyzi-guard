=== FYZI Guard ===
Contributors: fyzishield
Tags: security, malware, firewall, hack, admin
Requires at least: 5.8
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Free protection against mass WordPress hacking: closes popular attack channels, watches administrators and files, sends alerts to Telegram.

== Description ==

FYZI Guard is a free security plugin developed in Russia by specialists who clean hacked websites every day. It closes exactly the channels that are used in today's mass hacking campaigns against WordPress sites, and tells you within minutes when something suspicious happens.

= Protection =

* Closes unauthenticated REST batch requests (`/wp-json/batch/v1`) that bots abuse to create fake administrators.
* Hides user logins: `/wp-json/wp/v2/users`, `?author=` and the users sitemap.
* Disables XML-RPC, the main channel for password brute force.
* Disables the theme and plugin file editor in the admin.
* Limits login attempts per IP address.
* Blocks PHP execution in the uploads folder with one click (Apache), or gives a ready rule for nginx.
* Hides the WordPress version.

Every measure can be turned off separately.

= Monitoring =

* Watches administrators directly in the database, so it notices accounts inserted around WordPress and administrators hidden from the user list by malicious code.
* Reports new application passwords created for administrators.
* Every day compares WordPress core files with the original checksums from wordpress.org and finds extra PHP files inside the core.
* Finds PHP files in the uploads folder and PHP code hidden inside images.
* Tracks new and modified PHP files in plugins, themes and mu-plugins and checks them for typical malicious constructs.
* Reminds you about outdated plugins and other weak spots.

= Alerts =

* By e-mail and to your own Telegram bot. Step-by-step setup inside the plugin.

= Privacy =

The plugin works entirely on your site. It does not send any data about your site to us. See the "External services" section below.

= FYZI Shield Pro =

An optional paid service by the same team: 24/7 external monitoring, tracking of "dangerous site" warnings in Yandex and Google, infection cleanup by a specialist, backups and the "Clean site" guarantee. The free plugin is fully functional without it. Learn more at [fyzi.ru](https://fyzi.ru/).

= External services =

This plugin connects to the following services:

* **WordPress.org Checksums API** (`api.wordpress.org`) — to download the reference checksums of WordPress core files for the daily core check. Only the WordPress version and locale are sent. This happens during the daily check and when you click "Check now". [WordPress.org privacy policy](https://wordpress.org/about/privacy/).
* **Telegram Bot API** (`api.telegram.org`) — only if you enable Telegram alerts and enter your own bot token and chat ID. The alert text (event description and your site domain) is sent to your bot when a security event happens. [Telegram privacy policy](https://telegram.org/privacy), [Terms of service](https://telegram.org/tos).

== Installation ==

1. Install the plugin through "Plugins → Add New" or upload the archive via "Plugins → Add New → Upload Plugin".
2. Activate the plugin. Administrators that exist at this moment are saved as known.
3. Open the "FYZI Guard" menu item and click "Check now".
4. On the "Notifications" tab, connect Telegram alerts.

== Frequently Asked Questions ==

= Does the plugin send data about my site anywhere? =

No. It works entirely on your site. It only downloads core checksums from api.wordpress.org, and alerts go only to your e-mail and to your own Telegram bot.

= Can it break my site? =

Each protection measure can be turned off separately on the "Protection" tab. Application passwords are not disabled by default because some integrations need them.

= Can I use it together with Wordfence or another security plugin? =

Yes, the features barely overlap. If another plugin already limits login attempts, turn this feature off in FYZI Guard to avoid duplication.

= I got an alert about a new administrator, but it is mine. =

Click "This is my administrator" next to the user on the "Overview" tab, and the plugin will remember it.

= Is the plugin translated? =

The plugin includes a Russian translation. Other languages can be added through translate.wordpress.org.

== Changelog ==

= 1.1.0 =
* English source strings with a bundled Russian translation.
* Uploads protection is written with the WordPress core `insert_with_markers()` function.
* Finding IDs no longer depend on the interface language.

= 1.0.0 =
* First release.

== Upgrade Notice ==

= 1.1.0 =
Interface translation support and safer .htaccess handling.
