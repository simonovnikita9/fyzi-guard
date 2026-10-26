<?php
/**
 * Plugin Name:       FYZI Guard
 * Plugin URI:        https://fyzi.ru/fyzi-guard/
 * Description:       Free WordPress protection against mass hacking campaigns: closes popular attack channels, watches for new administrators and modified files, verifies core files and sends alerts to Telegram.
 * Version:           1.1.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            FYZI Shield
 * Author URI:        https://fyzi.ru/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       fyzi-guard
 * Domain Path:       /languages
 */

if (!defined('ABSPATH')) {
    exit;
}

define('FYZI_GUARD_VERSION', '1.1.0');
define('FYZI_GUARD_FILE', __FILE__);
define('FYZI_GUARD_DIR', plugin_dir_path(__FILE__));
define('FYZI_GUARD_URL', plugin_dir_url(__FILE__));

require_once FYZI_GUARD_DIR . 'includes/class-settings.php';
require_once FYZI_GUARD_DIR . 'includes/class-log.php';
require_once FYZI_GUARD_DIR . 'includes/class-notifier.php';
require_once FYZI_GUARD_DIR . 'includes/class-hardening.php';
require_once FYZI_GUARD_DIR . 'includes/class-login-guard.php';
require_once FYZI_GUARD_DIR . 'includes/class-watchdog.php';
require_once FYZI_GUARD_DIR . 'includes/class-scanner.php';

if (is_admin()) {
    require_once FYZI_GUARD_DIR . 'includes/class-admin.php';
}

add_action('init', 'fyzi_guard_load_textdomain');

function fyzi_guard_load_textdomain() {
    load_plugin_textdomain('fyzi-guard', false, dirname(plugin_basename(FYZI_GUARD_FILE)) . '/languages');
}

// Hardening rules must be registered as early as possible.
FYZI_Guard_Hardening::init();
FYZI_Guard_Login_Guard::init();
FYZI_Guard_Watchdog::init();
FYZI_Guard_Scanner::init();

if (is_admin()) {
    FYZI_Guard_Admin::init();
}

register_activation_hook(__FILE__, 'fyzi_guard_activate');
register_deactivation_hook(__FILE__, 'fyzi_guard_deactivate');

function fyzi_guard_activate() {
    FYZI_Guard_Settings::install();
    if (!wp_next_scheduled('fyzi_guard_hourly')) {
        wp_schedule_event(time() + 60, 'hourly', 'fyzi_guard_hourly');
    }
    if (!wp_next_scheduled('fyzi_guard_daily')) {
        wp_schedule_event(time() + 300, 'daily', 'fyzi_guard_daily');
    }
    // Current administrators are treated as known, so activation causes no false alarm.
    FYZI_Guard_Watchdog::baseline();
    fyzi_guard_load_textdomain();
    FYZI_Guard_Log::add('info', __('Plugin activated, current administrators saved as known.', 'fyzi-guard'));
}

function fyzi_guard_deactivate() {
    wp_clear_scheduled_hook('fyzi_guard_hourly');
    wp_clear_scheduled_hook('fyzi_guard_daily');
}

add_action('fyzi_guard_hourly', array('FYZI_Guard_Watchdog', 'check'));
add_action('fyzi_guard_daily', array('FYZI_Guard_Scanner', 'run'));
