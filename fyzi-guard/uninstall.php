<?php
// Removes all FYZI Guard data when the plugin is deleted.
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

require_once __DIR__ . '/includes/class-settings.php';
require_once __DIR__ . '/includes/class-log.php';
require_once __DIR__ . '/includes/class-hardening.php';

FYZI_Guard_Hardening::unprotect_uploads();

foreach (array('settings', 'log', 'known_admins', 'alerted_admins', 'app_passwords', 'hidden_sig', 'last_admin_check', 'findings', 'last_scan', 'file_index', 'ignored') as $fyzi_guard_key) {
    delete_option('fyzi_guard_' . $fyzi_guard_key);
}

global $wpdb;
// Login-limit transients are keyed by hashed IP addresses, so they can only be removed by pattern.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_fyzi\\_guard\\_%' OR option_name LIKE '\\_transient\\_timeout\\_fyzi\\_guard\\_%'");
