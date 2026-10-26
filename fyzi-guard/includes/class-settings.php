<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Plugin settings. All protection switches live here, with safe defaults.
 */
class FYZI_Guard_Settings {
    const OPTION = 'fyzi_guard_settings';

    public static function defaults() {
        return array(
            // Protection
            'block_rest_batch'      => 1,   // unauthenticated REST batch requests (channel of the wp2shell wave)
            'block_user_enum'       => 1,   // user enumeration via REST and ?author=
            'disable_xmlrpc'        => 1,
            'disable_file_edit'     => 1,
            'disable_app_passwords' => 0,   // application passwords are needed by some integrations
            'hide_version'          => 1,
            'limit_login'           => 1,
            'login_max_attempts'    => 5,
            'login_lockout_minutes' => 30,
            'trust_proxy_ip'        => 0,
            // Monitoring
            'scan_core'             => 1,
            'scan_uploads'          => 1,
            'scan_changes'          => 1,
            // Notifications
            'notify_email'          => 1,
            'email_to'              => '',
            'notify_telegram'       => 0,
            'tg_token'              => '',
            'tg_chat_id'            => '',
        );
    }

    public static function install() {
        $current = get_option(self::OPTION);
        if (!is_array($current)) {
            add_option(self::OPTION, self::defaults(), '', 'yes');
        } else {
            update_option(self::OPTION, array_merge(self::defaults(), $current));
        }
    }

    public static function all() {
        $s = get_option(self::OPTION);
        return array_merge(self::defaults(), is_array($s) ? $s : array());
    }

    public static function get($key) {
        $all = self::all();
        return isset($all[$key]) ? $all[$key] : null;
    }

    public static function save(array $input) {
        $defaults = self::defaults();
        $clean = array();
        foreach ($defaults as $key => $default) {
            if (is_int($default)) {
                $clean[$key] = isset($input[$key]) ? absint($input[$key]) : 0;
            } else {
                $clean[$key] = isset($input[$key]) ? sanitize_text_field(wp_unslash($input[$key])) : '';
            }
        }
        $clean['login_max_attempts'] = max(3, min(20, $clean['login_max_attempts'] ?: 5));
        $clean['login_lockout_minutes'] = max(5, min(1440, $clean['login_lockout_minutes'] ?: 30));
        if ($clean['email_to'] !== '' && !is_email($clean['email_to'])) {
            $clean['email_to'] = '';
        }
        update_option(self::OPTION, $clean);
        return $clean;
    }

    /** State (not settings): known administrators, file index, check results. */
    public static function state($key, $default = null) {
        $v = get_option('fyzi_guard_' . $key, null);
        return $v === null ? $default : $v;
    }

    public static function set_state($key, $value) {
        update_option('fyzi_guard_' . $key, $value, false);
    }
}
