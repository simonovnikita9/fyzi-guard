<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Limits login attempts per IP address.
 */
class FYZI_Guard_Login_Guard {

    public static function init() {
        if (!FYZI_Guard_Settings::get('limit_login')) {
            return;
        }
        add_filter('authenticate', array(__CLASS__, 'check_lock'), 30, 1);
        add_action('wp_login_failed', array(__CLASS__, 'on_fail'));
        add_action('wp_login', array(__CLASS__, 'on_success'), 10, 0);
    }

    public static function client_ip() {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
        if (FYZI_Guard_Settings::get('trust_proxy_ip') && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $list = explode(',', sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR'])));
            $candidate = trim($list[0]);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                $ip = $candidate;
            }
        }
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
    }

    private static function key($ip) {
        return 'fyzi_guard_login_' . md5($ip);
    }

    public static function check_lock($user) {
        $data = get_transient(self::key(self::client_ip()));
        if (is_array($data) && !empty($data['locked_until']) && $data['locked_until'] > time()) {
            $minutes = (int) ceil(($data['locked_until'] - time()) / 60);
            return new WP_Error('fyzi_guard_locked', sprintf(
                /* translators: %d: minutes until the lock expires */
                _n('Too many failed login attempts. Try again in %d minute.', 'Too many failed login attempts. Try again in %d minutes.', $minutes, 'fyzi-guard'),
                $minutes
            ));
        }
        return $user;
    }

    public static function on_fail($username) {
        $ip = self::client_ip();
        $key = self::key($ip);
        $max = (int) FYZI_Guard_Settings::get('login_max_attempts');
        $lock_min = (int) FYZI_Guard_Settings::get('login_lockout_minutes');

        $data = get_transient($key);
        if (!is_array($data)) {
            $data = array('count' => 0, 'locked_until' => 0);
        }
        $data['count']++;
        if ($data['count'] >= $max) {
            $data['locked_until'] = time() + $lock_min * 60;
            $data['count'] = 0;
            FYZI_Guard_Log::add('warning', __('IP address locked after failed login attempts', 'fyzi-guard'), array(
                'ip'      => $ip,
                'login'   => sanitize_user((string) $username),
                'minutes' => $lock_min,
            ));
            set_transient($key, $data, $lock_min * 60);
            return;
        }
        set_transient($key, $data, 15 * MINUTE_IN_SECONDS);
    }

    public static function on_success() {
        delete_transient(self::key(self::client_ip()));
    }
}
