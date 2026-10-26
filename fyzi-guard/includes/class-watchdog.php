<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Administrator watchdog.
 * Catches regular creation through WordPress, direct database inserts
 * and administrators hidden from the admin user list.
 */
class FYZI_Guard_Watchdog {

    public static function init() {
        add_action('user_register', array(__CLASS__, 'on_user_change'), 99, 1);
        add_action('set_user_role', array(__CLASS__, 'on_user_change'), 99, 1);
        add_action('add_user_role', array(__CLASS__, 'on_user_change'), 99, 1);
        add_action('grant_super_admin', array(__CLASS__, 'on_user_change'), 99, 1);
    }

    /** Administrators read directly from the database, so no filter can hide them. */
    public static function admins_from_db() {
        global $wpdb;
        $key = $wpdb->get_blog_prefix() . 'capabilities';
        // A direct query is intentional: get_users() can be filtered by malicious code to hide accounts.
        // Results must be fresh on every check, so they are not cached.
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT u.ID, u.user_login, u.user_email, u.user_registered
             FROM {$wpdb->users} u
             INNER JOIN {$wpdb->usermeta} m ON m.user_id = u.ID
             WHERE m.meta_key = %s AND m.meta_value LIKE %s
             ORDER BY u.ID",
            $key,
            '%' . $wpdb->esc_like('"administrator"') . '%'
        ), ARRAY_A);
        $out = array();
        foreach ((array) $rows as $r) {
            $out[(int) $r['ID']] = $r;
        }
        return $out;
    }

    /** Administrators as WordPress shows them (with all filters applied). */
    public static function admins_visible() {
        $users = get_users(array('role' => 'administrator', 'fields' => array('ID')));
        $ids = array();
        foreach ($users as $u) {
            $ids[] = (int) $u->ID;
        }
        return $ids;
    }

    public static function known() {
        $k = FYZI_Guard_Settings::state('known_admins', array());
        return is_array($k) ? array_map('intval', $k) : array();
    }

    public static function baseline() {
        FYZI_Guard_Settings::set_state('known_admins', array_keys(self::admins_from_db()));
        FYZI_Guard_Settings::set_state('app_passwords', self::app_password_index());
    }

    public static function approve($user_id) {
        $known = self::known();
        $known[] = (int) $user_id;
        FYZI_Guard_Settings::set_state('known_admins', array_values(array_unique($known)));
        FYZI_Guard_Log::add('info', __('Administrator marked as known', 'fyzi-guard'), array('user_id' => (int) $user_id));
    }

    /** Reacts to user creation or role change through WordPress. */
    public static function on_user_change($user_id) {
        $user = get_userdata($user_id);
        if (!$user || !in_array('administrator', (array) $user->roles, true)) {
            return;
        }
        if (in_array((int) $user_id, self::known(), true) || self::already_alerted($user_id)) {
            return;
        }
        $actor = get_current_user_id();
        $lines = array(
            /* translators: %s: user login */
            sprintf(__('Login: %s', 'fyzi-guard'), $user->user_login),
            /* translators: %s: user e-mail */
            sprintf(__('E-mail: %s', 'fyzi-guard'), $user->user_email),
            $actor
                /* translators: %d: ID of the user who created the account */
                ? sprintf(__('Created by: user #%d', 'fyzi-guard'), $actor)
                : __('Created by: nobody logged in (suspicious!)', 'fyzi-guard'),
            /* translators: %s: IP address */
            sprintf(__('Request IP: %s', 'fyzi-guard'), FYZI_Guard_Login_Guard::client_ip()),
            /* translators: %s: request URI */
            sprintf(__('Request URI: %s', 'fyzi-guard'), isset($_SERVER['REQUEST_URI']) ? esc_url_raw(wp_unslash($_SERVER['REQUEST_URI'])) : '-'),
            '',
            __('If this was not you, delete the user and change all passwords. If it is yours, click “This is my administrator” in the FYZI Guard dashboard.', 'fyzi-guard'),
        );
        self::remember_alerted((int) $user_id);
        FYZI_Guard_Notifier::alert(__('A new administrator appeared', 'fyzi-guard'), $lines, 'critical');
    }

    private static function remember_alerted($user_id) {
        $alerted = FYZI_Guard_Settings::state('alerted_admins', array());
        $alerted = is_array($alerted) ? $alerted : array();
        $alerted[] = $user_id;
        FYZI_Guard_Settings::set_state('alerted_admins', array_values(array_unique(array_map('intval', $alerted))));
    }

    private static function already_alerted($user_id) {
        $alerted = FYZI_Guard_Settings::state('alerted_admins', array());
        return is_array($alerted) && in_array((int) $user_id, array_map('intval', $alerted), true);
    }

    /** Hourly check: administrators in the database and application passwords. */
    public static function check() {
        $db = self::admins_from_db();
        $known = self::known();
        $visible = self::admins_visible();

        foreach ($db as $id => $row) {
            if (in_array($id, $known, true) || self::already_alerted($id)) {
                continue;
            }
            self::remember_alerted($id);
            FYZI_Guard_Notifier::alert(__('Unknown administrator detected', 'fyzi-guard'), array(
                /* translators: %s: user login */
                sprintf(__('Login: %s', 'fyzi-guard'), $row['user_login']),
                /* translators: %s: user e-mail */
                sprintf(__('E-mail: %s', 'fyzi-guard'), $row['user_email']),
                /* translators: %s: registration date */
                sprintf(__('Registered: %s', 'fyzi-guard'), $row['user_registered']),
                __('The user exists in the database, but WordPress never reported creating it. This happens when an administrator is inserted directly into the database or through a vulnerability.', 'fyzi-guard'),
            ), 'critical');
        }

        $hidden = array_diff(array_keys($db), $visible);
        if ($hidden) {
            $names = array();
            foreach ($hidden as $id) {
                $names[] = $db[$id]['user_login'] . ' (#' . $id . ')';
            }
            $sig = md5(implode(',', $hidden));
            if (FYZI_Guard_Settings::state('hidden_sig') !== $sig) {
                FYZI_Guard_Settings::set_state('hidden_sig', $sig);
                FYZI_Guard_Notifier::alert(__('Hidden administrators found', 'fyzi-guard'), array(
                    /* translators: %s: comma-separated list of logins */
                    sprintf(__('The database contains administrators that are not shown in the user list: %s', 'fyzi-guard'), implode(', ', $names)),
                    __('Most likely, malicious code on the site is hiding them.', 'fyzi-guard'),
                ), 'critical');
            }
        } else {
            FYZI_Guard_Settings::set_state('hidden_sig', '');
        }

        self::check_app_passwords($db);
        FYZI_Guard_Settings::set_state('last_admin_check', time());
    }

    /** Application password index of administrators: user_id => [uuid, ...]. */
    public static function app_password_index() {
        if (!class_exists('WP_Application_Passwords')) {
            return array();
        }
        $index = array();
        foreach (self::admins_from_db() as $id => $row) {
            $list = WP_Application_Passwords::get_user_application_passwords($id);
            foreach ((array) $list as $item) {
                if (!empty($item['uuid'])) {
                    $index[$id][] = $item['uuid'];
                }
            }
        }
        return $index;
    }

    private static function check_app_passwords(array $db) {
        if (!class_exists('WP_Application_Passwords')) {
            return;
        }
        $old = FYZI_Guard_Settings::state('app_passwords', array());
        $old = is_array($old) ? $old : array();
        $now = self::app_password_index();
        foreach ($now as $id => $uuids) {
            $prev = isset($old[$id]) ? (array) $old[$id] : array();
            $new = array_diff($uuids, $prev);
            if ($new && isset($db[$id])) {
                FYZI_Guard_Notifier::alert(__('An application password was created for an administrator', 'fyzi-guard'), array(
                    /* translators: %s: user login */
                    sprintf(__('User: %s', 'fyzi-guard'), $db[$id]['user_login']),
                    __('An application password gives API access to the site and is not revoked when the regular password changes.', 'fyzi-guard'),
                    __('If you did not create it, delete it in the user profile.', 'fyzi-guard'),
                ), 'warning');
            }
        }
        FYZI_Guard_Settings::set_state('app_passwords', $now);
    }
}
