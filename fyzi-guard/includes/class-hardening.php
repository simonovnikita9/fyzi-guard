<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Closes popular channels of mass attacks on WordPress.
 */
class FYZI_Guard_Hardening {
    const MARKER = 'FYZI Guard';

    public static function init() {
        $s = FYZI_Guard_Settings::all();

        if ($s['block_rest_batch'] || $s['block_user_enum']) {
            add_filter('rest_pre_dispatch', array(__CLASS__, 'rest_guard'), 1, 3);
        }
        if ($s['block_user_enum']) {
            add_action('template_redirect', array(__CLASS__, 'block_author_enum'), 1);
            // Do not expose logins in the WordPress sitemap.
            add_filter('wp_sitemaps_add_provider', array(__CLASS__, 'drop_users_sitemap'), 10, 2);
        }
        if ($s['disable_xmlrpc']) {
            add_filter('xmlrpc_enabled', '__return_false');
            add_filter('xmlrpc_methods', '__return_empty_array', 999);
            add_filter('wp_headers', array(__CLASS__, 'drop_pingback_header'));
            remove_action('wp_head', 'rsd_link');
        }
        if ($s['disable_file_edit'] && !defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }
        if ($s['disable_app_passwords']) {
            add_filter('wp_is_application_passwords_available', '__return_false');
        }
        if ($s['hide_version']) {
            remove_action('wp_head', 'wp_generator');
            add_filter('the_generator', '__return_empty_string');
        }
    }

    /**
     * The /batch/v1 endpoint runs chains of sub-requests. Bots abuse it en masse
     * to create administrators, so it is closed for visitors who are not logged in.
     */
    public static function rest_guard($result, $server, $request) {
        if ($result !== null) {
            return $result;
        }
        $route = '/' . ltrim((string) $request->get_route(), '/');
        $s = FYZI_Guard_Settings::all();

        if ($s['block_rest_batch'] && strpos($route, '/batch/') === 0 && !is_user_logged_in()) {
            FYZI_Guard_Log::add('warning', __('Blocked an unauthenticated REST batch request', 'fyzi-guard'), array(
                'ip' => FYZI_Guard_Login_Guard::client_ip(),
            ));
            return new WP_Error('fyzi_guard_blocked', __('Request blocked by FYZI Guard.', 'fyzi-guard'), array('status' => 403));
        }

        if ($s['block_user_enum'] && preg_match('#^/wp/v2/users(/|$)#', $route) && !current_user_can('list_users')) {
            // A logged-in user may still read their own profile (/users/me).
            if (is_user_logged_in() && preg_match('#^/wp/v2/users/me/?$#', $route)) {
                return $result;
            }
            return new WP_Error('fyzi_guard_blocked', __('The user list is not available.', 'fyzi-guard'), array('status' => 401));
        }
        return $result;
    }

    public static function block_author_enum() {
        if (is_user_logged_in()) {
            return;
        }
        if (isset($_GET['author']) && !is_admin()) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            wp_safe_redirect(home_url('/'), 301);
            exit;
        }
    }

    public static function drop_users_sitemap($provider, $name) {
        return $name === 'users' ? false : $provider;
    }

    public static function drop_pingback_header($headers) {
        unset($headers['X-Pingback']);
        return $headers;
    }

    // ---------- No PHP execution in the uploads folder ----------

    public static function uploads_dir() {
        $u = wp_upload_dir(null, false);
        return isset($u['basedir']) ? $u['basedir'] : WP_CONTENT_DIR . '/uploads';
    }

    public static function is_apache() {
        $sw = isset($_SERVER['SERVER_SOFTWARE']) ? strtolower(sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE']))) : '';
        return strpos($sw, 'apache') !== false || strpos($sw, 'litespeed') !== false || function_exists('apache_get_modules');
    }

    public static function uploads_rules() {
        return array(
            '<FilesMatch "\.(php[0-9]?|phtml|phar|pht|phps)$">',
            '  <IfModule mod_authz_core.c>',
            '    Require all denied',
            '  </IfModule>',
            '  <IfModule !mod_authz_core.c>',
            '    Order allow,deny',
            '    Deny from all',
            '  </IfModule>',
            '</FilesMatch>',
        );
    }

    public static function nginx_rule() {
        $rel = str_replace(wp_normalize_path(untrailingslashit(ABSPATH)), '', wp_normalize_path(self::uploads_dir()));
        return "location ~* ^" . $rel . "/.*\\.(php[0-9]?|phtml|phar)$ {\n    deny all;\n}";
    }

    private static function load_misc() {
        if (!function_exists('insert_with_markers')) {
            require_once ABSPATH . 'wp-admin/includes/misc.php';
        }
    }

    public static function uploads_protected() {
        self::load_misc();
        $file = self::uploads_dir() . '/.htaccess';
        if (!is_readable($file)) {
            return false;
        }
        return strpos(implode("\n", extract_from_markers($file, self::MARKER)), 'FilesMatch') !== false;
    }

    /** Adds the rule to uploads/.htaccess while keeping the existing content. */
    public static function protect_uploads() {
        self::load_misc();
        $dir = self::uploads_dir();
        if (!wp_is_writable($dir)) {
            return new WP_Error('fyzi_guard_fs', __('The uploads folder is not writable.', 'fyzi-guard'));
        }
        if (!insert_with_markers($dir . '/.htaccess', self::MARKER, self::uploads_rules())) {
            return new WP_Error('fyzi_guard_fs', __('Could not write .htaccess to the uploads folder.', 'fyzi-guard'));
        }
        FYZI_Guard_Log::add('info', __('PHP execution in the uploads folder is now blocked.', 'fyzi-guard'));
        return true;
    }

    public static function unprotect_uploads() {
        self::load_misc();
        $file = self::uploads_dir() . '/.htaccess';
        if (!is_readable($file) || !wp_is_writable($file)) {
            return;
        }
        insert_with_markers($file, self::MARKER, array());
        FYZI_Guard_Log::add('info', __('The rule blocking PHP in the uploads folder was removed.', 'fyzi-guard'));
    }
}
