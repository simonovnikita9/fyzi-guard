<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * FYZI Guard page in the WordPress admin.
 */
class FYZI_Guard_Admin {
    const SLUG = 'fyzi-guard';
    const PRO_URL = 'https://fyzi.ru/?utm_source=fyzi-guard&utm_medium=plugin&utm_campaign=pro#pricing';
    const HELP_URL = 'https://fyzi.ru/?utm_source=fyzi-guard&utm_medium=plugin&utm_campaign=infected#start';
    const SITE_URL = 'https://fyzi.ru/?utm_source=fyzi-guard&utm_medium=plugin';

    public static function init() {
        add_action('admin_menu', array(__CLASS__, 'menu'));
        add_action('admin_enqueue_scripts', array(__CLASS__, 'assets'));
        foreach (array('scan', 'save', 'uploads', 'approve', 'ignore', 'test', 'clear_log', 'baseline') as $a) {
            add_action('admin_post_fyzi_guard_' . $a, array(__CLASS__, 'action_' . $a));
        }
        add_filter('plugin_action_links_' . plugin_basename(FYZI_GUARD_FILE), array(__CLASS__, 'action_links'));
    }

    public static function menu() {
        $c = FYZI_Guard_Scanner::counts();
        $badge = $c['critical'] ? ' <span class="awaiting-mod">' . (int) $c['critical'] . '</span>' : '';
        add_menu_page('FYZI Guard', 'FYZI Guard' . $badge, 'manage_options', self::SLUG, array(__CLASS__, 'page'), 'dashicons-shield', 80);
    }

    public static function assets($hook) {
        if (strpos((string) $hook, self::SLUG) === false) {
            return;
        }
        wp_enqueue_style('fyzi-guard', FYZI_GUARD_URL . 'assets/admin.css', array(), FYZI_GUARD_VERSION);
    }

    public static function action_links($links) {
        array_unshift($links, '<a href="' . esc_url(admin_url('admin.php?page=' . self::SLUG)) . '">' . esc_html__('Dashboard', 'fyzi-guard') . '</a>');
        $links[] = '<a href="' . esc_url(self::PRO_URL) . '" target="_blank" rel="noopener" style="color:#00a36c;font-weight:600">Pro</a>';
        return $links;
    }

    // ---------- Actions ----------

    private static function require_cap() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to do this.', 'fyzi-guard'));
        }
    }

    private static function back($tab = 'overview', $msg = '') {
        $url = add_query_arg(array('page' => self::SLUG, 'tab' => $tab, 'fg_msg' => $msg), admin_url('admin.php'));
        wp_safe_redirect($url);
        exit;
    }

    public static function action_scan() {
        self::require_cap();
        check_admin_referer('fyzi_guard_scan');
        FYZI_Guard_Watchdog::check();
        FYZI_Guard_Scanner::run();
        self::back('overview', 'scan');
    }

    public static function action_save() {
        self::require_cap();
        check_admin_referer('fyzi_guard_save');
        // Values are sanitized field by field in FYZI_Guard_Settings::save().
        $input = isset($_POST['fg']) && is_array($_POST['fg']) ? wp_unslash($_POST['fg']) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $section = isset($_POST['section']) ? sanitize_key(wp_unslash($_POST['section'])) : '';
        $current = FYZI_Guard_Settings::all();
        $defaults = FYZI_Guard_Settings::defaults();
        // Only the fields of the current tab are saved; the rest stay as they were.
        $fields = $section === 'notify'
            ? array('notify_email', 'email_to', 'notify_telegram', 'tg_token', 'tg_chat_id')
            : array('block_rest_batch', 'block_user_enum', 'disable_xmlrpc', 'disable_file_edit', 'disable_app_passwords', 'hide_version', 'limit_login', 'login_max_attempts', 'login_lockout_minutes', 'trust_proxy_ip', 'scan_core', 'scan_uploads', 'scan_changes');
        foreach ($fields as $f) {
            $current[$f] = isset($input[$f]) ? $input[$f] : (is_int($defaults[$f]) ? 0 : '');
        }
        FYZI_Guard_Settings::save($current);
        self::back($section === 'notify' ? 'notify' : 'protect', 'saved');
    }

    public static function action_uploads() {
        self::require_cap();
        check_admin_referer('fyzi_guard_uploads');
        $mode = isset($_POST['mode']) ? sanitize_key(wp_unslash($_POST['mode'])) : 'on';
        if ($mode === 'off') {
            FYZI_Guard_Hardening::unprotect_uploads();
            self::back('protect', 'uploads_off');
        }
        $r = FYZI_Guard_Hardening::protect_uploads();
        self::back('protect', is_wp_error($r) ? 'uploads_err' : 'uploads_on');
    }

    public static function action_approve() {
        self::require_cap();
        check_admin_referer('fyzi_guard_approve');
        $id = isset($_POST['user_id']) ? absint($_POST['user_id']) : 0;
        if ($id) {
            FYZI_Guard_Watchdog::approve($id);
        }
        self::back('overview', 'approved');
    }

    public static function action_baseline() {
        self::require_cap();
        check_admin_referer('fyzi_guard_baseline');
        FYZI_Guard_Watchdog::baseline();
        FYZI_Guard_Log::add('info', __('All current administrators marked as known.', 'fyzi-guard'));
        self::back('overview', 'approved');
    }

    public static function action_ignore() {
        self::require_cap();
        check_admin_referer('fyzi_guard_ignore');
        $id = isset($_POST['finding']) ? sanitize_key(wp_unslash($_POST['finding'])) : '';
        if ($id) {
            $ignored = FYZI_Guard_Settings::state('ignored', array());
            $ignored = is_array($ignored) ? $ignored : array();
            $ignored[] = $id;
            FYZI_Guard_Settings::set_state('ignored', array_values(array_unique($ignored)));
            $findings = array_values(array_filter((array) FYZI_Guard_Settings::state('findings', array()), function ($f) use ($id) {
                return $f['id'] !== $id;
            }));
            FYZI_Guard_Settings::set_state('findings', $findings);
        }
        self::back('overview', 'ignored');
    }

    public static function action_test() {
        self::require_cap();
        check_admin_referer('fyzi_guard_test');
        $ok = FYZI_Guard_Notifier::alert(
            __('Test notification', 'fyzi-guard'),
            array(__('If you see this message, FYZI Guard notifications are set up correctly.', 'fyzi-guard')),
            'warning'
        );
        self::back('notify', $ok ? 'test_ok' : 'test_fail');
    }

    public static function action_clear_log() {
        self::require_cap();
        check_admin_referer('fyzi_guard_clear_log');
        FYZI_Guard_Log::clear();
        self::back('log', 'cleared');
    }

    // ---------- Output ----------

    private static function form_open($action, $class = '') {
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" class="' . esc_attr($class) . '">';
        echo '<input type="hidden" name="action" value="' . esc_attr('fyzi_guard_' . $action) . '">';
        wp_nonce_field('fyzi_guard_' . $action);
    }

    private static function tab_url($tab) {
        return add_query_arg(array('page' => self::SLUG, 'tab' => $tab), admin_url('admin.php'));
    }

    private static function messages() {
        $map = array(
            'scan'        => array('success', __('Check finished.', 'fyzi-guard')),
            'saved'       => array('success', __('Settings saved.', 'fyzi-guard')),
            'uploads_on'  => array('success', __('PHP execution in the uploads folder is now blocked.', 'fyzi-guard')),
            'uploads_off' => array('warning', __('The rule blocking PHP in the uploads folder was removed.', 'fyzi-guard')),
            'uploads_err' => array('error', __('Could not write .htaccess to the uploads folder: it is not writable.', 'fyzi-guard')),
            'approved'    => array('success', __('Administrator marked as known.', 'fyzi-guard')),
            'ignored'     => array('success', __('Finding hidden.', 'fyzi-guard')),
            'test_ok'     => array('success', __('Test notification sent.', 'fyzi-guard')),
            'test_fail'   => array('error', __('Could not send the notification. Check the settings and the log.', 'fyzi-guard')),
            'cleared'     => array('success', __('Log cleared.', 'fyzi-guard')),
        );
        $m = isset($_GET['fg_msg']) ? sanitize_key(wp_unslash($_GET['fg_msg'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        if (isset($map[$m])) {
            printf('<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr($map[$m][0]), esc_html($map[$m][1]));
        }
    }

    public static function page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        $tab = isset($_GET['tab']) ? sanitize_key(wp_unslash($_GET['tab'])) : 'overview'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $tabs = array(
            'overview' => __('Overview', 'fyzi-guard'),
            'protect'  => __('Protection', 'fyzi-guard'),
            'notify'   => __('Notifications', 'fyzi-guard'),
            'log'      => __('Log', 'fyzi-guard'),
            'pro'      => 'Pro',
        );
        echo '<div class="wrap fg">';
        echo '<div class="fg-head"><div class="fg-logo">';
        self::shield_svg();
        echo '<div><h1>FYZI Guard</h1><p>' . esc_html__('Made in Russia: protection of WordPress against mass hacking', 'fyzi-guard') . '</p></div></div>';
        echo '<span class="fg-ver">v' . esc_html(FYZI_GUARD_VERSION) . '</span></div>';
        self::messages();
        echo '<nav class="nav-tab-wrapper fg-tabs">';
        foreach ($tabs as $k => $label) {
            printf(
                '<a href="%s" class="nav-tab%s%s">%s</a>',
                esc_url(self::tab_url($k)),
                $tab === $k ? ' nav-tab-active' : '',
                $k === 'pro' ? ' fg-tab-pro' : '',
                esc_html($label)
            );
        }
        echo '</nav>';

        switch ($tab) {
            case 'protect':
                self::tab_protect();
                break;
            case 'notify':
                self::tab_notify();
                break;
            case 'log':
                self::tab_log();
                break;
            case 'pro':
                self::tab_pro();
                break;
            default:
                self::tab_overview();
        }
        echo '<p class="fg-foot">' . esc_html__('FYZI Guard is developed in Russia by specialists who clean hacked websites every day.', 'fyzi-guard') . ' <a href="' . esc_url(self::SITE_URL) . '" target="_blank" rel="noopener">fyzi.ru</a></p>';
        echo '</div>';
    }

    private static function tab_overview() {
        $c = FYZI_Guard_Scanner::counts();
        $last = (int) FYZI_Guard_Settings::state('last_scan', 0);
        if ($c['critical']) {
            $state = array('bad', __('Signs of infection found', 'fyzi-guard'), __('See the findings below. If you are not sure what to do, FYZI Shield specialists will help clean the site.', 'fyzi-guard'));
        } elseif ($c['warning']) {
            $state = array('warn', __('There are weak spots', 'fyzi-guard'), __('No serious threats found, but some things are worth fixing.', 'fyzi-guard'));
        } elseif ($last) {
            $state = array('ok', __('The site is protected', 'fyzi-guard'), __('The last check found no problems.', 'fyzi-guard'));
        } else {
            $state = array('warn', __('The first check has not run yet', 'fyzi-guard'), __('Run it now, it takes up to a minute.', 'fyzi-guard'));
        }

        echo '<div class="fg-grid">';
        echo '<div class="fg-card fg-status fg-' . esc_attr($state[0]) . '"><h2>' . esc_html($state[1]) . '</h2><p>' . esc_html($state[2]) . '</p>';
        /* translators: %s: date and time of the last check */
        echo '<p class="fg-muted">' . esc_html(sprintf(__('Last check: %s', 'fyzi-guard'), $last ? wp_date('d.m.Y H:i', $last) : __('never', 'fyzi-guard'))) . '</p>';
        self::form_open('scan');
        submit_button(__('Check now', 'fyzi-guard'), 'primary large', 'submit', false);
        echo '</form></div>';

        echo '<div class="fg-card"><h3>' . esc_html__('Protection', 'fyzi-guard') . '</h3><ul class="fg-checks">';
        $s = FYZI_Guard_Settings::all();
        $checks = array(
            array($s['block_rest_batch'], __('REST batch requests closed for visitors', 'fyzi-guard')),
            array($s['block_user_enum'], __('User logins hidden', 'fyzi-guard')),
            array($s['disable_xmlrpc'], __('XML-RPC disabled', 'fyzi-guard')),
            array($s['disable_file_edit'] || (defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT), __('File editor in the admin disabled', 'fyzi-guard')),
            array($s['limit_login'], __('Login attempts limited', 'fyzi-guard')),
            array(FYZI_Guard_Hardening::uploads_protected(), __('PHP blocked in the uploads folder', 'fyzi-guard')),
        );
        foreach ($checks as $ch) {
            echo '<li class="' . ($ch[0] ? 'on' : 'off') . '">' . esc_html($ch[1]) . '</li>';
        }
        echo '</ul><a href="' . esc_url(self::tab_url('protect')) . '">' . esc_html__('Configure protection →', 'fyzi-guard') . '</a></div>';
        echo '</div>';

        // Administrators
        $db = FYZI_Guard_Watchdog::admins_from_db();
        $visible = FYZI_Guard_Watchdog::admins_visible();
        $known = FYZI_Guard_Watchdog::known();
        echo '<div class="fg-card"><h3>' . esc_html__('Site administrators', 'fyzi-guard') . '</h3><p class="fg-muted">' . esc_html__('The list is read directly from the database, so hidden administrators are visible here too.', 'fyzi-guard') . '</p>';
        echo '<table class="widefat striped fg-table"><thead><tr><th>' . esc_html__('Login', 'fyzi-guard') . '</th><th>E-mail</th><th>' . esc_html__('Created', 'fyzi-guard') . '</th><th>' . esc_html__('Status', 'fyzi-guard') . '</th><th></th></tr></thead><tbody>';
        foreach ($db as $id => $row) {
            $is_known = in_array($id, $known, true);
            $is_hidden = !in_array($id, $visible, true);
            if ($is_hidden) {
                $status = '<span class="fg-tag bad">' . esc_html__('Hidden from the list!', 'fyzi-guard') . '</span>';
            } elseif ($is_known) {
                $status = '<span class="fg-tag ok">' . esc_html__('Known', 'fyzi-guard') . '</span>';
            } else {
                $status = '<span class="fg-tag warn">' . esc_html__('Unknown', 'fyzi-guard') . '</span>';
            }
            echo '<tr><td><strong>' . esc_html($row['user_login']) . '</strong></td><td>' . esc_html($row['user_email']) . '</td><td>' . esc_html($row['user_registered']) . '</td><td>' . $status . '</td><td>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $status is built from escaped parts above.
            if (!$is_known) {
                self::form_open('approve', 'fg-inline');
                echo '<input type="hidden" name="user_id" value="' . (int) $id . '"><button class="button">' . esc_html__('This is my administrator', 'fyzi-guard') . '</button></form> ';
                echo '<a class="button-link-delete" href="' . esc_url(admin_url('users.php?s=' . rawurlencode($row['user_login']))) . '">' . esc_html__('Find and delete', 'fyzi-guard') . '</a>';
            }
            echo '</td></tr>';
        }
        echo '</tbody></table></div>';

        // Findings
        $findings = (array) FYZI_Guard_Settings::state('findings', array());
        $order = array('critical' => 0, 'warning' => 1, 'info' => 2);
        usort($findings, function ($a, $b) use ($order) {
            return $order[$a['severity']] - $order[$b['severity']];
        });
        echo '<div class="fg-card"><h3>' . esc_html__('Check results', 'fyzi-guard') . '</h3>';
        if (!$findings) {
            echo '<p class="fg-muted">' . esc_html($last ? __('No problems found.', 'fyzi-guard') : __('The check has not run yet.', 'fyzi-guard')) . '</p>';
        } else {
            $labels = array(
                'critical' => __('Threat', 'fyzi-guard'),
                'warning'  => __('Attention', 'fyzi-guard'),
                'info'     => __('Info', 'fyzi-guard'),
            );
            echo '<table class="widefat fg-table"><tbody>';
            foreach (array_slice($findings, 0, 300) as $f) {
                $cls = $f['severity'] === 'critical' ? 'bad' : ($f['severity'] === 'warning' ? 'warn' : 'info');
                echo '<tr class="fg-row-' . esc_attr($f['severity']) . '"><td class="fg-sev"><span class="fg-tag ' . esc_attr($cls) . '">' . esc_html($labels[$f['severity']]) . '</span></td>';
                echo '<td><strong>' . esc_html($f['title']) . '</strong>';
                if ($f['path']) {
                    echo '<br><code>' . esc_html($f['path']) . '</code>';
                }
                if ($f['detail']) {
                    echo '<br><span class="fg-muted">' . esc_html($f['detail']) . '</span>';
                }
                echo '</td><td class="fg-act">';
                self::form_open('ignore', 'fg-inline');
                echo '<input type="hidden" name="finding" value="' . esc_attr($f['id']) . '"><button class="button-link">' . esc_html__('Hide', 'fyzi-guard') . '</button></form></td></tr>';
            }
            echo '</tbody></table>';
        }
        if ($findings && $c['critical']) {
            echo '<div class="fg-help"><span><strong>' . esc_html__('Is the site infected?', 'fyzi-guard') . '</strong> ' . esc_html__('FYZI Shield specialists will find and remove the malicious code, close the vulnerability and get search engine warnings removed.', 'fyzi-guard') . '</span> <a class="button button-primary" target="_blank" rel="noopener" href="' . esc_url(self::HELP_URL) . '">' . esc_html__('Clean the site', 'fyzi-guard') . '</a></div>';
        }
        echo '</div>';

        self::pro_promo();
    }

    private static function toggle($key, $label, $hint = '') {
        $s = FYZI_Guard_Settings::all();
        echo '<label class="fg-toggle"><input type="checkbox" name="fg[' . esc_attr($key) . ']" value="1" ' . checked(!empty($s[$key]), true, false) . '> <span><strong>' . esc_html($label) . '</strong>';
        if ($hint) {
            echo '<em>' . esc_html($hint) . '</em>';
        }
        echo '</span></label>';
    }

    private static function tab_protect() {
        $s = FYZI_Guard_Settings::all();
        echo '<div class="fg-card">';
        self::form_open('save');
        echo '<input type="hidden" name="section" value="protect">';
        echo '<h3>' . esc_html__('Closing attack channels', 'fyzi-guard') . '</h3>';
        self::toggle('block_rest_batch', __('Close REST batch requests for visitors', 'fyzi-guard'), __('Bots massively create fake administrators through /wp-json/batch/v1. Site editors are not affected.', 'fyzi-guard'));
        self::toggle('block_user_enum', __('Hide user logins', 'fyzi-guard'), __('Closes /wp-json/wp/v2/users and ?author= for visitors, so bots cannot learn logins for password guessing.', 'fyzi-guard'));
        self::toggle('disable_xmlrpc', __('Disable XML-RPC', 'fyzi-guard'), __('Needed only by old mobile apps and some integrations. The main channel for password brute force.', 'fyzi-guard'));
        self::toggle('disable_file_edit', __('Disable the file editor in the admin', 'fyzi-guard'), __('Even with a stolen password, nobody can inject code into a theme or plugin from the admin.', 'fyzi-guard'));
        self::toggle('disable_app_passwords', __('Disable application passwords', 'fyzi-guard'), __('Turn on if you do not use REST API integrations (WordPress mobile app, external services).', 'fyzi-guard'));
        self::toggle('hide_version', __('Hide the WordPress version in page code', 'fyzi-guard'));

        echo '<h3>' . esc_html__('Admin login', 'fyzi-guard') . '</h3>';
        self::toggle('limit_login', __('Limit login attempts', 'fyzi-guard'));
        echo '<p class="fg-row"><label>' . esc_html__('Attempts before lock', 'fyzi-guard') . ' <input type="number" min="3" max="20" name="fg[login_max_attempts]" value="' . (int) $s['login_max_attempts'] . '"></label> ';
        echo '<label>' . esc_html__('Lock duration, minutes', 'fyzi-guard') . ' <input type="number" min="5" max="1440" name="fg[login_lockout_minutes]" value="' . (int) $s['login_lockout_minutes'] . '"></label></p>';
        self::toggle('trust_proxy_ip', __('The site is behind a proxy or CDN (use X-Forwarded-For)', 'fyzi-guard'), __('Turn on only if all visitors look like a single IP address to the site.', 'fyzi-guard'));

        echo '<h3>' . esc_html__('Daily check', 'fyzi-guard') . '</h3>';
        self::toggle('scan_core', __('Compare WordPress core with the original from wordpress.org', 'fyzi-guard'));
        self::toggle('scan_uploads', __('Look for PHP files and code in the uploads folder', 'fyzi-guard'));
        self::toggle('scan_changes', __('Watch for new and modified PHP files in plugins and themes', 'fyzi-guard'));
        submit_button(__('Save', 'fyzi-guard'));
        echo '</form></div>';

        echo '<div class="fg-card"><h3>' . esc_html__('Block PHP in the uploads folder', 'fyzi-guard') . '</h3>';
        echo '<p>' . esc_html__('One of the strongest measures: even if a web shell is uploaded through a vulnerability, the server will not execute it.', 'fyzi-guard') . '</p>';
        if (FYZI_Guard_Hardening::is_apache()) {
            if (FYZI_Guard_Hardening::uploads_protected()) {
                echo '<p><span class="fg-tag ok">' . esc_html__('Enabled', 'fyzi-guard') . '</span></p>';
                self::form_open('uploads', 'fg-inline');
                echo '<input type="hidden" name="mode" value="off"><button class="button">' . esc_html__('Remove the block', 'fyzi-guard') . '</button></form>';
            } else {
                self::form_open('uploads', 'fg-inline');
                echo '<input type="hidden" name="mode" value="on"><button class="button button-primary">' . esc_html__('Block PHP in uploads', 'fyzi-guard') . '</button></form>';
            }
        } else {
            echo '<p>' . esc_html__('The site seems to run on nginx without Apache. Ask your hosting to add this rule to the site configuration:', 'fyzi-guard') . '</p><pre>' . esc_html(FYZI_Guard_Hardening::nginx_rule()) . '</pre>';
            echo '<p class="fg-muted">' . esc_html__('If you actually use Apache, you can enable the block with the button:', 'fyzi-guard') . '</p>';
            self::form_open('uploads', 'fg-inline');
            echo '<input type="hidden" name="mode" value="on"><button class="button">' . esc_html__('Write .htaccess', 'fyzi-guard') . '</button></form>';
        }
        echo '</div>';
    }

    private static function tab_notify() {
        $s = FYZI_Guard_Settings::all();
        echo '<div class="fg-card">';
        self::form_open('save');
        echo '<input type="hidden" name="section" value="notify">';
        echo '<h3>' . esc_html__('E-mail', 'fyzi-guard') . '</h3>';
        self::toggle('notify_email', __('Send alerts by e-mail', 'fyzi-guard'));
        echo '<p class="fg-row"><label>' . esc_html__('Address', 'fyzi-guard') . ' <input type="email" class="regular-text" name="fg[email_to]" value="' . esc_attr($s['email_to']) . '" placeholder="' . esc_attr(get_option('admin_email')) . '"></label></p>';

        echo '<h3>Telegram</h3>';
        self::toggle('notify_telegram', __('Send alerts to Telegram', 'fyzi-guard'));
        echo '<ol class="fg-steps">';
        /* translators: %s: link to @BotFather */
        echo '<li>' . sprintf(esc_html__('Open %s, send /newbot and copy the token.', 'fyzi-guard'), '<a href="https://t.me/BotFather" target="_blank" rel="noopener">@BotFather</a>') . '</li>';
        echo '<li>' . esc_html__('Send any message to your new bot.', 'fyzi-guard') . '</li>';
        /* translators: %s: link to @userinfobot */
        echo '<li>' . sprintf(esc_html__('Open %s, it will show your ID. Paste it below.', 'fyzi-guard'), '<a href="https://t.me/userinfobot" target="_blank" rel="noopener">@userinfobot</a>') . '</li>';
        echo '</ol>';
        echo '<p class="fg-row"><label>' . esc_html__('Bot token', 'fyzi-guard') . ' <input type="text" class="regular-text" name="fg[tg_token]" value="' . esc_attr($s['tg_token']) . '" autocomplete="off"></label></p>';
        echo '<p class="fg-row"><label>' . esc_html__('Chat ID', 'fyzi-guard') . ' <input type="text" name="fg[tg_chat_id]" value="' . esc_attr($s['tg_chat_id']) . '"></label></p>';
        submit_button(__('Save', 'fyzi-guard'));
        echo '</form>';
        self::form_open('test', 'fg-inline');
        submit_button(__('Send a test notification', 'fyzi-guard'), 'secondary', 'submit', false);
        echo '</form></div>';
    }

    private static function tab_log() {
        $log = FYZI_Guard_Log::all();
        echo '<div class="fg-card"><h3>' . esc_html__('Event log', 'fyzi-guard') . '</h3>';
        if (!$log) {
            echo '<p class="fg-muted">' . esc_html__('No events yet.', 'fyzi-guard') . '</p>';
        } else {
            echo '<table class="widefat striped fg-table"><thead><tr><th>' . esc_html__('Time', 'fyzi-guard') . '</th><th>' . esc_html__('Event', 'fyzi-guard') . '</th><th>' . esc_html__('Details', 'fyzi-guard') . '</th></tr></thead><tbody>';
            foreach ($log as $e) {
                $details = array();
                foreach ((array) $e['context'] as $k => $v) {
                    $details[] = is_array($v) ? implode('; ', array_map('strval', $v)) : $k . ': ' . $v;
                }
                $cls = $e['level'] === 'critical' ? 'bad' : ($e['level'] === 'warning' ? 'warn' : 'info');
                echo '<tr><td>' . esc_html(wp_date('d.m.Y H:i', (int) $e['time'])) . '</td><td><span class="fg-tag ' . esc_attr($cls) . '">' . esc_html($e['message']) . '</span></td><td class="fg-muted">' . esc_html(implode(' · ', $details)) . '</td></tr>';
            }
            echo '</tbody></table>';
            self::form_open('clear_log', 'fg-inline');
            submit_button(__('Clear the log', 'fyzi-guard'), 'secondary', 'submit', false);
            echo '</form>';
        }
        echo '</div>';
    }

    private static function pro_promo() {
        echo '<div class="fg-card fg-pro-promo"><div><h3>FYZI Shield Pro</h3><p>' . esc_html__('The plugin protects the site from the inside. Pro watches it from the outside and brings in a specialist when something happens: uptime and Yandex/Google blacklist monitoring, infection cleanup, the “Clean site” guarantee.', 'fyzi-guard') . '</p></div>';
        echo '<a class="button button-primary button-hero" target="_blank" rel="noopener" href="' . esc_url(self::PRO_URL) . '">' . esc_html__('Learn about Pro', 'fyzi-guard') . '</a></div>';
    }

    private static function tab_pro() {
        $free = array(
            __('Closing channels of mass attacks', 'fyzi-guard'),
            __('Login attempt limiting', 'fyzi-guard'),
            __('Administrator watchdog, including hidden ones', 'fyzi-guard'),
            __('Daily comparison of core files with wordpress.org', 'fyzi-guard'),
            __('Search for web shells and malicious code', 'fyzi-guard'),
            __('Alerts by e-mail and to your own Telegram', 'fyzi-guard'),
        );
        $pro = array(
            __('24/7 external monitoring: uptime, SSL, redirects for mobile visitors', 'fyzi-guard'),
            __('Tracking of “dangerous site” warnings in Yandex and Google', 'fyzi-guard'),
            __('Infection cleanup by a specialist, not just a notification', 'fyzi-guard'),
            __('Removal of malicious code from the database', 'fyzi-guard'),
            __('Daily backups to external storage', 'fyzi-guard'),
            __('The “Clean site” guarantee and priority support in Telegram', 'fyzi-guard'),
            __('White-label reports for web studio clients', 'fyzi-guard'),
        );
        echo '<div class="fg-grid fg-plans"><div class="fg-card"><h3>FYZI Guard</h3><p class="fg-price">' . esc_html__('Free', 'fyzi-guard') . '</p><ul class="fg-checks">';
        foreach ($free as $f) {
            echo '<li class="on">' . esc_html($f) . '</li>';
        }
        echo '</ul><p class="fg-muted">' . esc_html__('Already working on your site.', 'fyzi-guard') . '</p></div>';
        echo '<div class="fg-card fg-pro"><h3>FYZI Shield Pro</h3><p class="fg-price">' . esc_html__('from 490 ₽ / month', 'fyzi-guard') . '</p><ul class="fg-checks"><li class="on">' . esc_html__('Everything in the free version', 'fyzi-guard') . '</li>';
        foreach ($pro as $f) {
            echo '<li class="on">' . esc_html($f) . '</li>';
        }
        echo '</ul><a class="button button-primary button-hero" target="_blank" rel="noopener" href="' . esc_url(self::PRO_URL) . '">' . esc_html__('Get Pro', 'fyzi-guard') . '</a>';
        echo '<p class="fg-muted">' . esc_html__('A Russian service: payment in rubles, support in Russian.', 'fyzi-guard') . '</p></div></div>';
    }

    private static function shield_svg() {
        echo '<svg viewBox="0 0 32 32" width="44" height="44" aria-hidden="true"><defs><linearGradient id="fgg" x1="4" y1="2" x2="28" y2="30"><stop stop-color="#38f5a0"/><stop offset="1" stop-color="#2dd4ff"/></linearGradient></defs><path d="M16 2l12 5v8c0 7.5-5.1 13.4-12 15-6.9-1.6-12-7.5-12-15V7l12-5z" fill="url(#fgg)"/><path d="M11 16.5l3.5 3.5 7-7.5" fill="none" stroke="#04120b" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    }
}
