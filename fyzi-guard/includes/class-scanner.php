<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Daily site check: core files against the wordpress.org reference, PHP in uploads,
 * new and modified PHP files, typical malicious constructs, outdated components.
 */
class FYZI_Guard_Scanner {
    const MAX_FILES = 40000;
    const MAX_READ = 2097152; // 2 MB per file

    public static function init() {
        add_action('admin_notices', array(__CLASS__, 'admin_notice'));
    }

    /** Malware signatures: [regex, description]. */
    public static function signatures() {
        return array(
            array('/eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|gzdecode|strrev)\s*\(/i', __('eval() that decodes hidden code', 'fyzi-guard')),
            array('/(eval|assert)\s*\(\s*(stripslashes\s*\(\s*)?\$_(POST|GET|REQUEST|COOKIE|SERVER)/i', __('executes code from request parameters (web shell)', 'fyzi-guard')),
            array('/(system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i', __('runs server commands from the request (web shell)', 'fyzi-guard')),
            array('/preg_replace\s*\(\s*[\'"](.).*\1[a-z]*e[a-z]*[\'"]\s*,/i', __('preg_replace with the /e modifier', 'fyzi-guard')),
            array('/\$\w+\s*=\s*[\'"](as|ba|ev|sy|cr)[\'"]\s*\.\s*[\'"]/i', __('dangerous function name assembled from string pieces', 'fyzi-guard')),
            array('/(include|require)(_once)?\s*\(?\s*[\'"][^\'"]+\.(ico|jpg|jpeg|png|gif|txt|css)[\'"]/i', __('includes PHP code from an image or text file', 'fyzi-guard')),
            array('/move_uploaded_file\s*\(\s*\$_FILES\[[^\]]+\]\[[\'"]tmp_name[\'"]\]\s*,\s*\$_(POST|GET|REQUEST)/i', __('file uploader driven by the request', 'fyzi-guard')),
            array('/wp_(create|insert)_user\s*\([^;]*administrator/i', __('creates an administrator in code', 'fyzi-guard')),
            array('/\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}\\\\x[0-9a-f]{2}/i', __('long hex-encoded string (obfuscation)', 'fyzi-guard')),
            array('/hacked\s+by|wp2shell/i', __('attacker signature', 'fyzi-guard')),
        );
    }

    public static function run() {
        $s = FYZI_Guard_Settings::all();
        $findings = array();

        if ($s['scan_core']) {
            $findings = array_merge($findings, self::scan_core());
        }
        if ($s['scan_uploads']) {
            $findings = array_merge($findings, self::scan_uploads());
        }
        if ($s['scan_changes']) {
            $findings = array_merge($findings, self::scan_changes());
        }
        $findings = array_merge($findings, self::scan_hygiene());

        // Findings hidden by the user.
        $ignored = FYZI_Guard_Settings::state('ignored', array());
        $ignored = is_array($ignored) ? $ignored : array();
        $findings = array_values(array_filter($findings, function ($f) use ($ignored) {
            return !in_array($f['id'], $ignored, true);
        }));

        // Alert only about new serious findings.
        $prev = FYZI_Guard_Settings::state('findings', array());
        $prev_ids = array();
        foreach ((array) $prev as $p) {
            $prev_ids[] = $p['id'];
        }
        $fresh = array();
        foreach ($findings as $f) {
            if (in_array($f['severity'], array('critical', 'warning'), true) && !in_array($f['id'], $prev_ids, true)) {
                $fresh[] = $f;
            }
        }
        if ($fresh) {
            $critical = count(array_filter($fresh, function ($f) {
                return $f['severity'] === 'critical';
            }));
            $lines = array();
            foreach (array_slice($fresh, 0, 15) as $f) {
                $lines[] = ($f['severity'] === 'critical' ? '• [!] ' : '• ') . $f['title'] . ($f['path'] ? ': ' . $f['path'] : '');
            }
            if (count($fresh) > 15) {
                /* translators: %d: number of additional findings */
                $lines[] = sprintf(__('…and %d more', 'fyzi-guard'), count($fresh) - 15);
            }
            FYZI_Guard_Notifier::alert(
                $critical ? __('Signs of infection found', 'fyzi-guard') : __('The check found problems', 'fyzi-guard'),
                $lines,
                $critical ? 'critical' : 'warning'
            );
        }

        FYZI_Guard_Settings::set_state('findings', $findings);
        FYZI_Guard_Settings::set_state('last_scan', time());
        /* translators: %d: number of findings */
        FYZI_Guard_Log::add('info', sprintf(__('Check finished: %d findings', 'fyzi-guard'), count($findings)));
        return $findings;
    }

    /**
     * @param string $code stable machine code of the finding (does not depend on the language)
     */
    private static function finding($type, $severity, $code, $title, $path = '', $detail = '') {
        return array(
            'id'       => md5($type . '|' . $code . '|' . $path),
            'type'     => $type,
            'code'     => $code,
            'severity' => $severity, // critical | warning | info
            'title'    => $title,
            'path'     => $path,
            'detail'   => $detail,
        );
    }

    private static function rel($path) {
        return ltrim(str_replace(wp_normalize_path(ABSPATH), '', wp_normalize_path($path)), '/');
    }

    // ---------- Core ----------

    public static function scan_core() {
        global $wp_version, $wp_local_package;
        if (!function_exists('get_core_checksums')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }
        $locale = isset($wp_local_package) ? $wp_local_package : 'en_US';
        $sums = get_core_checksums($wp_version, $locale);
        if (!is_array($sums) || !$sums) {
            $sums = get_core_checksums($wp_version, 'en_US');
        }
        if (!is_array($sums) || !$sums) {
            return array(self::finding('core', 'info', 'no_checksums', __('Could not get reference checksums from wordpress.org, the core check was skipped', 'fyzi-guard')));
        }

        $out = array();
        foreach ($sums as $file => $md5) {
            if (strpos($file, 'wp-content/') === 0) {
                continue;
            }
            $full = ABSPATH . $file;
            if (!file_exists($full)) {
                if (substr($file, -4) === '.php') {
                    $out[] = self::finding('core', 'info', 'core_missing', __('Core file is missing', 'fyzi-guard'), $file);
                }
                continue;
            }
            if (md5_file($full) !== $md5) {
                $out[] = self::finding('core', 'critical', 'core_modified', __('WordPress core file modified', 'fyzi-guard'), $file, __('The content differs from the original wordpress.org release of the same version.', 'fyzi-guard'));
            }
        }

        // Extra PHP files inside core are a typical place for a backdoor.
        foreach (array('wp-admin', 'wp-includes') as $dir) {
            foreach (self::list_files(ABSPATH . $dir, array('php', 'phtml', 'phar')) as $full) {
                $rel = self::rel($full);
                if (!isset($sums[$rel])) {
                    $out[] = self::finding('core', 'critical', 'core_extra', __('Unknown PHP file inside WordPress core', 'fyzi-guard'), $rel, __('This file is not part of the original release. A common hiding place for a backdoor.', 'fyzi-guard'));
                }
            }
        }
        foreach (glob(ABSPATH . '*.php') ?: array() as $full) {
            $rel = self::rel($full);
            if (!isset($sums[$rel]) && $rel !== 'wp-config.php') {
                $out[] = self::finding('core', 'warning', 'root_extra', __('Unknown PHP file in the site root', 'fyzi-guard'), $rel, __('Check whether this file is needed.', 'fyzi-guard'));
            }
        }
        return $out;
    }

    // ---------- Uploads ----------

    public static function scan_uploads() {
        $out = array();
        $dir = FYZI_Guard_Hardening::uploads_dir();
        foreach (self::list_files($dir, array('php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar', 'pht')) as $full) {
            $sig = self::match_signatures($full);
            $out[] = self::finding(
                'uploads',
                'critical',
                'uploads_php',
                __('PHP file in the uploads folder', 'fyzi-guard'),
                self::rel($full),
                /* translators: %s: description of the detected malicious construct */
                $sig ? sprintf(__('Detected: %s', 'fyzi-guard'), $sig) : __('There should be no PHP files in the uploads folder. Most often this is a web shell.', 'fyzi-guard')
            );
        }
        // PHP code inside "images".
        $n = 0;
        foreach (self::list_files($dir, array('jpg', 'jpeg', 'png', 'gif', 'ico', 'webp')) as $full) {
            if (++$n > 20000) {
                break;
            }
            if (filesize($full) > 5242880) {
                continue;
            }
            $head = (string) file_get_contents($full, false, null, 0, 65536); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
            if (stripos($head, '<?php') !== false) {
                $out[] = self::finding('uploads', 'critical', 'image_php', __('PHP code inside an image', 'fyzi-guard'), self::rel($full), __('The file pretends to be an image but contains PHP code.', 'fyzi-guard'));
            }
        }
        return $out;
    }

    // ---------- Changes in wp-content ----------

    public static function scan_changes() {
        $out = array();
        $roots = array(WP_CONTENT_DIR . '/plugins', get_theme_root(), WPMU_PLUGIN_DIR);
        $index = array();
        $paths = array(); // rel => full path (wp-content may live outside ABSPATH)
        $files = array();
        foreach ($roots as $root) {
            $files = array_merge($files, self::list_files($root, array('php', 'phtml', 'phar')));
        }
        $files = array_merge($files, glob(WP_CONTENT_DIR . '/*.php') ?: array());
        foreach (array_unique($files) as $full) {
            $rel = self::rel($full);
            $index[$rel] = filesize($full) . ':' . filemtime($full);
            $paths[$rel] = $full;
        }

        $old = FYZI_Guard_Settings::state('file_index', null);
        $first = !is_array($old);
        $old = is_array($old) ? $old : array();

        $to_check = array();
        if (!$first) {
            foreach ($index as $rel => $sig) {
                if (!isset($old[$rel])) {
                    $to_check[$rel] = 'new';
                } elseif ($old[$rel] !== $sig) {
                    $to_check[$rel] = 'changed';
                }
            }
        }
        // mu-plugins and PHP in the wp-content root are always checked: backdoors love these places.
        $mu = wp_normalize_path(WPMU_PLUGIN_DIR);
        $content = wp_normalize_path(WP_CONTENT_DIR);
        foreach ($paths as $rel => $abs) {
            $abs = wp_normalize_path($abs);
            if ((strpos($abs, $mu) === 0 || dirname($abs) === $content) && !isset($to_check[$rel])) {
                $to_check[$rel] = 'always';
            }
        }

        $new_count = 0;
        foreach ($to_check as $rel => $why) {
            $sig = self::match_signatures($paths[$rel]);
            if ($sig) {
                /* translators: %s: description of the detected malicious construct */
                $out[] = self::finding('malware', 'critical', 'malware', __('Malicious code', 'fyzi-guard'), $rel, sprintf(__('Detected: %s', 'fyzi-guard'), $sig));
            } elseif ($why === 'new') {
                $new_count++;
                if ($new_count <= 50) {
                    $out[] = self::finding('changes', 'info', 'new_file', __('New PHP file', 'fyzi-guard'), $rel, __('Appeared since the previous check. Normal after installing or updating a plugin.', 'fyzi-guard'));
                }
            } elseif ($why === 'changed') {
                $out[] = self::finding('changes', 'info', 'changed_file', __('PHP file modified', 'fyzi-guard'), $rel, __('Changed since the previous check.', 'fyzi-guard'));
            }
        }

        // mu-plugins are listed for the owner's information.
        foreach ($paths as $rel => $abs) {
            if (strpos(wp_normalize_path($abs), $mu) === 0) {
                $out[] = self::finding('mu', 'info', 'mu_plugin', __('Must-use plugin (mu-plugins)', 'fyzi-guard'), $rel, __('Always active and not shown in the regular plugin list. Make sure you know it.', 'fyzi-guard'));
            }
        }

        if (count($index) <= self::MAX_FILES) {
            FYZI_Guard_Settings::set_state('file_index', $index);
        }
        return $out;
    }

    // ---------- Hygiene ----------

    public static function scan_hygiene() {
        $out = array();
        $upd = get_site_transient('update_plugins');
        if (is_object($upd) && !empty($upd->response)) {
            foreach ($upd->response as $file => $data) {
                $name = isset($data->slug) ? $data->slug : $file;
                $ver = isset($data->new_version) ? $data->new_version : '';
                $out[] = self::finding(
                    'updates',
                    'warning',
                    'plugin_update',
                    __('Plugin needs an update', 'fyzi-guard'),
                    $name,
                    /* translators: %s: plugin version */
                    $ver ? sprintf(__('Version %s is available. Outdated plugins are the main cause of hacks.', 'fyzi-guard'), $ver) : ''
                );
            }
        }
        $core = get_site_transient('update_core');
        if (is_object($core) && !empty($core->updates)) {
            foreach ($core->updates as $u) {
                if (isset($u->response) && $u->response === 'upgrade') {
                    /* translators: %s: WordPress version */
                    $out[] = self::finding('updates', 'warning', 'core_update', __('A WordPress update is available', 'fyzi-guard'), '', sprintf(__('New version: %s', 'fyzi-guard'), $u->current));
                    break;
                }
            }
        }

        $log = WP_CONTENT_DIR . '/debug.log';
        if (file_exists($log)) {
            $out[] = self::finding(
                'hygiene',
                'warning',
                'debug_log',
                __('debug.log is accessible in wp-content', 'fyzi-guard'),
                self::rel($log),
                /* translators: %s: file size */
                sprintf(__('Size %s. It may reveal paths and errors of the site. Disable WP_DEBUG_LOG or move the log.', 'fyzi-guard'), size_format(filesize($log)))
            );
        }
        if (file_exists(ABSPATH . 'readme.html')) {
            $out[] = self::finding('hygiene', 'info', 'readme', __('readme.html reveals the WordPress version', 'fyzi-guard'), 'readme.html', __('You can delete it; it comes back with the next update.', 'fyzi-guard'));
        }
        if (FYZI_Guard_Hardening::is_apache() && !FYZI_Guard_Hardening::uploads_protected()) {
            $out[] = self::finding('hygiene', 'warning', 'uploads_open', __('PHP execution is allowed in the uploads folder', 'fyzi-guard'), '', __('Turn on the protection on the FYZI Guard “Protection” tab, it is one click.', 'fyzi-guard'));
        }
        if (!is_ssl() && strpos(home_url(), 'https://') !== 0) {
            $out[] = self::finding('hygiene', 'warning', 'no_https', __('The site works without HTTPS', 'fyzi-guard'), '', __('Administrator passwords are sent unencrypted.', 'fyzi-guard'));
        }
        return $out;
    }

    // ---------- Utilities ----------

    /** Recursive list of files with the given extensions (symbolic links are skipped). */
    public static function list_files($dir, array $exts) {
        $result = array();
        if (!is_dir($dir)) {
            return $result;
        }
        try {
            $it = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY,
                RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            $count = 0;
            foreach ($it as $file) {
                if (++$count > self::MAX_FILES * 3) {
                    break;
                }
                if ($file->isLink() || !$file->isFile()) {
                    continue;
                }
                $name = strtolower($file->getFilename());
                $parts = explode('.', $name);
                $ext = end($parts);
                if (in_array($ext, $exts, true)) {
                    $result[] = $file->getPathname();
                } elseif (in_array('php', $exts, true) && preg_match('/\.php\d?\./', $name)) {
                    // Double extensions like shell.php.jpg are interesting for the PHP search too.
                    $result[] = $file->getPathname();
                }
            }
        } catch (Exception $e) {
            /* translators: %s: folder path */
            FYZI_Guard_Log::add('warning', sprintf(__('Could not read the folder %s', 'fyzi-guard'), self::rel($dir)));
        }
        return $result;
    }

    public static function match_signatures($full) {
        if (!is_readable($full) || filesize($full) > self::MAX_READ) {
            return '';
        }
        $code = (string) file_get_contents($full); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
        foreach (self::signatures() as $sig) {
            if (preg_match($sig[0], $code)) {
                return $sig[1];
            }
        }
        // A very long string without spaces is a sign of obfuscation.
        if (preg_match('/[A-Za-z0-9+\/=]{4000,}/', $code) && preg_match('/(eval|assert|create_function|base64_decode)/i', $code)) {
            return __('obfuscated code block', 'fyzi-guard');
        }
        return '';
    }

    public static function counts() {
        $c = array('critical' => 0, 'warning' => 0, 'info' => 0);
        foreach ((array) FYZI_Guard_Settings::state('findings', array()) as $f) {
            if (isset($c[$f['severity']])) {
                $c[$f['severity']]++;
            }
        }
        return $c;
    }

    public static function admin_notice() {
        if (!current_user_can('manage_options')) {
            return;
        }
        $screen = function_exists('get_current_screen') ? get_current_screen() : null;
        if ($screen && strpos((string) $screen->id, 'fyzi-guard') !== false) {
            return;
        }
        $c = self::counts();
        if ($c['critical'] > 0) {
            printf(
                '<div class="notice notice-error is-dismissible"><p><strong>FYZI Guard:</strong> %s <a href="%s">%s</a></p></div>',
                /* translators: %d: number of critical findings */
                esc_html(sprintf(__('signs of site infection found (%d).', 'fyzi-guard'), (int) $c['critical'])),
                esc_url(admin_url('admin.php?page=fyzi-guard')),
                esc_html__('View', 'fyzi-guard')
            );
        }
    }
}
