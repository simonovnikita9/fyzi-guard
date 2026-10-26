<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Alerts for the site owner: e-mail and/or the owner's own Telegram bot.
 */
class FYZI_Guard_Notifier {

    /**
     * @param string $title  short title
     * @param array  $lines  detail lines
     * @param string $level  warning | critical
     */
    public static function alert($title, array $lines = array(), $level = 'critical') {
        $site = wp_parse_url(home_url(), PHP_URL_HOST);
        $icon = $level === 'critical' ? '🚨' : '⚠️';
        $text = $icon . ' ' . $title . "\n"
            /* translators: %s: site domain */
            . sprintf(__('Site: %s', 'fyzi-guard'), $site) . "\n\n" . implode("\n", $lines) . "\n\n"
            /* translators: %s: URL of the plugin dashboard */
            . sprintf(__('Dashboard: %s', 'fyzi-guard'), admin_url('admin.php?page=fyzi-guard'));

        FYZI_Guard_Log::add($level, $title, array('details' => $lines));

        $sent = false;
        if (FYZI_Guard_Settings::get('notify_telegram')) {
            $sent = self::telegram($text) || $sent;
        }
        if (FYZI_Guard_Settings::get('notify_email')) {
            $sent = self::email('[FYZI Guard] ' . $title . ' — ' . $site, $text) || $sent;
        }
        return $sent;
    }

    public static function email($subject, $text) {
        $to = FYZI_Guard_Settings::get('email_to');
        if (!$to) {
            $to = get_option('admin_email');
        }
        if (!$to) {
            return false;
        }
        return wp_mail($to, $subject, $text);
    }

    public static function telegram($text) {
        $token = trim((string) FYZI_Guard_Settings::get('tg_token'));
        $chat = trim((string) FYZI_Guard_Settings::get('tg_chat_id'));
        if ($token === '' || $chat === '' || !preg_match('/^\d+:[A-Za-z0-9_-]{30,}$/', $token)) {
            return false;
        }
        $res = wp_remote_post('https://api.telegram.org/bot' . $token . '/sendMessage', array(
            'timeout' => 10,
            'body'    => array(
                'chat_id'                  => $chat,
                'text'                     => mb_substr($text, 0, 4000),
                'disable_web_page_preview' => 'true',
            ),
        ));
        if (is_wp_error($res)) {
            /* translators: %s: error message */
            FYZI_Guard_Log::add('warning', sprintf(__('Could not send a Telegram message: %s', 'fyzi-guard'), $res->get_error_message()));
            return false;
        }
        $code = wp_remote_retrieve_response_code($res);
        if ($code !== 200) {
            /* translators: %d: HTTP status code */
            FYZI_Guard_Log::add('warning', sprintf(__('Telegram returned error %d. Check the bot token and chat ID.', 'fyzi-guard'), $code));
            return false;
        }
        return true;
    }
}
