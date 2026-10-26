<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Event log: the last 200 entries stored in an option.
 */
class FYZI_Guard_Log {
    const OPTION = 'fyzi_guard_log';
    const MAX = 200;

    /**
     * @param string $level info | warning | critical
     */
    public static function add($level, $message, array $context = array()) {
        $log = get_option(self::OPTION, array());
        if (!is_array($log)) {
            $log = array();
        }
        array_unshift($log, array(
            'time'    => time(),
            'level'   => $level,
            'message' => $message,
            'context' => $context,
        ));
        update_option(self::OPTION, array_slice($log, 0, self::MAX), false);
    }

    public static function all() {
        $log = get_option(self::OPTION, array());
        return is_array($log) ? $log : array();
    }

    public static function clear() {
        update_option(self::OPTION, array(), false);
    }
}
