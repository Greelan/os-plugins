<?php

/*
 * Saved URLs rewritten so Apprise 2 reads them as Apprise 1.13 did (checked against both; the
 * reading of a query part against Apprise's own in test_notify.py), the migration run on a saved
 * config, and a saved URL as the model shows it.
 */

namespace Phalcon\Filter {
    /* core's own validators do the work; only the Phalcon pass they run beside is absent here */
    if (!class_exists(Validation::class)) {
        class Validation
        {
            public function add($field, $validator)
            {
                return $this;
            }
            public function validate($data)
            {
                return [];
            }
        }
    }
}

namespace {
    use OPNsense\Core\AppConfig;
    use OPNsense\Core\Config;
    use OPNsense\Notify\Migrations\M1_0_1;
    use OPNsense\Notify\Notify;

    require __DIR__ . '/../../../tools/tests/bootstrap.php';
    require getenv('OPNSENSE_CORE') . '/src/opnsense/mvc/app/config/AppConfig.php';

    $base = 'mailtos://u:p@example.com?to=a@example.com';
    $cases = [
    // a pgp= Apprise 2 refuses: what Apprise 1.13 read it as
    "{$base}&pgp=off" => "{$base}&pgp=no",
    "{$base}&PGP=False" => "{$base}&pgp=no",
    "{$base}&pgp=0" => "{$base}&pgp=no",
    "{$base}&pgp=junk" => "{$base}&pgp=no",
    "{$base}&pgp=yes" => "{$base}&pgp=encrypt",
    "{$base}&pgp=%20on%20" => "{$base}&pgp=encrypt",
    "{$base}&%70gp=1" => "{$base}&pgp=encrypt",
    "{$base};pgp=t" => "{$base};pgp=encrypt",
    // one Apprise 2 reads the same is left as written
    "{$base}&pgp=no" => "{$base}&pgp=no",
    "{$base}&pgp=NONE" => "{$base}&pgp=NONE",
    "{$base}&pgp=enc" => "{$base}&pgp=enc",
    "{$base}&pgp=" => "{$base}&pgp=",
    // whitespace and case as Python reads them, Unicode's included
    "{$base}&pgp=%C2%A0encrypt" => "{$base}&pgp=%C2%A0encrypt",
    "{$base}&pgp=%C2%A0yes" => "{$base}&pgp=encrypt",
    "{$base}&pgp%E2%80%83=1" => "{$base}&pgp=encrypt",
    // bytes that are no UTF-8 Python reads as U+FFFD, which it keeps; the whitespace before still goes
    "{$base}&pgp=%C2%A0yes%FF" => "{$base}&pgp=encrypt",
    "{$base}&pgp=%FFyes" => "{$base}&pgp=no",
    "{$base}&pgp%FF=yes" => "{$base}&pgp%FF=yes",
    // U+180E, which Python's strip() leaves, is no whitespace: Apprise 1.13 read these as no PGP
    "{$base}&pgp=%E1%A0%8Eyes" => "{$base}&pgp=no",
    "{$base}&pgp%E1%A0%8E=yes" => "{$base}&pgp%E1%A0%8E=yes",
    // pgpkey= becomes pgppub=, unless a pgppub= was given, which Apprise 1.13 took instead
    "{$base}&pgpkey=https://h/k.asc" => "{$base}&pgppub=https://h/k.asc",
    "{$base}&pgpkey=https://h/k.asc&pgppub=" => "{$base}&pgppub=https://h/k.asc",
    "{$base}&pgppub=https://h/p.asc&pgpkey=https://h/k.asc" => "{$base}&pgppub=https://h/p.asc",
    "{$base}&pgpkey=" => $base,
    'mailtos://u:p@example.com?pgpkey=x' => 'mailtos://u:p@example.com?pgppub=x',
    'mailtos://u:p@example.com?pgpkey=' => 'mailtos://u:p@example.com',
    "{$base}&%C2%A0pgppub=p.asc&pgpkey=k.asc" => "{$base}&%C2%A0pgppub=p.asc",
    "{$base}&pgp%E2%84%AAey=k.asc" => "{$base}&pgppub=k.asc",
    // Apprise API keeps the configuration ID in the request path: Apprise 1.13 read no version=
    'apprises://h/abc123' => 'apprises://h/abc123?version=1',
    'apprise://h/abc123?method=json' => 'apprise://h/abc123?method=json&version=1',
    'apprises://h/abc123?version=' => 'apprises://h/abc123?version=1',
    'apprises://h/abc123?version=2' => 'apprises://h/abc123?version=1',
    'apprises://h/abc123?version=junk&method=json' => 'apprises://h/abc123?method=json&version=1',
    'APPRISES://h/abc123?Version=1' => 'APPRISES://h/abc123?version=1',
    'apprise://h/abc123?method=json;v=2' => 'apprise://h/abc123?method=json&version=1',
    // a self-hosted Fluxer posts to the host root: Apprise 1.13 read no path=
    'fluxers://fluxer.example.com/123456789012345678/abcdefABCDEF1234' =>
        'fluxers://fluxer.example.com/123456789012345678/abcdefABCDEF1234?path=/',
    'fluxer://h:8080/1/2/3?tts=yes' => 'fluxer://h:8080/1/2/3?tts=yes&path=/',
    'fluxers://h/1/2/3?path=/x&mode=private' => 'fluxers://h/1/2/3?mode=private&path=/',
    'fluxers://h/1/2/3?' => 'fluxers://h/1/2/3?',
    // other services, and a URL Apprise could not read, are not touched
    'json://h/?pgp=off&pgpkey=x' => 'json://h/?pgp=off&pgpkey=x',
    'mailtos://u:p@example.com?' => 'mailtos://u:p@example.com?',
    'apprises://h/abc123?' => 'apprises://h/abc123?',
    // a newline at the end, which Apprise reads past, goes before the part added
    "apprises://h/abc123\n" => 'apprises://h/abc123?version=1',
    "apprises://h/abc123?method=json\n" => 'apprises://h/abc123?method=json&version=1',
    // only a first ? at the end is unreadable
    'apprises://h/abc123?tags=x?' => 'apprises://h/abc123?tags=x?&version=1',
    'fluxers://h/1/2/3?tts=yes?' => 'fluxers://h/1/2/3?tts=yes?&path=/',
    ];
    foreach ($cases as $url => $expected) {
        check("rewrite {$url}", M1_0_1::rewrite($url, [])[0], $expected);
    }

/* a stored key file moves with its argument */
    $renamed = M1_0_1::rewrite("{$base}&pgpkey=stored", ['pgpkey' => 'KEY']);
    check('stored key renamed', $renamed, ["{$base}&pgppub=stored", ['pgppub' => 'KEY']]);
    $dropped = M1_0_1::rewrite("{$base}&pgppub=stored&pgpkey=stored", ['pgpkey' => 'KEY', 'pgppub' => 'PUB']);
    check('stored key dropped beside pgppub', $dropped, ["{$base}&pgppub=stored", ['pgppub' => 'PUB']]);
    $kept = M1_0_1::rewrite("{$base}&pgppub=stored", ['pgppub' => 'PUB']);
    check('files kept when nothing changes', $kept, ["{$base}&pgppub=stored", ['pgppub' => 'PUB']]);

/* a saved URL as the model shows it, also one saved earlier: no webhook path, Matrix token or Threema gateway ID */
    $targets = [
    ['JSON', 'json://hooks.example.com/api/webhook/abc123', 'json://hooks.example.com/...'],
    ['Form', 'forms://u:****@hooks.example.com:8443/abc123', 'forms://u:****@hooks.example.com:8443/...'],
    ['XML', 'xml://hooks.example.com/', 'xml://hooks.example.com/'],
    ['Matrix', 'matrixs://syt_TOKEN@matrix.example.com/#ops', 'matrixs://****@matrix.example.com/#ops'],
    ['Matrix', 'matrixs://user:****@matrix.example.com/#ops', 'matrixs://user:****@matrix.example.com/#ops'],
    ['Matrix', 'matrix://a...a/', 'matrix://a...a/'],
    ['Threema Gateway', 'threema://*ABCDEFG@****/user@example.com', 'threema://****@****/user@example.com'],
    ['ntfy', 'ntfys://t...f@ntfy.example.com/alerts', 'ntfys://t...f@ntfy.example.com/alerts'],
    ];
    foreach ($targets as [$service, $target, $expected]) {
        check("target {$target}", Notify::shownTarget($service, $target), $expected);
    }

/* the migration on a config saved by 1.5, its channels at model version 1.0.0 */
    $conf = sys_get_temp_dir() . '/notify-migration-' . getmypid();
    @mkdir($conf);
    new AppConfig(['application' => ['configDir' => $conf, 'tempDir' => $conf], 'globals' => ['simulate_mode' => '1']]);
    $channels = [
    'a1111111-2222-4333-8444-555555555555' => ['apprises://h/abc123', '{}', 'apprises://h/abc123?version=1', '{}'],
    'b1111111-2222-4333-8444-555555555555' => ["{$base}&pgpkey=stored", '{"pgpkey":"KEY"}',
        "{$base}&pgppub=stored", '{"pgppub":"KEY"}'],
    'c1111111-2222-4333-8444-555555555555' => ['json://h/x', '{}', 'json://h/x', '{}'],
    ];
    $xml = '';
    foreach ($channels as $uuid => [$url, $files]) {
        $xml .= sprintf('<channels uuid="%s"><enabled>1</enabled><description>c</description><url>%s</url>' .
        '<files>%s</files></channels>', $uuid, htmlspecialchars($url), htmlspecialchars($files));
    }
    file_put_contents("{$conf}/config.xml", "<?xml version=\"1.0\"?>\n" .
    "<opnsense><OPNsense><notify version=\"1.0.0\"><general/>{$xml}</notify></OPNsense></opnsense>\n");
    Config::getInstance()->forceReload();
    $model = new Notify();
    check('migrated', $model->runMigrations(), true);
    foreach ($channels as $uuid => [$url, $files, $expected, $expectedFiles]) {
        $channel = $model->getNodeByReference("channels.{$uuid}");
        check("migrated {$url}", [$channel->url->getValue(), $channel->files->getValue()], [$expected, $expectedFiles]);
    }
    array_map('unlink', glob("{$conf}/*"));
    @rmdir($conf);
}
