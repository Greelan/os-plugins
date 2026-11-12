<?php

/*
 * Drives the S3 provider for test_s3.py: the steps in argv[1] (JSON) run against the provider
 * with its settings stubbed, and each step's answer is printed as one JSON line.
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

namespace OPNsense\Backup {
    /* the provider's log lines, for the log step */
    function syslog($priority, $message)
    {
        $GLOBALS['s3_log'][] = $message;
        return true;
    }
}

namespace {
require __DIR__ . '/../../../tools/tests/bootstrap.php';

$spec = json_decode($argv[1], true);

/* the real settings model over the config.xml given, else an empty one, as core loads it; no configd is running */
require getenv('OPNSENSE_CORE') . '/src/opnsense/mvc/app/config/AppConfig.php';
$conf = sys_get_temp_dir() . '/s3-harness-' . getmypid();
@mkdir($conf);
register_shutdown_function(function () use ($conf) {
    exec('rm -rf ' . escapeshellarg($conf));
});
file_put_contents("{$conf}/config.xml", $spec['config'] ?? "<?xml version=\"1.0\"?>\n<opnsense/>\n");
new OPNsense\Core\AppConfig([
    'application' => ['configDir' => $conf, 'tempDir' => sys_get_temp_dir()],
    'globals' => ['simulate_mode' => '1', 'owner' => ''],
]);
/* core reads /etc/services once, for a port given by its service name, and warns on lines it does not expect */
@OPNsense\Firewall\Util::getservbyname('');

/* core's Config as far as the upload uses it: the local backups, newest first */
class StubConfig
{
    public function __construct(private array $backups)
    {
    }
    public function getBackups()
    {
        return $this->backups;
    }
}

/* core's encryption needs openssl and opnsense-version, so a marker stands in for it */
class TestS3 extends OPNsense\Backup\S3
{
    public static $config = null;

    protected function configFile()
    {
        return self::$config;
    }

    /* the production command with the test's limits(1), timeout(1) and logging wrapper, and what they need in
     * the environment, trusting the test certificate */
    protected function command()
    {
        $paths = ['/usr/bin/limits' => getenv('S3_LIMITS'), '/usr/bin/timeout' => getenv('S3_TIMEOUT'),
            '/usr/local/bin/rclone' => getenv('S3_RCLONE')];
        $argv = array_merge(['/usr/bin/env', 'PATH=' . getenv('PATH'), 'RCLONE=' . getenv('RCLONE'),
            'S3_RCLONE_LOG=' . getenv('S3_RCLONE_LOG')], array_map(function ($arg) use ($paths) {
                return $paths[$arg] ?? $arg;
            }, parent::command()));
        return getenv('S3_CA') ? array_merge($argv, ['--ca-cert', getenv('S3_CA')]) : $argv;
    }

    protected function deadline()
    {
        return 5;
    }

    /* core's backup page, as given, else none */
    protected function page()
    {
        return getenv('S3_PAGE') ?: '/nonexistent';
    }

    public function encrypt($data, $pass, $tag = 'config.xml')
    {
        return "---- BEGIN config.xml ----\n" . base64_encode($data) . "\n---- END config.xml ----\n";
    }
}

$provider = (new ReflectionClass('TestS3'))->newInstanceWithoutConstructor();
$settings = new OPNsense\Backup\S3Settings();
foreach ($spec['settings'] as $name => $value) {
    $settings->$name = $value;
}
(new ReflectionProperty('OPNsense\Backup\S3', 'model'))->setValue($provider, $settings);
$call = function ($method, ...$args) use ($provider) {
    return (new ReflectionMethod('OPNsense\Backup\S3', $method))->invoke($provider, ...$args);
};

foreach ($spec['steps'] as $step) {
    try {
        switch ($step[0]) {
            case 'list':
                $answer = $call('listBackups', $step[1]);
                break;
            case 'upload':
                /* the running config: the one given, else the first local backup */
                TestS3::$config = $step[2] ?? $step[1][0];
                $answer = $call('upload', new StubConfig($step[1]));
                break;
            case 'fields':
                $answer = array_column($call('getConfigurationFields'), null, 'name');
                break;
            case 'setup':
                /* as the page posts it, then what the secrets hold */
                $answer = [
                    'messages' => $provider->setConfiguration($step[1]),
                    'secretKey' => $settings->secretKey->getValue(),
                    'password' => $settings->password->getValue(),
                    'provider' => (string)$settings->provider,
                ];
                break;
            case 'endpoint':
                /* the URL rclone is given */
                $answer = $call('remote')['RCLONE_CONFIG_S3_ENDPOINT'];
                break;
            case 'backup':
                $answer = $provider->backup();
                break;
            case 'log':
                $answer = $GLOBALS['s3_log'] ?? [];
                $GLOBALS['s3_log'] = [];
                break;
            case 'migrate':
                /* as the package install does, from the config.xml given; what it wrote back, if anything */
                (new OPNsense\Backup\S3Settings())->runMigrations();
                $answer = (new OPNsense\Backup\S3Settings())->provider->getValue();
                break;
        }
    } catch (Exception $e) {
        $answer = ['error' => $e->getMessage()];
    }
    echo json_encode($answer) . "\n";
}
$GLOBALS['test_checks'] = count($spec['steps']);
}
