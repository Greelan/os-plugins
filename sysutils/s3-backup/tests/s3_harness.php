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

namespace {
require __DIR__ . '/../../../tools/tests/bootstrap.php';

/* the real settings model over an empty config.xml, as core loads it; no configd is running */
require getenv('OPNSENSE_CORE') . '/src/opnsense/mvc/app/config/AppConfig.php';
$conf = sys_get_temp_dir() . '/s3-harness-' . getmypid();
@mkdir($conf);
file_put_contents("{$conf}/config.xml", "<?xml version=\"1.0\"?>\n<opnsense/>\n");
new OPNsense\Core\AppConfig(['application' => ['configDir' => $conf], 'globals' => ['simulate_mode' => '1']]);

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

    public function encrypt($data, $pass, $tag = 'config.xml')
    {
        return "---- BEGIN config.xml ----\n" . base64_encode($data) . "\n---- END config.xml ----\n";
    }
}

$spec = json_decode($argv[1], true);
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
            case 'put':
                $call('request', 'PUT', $step[1], [], 'x');
                $answer = true;
                break;
            case 'list':
                $answer = $call('listBackups', $step[1]);
                break;
            case 'upload':
                /* the running config: the one given, else the first local backup */
                TestS3::$config = $step[2] ?? $step[1][0];
                $answer = $call('upload', new StubConfig($step[1]));
                break;
            case 'fields':
                $answer = array_column($call('getConfigurationFields'), 'value', 'name');
                break;
        }
    } catch (Exception $e) {
        $answer = ['error' => $e->getMessage()];
    }
    echo json_encode($answer) . "\n";
}
$GLOBALS['test_checks'] = count($spec['steps']);
}
