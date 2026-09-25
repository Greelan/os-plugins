<?php

/*
 * Drives the S3 provider for test_s3.py: the steps in argv[1] (JSON) run against the provider
 * with its settings stubbed, and each step's answer is printed as one JSON line.
 */

require __DIR__ . '/../../../tools/tests/bootstrap.php';

/* the settings model's fields, as the provider reads them */
class StubField
{
    public function __construct(private string $value)
    {
    }
    public function __toString(): string
    {
        return $this->value;
    }
    public function getValue(): string
    {
        return $this->value;
    }
}

class StubSettings
{
    public array $invalid = [];
    public function __construct(public array $values)
    {
    }
    public function __get($name)
    {
        return new StubField((string)($this->values[$name] ?? ''));
    }
    public function getNodeByReference($name)
    {
        return $this->__get($name);
    }
    public function performValidation($full = false)
    {
        return $this->invalid;
    }
}

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
    public function encrypt($data, $pass, $tag = 'config.xml')
    {
        return "---- BEGIN config.xml ----\n" . base64_encode($data) . "\n---- END config.xml ----\n";
    }
}

$spec = json_decode($argv[1], true);
$provider = (new ReflectionClass('TestS3'))->newInstanceWithoutConstructor();
$settings = new StubSettings($spec['settings']);
$settings->invalid = $spec['invalid'] ?? [];
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
