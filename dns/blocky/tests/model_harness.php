<?php

/*
 * Drives the Blocky model for test_blocky_validate.py: each case in the JSON file named by argv[1]
 * sets fields on a fresh model, and one JSON line per case reports the model's messages and,
 * when it accepts the case, the model as config.xml holds it.
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

namespace OPNsense\Core {
    /* configd is not running: the port check sees no other services, without waiting for it */
    class Backend
    {
        public function configdpRun($event, $params = [], $detach = false)
        {
            return '[]';
        }
    }
}

namespace {
    require __DIR__ . '/../../../tools/tests/bootstrap.php';
    require getenv('OPNSENSE_CORE') . '/src/opnsense/mvc/app/config/AppConfig.php';

    /* an empty config.xml, and no waiting for configd, which is not running */
    $conf = sys_get_temp_dir() . '/blocky-harness-' . getmypid();
    @mkdir($conf);
    file_put_contents("{$conf}/config.xml", "<?xml version=\"1.0\"?>\n<opnsense/>\n");
    new OPNsense\Core\AppConfig(['application' => ['configDir' => $conf], 'globals' => ['simulate_mode' => '1']]);

    foreach (json_decode(file_get_contents($argv[1]), true) as $case) {
        $model = new OPNsense\Blocky\Blocky();
        foreach ($case['fields'] as $ref => $value) {
            $model->getNodeByReference($ref)->setValue($value);
        }
        /* row messages name the row's uuid; report them as array.index.field */
        $rows = [];
        foreach ($case['rows'] as $array => $list) {
            foreach ($list as $index => $values) {
                $row = $model->getNodeByReference($array)->Add();
                $rows[$row->getAttributes()['uuid']] = "{$array}.{$index}";
                foreach ($values as $field => $value) {
                    $row->$field->setValue($value);
                }
            }
        }
        $messages = [];
        foreach ($model->performValidation(true) as $message) {
            $field = preg_replace_callback('/^(\w+)\.([0-9a-f-]{36})\./', function ($m) use ($rows) {
                return ($rows[$m[2]] ?? $m[1]) . '.';
            }, $message->getField());
            $messages[] = [$field, (string)$message->getMessage()];
        }
        echo json_encode([
            'messages' => $messages,
            'xml' => $messages ? null :
                '<opnsense>' . preg_replace('/^<\?xml[^>]*>\s*/', '', $model->toXML()->asXML()) . '</opnsense>',
        ]) . "\n";
    }
    array_map('unlink', glob("{$conf}/*"));
    @rmdir($conf);
}
