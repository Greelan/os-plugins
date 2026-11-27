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
        /* a case may carry an importer answer, applied on top of what it set as importAction does */
        $imported = isset($case['import']) ? $model->applyImport($case['import']) : null;
        /* a case may name migrations to run on what it set, as an upgrade would: on the values as
         * config.xml holds them, checking what changed, as core's runMigrations() saves */
        $validateFullModel = empty($case['migrate']);
        if (!$validateFullModel) {
            file_put_contents("{$conf}/config.xml", "<?xml version=\"1.0\"?>\n<opnsense>" .
                preg_replace('/^<\?xml[^>]*>\s*/', '', $model->toXML()->asXML()) . '</opnsense>');
            OPNsense\Core\Config::getInstance()->forceReload();
            $model = new OPNsense\Blocky\Blocky();
            foreach ((array)$case['migrate'] as $name) {
                $migration = "OPNsense\\Blocky\\Migrations\\{$name}";
                (new $migration())->run($model);
            }
            /* then what a later save changes, as array.index.field or section.field */
            foreach ($case['after'] ?? [] as $ref => $value) {
                $parts = explode('.', $ref);
                if (count($parts) == 3) {
                    $row = array_values(iterator_to_array($model->getNodeByReference($parts[0])->iterateItems()))[$parts[1]];
                    $row->{$parts[2]}->setValue($value);
                } else {
                    $model->getNodeByReference($ref)->setValue($value);
                }
            }
        }
        $messages = [];
        foreach ($model->performValidation($validateFullModel) as $message) {
            $field = preg_replace_callback('/^(\w+)\.([0-9a-f-]{36})\./', function ($m) use ($rows) {
                return ($rows[$m[2]] ?? $m[1]) . '.';
            }, $message->getField());
            $messages[] = [$field, (string)$message->getMessage()];
        }
        echo json_encode([
            'messages' => $messages,
            'import' => $imported,
            'xml' => $messages || !empty($imported['errors']) ? null :
                '<opnsense>' . preg_replace('/^<\?xml[^>]*>\s*/', '', $model->toXML()->asXML()) . '</opnsense>',
        ]) . "\n";
        if (!$validateFullModel) {
            file_put_contents("{$conf}/config.xml", "<?xml version=\"1.0\"?>\n<opnsense/>\n");
            OPNsense\Core\Config::getInstance()->forceReload();
        }
    }
    array_map('unlink', glob("{$conf}/*"));
    @rmdir($conf);
}
