<?php

/*
 * Shared by the plugins' PHP tests: autoloads the plugins' models and libraries, then core's
 * from the checkout named by OPNSENSE_CORE, and collects failed checks.
 */

$core = getenv('OPNSENSE_CORE');
if (empty($core) || !is_dir("{$core}/src/opnsense/mvc/app")) {
    fwrite(STDERR, "OPNSENSE_CORE must name an opnsense/core checkout\n");
    exit(1);
}
$roots = glob(dirname(__DIR__, 2) . '/*/*/src/opnsense/mvc/app/{models,library}', GLOB_BRACE);
array_push($roots, "{$core}/src/opnsense/mvc/app/models", "{$core}/src/opnsense/mvc/app/library");
spl_autoload_register(function ($class) use ($roots) {
    $path = str_replace('\\', '/', $class) . '.php';
    foreach ($roots as $root) {
        if (is_file("{$root}/{$path}")) {
            require "{$root}/{$path}";
            return;
        }
    }
});

$GLOBALS['test_failures'] = 0;
$GLOBALS['test_checks'] = 0;

function check($label, $actual, $expected)
{
    $GLOBALS['test_checks']++;
    if ($actual !== $expected) {
        $GLOBALS['test_failures']++;
        printf("FAIL %s: expected %s, got %s\n", $label, var_export($expected, true), var_export($actual, true));
    }
}

register_shutdown_function(function () {
    printf("%s: %d checks, %d failed\n", basename($_SERVER['argv'][0]), $GLOBALS['test_checks'], $GLOBALS['test_failures']);
    if ($GLOBALS['test_failures'] > 0) {
        exit(1);
    }
});
