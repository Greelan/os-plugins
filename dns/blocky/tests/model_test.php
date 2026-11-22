<?php

/* The model's rules for what Blocky, which runs as root, may read or connect to, and the write-only
 * secret field. */

require __DIR__ . '/../../../tools/tests/bootstrap.php';

use OPNsense\Blocky\Blocky;
use OPNsense\Blocky\FieldTypes\SecretField;

/* a list or hosts file Blocky reads from disk lives in the plugin's own directory */
foreach ([
    'https://example.com/list.txt' => true,
    'ads.example.com' => true,
    '/^ad[sx]?\./' => true,
    '/usr/local/etc/blocky/lists/mine.txt' => true,
    'file:///usr/local/etc/blocky/lists/sub/mine.txt' => true,
    '/usr/local/etc/blocky/lists/../config.yml' => false,
    '/usr/local/etc/blocky/lists//x' => false,
    '/etc/master.passwd' => false,
    'file:///etc/master.passwd' => false,
    'FILE:///etc/master.passwd' => false,
] as $source => $allowed) {
    check("isAllowedFile {$source}", Blocky::isAllowedFile($source), $allowed);
}
check('hosts file /etc/hosts', Blocky::isAllowedFile('/etc/hosts', Blocky::HOSTS_FILES), true);
check('list file /etc/hosts', Blocky::isAllowedFile('/etc/hosts'), false);
check('resolv file in list dir', Blocky::isListFile('/usr/local/etc/blocky/lists/resolv.conf'), true);
check('resolv file elsewhere', Blocky::isListFile('/etc/resolv.conf'), false);
/* a bootstrap entry cannot refuse line breaks, so it is checked as the template writes it, without \r */
check('resolv file, CR in each ..', Blocky::isListFile("/usr/local/etc/blocky/lists/\r../\r../etc/x"), false);

/* Blocky reads a file: secret from disk, so only the secrets directory is allowed */
foreach ([
    'hunter2' => true,
    'FILE:/etc/master.passwd' => true,
    'file:/usr/local/etc/blocky/secrets/redis' => true,
    'file:///usr/local/etc/blocky/secrets/redis' => true,
    'file:/etc/master.passwd' => false,
    'file:///etc/master.passwd' => false,
    'file://usr/local/etc/blocky/secrets/redis' => false,
    'file:/usr/local/etc/blocky/secrets/../config.yml' => false,
] as $value => $allowed) {
    check("isAllowedSecret {$value}", Blocky::isAllowedSecret($value), $allowed);
}

/* no socket of the page's choosing */
foreach (['127.0.0.1:6379' => true, 'mymaster' => true, '/var/run/redis/redis.sock' => true,
    '/var/run/configd.socket' => false, '/var/run/redis/redis.sock/' => false] as $address => $allowed) {
    check("Redis address {$address}", Blocky::isAllowedRedisAddress($address), $allowed);
}
foreach (['tcp://127.0.0.1:6000' => true, 'file:/usr/local/etc/blocky/secrets/dnstap' => true, '' => false,
    'TCP://127.0.0.1:6000' => false, 'unix:/var/run/configd.socket' => false, '/var/run/x.sock' => false,
    'tcp://127.0.0.1' => false] as $target => $allowed) {
    check("dnstap target {$target}", Blocky::isDnstapTarget($target), $allowed);
}

/* a write-only secret: kept on empty, replaced on text, removed only by CLEAR, never rendered */
$secret = new SecretField();
$secret->setValue('hunter2');
check('secret stored', $secret->getValue(), 'hunter2');
check('secret never rendered', (string)$secret, '');
$secret->setValue('');
check('empty keeps the secret', $secret->getValue(), 'hunter2');
$secret->setValue(json_decode(json_encode(SecretField::CLEAR)));
check('CLEAR, through JSON, removes it', $secret->getValue(), '');
$secret->setValue('new');
check('text replaces it', $secret->getValue(), 'new');
