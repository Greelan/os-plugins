<?php

/* The model's rules for what Blocky, which runs as root, may read, connect to or keep secret. */

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

/* nothing that makes Blocky read a file or connect to a socket of the page's choosing */
check('zone $INCLUDE', Blocky::hasZoneInclude("\$TTL 3600\n  \$include /etc/master.passwd\n"), true);
check('zone without include', Blocky::hasZoneInclude("host IN A 10.0.0.1\n; \$INCLUDE in a comment"), false);
foreach (['127.0.0.1:6379' => true, 'mymaster' => true, '/var/run/redis/redis.sock' => true,
    '/var/run/configd.socket' => false, '/var/run/redis/redis.sock/' => false] as $address => $allowed) {
    check("Redis address {$address}", Blocky::isAllowedRedisAddress($address), $allowed);
}
foreach (['' => true, 'tcp://127.0.0.1:6000' => true, 'file:/usr/local/etc/blocky/secrets/dnstap' => true,
    'TCP://127.0.0.1:6000' => false, 'unix:/var/run/configd.socket' => false, '/var/run/x.sock' => false,
    'file:/etc/passwd' => false] as $target => $allowed) {
    check("dnstap target {$target}", Blocky::isDnstapTarget($target), $allowed);
}
foreach ([
    'u:p@tcp(db:3306)/blocky?parseTime=true' => true,
    'postgres://u:p@db:5432/blocky?sslmode=verify-full' => true,
    'host=db user=u dbname=blocky sslmode=require' => true,
    'file:/usr/local/etc/blocky/secrets/db' => true,
    'u:p@tcp(evil:3306)/b?allowAllFiles=true' => false,
    'u:p@tcp(evil:3306)/b?x=1&allowallfiles=1' => false,
    'postgres://u:p@db/b?sslrootcert=/etc/master.passwd' => false,
    'postgres://u:p@db/b?ssl%63ert=/root/c.pem&sslkey=/root/k.pem' => false,
    'host=db sslkey = /root/k.pem' => false,
    'host=db passfile=/etc/master.passwd' => false,
    'host=db service=a servicefile=/etc/master.passwd' => false,
    'FILE:/etc/x?allowAllFiles=true' => false,
] as $target => $allowed) {
    check("database target {$target}", Blocky::isDatabaseTarget($target), $allowed);
}
foreach ([
    'postgres://u:mypassfile@db/b' => true,
    'postgres://u@db/sslkeys' => true,
    "host=db\tsslkey=/root/k.pem" => false,
] as $target => $allowed) {
    check('database target ' . json_encode($target), Blocky::isDatabaseTarget($target), $allowed);
}

/* fields that cannot refuse line breaks are checked as the template writes them, without \r */
check('resolv file, CR in each ..', Blocky::isListFile("/usr/local/etc/blocky/lists/\r../\r../etc/x"), false);
check('zone $INCLUDE with a CR', Blocky::hasZoneInclude("\$INC\rLUDE /etc/master.passwd\n"), true);

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
