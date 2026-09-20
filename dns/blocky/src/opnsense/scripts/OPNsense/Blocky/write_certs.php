#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 Greelan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Write the certificate chosen in the settings to the files config.yml points at,
 * so Blocky serves DoT/DoH with a certificate managed by OPNsense. Removes them
 * again when no certificate is selected.
 */

require_once 'config.inc';
require_once 'util.inc';

use OPNsense\Blocky\Blocky;
use OPNsense\Core\Config;

$cert_file = '/usr/local/etc/blocky/cert.pem';
$key_file = '/usr/local/etc/blocky/key.pem';
$refid = (string)(new Blocky())->general->certificate;

if (empty($refid)) {
    @unlink($cert_file);
    @unlink($key_file);
    exit(0);
}

foreach (Config::getInstance()->object()->cert ?? [] as $cert) {
    if ((string)$cert->refid != $refid) {
        continue;
    }
    if (empty($cert->crt) || empty($cert->prv)) {
        log_msg('blocky: certificate ' . $refid . ' has no key, keeping the previous files', LOG_ERR);
        exit(1);
    }
    /* the key is secret: create the files unreadable before writing, as core does for IPsec */
    foreach ([$cert_file => (string)$cert->crt, $key_file => (string)$cert->prv] as $file => $pem) {
        @touch($file);
        @chmod($file, 0600);
        file_put_contents($file, base64_decode($pem));
    }
    exit(0);
}

log_msg('blocky: certificate ' . $refid . ' was not found', LOG_ERR);
exit(1);
