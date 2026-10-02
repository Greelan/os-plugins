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

require_once('script/load_phalcon.php');

use OPNsense\Blocky\Blocky;
use OPNsense\Trust\Store as CertStore;

$cert_file = '/usr/local/etc/blocky/cert.pem';
$key_file = '/usr/local/etc/blocky/key.pem';
$refid = (string)(new Blocky())->general->certificate;

if (empty($refid)) {
    @unlink($cert_file);
    @unlink($key_file);
    exit(0);
}

$cert = CertStore::getCertificate($refid);
if (!is_array($cert)) {
    syslog(LOG_ERR, 'blocky: certificate ' . $refid . ' was not found');
    exit(1);
}
if (empty($cert['prv']) || empty($cert['subject'])) {
    /* a signing request has a key but no certificate yet */
    syslog(LOG_ERR, 'blocky: certificate ' . $refid . ' has no key or no certificate, keeping the previous files');
    exit(1);
}
$chain = $cert['crt'] . ($cert['ca']['crt'] ?? '');
$written = false;
foreach ([$cert_file => $chain, $key_file => $cert['prv']] as $file => $pem) {
    @touch($file);
    @chmod($file, 0600);
    if (hash('sha256', $pem) !== @hash_file('sha256', $file)) {
        file_put_contents($file, $pem);
        $written = true;
    }
}
if ($written) {
    /* the files are named for Blocky, so record which certificate they hold */
    syslog(LOG_NOTICE, sprintf(
        'blocky: exported certificate %s (%s)',
        $cert['subject']['CN'] ?? $cert['name'] ?? $refid,
        $refid
    ));
}
exit(0);
