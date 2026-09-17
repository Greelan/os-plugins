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
 * Everything the notify backend reads out of the configuration, as JSON: its own
 * settings, the channels with their Monit services resolved to names, and the few
 * facts the checks need from elsewhere. Certificate expiry is worked out here, so
 * the backend never handles a PEM.
 */

require_once('script/load_phalcon.php');

use OPNsense\Core\Config;
use OPNsense\Monit\Monit;
use OPNsense\Notify\Notify;
use OPNsense\Trust\Ca;
use OPNsense\Trust\Cert;

$config = Config::getInstance()->object();
$model = new Notify();

$general = [];
foreach ($model->general->iterateItems() as $key => $field) {
    $general[$key] = $field->getValue();
}

/* uuid => name, so a channel can name the Monit services it wants */
$services = [];
foreach ((new Monit())->service->iterateItems() as $uuid => $service) {
    $services[$uuid] = (string)$service->name;
}

$channels = [];
foreach ($model->channels->iterateItems() as $uuid => $channel) {
    $monit = [];
    foreach (explode(',', (string)$channel->monitServices) as $ref) {
        if (isset($services[$ref])) {
            $monit[] = $services[$ref];
        }
    }
    $channels[] = [
        'uuid' => $uuid,
        'enabled' => (string)$channel->enabled,
        'description' => (string)$channel->description,
        'service' => (string)$channel->service,
        'target' => (string)$channel->target,
        /* write-only in the UI, but the backend has to send with it */
        'url' => $channel->url->getValue(),
        'events' => array_values(array_filter(explode(',', (string)$channel->events))),
        'monit' => $monit,
    ];
}

$certificates = [];
foreach ([['cert', 'Certificate', (new Cert())->cert], ['ca', 'Authority', (new Ca())->ca]] as $set) {
    [$kind, $label, $items] = $set;
    foreach ($items->iterateItems() as $item) {
        $parsed = @openssl_x509_parse(base64_decode((string)$item->crt));
        if (empty($parsed['validTo_time_t'])) {
            continue;
        }
        $certificates[] = [
            'key' => $kind . ':' . (string)$item->refid,
            'label' => $label,
            'description' => (string)$item->descr ?: (string)$item->refid,
            'expires' => (int)$parsed['validTo_time_t'],
        ];
    }
}

$interfaces = [];
$uplinks = [];
foreach ($config->interfaces->children() ?? [] as $name => $interface) {
    $device = (string)$interface->if;
    if (empty($device)) {
        continue;
    }
    $interfaces[$device] = (string)$interface->descr ?: strtoupper($name);
    /* an uplink is anything with a gateway or a dynamically assigned address */
    $address = strtolower((string)$interface->ipaddr);
    if (!empty((string)$interface->gateway) || in_array($address, ['dhcp', 'pppoe', 'pptp', 'l2tp', 'ppp'])) {
        $uplinks[] = $device;
    }
}

$monit = new Monit();

echo json_encode([
    'revision' => [
        'time' => (string)($config->revision->time ?? ''),
        'username' => (string)($config->revision->username ?? ''),
        'description' => (string)($config->revision->description ?? ''),
    ],
    'hostname' => implode('.', array_filter([
        (string)($config->system->hostname ?? ''),
        (string)($config->system->domain ?? ''),
    ])),
    'general' => $general,
    'channels' => $channels,
    'certificates' => $certificates,
    'interfaces' => $interfaces,
    'uplinks' => $uplinks,
    'monit' => [
        'username' => trim((string)$monit->general->httpdUsername),
        'password' => trim((string)$monit->general->httpdPassword),
    ],
]);
