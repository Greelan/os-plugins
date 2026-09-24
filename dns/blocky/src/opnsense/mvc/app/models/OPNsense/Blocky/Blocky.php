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

namespace OPNsense\Blocky;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;
use OPNsense\Core\Backend;
use OPNsense\Trust\Cert;

/**
 * Class Blocky
 * @package OPNsense\Blocky
 */
class Blocky extends BaseModel
{
    /* Blocky runs as root, so what it writes stays under /var, without . or .. segments */
    private const VAR_PATH = '/^\/var(\/(?!\.\.?(\/|$))[^\/\0]+)+\/?$/u';

    /**
     * {@inheritdoc}
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);

        /* Require at least one enabled upstream in the "default" group whenever
         * the service is enabled -- Blocky refuses to start without it. */
        if ((string)$this->general->enabled == '1') {
            $has_default = false;
            foreach ($this->upstreams->iterateItems() as $upstream) {
                if ((string)$upstream->enabled == '1' && (string)$upstream->group == 'default') {
                    $has_default = true;
                    break;
                }
            }
            if (!$has_default) {
                $messages->appendMessage(new Message(
                    gettext('Add at least one enabled upstream resolver in the "default" group before enabling Blocky.'),
                    'general.enabled'
                ));
            }
        }

        /* warn when a configured DNS port is already claimed by another service */
        if (
            ($validateFullModel || $this->general->enabled->isFieldChanged() || $this->general->dnsPort->isFieldChanged()) &&
            (string)$this->general->enabled == '1'
        ) {
            $dns_ports = $this->listenPorts();
            foreach (json_decode((new Backend())->configdpRun('service list'), true) ?? [] as $service) {
                if (empty($service['dns_ports']) || !is_array($service['dns_ports'])) {
                    continue;
                }
                if ($service['name'] != 'blocky' && array_intersect($dns_ports, $service['dns_ports'])) {
                    $messages->appendMessage(new Message(
                        sprintf(gettext('%s is currently using this port.'), $service['description']),
                        'general.dnsPort'
                    ));
                    break;
                }
            }
        }

        /* a schedule window needs both start and end, or neither (all-day) */
        foreach ($this->schedules->iterateItems() as $schedule) {
            $start = (string)$schedule->start;
            $end = (string)$schedule->end;
            if (($start === '') !== ($end === '')) {
                $target = $start === '' ? $schedule->start : $schedule->end;
                $messages->appendMessage(new Message(
                    gettext('Set both Start and End, or leave both empty for an all-day schedule.'),
                    $target->__reference
                ));
            }
        }

        /* Blocky exits when a resolver it is given does not parse */
        if ($validateFullModel || $this->general->clientLookupUpstream->isFieldChanged()) {
            $lookup = trim((string)$this->general->clientLookupUpstream);
            if ($lookup !== '' && !$this->isUpstream($lookup)) {
                $messages->appendMessage(new Message(
                    gettext('Enter a resolver, e.g. 192.168.1.1 or tcp-tls:dns.quad9.net.'),
                    'general.clientLookupUpstream'
                ));
            }
        }
        foreach ($this->conditional->iterateItems() as $mapping) {
            if ((string)$mapping->enabled != '1' || !($validateFullModel || $mapping->resolver->isFieldChanged())) {
                continue;
            }
            foreach (explode(',', (string)$mapping->resolver) as $resolver) {
                if (trim($resolver) !== '' && !$this->isUpstream($resolver)) {
                    $messages->appendMessage(new Message(
                        gettext('Enter a resolver, e.g. 192.168.1.1 or tcp-tls:dns.quad9.net.'),
                        $mapping->resolver->__reference
                    ));
                    break;
                }
            }
        }

        /* Blocky exits when a trust anchor is not a DNSKEY record with the SEP flag */
        if ($validateFullModel || $this->dnssec->trustAnchors->isFieldChanged()) {
            foreach (explode(',', (string)$this->dnssec->trustAnchors) as $anchor) {
                $anchor = trim($anchor);
                $is_ksk = preg_match('/\sDNSKEY\s+([0-9]+)\s/i', $anchor, $flags) && ($flags[1] & 1);
                if ($anchor !== '' && !$is_ksk) {
                    $messages->appendMessage(new Message(
                        gettext('Enter key signing keys as DNSKEY records, e.g. ". 172800 IN DNSKEY 257 3 8 AwEAA".'),
                        'dnssec.trustAnchors'
                    ));
                    break;
                }
            }
        }

        /* Blocky writes the CSV query log into an existing directory, and exits without one */
        if (
            ($validateFullModel || $this->queryLog->type->isFieldChanged() ||
                $this->queryLog->target->isFieldChanged()) &&
            in_array((string)$this->queryLog->type, ['csv', 'csv-client'])
        ) {
            $target = trim((string)$this->queryLog->target);
            if ($target !== '' && stripos($target, 'file:') !== 0) {
                if (!preg_match(self::VAR_PATH, $target)) {
                    $messages->appendMessage(new Message(
                        gettext('Enter a directory under /var.'),
                        'queryLog.target'
                    ));
                } elseif (!is_dir($target)) {
                    $messages->appendMessage(new Message(
                        gettext('This directory does not exist.'),
                        'queryLog.target'
                    ));
                }
            }
        }

        /* Blocky creates the SQLite database and its parent directory */
        if (
            ($validateFullModel || $this->queryLog->type->isFieldChanged() ||
                $this->queryLog->target->isFieldChanged()) &&
            (string)$this->queryLog->type == 'sqlite'
        ) {
            $target = trim((string)$this->queryLog->target);
            if ($target !== '' && !preg_match(self::VAR_PATH, $target)) {
                $messages->appendMessage(new Message(
                    gettext('Enter a file path under /var.'),
                    'queryLog.target'
                ));
            }
        }

        /* Blocky exits when Redis is required but cannot be reached, so at least insist on an address */
        if (
            ($validateFullModel || $this->redis->required->isFieldChanged() ||
                $this->redis->address->isFieldChanged()) &&
            (string)$this->redis->required == '1' && trim((string)$this->redis->address) === ''
        ) {
            $messages->appendMessage(new Message(
                gettext('Enter an address when Redis is required.'),
                'redis.address'
            ));
        }

        /* Blocky exits when a PROXY protocol listener family has no port configured */
        $proxy_ports = [
            'dns' => 'dnsPort', 'http' => 'httpPort', 'https' => 'httpsPort', 'tls' => 'tlsPort',
        ];
        if ($validateFullModel || $this->general->proxyProtocol->isFieldChanged()) {
            foreach (explode(',', (string)$this->general->proxyProtocol) as $listener) {
                $listener = trim($listener);
                if ($listener !== '' && trim((string)$this->general->{$proxy_ports[$listener]}) === '') {
                    $messages->appendMessage(new Message(
                        sprintf(gettext('Configure a %s port before requiring the PROXY protocol on it.'), $listener),
                        'general.proxyProtocol'
                    ));
                    break;
                }
            }
        }

        /* Blocky needs somewhere to write for these query log types */
        if (
            ($validateFullModel || $this->queryLog->type->isFieldChanged() ||
                $this->queryLog->target->isFieldChanged()) &&
            !in_array((string)$this->queryLog->type, ['none', 'console']) &&
            trim((string)$this->queryLog->target) === ''
        ) {
            $messages->appendMessage(new Message(
                gettext('Enter a target for this log type.'),
                'queryLog.target'
            ));
        }

        /* Blocky resolves a bootstrap host name with the pinned addresses only, and refuses a
         * plain resolver it would have to look up first */
        foreach ($this->bootstrap->iterateItems() as $bootstrap) {
            if ((string)$bootstrap->enabled != '1' || (string)$bootstrap->type != 'resolver') {
                continue;
            }
            if (!$validateFullModel && !$bootstrap->content->isFieldChanged() && !$bootstrap->ips->isFieldChanged()) {
                continue;
            }
            $host = $this->upstreamHost((string)$bootstrap->content);
            if ($host === null || filter_var($host, FILTER_VALIDATE_IP) !== false) {
                continue;
            }
            if ($this->bootstrapIsPlain((string)$bootstrap->content)) {
                $messages->appendMessage(new Message(
                    gettext('A plain resolver must be an IP address, Blocky cannot look up a host name here.'),
                    $bootstrap->content->__reference
                ));
            } elseif ((string)$bootstrap->ips == '') {
                $messages->appendMessage(new Message(
                    gettext('Pin the addresses of this host name, Blocky cannot look it up here.'),
                    $bootstrap->ips->__reference
                ));
            }
        }

        /* Blocky only warns about a group with no list, and that blocking never applies */
        $list_groups = [];
        foreach (['denylists', 'allowlists'] as $section) {
            foreach ($this->$section->iterateItems() as $item) {
                if ((string)$item->enabled == '1') {
                    $list_groups[(string)$item->group] = true;
                }
            }
        }
        foreach (['clientgroups', 'schedules'] as $section) {
            foreach ($this->$section->iterateItems() as $item) {
                if ((string)$item->enabled != '1' || !($validateFullModel || $item->groups->isFieldChanged())) {
                    continue;
                }
                foreach (explode(',', (string)$item->groups) as $group) {
                    $group = trim($group);
                    if ($group !== '' && empty($list_groups[$group])) {
                        $messages->appendMessage(new Message(
                            sprintf(gettext('There is no enabled deny or allow list in group "%s".'), $group),
                            $item->groups->__reference
                        ));
                        break;
                    }
                }
            }
        }

        /* Blocky exits on rate limiting with no rate, or a burst below it */
        if (
            ($validateFullModel || $this->rateLimit->enable->isFieldChanged() ||
                $this->rateLimit->rate->isFieldChanged() || $this->rateLimit->burst->isFieldChanged()) &&
            (string)$this->rateLimit->enable == '1'
        ) {
            $rate = (int)(string)$this->rateLimit->rate;
            $burst = (int)(string)$this->rateLimit->burst;
            if ($rate < 1) {
                $messages->appendMessage(new Message(
                    gettext('Set a rate of at least 1 when rate limiting is enabled.'),
                    'rateLimit.rate'
                ));
            }
            if ($burst > 0 && $burst < $rate) {
                $messages->appendMessage(new Message(
                    gettext('Burst must be at least the rate, or 0 to allow twice the rate.'),
                    'rateLimit.burst'
                ));
            }
        }

        /* Blocky exits on DNS64 with AAAA filtered, or a prefix it cannot synthesize with */
        if (
            ($validateFullModel || $this->dns64->enable->isFieldChanged() ||
                $this->dns64->prefix->isFieldChanged() || $this->filtering->queryTypes->isFieldChanged()) &&
            (string)$this->dns64->enable == '1'
        ) {
            foreach (explode(',', (string)$this->filtering->queryTypes) as $qtype) {
                if (strcasecmp(trim($qtype), 'AAAA') == 0) {
                    $messages->appendMessage(new Message(
                        gettext('Blocky will not start with DNS64 enabled while AAAA is a filtered query type.'),
                        'dns64.enable'
                    ));
                    break;
                }
            }
            foreach (explode(',', (string)$this->dns64->prefix) as $prefix) {
                $prefix = trim($prefix);
                if ($prefix === '') {
                    continue;
                }
                $bits = strpos($prefix, '/') === false ? '' : substr($prefix, strpos($prefix, '/') + 1);
                if (!in_array($bits, ['32', '40', '48', '56', '64', '96'], true)) {
                    $messages->appendMessage(new Message(
                        gettext('A DNS64 prefix must be /32, /40, /48, /56, /64 or /96.'),
                        'dns64.prefix'
                    ));
                    break;
                }
            }
        }

        /* Blocky exits when it cannot read the certificate it is pointed at */
        if ($validateFullModel || $this->general->certificate->isFieldChanged()) {
            $refid = (string)$this->general->certificate;
            if ($refid != '' && !$this->hasPrivateKey($refid)) {
                $messages->appendMessage(new Message(
                    gettext('This certificate is missing or has no private key.'),
                    'general.certificate'
                ));
            }
        }

        /* one of cert/key alone stops DoT/DoH, both empty means self-signed; a selected
         * certificate wins, so the paths are not used either way */
        if (
            (string)$this->general->certificate == '' && (
                $validateFullModel || $this->general->certFile->isFieldChanged() ||
                $this->general->keyFile->isFieldChanged()
            )
        ) {
            $cert = trim((string)$this->general->certFile);
            $key = trim((string)$this->general->keyFile);
            if (($cert === '') !== ($key === '')) {
                $messages->appendMessage(new Message(
                    gettext('Set both the certificate and key file, or leave both empty to self-sign.'),
                    $cert === '' ? 'general.certFile' : 'general.keyFile'
                ));
            }
        }

        return $messages;
    }

    /**
     * Is this certificate in the trust store, with a private key to serve it?
     */
    private function hasPrivateKey($refid)
    {
        foreach ((new Cert())->cert->iterateItems() as $cert) {
            if ((string)$cert->refid == $refid) {
                return !empty((string)$cert->prv);
            }
        }
        return false;
    }

    /**
     * Host part of an upstream, or null when it cannot be determined (a DNS stamp
     * carries its own addresses).
     */
    private function upstreamHost($value)
    {
        $value = trim($value);
        if ($value === '' || stripos($value, 'sdns://') === 0) {
            return null;
        }
        $rest = preg_replace('/^(tcp\+udp|tcp-tls|tcp|udp|https|quic):(\/\/)?/i', '', $value);
        $rest = preg_replace('/#.*$/', '', $rest);
        $rest = preg_replace('/\/.*$/', '', $rest);
        if (preg_match('/^\[(.+)\](?::[0-9]+)?$/', $rest, $matches)) {
            return $matches[1];
        }
        if (substr_count($rest, ':') > 1) {
            return $rest; /* bare IPv6 */
        }
        if (preg_match('/^(.*):[0-9]+$/', $rest, $matches)) {
            return $matches[1];
        }
        return $rest;
    }

    /**
     * Does this parse as an upstream resolver? Blocky exits when one does not.
     */
    private function isUpstream($value)
    {
        $value = trim($value);
        if ($value === '') {
            return false;
        }
        if (stripos($value, 'sdns://') === 0) {
            return true; /* a DNS stamp carries its own address */
        }
        $host = $this->upstreamHost($value);
        if (empty($host)) {
            return false;
        }
        return filter_var($host, FILTER_VALIDATE_IP) !== false ||
            filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }

    /**
     * Is this bootstrap resolver plain DNS, which Blocky requires to be an IP address?
     */
    private function bootstrapIsPlain($value)
    {
        return (bool)preg_match('/^(tcp\+udp|tcp|udp):/i', trim($value)) ||
            !preg_match('/^(tcp-tls|https|quic|sdns):/i', trim($value));
    }

    /**
     * DNS listener ports, one bare port per entry, deduped. dnsPort is a comma
     * list of "port" or "[ip]:port"; falls back to ['53'].
     */
    public function listenPorts()
    {
        $ports = [];
        foreach (explode(',', (string)$this->general->dnsPort) as $listener) {
            $listener = trim($listener);
            if ($listener === '') {
                continue;
            }
            $pos = strrpos($listener, ':');
            $port = trim($pos === false ? $listener : substr($listener, $pos + 1));
            if ($port !== '' && !in_array($port, $ports, true)) {
                $ports[] = $port;
            }
        }
        return $ports ?: ['53'];
    }
}
