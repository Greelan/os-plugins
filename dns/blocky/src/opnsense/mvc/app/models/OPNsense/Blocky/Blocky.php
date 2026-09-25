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
    /* Blocky runs as root, so a list it reads from disk lives in the plugin's own directory */
    public const HOSTS_FILES = ['/etc/hosts'];
    /* the socket the Redis plugin (databases/redis) opens */
    public const REDIS_SOCKETS = ['/var/run/redis/redis.sock'];
    private const LIST_DIR = '/^\/usr\/local\/etc\/blocky\/lists(\/(?!\.\.?(\/|$))[^\/\0]+)+$/u';
    /* the DNS type names Blocky 0.35 knows */
    private const QUERY_TYPES = ['A', 'AAAA', 'AFSDB', 'AMTRELAY', 'ANY', 'APL', 'ATMA', 'AVC', 'AXFR', 'CAA',
        'CDNSKEY', 'CDS', 'CERT', 'CNAME', 'CSYNC', 'DHCID', 'DLV', 'DNAME', 'DNSKEY', 'DS', 'EID', 'EUI48', 'EUI64',
        'GID', 'GPOS', 'HINFO', 'HIP', 'HTTPS', 'IPSECKEY', 'ISDN', 'IXFR', 'KEY', 'KX', 'L32', 'L64', 'LOC', 'LP',
        'MAILA', 'MAILB', 'MB', 'MD', 'MF', 'MG', 'MINFO', 'MR', 'MX', 'NAPTR', 'NID', 'NIMLOC', 'NINFO', 'NS',
        'NSAP-PTR', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'NULL', 'NXNAME', 'NXT', 'OPENPGPKEY', 'OPT', 'PTR', 'PX', 'RESINFO',
        'RKEY', 'RP', 'RRSIG', 'RT', 'SIG', 'SMIMEA', 'SOA', 'SPF', 'SRV', 'SSHFP', 'SVCB', 'TA', 'TALINK', 'TKEY',
        'TLSA', 'TSIG', 'TXT', 'UID', 'UINFO', 'UNSPEC', 'URI', 'X25', 'ZONEMD'];
    private const SECRET_DIR = '/^\/usr\/local\/etc\/blocky\/secrets(\/(?!\.\.?(\/|$))[^\/\0]+)+$/u';

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

        /* the masks take any five digits */
        foreach (['dnsPort', 'httpPort', 'tlsPort', 'httpsPort'] as $name) {
            $field = $this->general->$name;
            if (!$validateFullModel && !$field->isFieldChanged()) {
                continue;
            }
            foreach (explode(',', (string)$field) as $listener) {
                $pos = strrpos($listener, ':');
                if ((int)trim($pos === false ? $listener : substr($listener, $pos + 1)) > 65535) {
                    $messages->appendMessage(new Message(gettext('Enter a port no higher than 65535.'), $field->__reference));
                    break;
                }
            }
        }
        if ($validateFullModel || $this->filtering->queryTypes->isFieldChanged()) {
            foreach (explode(',', (string)$this->filtering->queryTypes) as $type) {
                if (trim($type) !== '' && !in_array(trim($type), self::QUERY_TYPES, true)) {
                    $messages->appendMessage(new Message(
                        sprintf(gettext('Blocky does not know the DNS type %s.'), trim($type)),
                        $this->filtering->queryTypes->__reference
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
        foreach ($this->upstreams->iterateItems() as $upstream) {
            if (
                (string)$upstream->enabled == '1' && ($validateFullModel || $upstream->server->isFieldChanged()) &&
                !$this->isUpstream((string)$upstream->server)
            ) {
                $messages->appendMessage(new Message(
                    gettext('Enter a resolver, e.g. 192.168.1.1 or tcp-tls:dns.quad9.net.'),
                    $upstream->server->__reference
                ));
            }
        }
        foreach ($this->conditional->iterateItems() as $mapping) {
            if ((string)$mapping->enabled != '1' || !($validateFullModel || $mapping->resolver->isFieldChanged())) {
                continue;
            }
            foreach (explode(',', (string)$mapping->resolver) as $resolver) {
                if (!$this->isUpstream($resolver)) { /* an empty entry too, which Blocky gets as '' */
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

        /* database and dnstap logs need a target (write-only, so read the stored value);
         * CSV and SQLite logs have fixed locations */
        if (
            ($validateFullModel || $this->queryLog->type->isFieldChanged() ||
                $this->queryLog->target->isFieldChanged()) &&
            in_array((string)$this->queryLog->type, ['mysql', 'postgresql', 'timescale', 'dnstap']) &&
            trim($this->queryLog->target->getValue()) === ''
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
            if (!$this->isUpstream((string)$bootstrap->content)) {
                $messages->appendMessage(new Message(
                    gettext('Enter a resolver, e.g. 1.1.1.1, tcp+udp:1.1.1.1 or https://1.1.1.1/dns-query.'),
                    $bootstrap->content->__reference
                ));
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

        /* Blocky reads a secret from the file a file: value names, as root, and refuses to start
         * when it cannot; a stored secret is checked again once a change puts it to use */
        $secrets = [
            'redis.password' => [['redis.address'], trim((string)$this->redis->address) !== ''],
            'redis.sentinelPassword' => [
                ['redis.address', 'redis.sentinelAddresses'],
                trim((string)$this->redis->address) !== '' && trim((string)$this->redis->sentinelAddresses) !== '',
            ],
            'queryLog.target' => [
                ['queryLog.type'],
                in_array((string)$this->queryLog->type, ['mysql', 'postgresql', 'timescale', 'dnstap']),
            ],
        ];
        foreach ($secrets as $ref => [$users, $used]) {
            $node = $this->getNodeByReference($ref);
            $changed = $validateFullModel || $node->isFieldChanged();
            if ($changed && !self::isAllowedSecret($node->getValue())) {
                $messages->appendMessage(new Message(
                    gettext('A file: value must name a file in /usr/local/etc/blocky/secrets.'),
                    $ref
                ));
                continue;
            }
            $recheck = false;
            foreach ($users as $user) {
                $recheck = $recheck || $this->getNodeByReference($user)->isFieldChanged();
            }
            $file = self::secretFile($node->getValue());
            if (($changed || ($used && $recheck)) && $file !== null && !is_file($file)) {
                $messages->appendMessage(new Message(gettext('This file does not exist.'), $ref));
            }
        }

        /* Blocky reads a zone $INCLUDE from disk as root */
        if (
            ($validateFullModel || $this->general->customZone->isFieldChanged()) &&
            self::hasZoneInclude((string)$this->general->customZone)
        ) {
            $messages->appendMessage(new Message(
                gettext('Enter the records themselves; Blocky would read an $INCLUDE file from disk.'),
                'general.customZone'
            ));
        } elseif (
            ($validateFullModel || $this->general->customZone->isFieldChanged()) &&
            ($error = self::zoneError((string)$this->general->customZone)) !== null
        ) {
            $messages->appendMessage(new Message($error, 'general.customZone'));
        }

        /* a resolv file Blocky reads is one the plugin keeps */
        foreach ($this->bootstrap->iterateItems() as $bootstrap) {
            if (
                (string)$bootstrap->type == 'resolvfile' &&
                ($validateFullModel || $bootstrap->content->isFieldChanged() || $bootstrap->type->isFieldChanged()) &&
                !self::isListFile((string)$bootstrap->content)
            ) {
                $messages->appendMessage(new Message(
                    gettext('A resolv file must be in /usr/local/etc/blocky/lists.'),
                    $bootstrap->content->__reference
                ));
            }
        }

        /* Blocky connects to a Unix socket as root, so only network addresses and the Redis
         * plugin's socket are taken */
        if (
            ($validateFullModel || $this->redis->address->isFieldChanged()) &&
            !self::isAllowedRedisAddress((string)$this->redis->address)
        ) {
            $messages->appendMessage(new Message(
                gettext('Enter a host and port, or the Redis plugin socket /var/run/redis/redis.sock.'),
                'redis.address'
            ));
        }
        if ($validateFullModel || $this->redis->sentinelAddresses->isFieldChanged()) {
            foreach (explode(',', (string)$this->redis->sentinelAddresses) as $address) {
                if (self::isSocket(trim($address))) {
                    $messages->appendMessage(new Message(
                        gettext('Enter hosts and ports, not Unix sockets.'),
                        'redis.sentinelAddresses'
                    ));
                    break;
                }
            }
        }
        if (
            ($validateFullModel || $this->queryLog->type->isFieldChanged() ||
                $this->queryLog->target->isFieldChanged()) &&
            (string)$this->queryLog->type == 'dnstap' &&
            !self::isDnstapTarget($this->queryLog->target->getValue())
        ) {
            $messages->appendMessage(new Message(
                gettext('Enter a tcp:// address, not a Unix socket.'),
                'queryLog.target'
            ));
        }

        /* a list or hosts file on disk must be one the plugin keeps, or the system hosts file */
        foreach (['denylists', 'allowlists'] as $section) {
            foreach ($this->$section->iterateItems() as $item) {
                if (
                    ($validateFullModel || $item->source->isFieldChanged()) &&
                    !self::isAllowedFile((string)$item->source)
                ) {
                    $messages->appendMessage(new Message(
                        gettext('A file must be in /usr/local/etc/blocky/lists.'),
                        $item->source->__reference
                    ));
                }
            }
        }
        if ($validateFullModel || $this->hostsFile->sources->isFieldChanged()) {
            foreach (explode(',', (string)$this->hostsFile->sources) as $source) {
                if (!self::isAllowedFile(trim($source), self::HOSTS_FILES)) {
                    $messages->appendMessage(new Message(
                        gettext('A file must be /etc/hosts or in /usr/local/etc/blocky/lists.'),
                        'hostsFile.sources'
                    ));
                    break;
                }
            }
        }

        return $messages;
    }

    /**
     * Does this custom zone pull in a file? The directive is matched case-insensitively.
     */
    public static function hasZoneInclude($zone)
    {
        return preg_match('/^\s*\$INCLUDE\b/mi', (string)$zone) === 1;
    }

    /**
     * Why Blocky would not parse this zone, or null. It follows miekg/dns as Blocky calls it, with no
     * origin; record types it does not know in detail pass, so a zone Blocky takes is never refused.
     */
    public static function zoneError($zone)
    {
        /* split into records: quotes, ; comments and ( ) continuations as the zone format has them */
        $records = [];
        $tokens = [];
        $token = null;
        $blank = false;
        $depth = 0;
        $quoted = false;
        $line = 1;
        $start = 1;
        $zone = str_replace("\r", '', (string)$zone);
        $length = strlen($zone);
        for ($i = 0; $i <= $length; $i++) {
            $c = $i < $length ? $zone[$i] : "\n";
            if ($quoted) {
                if ($c === "\n") {
                    return sprintf(gettext('Line %d: a quote is not closed.'), $line);
                }
                $token .= $c;
                if ($c === '\\' && $i + 1 < $length) {
                    $token .= $zone[++$i];
                } elseif ($c === '"') {
                    $quoted = false;
                }
                continue;
            }
            if ($c === '"') {
                $token .= $c;
                $quoted = true;
                continue;
            }
            if ($c === ';') {
                while ($i + 1 < $length && $zone[$i + 1] !== "\n") {
                    $i++;
                }
                continue;
            }
            if (in_array($c, [' ', "\t", "\n", '(', ')'], true)) {
                if ($token !== null) {
                    $tokens[] = $token;
                    $token = null;
                }
                if (($c === ' ' || $c === "\t") && empty($tokens) && ($i === 0 || $zone[$i - 1] === "\n")) {
                    $blank = true;
                } elseif ($c === '(') {
                    $depth++;
                } elseif ($c === ')' && --$depth < 0) {
                    return sprintf(gettext('Line %d: a ) has no ( before it.'), $line);
                } elseif ($c === "\n") {
                    if ($depth === 0) {
                        if (!empty($tokens)) {
                            $records[] = [$start, $blank, $tokens];
                        }
                        $tokens = [];
                        $blank = false;
                        $start = $line + 1;
                    }
                    $line++;
                }
                continue;
            }
            $token .= $c;
            if ($c === '\\' && $i + 1 < $length) {
                $token .= $zone[++$i];
            }
        }
        if ($depth > 0) {
            return sprintf(gettext('Line %d: a ( is not closed.'), $start);
        }

        $origin = false;
        $defaultTtl = false;
        $lastTtl = false;
        $isTtl = function ($value) {
            if (!preg_match('/^([0-9]+[smhdw]?)+$/i', $value)) {
                return false;
            }
            $total = 0;
            preg_match_all('/([0-9]+)([smhdw]?)/i', $value, $parts, PREG_SET_ORDER);
            foreach ($parts as $part) {
                $total += (int)$part[1] * ['' => 1, 's' => 1, 'm' => 60, 'h' => 3600, 'd' => 86400,
                    'w' => 604800][strtolower($part[2])];
            }
            return $total <= 4294967295;
        };
        $isName = function ($value) use (&$origin) {
            if ($value === '@') {
                return $origin;
            }
            if ($value !== '.' && preg_match('/(^|[^\\\\])\.\.|^\./', $value)) {
                return false;
            }
            return substr($value, -1) === '.' || $origin;
        };
        $isPort = function ($value) {
            return preg_match('/^[0-9]+$/', $value) && (int)$value <= 65535;
        };
        foreach ($records as [$at, $blank, $tokens]) {
            if (!$blank && $tokens[0][0] === '$') {
                $directive = strtoupper($tokens[0]);
                if ($directive === '$TTL' && count($tokens) === 2 && $isTtl($tokens[1])) {
                    $defaultTtl = true;
                } elseif ($directive === '$ORIGIN' && count($tokens) === 2 && $isName($tokens[1])) {
                    $origin = true;
                } elseif ($directive === '$GENERATE' && count($tokens) > 2 && !$isName($tokens[2])) {
                    return sprintf(gettext('Line %d: end the name %s with a dot, or put an $ORIGIN line before it.'),
                        $at, $tokens[2]);
                } elseif ($directive !== '$GENERATE' && $directive !== '$INCLUDE') {
                    return sprintf(gettext('Line %d: %s is not a directive Blocky reads this way.'), $at, $tokens[0]);
                }
                continue;
            }
            $i = 0;
            if (!$blank && !$isName($tokens[$i++])) {
                return sprintf(gettext('Line %d: end the name %s with a dot, or put an $ORIGIN line before it.'),
                    $at, $tokens[0]);
            }
            $ttl = $class = false;
            while ($i < count($tokens)) {
                if (!$ttl && $isTtl($tokens[$i])) {
                    $ttl = true;
                } elseif (!$class && preg_match('/^(IN|CS|CH|HS|NONE|ANY|CLASS[0-9]+)$/i', $tokens[$i])) {
                    $class = true;
                } else {
                    break;
                }
                $i++;
            }
            $type = strtoupper($tokens[$i++] ?? '');
            if (
                !preg_match('/^TYPE[0-9]+$/', $type) &&
                (!in_array($type, self::QUERY_TYPES, true) || in_array($type, ['ANY', 'OPT'], true))
            ) {
                return sprintf(gettext('Line %d: expected a record type such as A, AAAA or CNAME.'), $at);
            }
            if (!$ttl && !$class && !$defaultTtl && !$lastTtl) {
                return sprintf(gettext('Line %d: give the record a TTL or the class IN, or put a $TTL line before it.'), $at);
            }
            $lastTtl = $lastTtl || $ttl;
            $data = array_slice($tokens, $i);
            $valid = true;
            if (count($data) > 0) {
                switch ($type) {
                    case 'A':
                        $valid = count($data) === 1 && preg_match('/^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}' .
                            '(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$/', $data[0]);
                        break;
                    case 'AAAA':
                        $valid = count($data) === 1 && filter_var($data[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
                        break;
                    case 'CNAME':
                    case 'DNAME':
                    case 'NS':
                    case 'PTR':
                        $valid = count($data) === 1 && $isName($data[0]);
                        break;
                    case 'MX':
                        $valid = count($data) === 2 && $isPort($data[0]) && $isName($data[1]);
                        break;
                    case 'SRV':
                        $valid = count($data) === 4 && $isPort($data[0]) && $isPort($data[1]) && $isPort($data[2]) &&
                            $isName($data[3]);
                        break;
                }
            }
            if (!$valid) {
                return sprintf(gettext('Line %d: the %s record data is not valid; names end with a dot unless ' .
                    'an $ORIGIN line comes first.'), $at, $type);
            }
        }
        return null;
    }

    /**
     * Is this a file in the plugin's list directory?
     */
    public static function isListFile($path)
    {
        return preg_match(self::LIST_DIR, (string)$path) === 1;
    }

    /**
     * Would Blocky read this address as a Unix socket? It does for a leading slash.
     */
    public static function isSocket($address)
    {
        return substr((string)$address, 0, 1) === '/';
    }

    /**
     * Is this Redis address a network address, or the Redis plugin's own socket?
     */
    public static function isAllowedRedisAddress($address)
    {
        return !self::isSocket($address) || in_array((string)$address, self::REDIS_SOCKETS, true);
    }

    /**
     * Is this dnstap target empty, a tcp:// address, or a file: secret the plugin allows?
     */
    public static function isDnstapTarget($target)
    {
        $target = trim((string)$target);
        return $target === '' || strpos($target, 'tcp://') === 0 ||
            (self::secretFile($target) !== null && self::isAllowedSecret($target));
    }

    /**
     * Is this a literal secret, or a file: value Blocky may read? Blocky cuts file:// first,
     * then file:, case-sensitively.
     */
    public static function isAllowedSecret($value)
    {
        $path = self::secretFile($value);
        return $path === null || preg_match(self::SECRET_DIR, $path) === 1;
    }

    /**
     * The file Blocky reads a file: secret from, or null for a literal value.
     */
    private static function secretFile($value)
    {
        foreach (['file://', 'file:'] as $prefix) {
            if (strpos((string)$value, $prefix) === 0) {
                return substr((string)$value, strlen($prefix));
            }
        }
        return null;
    }

    /**
     * Is this source a URL or inline entry, or a file Blocky may read? Blocky reads a
     * source as a file when it has a file:// prefix, or starts but does not end with a slash.
     */
    public static function isAllowedFile($source, $extra = [])
    {
        $path = stripos($source, 'file://') === 0 ? substr($source, 7) : $source;
        if ($path === $source && (substr($source, 0, 1) !== '/' || substr($source, -1) === '/')) {
            return true;
        }
        return in_array($path, $extra, true) || preg_match(self::LIST_DIR, $path) === 1;
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
    private function upstreamHost($value, &$port = null)
    {
        $port = null;
        $value = trim($value);
        if ($value === '' || strpos($value, 'sdns://') === 0) {
            return null;
        }
        /* the prefixes Blocky knows, as it spells them; only https and quic take // */
        $rest = preg_replace('/^(tcp\+udp:|tcp-tls:|(https|quic):(\/\/)?)/', '', $value);
        $rest = preg_replace('/#.*$/', '', $rest);
        $rest = preg_replace('/\/.*$/', '', $rest);
        if (preg_match('/^\[(.+)\](?::([0-9]+))?$/', $rest, $matches)) {
            $port = $matches[2] ?? null;
            return $matches[1];
        }
        if (substr_count($rest, ':') > 1) {
            return $rest; /* bare IPv6 */
        }
        if (preg_match('/^(.*):([0-9]+)$/', $rest, $matches)) {
            $port = $matches[2];
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
        if (strpos($value, 'sdns://') === 0) {
            return $this->isStamp(substr($value, strlen('sdns://')));
        }
        $host = $this->upstreamHost($value, $port);
        if (empty($host) || ($port !== null && ((int)$port < 1 || (int)$port > 65535))) {
            return false;
        }
        return filter_var($host, FILTER_VALIDATE_IP) !== false ||
            filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }

    /**
     * Does this DNS stamp parse as one Blocky uses: plain DNS, DoH, DoT or DoQ, per draft-denis-dns-stamps?
     */
    private function isStamp($encoded)
    {
        $raw = base64_decode(strtr($encoded, '-_', '+/'), true);
        if ($raw === false || strlen($raw) < 9 || !in_array(ord($raw[0]), [0x00, 0x02, 0x03, 0x04], true)) {
            return false;
        }
        $proto = ord($raw[0]);
        $pos = 9; /* protocol byte and 8 bytes of properties */
        $lp = function () use ($raw, &$pos) {
            if ($pos >= strlen($raw) || $pos + 1 + ord($raw[$pos]) > strlen($raw)) {
                return null;
            }
            $value = substr($raw, $pos + 1, ord($raw[$pos]));
            $pos += 1 + ord($raw[$pos]);
            return $value;
        };
        $vlp = function () use ($raw, &$pos) {
            do {
                if ($pos >= strlen($raw)) {
                    return false;
                }
                $more = ord($raw[$pos]) & 0x80;
                $length = ord($raw[$pos]) & 0x7f;
                if ($pos + 1 + $length > strlen($raw)) {
                    return false;
                }
                $pos += 1 + $length;
            } while ($more);
            return true;
        };
        if ($lp() === null) {
            return false; /* address */
        }
        if ($proto != 0x00) {
            if (!$vlp() || ($hostname = $lp()) === null || ($proto == 0x02 && $lp() === null)) {
                return false; /* hashes, host name, and a DoH path */
            }
            $hostname = preg_replace('/:[0-9]+$/', '', $hostname);
            if (
                $hostname !== '' && filter_var(trim($hostname, '[]'), FILTER_VALIDATE_IP) === false &&
                filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false
            ) {
                return false;
            }
            if ($pos < strlen($raw) && !$vlp()) {
                return false; /* optional bootstrap addresses */
            }
        }
        return $pos == strlen($raw);
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
