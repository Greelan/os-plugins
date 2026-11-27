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
use OPNsense\Base\FieldTypes\BaseListField;
use OPNsense\Base\FieldTypes\BaseSetField;
use OPNsense\Base\Messages\Message;
use OPNsense\Core\Backend;
use OPNsense\Trust\Store;

/**
 * Class Blocky
 * @package OPNsense\Blocky
 */
class Blocky extends BaseModel
{
    /* Blocky runs as root, so a file it reads from disk lives in the plugin's own directory */
    public const HOSTS_FILES = ['/etc/hosts'];
    /* the socket the Redis plugin (databases/redis) opens */
    public const REDIS_SOCKETS = ['/var/run/redis/redis.sock'];
    /* the grid sections an import replaces */
    public const IMPORT_ARRAYS = ['upstreams', 'bootstrap', 'denylists', 'allowlists', 'customdns', 'conditional',
        'customdnsrewrite', 'conditionalrewrite', 'clientgroups', 'clientlookupclients', 'schedules'];
    /* control characters, but tab and line breaks, which fields take or refuse themselves */
    private const CONTROLS = '/[\x{0}-\x{8}\x{b}\x{c}\x{e}-\x{1f}\x{7f}-\x{9f}\x{2028}\x{2029}]/u';
    /* comma lists the settings keep as text */
    private const TEXT_LISTS = ['clientgroups.groups', 'schedules.groups'];
    private const LIST_DIR = '/^\/usr\/local\/etc\/blocky\/lists(\/(?!\.\.?(\/|$))[^\/\0]+)+$/u';
    private const SECRET_DIR = '/^\/usr\/local\/etc\/blocky\/secrets(\/(?!\.\.?(\/|$))[^\/\0]+)+$/u';
    /* database connection options that read a file, as root; matched anywhere, since PostgreSQL also
     * starts a keyword right after a quoted value */
    private const FILE_OPTIONS = '/(allowAllFiles|sslcert|sslkey|sslrootcert|passfile|servicefile)\s*=/i';

    /**
     * {@inheritdoc}
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);

        /* Blocky's YAML parser refuses DEL and the C1 controls, naming no setting; the template writes
         * NEL, LS and PS as the space YAML would read, and core drops the C0 controls on save */
        foreach ($this->getFlatNodes() as $ref => $node) {
            $value = $node->getValue();
            if (($validateFullModel || $node->isFieldChanged()) && preg_match(self::CONTROLS, $value)) {
                $messages->appendMessage(new Message(gettext('Enter text without control characters.'), $ref));
            }
        }

        /* Blocky refuses to start without an enabled upstream in the "default" group; a grid
         * dialog only sees messages on its own row, so the row edited away gets one too */
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
                foreach ($this->upstreams->iterateItems() as $upstream) {
                    if ($upstream->isFieldChanged()) {
                        $messages->appendMessage(new Message(
                            gettext('Blocky needs an enabled resolver in the "default" group; this was the last one.'),
                            $upstream->group->__reference
                        ));
                    }
                }
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

        /* each is a key in config.yml, and Blocky refuses a key given twice; the message goes on
         * the row being edited, else (checking the whole model) on the later rows. The template
         * writes a domain as Blocky matches it, lowercase and without a trailing dot, and keeps the
         * first of the rows stored that way, so a duplicate saved earlier does not stop Blocky. */
        foreach ([['customdnsrewrite', 'fromDomain'], ['conditionalrewrite', 'fromDomain'], ['schedules', 'name']] as [$array, $key]) {
            $rows = [];
            foreach ($this->$array->iterateItems() as $row) {
                if ((string)$row->enabled == '1') {
                    $name = (string)$row->$key;
                    $rows[$key == 'fromDomain' ? strtolower(rtrim($name, '.')) : $name][] = $row;
                }
            }
            foreach ($rows as $same) {
                if (count($same) < 2) {
                    continue;
                }
                $changed = array_filter($same, function ($row) {
                    return $row->isFieldChanged();
                });
                if (!$changed && !$validateFullModel) {
                    continue;
                }
                /* rows that are all new, as an import adds them, keep the first */
                foreach (count($changed) < count($same) ? $changed : array_slice($same, 1) as $row) {
                    $messages->appendMessage(new Message(
                        gettext('Another enabled entry already uses this; combine them or disable one.'),
                        $row->$key->__reference
                    ));
                }
            }
        }

        /* the database query log writer exits on a flush interval of zero */
        if (
            ($validateFullModel || $this->queryLog->flushInterval->isFieldChanged() ||
                $this->queryLog->type->isFieldChanged()) &&
            in_array((string)$this->queryLog->type, ['mysql', 'postgresql', 'timescale', 'sqlite']) &&
            preg_match('/^(0+(ns|us|ms|s|m|h))+$/', (string)$this->queryLog->flushInterval)
        ) {
            $messages->appendMessage(new Message(gettext('Enter a flush interval above zero.'), 'queryLog.flushInterval'));
        }

        /* Blocky exits on a block type that is neither a mode nor a list of addresses */
        if ($validateFullModel || $this->general->blockType->isFieldChanged()) {
            $type = trim((string)$this->general->blockType);
            foreach ($type === '' ? [] : explode(',', $type) as $part) {
                if (
                    !in_array(strtolower($type), ['zeroip', 'nxdomain', 'refused'], true) &&
                    filter_var(trim($part), FILTER_VALIDATE_IP) === false
                ) {
                    $messages->appendMessage(new Message(
                        gettext('Enter zeroIP, nxDomain, refused, or a comma separated list of IPv4/IPv6 addresses.'),
                        'general.blockType'
                    ));
                    break;
                }
            }
        }

        /* Blocky would connect to a dnstap socket, or a database that reads files, as root; the target is
         * write-only, so read the stored value */
        if (
            ($validateFullModel || $this->queryLog->type->isFieldChanged() ||
                $this->queryLog->target->isFieldChanged()) &&
            (string)$this->queryLog->type == 'dnstap' &&
            !self::isDnstapTarget($this->queryLog->target->getValue())
        ) {
            $messages->appendMessage(new Message(
                gettext('Enter a dnstap target as tcp://host:port.'),
                'queryLog.target'
            ));
        } elseif (
            ($validateFullModel || $this->queryLog->type->isFieldChanged() ||
                $this->queryLog->target->isFieldChanged()) &&
            in_array((string)$this->queryLog->type, ['mysql', 'postgresql', 'timescale']) &&
            !self::isDatabaseTarget($this->queryLog->target->getValue())
        ) {
            $messages->appendMessage(new Message(
                gettext('Leave out allowAllFiles, sslcert, sslkey, sslrootcert, passfile and servicefile, or give the connection string as a file: value.'),
                'queryLog.target'
            ));
        }

        /* Blocky resolves a bootstrap host name with the pinned addresses only, and refuses a plain
         * resolver it would have to look up first; one it cannot parse, blocky validate refuses */
        foreach ($this->bootstrap->iterateItems() as $bootstrap) {
            if ((string)$bootstrap->enabled != '1' || (string)$bootstrap->type != 'resolver') {
                continue;
            }
            if (!$validateFullModel && !$bootstrap->content->isFieldChanged() && !$bootstrap->ips->isFieldChanged()) {
                continue;
            }
            $host = $this->upstreamHost((string)$bootstrap->content) ?? $this->stampHost((string)$bootstrap->content);
            if ($host === null || $host === '' || filter_var(trim($host, '[]'), FILTER_VALIDATE_IP) !== false) {
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

        /* Blocky compiles the cache exclusions with Go's RE2 only once it serves, and exits on one it cannot */
        if ($validateFullModel || $this->general->cacheExclude->isFieldChanged()) {
            foreach (explode(',', (string)$this->general->cacheExclude) as $entry) {
                if (!self::isRegex(substr(trim($entry), 1, -1))) {
                    $messages->appendMessage(new Message(
                        gettext('Enter each pattern in Go syntax, without lookaround or backreferences.'),
                        'general.cacheExclude'
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

        /* Blocky reads a secret from the file a file: value names, as root */
        foreach (['redis.password', 'redis.sentinelPassword', 'queryLog.target'] as $ref) {
            $node = $this->getNodeByReference($ref);
            if (($validateFullModel || $node->isFieldChanged()) && !self::isAllowedSecret($node->getValue())) {
                $messages->appendMessage(new Message(
                    gettext('A file: value must name a file in /usr/local/etc/blocky/secrets.'),
                    $ref
                ));
            }
        }

        /* a resolv file Blocky reads is one the plugin keeps */
        foreach ($this->bootstrap->iterateItems() as $bootstrap) {
            if (
                (string)$bootstrap->enabled == '1' && (string)$bootstrap->type == 'resolvfile' &&
                ($validateFullModel || $bootstrap->isFieldChanged()) && !self::isListFile((string)$bootstrap->content)
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

        /* a list or hosts file on disk must be one the plugin keeps, or the system hosts file; a row is
         * checked whenever it changes, so switching one on that an upgrade switched off checks it too */
        foreach (['denylists', 'allowlists'] as $section) {
            foreach ($this->$section->iterateItems() as $item) {
                if (
                    (string)$item->enabled == '1' && ($validateFullModel || $item->isFieldChanged()) &&
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
     * Apply what import_config.py mapped: every setting back to its default except the service state and
     * the certificate, which are the plugin's own, and the grid sections replaced. As core's importCsv()
     * leaves out a record the model refuses, a refused row is left out and a refused setting goes back
     * to its default, or its whole section when the default is refused too; a refused list first keeps
     * the entries the model takes on their own.
     * @param array $parsed scalars, arrays and labels as import_config.py returns them
     * @return array 'left' says what was left out, 'errors' what no left out value answers (nothing is
     *               to be saved then), 'counts' the rows imported per grid section
     */
    public function applyImport(array $parsed)
    {
        $keep = ['general.enabled', 'general.certificate'];
        foreach ($this->getFlatNodes() as $ref => $node) {
            if (!in_array($ref, $keep)) {
                $node->applyDefault();
            }
        }
        foreach (self::IMPORT_ARRAYS as $name) {
            foreach (array_keys(iterator_to_array($this->$name->iterateItems())) as $uuid) {
                $this->$name->del($uuid);
            }
        }
        $labels = $parsed['labels']['scalars'] ?? [];
        $imported = [];
        foreach (($parsed['scalars'] ?? []) as $section => $fields) {
            $this->$section->setNodes($fields);
            foreach (array_keys($fields) as $field) {
                $imported["{$section}.{$field}"] = true;
            }
        }
        $rows = [];
        foreach (($parsed['arrays'] ?? []) as $name => $list) {
            foreach ($list as $index => $values) {
                $row = $this->$name->Add();
                $row->setNodes($values);
                $rows[$row->getAttributes()['uuid']] = [$name, $parsed['labels']['arrays'][$name][$index] ?? $name];
            }
        }

        $left = [];
        $reset = [];
        $tried = [];
        do {
            $errors = [];
            $todo = [];
            foreach ($this->performValidation(true) as $message) {
                $field = $message->getField();
                $text = (string)$message->getMessage();
                $section = strstr($field, '.', true);
                if (preg_match('/^\w+\.([0-9a-f-]{36})\./', $field, $match)) {
                    if (isset($rows[$match[1]])) {
                        $todo[] = [$match[1], $field, $rows[$match[1]][1], $text];
                    } else {
                        $errors[] = "{$field}: {$text}";
                    }
                } elseif (in_array($field, $keep) || isset($reset[$section])) {
                    $errors[] = ($labels[$field] ?? $field) . ": {$text}";
                } elseif (isset($imported[$field]) && !isset($reset[$field])) {
                    $todo[] = [$field, $field, $labels[$field] ?? $field, $text];
                } else {
                    $todo[] = [$section, null, $section, $text];
                }
            }
            if ($errors) {
                return ['left' => $left, 'errors' => $errors, 'counts' => []];
            }
            $done = [];
            foreach ($todo as [$what, $ref, $label, $text]) {
                if (isset($done[$what])) {
                    continue;
                }
                $done[$what] = true;
                if ($ref !== null && empty($tried[$ref])) {
                    $tried[$ref] = true;
                    if ($this->keepEntries($ref, $label, $left)) {
                        continue;
                    }
                }
                $left[] = sprintf(gettext('%s: not imported. %s'), $label, $text);
                if (isset($rows[$what])) {
                    $this->{$rows[$what][0]}->del($what);
                } elseif (strpos($what, '.') !== false) {
                    $this->getNodeByReference($what)->applyDefault();
                } else {
                    foreach ($this->getFlatNodes() as $ref => $node) {
                        if (strpos($ref, "{$what}.") === 0 && !in_array($ref, $keep)) {
                            $node->applyDefault();
                        }
                    }
                }
                $reset[$what] = true;
            }
        } while ($todo);

        $counts = [];
        foreach (array_keys($parsed['arrays'] ?? []) as $name) {
            $counts[$name] = count(iterator_to_array($this->$name->iterateItems()));
        }
        return ['left' => $left, 'errors' => [], 'counts' => $counts];
    }

    /**
     * Keep the entries of a refused list that the model takes on their own, saying in $left what it refuses.
     * @return bool whether an entry was kept
     */
    private function keepEntries($ref, $label, array &$left)
    {
        $node = $this->getNodeByReference($ref);
        if (
            !($node instanceof BaseSetField && $node->isList()) && !($node instanceof BaseListField) &&
            !in_array(preg_replace('/\.[0-9a-f-]{36}\./', '.', $ref), self::TEXT_LISTS)
        ) {
            return false;
        }
        $entries = array_values(array_filter(array_map('trim', explode(',', (string)$node)), 'strlen'));
        if (count($entries) < 2) {
            return false;
        }
        $kept = [];
        foreach ($entries as $entry) {
            $node->setValue($entry);
            $refused = null;
            foreach ($this->performValidation(true) as $message) {
                if ($message->getField() == $ref) {
                    $refused = (string)$message->getMessage();
                    break;
                }
            }
            if ($refused === null) {
                $kept[] = $entry;
            } else {
                $left[] = sprintf(gettext('%s: %s: not imported. %s'), $label, $entry, $refused);
            }
        }
        $node->setValue(implode(',', $kept));
        return !empty($kept);
    }

    /**
     * Is this a file in the plugin's list directory?
     */
    public static function isListFile($path)
    {
        return preg_match(self::LIST_DIR, self::rendered($path)) === 1;
    }

    /**
     * A value as the template writes it, which drops carriage returns; for a bootstrap entry's
     * content, which cannot refuse line breaks itself (AllowNewlines).
     */
    private static function rendered($value)
    {
        return str_replace("\r", '', (string)$value);
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
     * Does this database target leave files alone? MySQL's allowAllFiles lets the server read any file,
     * and PostgreSQL reads the files these options name, as root; a file: value is root's own. Matched
     * after URL decoding, as PostgreSQL decodes a URL's option names.
     */
    public static function isDatabaseTarget($target)
    {
        return self::secretFile($target) !== null || preg_match(self::FILE_OPTIONS, urldecode((string)$target)) !== 1;
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
     * Is this source a URL or inline entry, or a file Blocky may read? Blocky reads a source as a file
     * when it has a file:// prefix, or starts but does not end with a slash; a FILE:// one, which the
     * template writes inline, is refused all the same.
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
     * Is this certificate in the trust store, with a private key to serve it? A signing request
     * has a key but no certificate yet.
     */
    private function hasPrivateKey($refid)
    {
        $cert = Store::getCertificate($refid);
        return is_array($cert) && !empty($cert['prv']) && !empty($cert['subject']);
    }

    /**
     * Host part of an upstream, or null when it cannot be determined (a DNS stamp
     * carries its own addresses).
     */
    private function upstreamHost($value)
    {
        $value = trim($value);
        if ($value === '' || strpos($value, 'sdns://') === 0) {
            return null;
        }
        /* the prefixes Blocky knows, as it spells them; only https and quic take // */
        $rest = preg_replace('/^(tcp\+udp:|tcp-tls:|(https|quic):(\/\/)?)/', '', $value);
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
     * A dnstap target as Blocky parses it once it serves, which blocky validate does not: tcp:// and a
     * host and port as Go's SplitHostPort takes them. Blocky would connect to a Unix socket as root, so
     * none is taken. A file: value is read for one, and its directory checked with the other secrets.
     */
    public static function isDnstapTarget($target)
    {
        if (strpos((string)$target, 'file:') === 0) {
            return true;
        }
        return strpos((string)$target, 'tcp://') === 0 &&
            preg_match('/^(\[[^\[\]]+\]|[^:\[\]]+):[^:\[\]]+$/D', substr((string)$target, strlen('tcp://'))) === 1;
    }

    /**
     * Would Go's RE2 compile this pattern? It has no lookaround, backreferences, atomic groups,
     * possessive quantifiers or recursion, which PCRE has; past those, PCRE's verdict stands in for it.
     */
    private static function isRegex($pattern)
    {
        if (preg_match('/\(\?(<?[=!]|>|R|\(|[0-9])|\\\\[1-9gkGZ]|[*+?}]\+/', $pattern)) {
            return false;
        }
        /* a delimiter no setting can hold, as they refuse control characters */
        return @preg_match("\x01{$pattern}\x01u", '') !== false;
    }

    /**
     * A host name as Blocky's upstream parser takes it: no trailing dot, which PHP's filter allows.
     */
    private static function isHostName($host)
    {
        return substr($host, -1) !== '.' &&
            filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
    }

    /**
     * The host a stamp names, '' for none, null when the stamp does not parse.
     */
    private function stampHost($value)
    {
        $value = trim($value);
        if (strpos($value, 'sdns://') !== 0 || !$this->isStamp(substr($value, strlen('sdns://')), $host)) {
            return null;
        }
        return $host;
    }

    /**
     * Does this DNS stamp parse as one Blocky uses: plain DNS, DoH, DoT or DoQ, per draft-denis-dns-stamps?
     * $host receives the provider name, without its port, '' for a plain DNS stamp.
     */
    private function isStamp($encoded, &$host = null)
    {
        $host = '';
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
                !self::isHostName($hostname)
            ) {
                return false;
            }
            $host = $hostname;
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
        return (bool)preg_match('/^tcp\+udp:/i', trim($value)) ||
            !preg_match('/^(tcp-tls|https|quic|sdns):/i', trim($value));
    }

    /**
     * DNS ports Blocky answers on at every address: a bare port, :port, 0.0.0.0:port or [::]:port. Core
     * points clients and the firewall itself at the DNS service registered for port 53, so a listener on
     * one address is left out of that, as dns/bind and dns/dnscrypt-proxy do.
     */
    public function wildcardPorts()
    {
        $ports = [];
        foreach (explode(',', (string)$this->general->dnsPort) as $listener) {
            if (
                preg_match('/^(?:|:|0\.0\.0\.0:|\[::\]:)([0-9]+)$/', trim($listener), $match) &&
                !in_array($match[1], $ports, true)
            ) {
                $ports[] = $match[1];
            }
        }
        return trim((string)$this->general->dnsPort) === '' ? ['53'] : $ports;
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
