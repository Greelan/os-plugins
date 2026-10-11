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

namespace OPNsense\Notify\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\Notify\Notify;

/**
 * Saved email PGP settings, Apprise API and Fluxer URLs rewritten so Apprise 2 reads them as Apprise
 * 1.13 did.
 */
class M1_0_1 extends BaseModelMigration
{
    /* Apprise's PGP modes, its default first */
    private const PGP_MODES = ['no', 'sign', 'encrypt'];

    public function run($model)
    {
        if (!$model instanceof Notify) {
            return;
        }
        foreach ($model->channels->iterateItems() as $channel) {
            // an update-only field reads as empty when cast to a string
            $files = json_decode($channel->files->getValue(), true);
            [$url, $files] = self::rewrite($channel->url->getValue(), is_array($files) ? $files : []);
            if ($url !== $channel->url->getValue()) {
                $channel->url = $url;
                $channel->files = json_encode((object)$files);
            }
        }
    }

    /**
     * [url, files] as Apprise 1.13 read them; other URLs are returned as given
     */
    public static function rewrite(string $url, array $files): array
    {
        // Apprise 1.13 read no version=, v= or path= here
        // Apprise does not read a URL whose first ? ends it
        $readable = strpos($url, '?') !== strlen($url) - 1;
        if ($readable && preg_match('/\A\s*apprises?:[\/\\\\]+/i', $url)) {
            return [self::pinned($url, ['version', 'v'], 'version=1'), $files];
        }
        if ($readable && preg_match('/\A\s*fluxers?:[\/\\\\]+/i', $url)) {
            return [self::pinned($url, ['path'], 'path=/'), $files];
        }
        if (!preg_match('/\A\s*mailtos?:[\/\\\\]+[^?]+\?/i', $url)) {
            return [$url, $files];
        }
        [$base, $query] = explode('?', $url, 2);
        // parts and the & or ; before each, split where Apprise's parse_qsd splits
        $tokens = preg_split('/([&;])/', $query, -1, PREG_SPLIT_DELIM_CAPTURE);
        $parts = [];
        foreach ($tokens as $i => $token) {
            if ($i % 2 == 0) {
                $parts[] = ['sep' => $i ? $tokens[$i - 1] : '', 'text' => $token];
            }
        }
        $last = [];
        foreach ($parts as $i => $part) {
            [$key, $value] = self::pair($part['text']);
            $parts[$i] += ['key' => $key, 'value' => $value];
            $last[$key] = $value;
        }

        $changed = false;
        foreach ($parts as $i => $part) {
            if ($part['key'] == 'pgp' && !self::readByApprise2($part['value'])) {
                $parts[$i]['text'] = 'pgp=' . self::pgpMode($part['value']);
                $changed = true;
            }
        }

        // Apprise 1.13 took pgppub= over pgpkey=, and either only when not empty
        if (isset($last['pgpkey'])) {
            $changed = true;
            $rename = $last['pgpkey'] !== '' && ($last['pgppub'] ?? '') === '';
            foreach ($parts as $i => $part) {
                if ($part['key'] == 'pgpkey' && $rename) {
                    $parts[$i]['text'] = 'pgppub' . substr($part['text'], strcspn($part['text'], '='));
                } elseif ($part['key'] == 'pgpkey' || ($part['key'] == 'pgppub' && $rename)) {
                    unset($parts[$i]);
                }
            }
            if ($rename && isset($files['pgpkey'])) {
                $files['pgppub'] = $files['pgpkey'];
            } elseif ($rename) {
                unset($files['pgppub']);
            }
            unset($files['pgpkey']);
        }
        if (!$changed) {
            return [$url, $files];
        }

        $query = '';
        foreach (array_values($parts) as $i => $part) {
            $query .= ($i ? ($part['sep'] ?: '&') : '') . $part['text'];
        }
        // Apprise does not read a URL ending in a bare ?
        return [$base . ($query !== '' ? '?' . $query : ''), $files];
    }

    /**
     * The URL with any query part named in keys replaced by part, given last
     */
    private static function pinned(string $url, array $keys, string $part): string
    {
        // a newline at the end, which Apprise reads past, would otherwise come before the part
        $url = substr($url, -1) === "\n" ? substr($url, 0, -1) : $url;
        [$base, $query] = array_pad(explode('?', $url, 2), 2, '');
        $parts = [];
        foreach (preg_split('/[&;]/', $query) as $text) {
            if ($text !== '' && !in_array(self::pair($text)[0], $keys, true)) {
                $parts[] = $text;
            }
        }
        $parts[] = $part;
        return $base . '?' . implode('&', $parts);
    }

    /**
     * [key, value] of a query part as Apprise's parse_qsd reads it
     */
    private static function pair(string $text): array
    {
        $pair = explode('=', $text, 2);
        $name = substr($pair[0], 0, 1) . str_replace('+', ' ', substr($pair[0], 1));
        // the Kelvin sign is the one letter Python lowers to an ASCII one, k
        $name = strtolower(str_replace("\u{212A}", 'k', self::strip(self::decoded($name))));
        return [$name, self::strip(self::decoded($pair[1] ?? ''))];
    }

    /**
     * Percent-decoded as Python's unquote() does: bytes that are no UTF-8 become U+FFFD
     */
    private static function decoded(string $text): string
    {
        $valid = '[\x00-\x7F]|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|' .
            '[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}|\xED[\x80-\x9F][\x80-\xBF]|' .
            '\xF0[\x90-\xBF][\x80-\xBF]{2}|[\xF1-\xF3][\x80-\xBF]{3}|\xF4[\x80-\x8F][\x80-\xBF]{2}';
        // a sequence cut short goes as one U+FFFD, as Python decodes it, any other byte as one each
        $cut = '\xE0[\xA0-\xBF]?|[\xE1-\xEC\xEE\xEF][\x80-\xBF]?|\xED[\x80-\x9F]?|\xF0(?:[\x90-\xBF][\x80-\xBF]?)?|' .
            '[\xF1-\xF3](?:[\x80-\xBF][\x80-\xBF]?)?|\xF4(?:[\x80-\x8F][\x80-\xBF]?)?';
        return preg_replace_callback("/({$valid})|{$cut}|./s", function ($match) {
            return isset($match[1]) && $match[1] !== '' ? $match[1] : "\u{FFFD}";
        }, rawurldecode($text));
    }

    /**
     * The text without the whitespace around it, as Python's strip() takes it, Unicode's included
     */
    private static function strip(string $text): string
    {
        // Python's whitespace exactly; PCRE's \s also takes e.g. U+180E
        $space = '[\x{09}-\x{0D}\x{1C}-\x{20}\x{85}\x{A0}\x{1680}\x{2000}-\x{200A}' .
            '\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]';
        return preg_replace("/\\A{$space}+|{$space}+\\z/u", '', $text) ?? $text;
    }

    /**
     * Does Apprise 2 take this pgp= value: empty, none, or the start of a mode?
     */
    private static function readByApprise2(string $value): bool
    {
        $value = strtolower($value);
        if ($value === '' || $value === 'none') {
            return true;
        }
        foreach (self::PGP_MODES as $mode) {
            if (strpos($mode, $value) === 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * The mode Apprise 1.13 read for a pgp= Apprise 2 refuses: yes (parse_bool) as encrypt, else no
     */
    private static function pgpMode(string $value): string
    {
        $start = substr(strtolower($value), 0, 2);
        return in_array($start, ['en', 'al', 't', 'y', 'ye', 'on', '1', 'tr'], true) ? 'encrypt' : 'no';
    }
}
