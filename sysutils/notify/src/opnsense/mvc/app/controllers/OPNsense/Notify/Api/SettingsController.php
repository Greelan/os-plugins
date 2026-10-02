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

namespace OPNsense\Notify\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'notify';
    protected static $internalModelClass = '\OPNsense\Notify\Notify';
    protected static $internalSaveRequiresAdmin = true;


    /* channels */
    public function searchChannelAction()
    {
        $result = $this->searchBase('channels', null, 'description');
        /* a grid row carries every field, and the URL holds the channel's credentials */
        foreach ($result['rows'] as &$row) {
            unset($row['url'], $row['%url'], $row['files'], $row['%files']);
            $row['target'] = self::shownTarget($row['service'] ?? '', $row['target'] ?? '');
        }

        return $result;
    }

    public function getChannelAction($uuid = null)
    {
        $result = $this->getBase('channel', 'channels', $uuid);
        if (isset($result['channel']['target'])) {
            $result['channel']['target'] = self::shownTarget($result['channel']['service'], $result['channel']['target']);
        }
        /* service fields for the dialog, without secrets; a key no form element maps to */
        $describe = $uuid != null ? (new Backend())->configdpRun('notify describe', [$uuid]) : '';
        $result['notify_apprise'] = json_decode($describe, true) ?: ['service' => ''];
        return $result;
    }

    /**
     * A webhook receiver's secret is often its path, which the backend now leaves out of the saved
     * URL it shows; a channel saved earlier still carries it until it is saved again.
     */
    private static function shownTarget($service, $target)
    {
        if (in_array($service, ['JSON', 'Form', 'XML']) && preg_match('#^([a-z]+://[^/]+)/.#i', $target, $match)) {
            return $match[1] . '/...';
        }
        return $target;
    }

    public function setChannelAction($uuid)
    {
        $overlay = $this->channelUrl($uuid);
        if (isset($overlay['validations'])) {
            return ['result' => 'failed', 'validations' => $overlay['validations']];
        }
        return $this->setBase('channel', 'channels', $uuid, $overlay);
    }

    public function addChannelAction()
    {
        $overlay = $this->channelUrl(null);
        if (isset($overlay['validations'])) {
            return ['result' => 'failed', 'validations' => $overlay['validations']];
        }
        return $this->addBase('channel', 'channels', $overlay);
    }

    /**
     * Compose the channel URL from the chosen service's fields, or take the URL as entered,
     * and check it with Apprise. Returns the fields to store, or validation messages.
     */
    private function channelUrl($uuid)
    {
        /* as save() requires, before the backend builds a URL from the stored secrets */
        $this->throwNotFullAdmin();
        if (!$this->request->isPost() || ($uuid !== null && !preg_match('/^[0-9a-f-]{36}$/i', (string)$uuid))) {
            return ['validations' => ['channel.url' => gettext('The channel could not be found.')]];
        }
        $channel = $this->request->getPost('channel');
        $apprise = $this->request->getPost('apprise');
        $service = (string)$this->request->getPost('apprise_service', 'string', '');
        $request = [
            'uuid' => (string)$uuid,
            'url' => is_array($channel) ? (string)($channel['url'] ?? '') : '',
            'service' => $service === '__custom' ? '' : $service,
            'fields' => is_array($apprise) ? $apprise : [],
        ];

        /* the request carries secrets, so hand it over in a private file rather than as an argument */
        $tmpfile = tempnam(sys_get_temp_dir(), 'notify_build_');
        if ($tmpfile === false || file_put_contents($tmpfile, json_encode($request)) === false) {
            return ['validations' => ['channel.url' => gettext('The URL could not be checked.')]];
        }
        try {
            $output = trim((new Backend())->configdpRun('notify build', [$tmpfile]));
        } finally {
            @unlink($tmpfile);
        }

        $result = json_decode($output, true);
        if (!is_array($result)) {
            /* the backend failed rather than answering; pass on what it said */
            $message = gettext('The URL could not be checked.');
            if ($output != '') {
                $message .= ' ' . (strlen($output) > 200 ? substr($output, 0, 200) . '...' : $output);
            }
            return ['validations' => ['channel.url' => $message]];
        }
        if (isset($result['error'])) {
            /* point at a row the user can actually see */
            if ($service === '__custom') {
                $field = $result['field'] ?? 'channel.url';
            } else {
                $field = 'apprise_service';
            }
            return ['validations' => [$field => $result['error']]];
        }
        return [
            'url' => $result['url'],
            'service' => $result['service'],
            'target' => $result['target'],
            /* an object even when empty, so a channel that stops using a file drops it */
            'files' => json_encode((object)($result['files'] ?? [])),
        ];
    }

    public function delChannelAction($uuid)
    {
        return $this->delBase('channels', $uuid);
    }

    public function toggleChannelAction($uuid, $enabled = null)
    {
        return $this->toggleBase('channels', $uuid, $enabled);
    }
}
