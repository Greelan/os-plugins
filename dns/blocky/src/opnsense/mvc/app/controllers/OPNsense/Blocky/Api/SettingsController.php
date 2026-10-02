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

namespace OPNsense\Blocky\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Base\UserException;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'blocky';
    protected static $internalModelClass = '\OPNsense\Blocky\Blocky';

    /* array (grid) sections replaced wholesale on import */
    private static $importArrays = [
        'upstreams', 'bootstrap', 'denylists', 'allowlists', 'customdns', 'conditional',
        'customdnsrewrite', 'conditionalrewrite', 'clientgroups',
        'clientlookupclients', 'schedules',
    ];

    /**
     * Import an upstream Blocky config.yml: parse it via the Python helper,
     * replace the grid sections, overlay the scalar settings, validate, and
     * save. Existing grid entries are cleared so a re-import does not duplicate.
     */
    public function importAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'message' => gettext('Use a POST request.')];
        }
        /* unfiltered: the sanitiser escapes quotes and ampersands, which breaks the YAML */
        $payload = (string)$this->request->getPost('payload');
        if (trim($payload) === '') {
            return ['status' => 'failed', 'message' => gettext('No configuration was provided.')];
        }

        $tmpfile = tempnam(sys_get_temp_dir(), 'blocky_import_');
        if ($tmpfile === false || file_put_contents($tmpfile, $payload) === false) {
            return ['status' => 'failed', 'message' => gettext('Could not parse the configuration.')];
        }
        try {
            $raw = trim((new Backend())->configdpRun('blocky import', [$tmpfile]));
        } finally {
            @unlink($tmpfile);
        }

        $parsed = json_decode($raw, true);
        if (!is_array($parsed)) {
            return ['status' => 'failed', 'message' => gettext('Could not parse the configuration.')];
        }
        if (isset($parsed['error'])) {
            return ['status' => 'failed', 'message' => $parsed['error']];
        }

        Config::getInstance()->lock();
        $model = $this->getModel();

        // faithful mirror: reset everything to defaults so keys absent from the
        // file fall back to blocky's defaults (no stale values); keep the service
        // state and the certificate, plugin controls outside blocky's config.
        $enabled = (string)$model->general->enabled;
        $certificate = (string)$model->general->certificate;
        foreach ($model->getFlatNodes() as $node) {
            $node->applyDefault();
        }
        $model->general->enabled = $enabled;
        $model->general->certificate = $certificate;

        foreach (self::$importArrays as $name) {
            $uuids = [];
            foreach ($model->$name->iterateItems() as $uuid => $node) {
                $uuids[] = $uuid;
            }
            foreach ($uuids as $uuid) {
                $model->$name->del($uuid);
            }
        }
        foreach (($parsed['scalars'] ?? []) as $section => $fields) {
            $model->$section->setNodes($fields);
        }
        $counts = [];
        foreach (($parsed['arrays'] ?? []) as $name => $rows) {
            foreach ($rows as $row) {
                $model->$name->Add()->setNodes($row);
            }
            $counts[$name] = count($rows);
        }

        $errors = [];
        foreach ($model->performValidation(true) as $msg) {
            $errors[] = $msg->getField() . ': ' . $msg->getMessage();
        }
        if (!empty($errors)) {
            return [
                'status' => 'failed',
                'errors' => $errors,
                'message' => gettext('Imported values failed validation; nothing was saved.'),
            ];
        }

        /* the base save refuses read-only users and records the change */
        $this->save(false, true);
        return [
            'status' => 'ok',
            'counts' => $counts,
            'skipped' => $parsed['skipped'] ?? [],
            'warnings' => $parsed['warnings'] ?? [],
        ];
    }

    /**
     * toggleBase() and delBase() save without validating, so try the change first and refuse it
     * on any message it adds; the exception reaches the page as a dialog.
     */
    private function refuseIfInvalid(callable $change)
    {
        $before = [];
        foreach ($this->getModel()->performValidation(true) as $msg) {
            $before[$msg->getField() . ':' . $msg->getMessage()] = true;
        }
        $change($this->getModel());
        $added = [];
        foreach ($this->getModel()->performValidation(true) as $msg) {
            if (empty($before[$msg->getField() . ':' . $msg->getMessage()])) {
                $added[$msg->getMessage()] = true;
            }
        }
        $this->invalidateModel();
        if (!empty($added)) {
            throw new UserException(implode(' ', array_keys($added)), gettext('Blocky would not start'));
        }
    }

    private function toggleChecked($path, $uuids, $enabled)
    {
        if ($this->request->isPost()) {
            $this->refuseIfInvalid(function ($model) use ($path, $uuids, $enabled) {
                foreach (explode(',', (string)$uuids) as $uuid) {
                    $node = $model->getNodeByReference($path . '.' . $uuid);
                    if ($node !== null) {
                        $node->enabled = $enabled === null ? ((string)$node->enabled == '1' ? '0' : '1') : (string)$enabled;
                    }
                }
            });
        }
        return $this->toggleBase($path, $uuids, $enabled);
    }

    private function delChecked($path, $uuids)
    {
        if ($this->request->isPost()) {
            $this->refuseIfInvalid(function ($model) use ($path, $uuids) {
                foreach (explode(',', (string)$uuids) as $uuid) {
                    $model->getNodeByReference($path)->del($uuid);
                }
            });
        }
        return $this->delBase($path, $uuids);
    }

    /**
     * Which write-only secrets hold a value, so the page can offer to remove them. Never the values.
     */
    public function secretsAction()
    {
        $model = $this->getModel();
        $result = [];
        foreach (['redis.password', 'redis.sentinelPassword', 'queryLog.target'] as $ref) {
            $result[$ref] = $model->getNodeByReference($ref)->getValue() !== '';
        }
        return $result;
    }

    /* upstreams */
    public function searchUpstreamAction()
    {
        return $this->searchBase('upstreams', null, 'group');
    }

    public function getUpstreamAction($uuid = null)
    {
        return $this->getBase('upstream', 'upstreams', $uuid);
    }

    public function setUpstreamAction($uuid)
    {
        return $this->setBase('upstream', 'upstreams', $uuid);
    }

    public function addUpstreamAction()
    {
        return $this->addBase('upstream', 'upstreams');
    }

    public function delUpstreamAction($uuid)
    {
        return $this->delChecked('upstreams', $uuid);
    }

    public function toggleUpstreamAction($uuid, $enabled = null)
    {
        return $this->toggleChecked('upstreams', $uuid, $enabled);
    }

    /* bootstrap resolvers */
    public function searchBootstrapAction()
    {
        return $this->searchBase('bootstrap', null, 'content');
    }

    public function getBootstrapAction($uuid = null)
    {
        return $this->getBase('bootstrap', 'bootstrap', $uuid);
    }

    public function setBootstrapAction($uuid)
    {
        return $this->setBase('bootstrap', 'bootstrap', $uuid);
    }

    public function addBootstrapAction()
    {
        return $this->addBase('bootstrap', 'bootstrap');
    }

    public function delBootstrapAction($uuid)
    {
        return $this->delChecked('bootstrap', $uuid);
    }

    public function toggleBootstrapAction($uuid, $enabled = null)
    {
        return $this->toggleChecked('bootstrap', $uuid, $enabled);
    }

    /* denylists */
    public function searchDenylistAction()
    {
        return $this->searchBase('denylists', null, 'group');
    }

    public function getDenylistAction($uuid = null)
    {
        return $this->getBase('denylist', 'denylists', $uuid);
    }

    public function setDenylistAction($uuid)
    {
        return $this->setBase('denylist', 'denylists', $uuid);
    }

    public function addDenylistAction()
    {
        return $this->addBase('denylist', 'denylists');
    }

    public function delDenylistAction($uuid)
    {
        return $this->delChecked('denylists', $uuid);
    }

    public function toggleDenylistAction($uuid, $enabled = null)
    {
        return $this->toggleChecked('denylists', $uuid, $enabled);
    }

    /* allowlists */
    public function searchAllowlistAction()
    {
        return $this->searchBase('allowlists', null, 'group');
    }

    public function getAllowlistAction($uuid = null)
    {
        return $this->getBase('allowlist', 'allowlists', $uuid);
    }

    public function setAllowlistAction($uuid)
    {
        return $this->setBase('allowlist', 'allowlists', $uuid);
    }

    public function addAllowlistAction()
    {
        return $this->addBase('allowlist', 'allowlists');
    }

    public function delAllowlistAction($uuid)
    {
        return $this->delChecked('allowlists', $uuid);
    }

    public function toggleAllowlistAction($uuid, $enabled = null)
    {
        return $this->toggleChecked('allowlists', $uuid, $enabled);
    }

    /* custom DNS */
    public function searchCustomdnsAction()
    {
        return $this->searchBase('customdns', null, 'domain');
    }

    public function getCustomdnsAction($uuid = null)
    {
        return $this->getBase('customdns', 'customdns', $uuid);
    }

    public function setCustomdnsAction($uuid)
    {
        return $this->setBase('customdns', 'customdns', $uuid);
    }

    public function addCustomdnsAction()
    {
        return $this->addBase('customdns', 'customdns');
    }

    public function delCustomdnsAction($uuid)
    {
        return $this->delChecked('customdns', $uuid);
    }

    public function toggleCustomdnsAction($uuid, $enabled = null)
    {
        return $this->toggleChecked('customdns', $uuid, $enabled);
    }

    /* conditional forwarding */
    public function searchConditionalAction()
    {
        return $this->searchBase('conditional', null, 'domain');
    }

    public function getConditionalAction($uuid = null)
    {
        return $this->getBase('conditional', 'conditional', $uuid);
    }

    public function setConditionalAction($uuid)
    {
        return $this->setBase('conditional', 'conditional', $uuid);
    }

    public function addConditionalAction()
    {
        return $this->addBase('conditional', 'conditional');
    }

    public function delConditionalAction($uuid)
    {
        return $this->delChecked('conditional', $uuid);
    }

    public function toggleConditionalAction($uuid, $enabled = null)
    {
        return $this->toggleChecked('conditional', $uuid, $enabled);
    }

    /* client groups */
    public function searchClientgroupAction()
    {
        return $this->searchBase('clientgroups', null, 'client');
    }

    public function getClientgroupAction($uuid = null)
    {
        return $this->getBase('clientgroup', 'clientgroups', $uuid);
    }

    public function setClientgroupAction($uuid)
    {
        return $this->setBase('clientgroup', 'clientgroups', $uuid);
    }

    public function addClientgroupAction()
    {
        return $this->addBase('clientgroup', 'clientgroups');
    }

    public function delClientgroupAction($uuid)
    {
        return $this->delChecked('clientgroups', $uuid);
    }

    public function toggleClientgroupAction($uuid, $enabled = null)
    {
        return $this->toggleChecked('clientgroups', $uuid, $enabled);
    }

    /* client name mappings (clientLookup.clients) */
    public function searchClientlookupclientAction()
    {
        return $this->searchBase('clientlookupclients', null, 'name');
    }

    public function getClientlookupclientAction($uuid = null)
    {
        return $this->getBase('clientlookupclient', 'clientlookupclients', $uuid);
    }

    public function setClientlookupclientAction($uuid)
    {
        return $this->setBase('clientlookupclient', 'clientlookupclients', $uuid);
    }

    public function addClientlookupclientAction()
    {
        return $this->addBase('clientlookupclient', 'clientlookupclients');
    }

    public function delClientlookupclientAction($uuid)
    {
        return $this->delChecked('clientlookupclients', $uuid);
    }

    public function toggleClientlookupclientAction($uuid, $enabled = null)
    {
        return $this->toggleChecked('clientlookupclients', $uuid, $enabled);
    }

    /* custom DNS rewrites */
    public function searchCustomdnsrewriteAction()
    {
        return $this->searchBase('customdnsrewrite', null, 'fromDomain');
    }

    public function getCustomdnsrewriteAction($uuid = null)
    {
        return $this->getBase('customdnsrewrite', 'customdnsrewrite', $uuid);
    }

    public function setCustomdnsrewriteAction($uuid)
    {
        return $this->setBase('customdnsrewrite', 'customdnsrewrite', $uuid);
    }

    public function addCustomdnsrewriteAction()
    {
        return $this->addBase('customdnsrewrite', 'customdnsrewrite');
    }

    public function delCustomdnsrewriteAction($uuid)
    {
        return $this->delChecked('customdnsrewrite', $uuid);
    }

    public function toggleCustomdnsrewriteAction($uuid, $enabled = null)
    {
        return $this->toggleChecked('customdnsrewrite', $uuid, $enabled);
    }

    /* conditional rewrites */
    public function searchConditionalrewriteAction()
    {
        return $this->searchBase('conditionalrewrite', null, 'fromDomain');
    }

    public function getConditionalrewriteAction($uuid = null)
    {
        return $this->getBase('conditionalrewrite', 'conditionalrewrite', $uuid);
    }

    public function setConditionalrewriteAction($uuid)
    {
        return $this->setBase('conditionalrewrite', 'conditionalrewrite', $uuid);
    }

    public function addConditionalrewriteAction()
    {
        return $this->addBase('conditionalrewrite', 'conditionalrewrite');
    }

    public function delConditionalrewriteAction($uuid)
    {
        return $this->delChecked('conditionalrewrite', $uuid);
    }

    public function toggleConditionalrewriteAction($uuid, $enabled = null)
    {
        return $this->toggleChecked('conditionalrewrite', $uuid, $enabled);
    }

    /* schedules */
    public function searchScheduleAction()
    {
        return $this->searchBase('schedules', null, 'name');
    }

    public function getScheduleAction($uuid = null)
    {
        return $this->getBase('schedule', 'schedules', $uuid);
    }

    public function setScheduleAction($uuid)
    {
        return $this->setBase('schedule', 'schedules', $uuid);
    }

    public function addScheduleAction()
    {
        return $this->addBase('schedule', 'schedules');
    }

    public function delScheduleAction($uuid)
    {
        return $this->delChecked('schedules', $uuid);
    }

    public function toggleScheduleAction($uuid, $enabled = null)
    {
        return $this->toggleChecked('schedules', $uuid, $enabled);
    }
}
