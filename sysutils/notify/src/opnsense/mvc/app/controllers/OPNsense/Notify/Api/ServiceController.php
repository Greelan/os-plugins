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

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiControllerBase
{
    /**
     * Regenerate the cron jobs; the backend reads the saved settings on every run.
     */
    public function reconfigureAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        (new Backend())->configdRun('cron restart');
        return ['status' => 'ok'];
    }

    /**
     * Apprise services and the fields that make up their URLs.
     */
    public function servicesAction()
    {
        $services = json_decode((new Backend())->configdRun('notify services'), true);
        return is_array($services) ? ['status' => 'ok', 'services' => $services] : ['status' => 'failed'];
    }

    /**
     * What the last check recorded: when it ran and anything still queued.
     */
    public function statusAction()
    {
        $this->throwNotFullAdmin();

        $status = json_decode((new Backend())->configdRun('notify status'), true);
        return is_array($status) ? $status : ['status' => 'failed'];
    }

    /**
     * Take apart a URL the user pasted, so the dialog can fill in its fields.
     */
    public function importAction()
    {
        if (!$this->request->isPost()) {
            return ['error' => gettext('Use a POST request.')];
        }
        /* the URL carries credentials, so hand it over in a private file */
        $tmpfile = tempnam(sys_get_temp_dir(), 'notify_parse_');
        file_put_contents($tmpfile, json_encode(['url' => (string)$this->request->getPost('url', null, '')]));
        try {
            $result = json_decode((new Backend())->configdpRun('notify parse', [$tmpfile]), true);
        } finally {
            @unlink($tmpfile);
        }
        return is_array($result) ? $result : ['error' => gettext('The URL could not be read.')];
    }

    /**
     * Send a test notification to a saved channel.
     */
    public function testAction($uuid)
    {
        if (!$this->request->isPost() || !preg_match('/^[0-9a-f-]{36}$/i', (string)$uuid)) {
            return ['status' => 'failed', 'message' => gettext('Save the channel before testing it.')];
        }
        $result = json_decode((new Backend())->configdpRun('notify test', [$uuid]), true);
        if (!is_array($result)) {
            return ['status' => 'failed', 'message' => gettext('The test could not be run.')];
        }
        return $result;
    }
}
