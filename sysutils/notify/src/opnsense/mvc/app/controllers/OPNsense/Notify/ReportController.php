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

namespace OPNsense\Notify;

use OPNsense\Base\ControllerBase;
use OPNsense\Core\ACL;
use OPNsense\Core\Backend;
use OPNsense\Mvc\Dispatcher;

/**
 * One archived summary, as a page of its own; a GUI page, so an expired login returns here.
 */
class ReportController extends ControllerBase
{
    private $page = null;

    public function viewAction($name = null)
    {
        $name = (string)$name;
        if (
            !(new ACL())->hasPrivilege($this->getUserName(), 'page-all') ||
            !preg_match(Notify::REPORT_NAME, $name)
        ) {
            return;
        }
        $result = json_decode((new Backend())->configdpRun('notify report', [$name]), true);
        if (is_array($result) && ($result['status'] ?? '') === 'ok') {
            $this->page = base64_decode($result['payload']);
        }
    }

    public function afterExecuteRoute(Dispatcher $dispatcher)
    {
        if ($this->page === null) {
            $this->response->setStatusCode(404, 'Not Found');
            $this->response->setContent(gettext('This summary is not in the archive.'));
            return;
        }
        $this->response->setRawHeader('Content-Type: text/html; charset=utf-8');
        $this->response->setRawHeader(
            "Content-Security-Policy: default-src 'none'; img-src data:; style-src 'unsafe-inline'; sandbox"
        );
        $this->response->setRawHeader('X-Content-Type-Options: nosniff');
        $this->response->setContent($this->page);
    }
}
