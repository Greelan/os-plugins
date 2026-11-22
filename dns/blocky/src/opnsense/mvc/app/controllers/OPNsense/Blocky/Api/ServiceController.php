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

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

/**
 * Class ServiceController
 * @package OPNsense\Blocky
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\Blocky\Blocky';
    protected static $internalServiceTemplate = 'OPNsense/Blocky';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'blocky';

    /**
     * The template stages config.yml, and starting Blocky puts it in place only when Blocky can read it
     * (deploy.sh); a staged configuration Blocky would refuse to read leaves Blocky as it is, and says why.
     * A stopped Blocky also loses the configuration it last ran with, which a later start would run.
     */
    public function reconfigureAction()
    {
        if ($this->request->isPost() && $this->serviceEnabled()) {
            $backend = new Backend();
            if (trim($backend->configdpRun('template reload', [static::$internalServiceTemplate])) === 'OK') {
                /* "Error: " and Blocky's reason, or nothing */
                $refusal = trim($backend->configdRun('blocky configtest'));
                if (strpos($refusal, 'Error: ') === 0) {
                    $reason = substr($refusal, strlen('Error: '));
                    /* only when surely stopped: an unknown status may be a running Blocky */
                    if ($this->statusAction()['status'] === 'stopped') {
                        $backend->configdRun('blocky discard');
                        return ['status' => 'failed', 'status_msg' => sprintf(
                            gettext('Blocky would not start with this configuration, so it stays stopped: %s'),
                            $reason
                        )];
                    }
                    return ['status' => 'failed', 'status_msg' => sprintf(
                        gettext('Blocky would not start with this configuration, so it was left as it is: %s'),
                        $reason
                    )];
                }
            }
        }
        return parent::reconfigureAction();
    }
}
