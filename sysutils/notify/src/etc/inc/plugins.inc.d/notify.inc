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

function notify_cron()
{
    $jobs = [];
    $model = new \OPNsense\Notify\Notify();

    if ((string)$model->general->enabled == '1') {
        $minutes = (string)$model->general->interval;
        /* state poll; the gateway and CARP syshooks only make it sooner */
        $jobs[]['autocron'] = ['/usr/local/sbin/configctl -d notify check', $minutes == '1' ? '*' : "*/{$minutes}"];

        if ((string)$model->general->firmwareCheck == '1' && $model->hasEvent('firmware')) {
            $jobs[]['autocron'] = ['/usr/local/sbin/configctl -d firmware poll', '0', '4'];
        }
    }

    return $jobs;
}

function notify_xmlrpc_sync()
{
    $result = [];

    $result['id'] = 'notify';
    $result['section'] = 'OPNsense.notify';
    $result['description'] = gettext('Notify');

    return [$result];
}
