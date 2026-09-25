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

namespace OPNsense\Blocky\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\Blocky\Blocky;

class M1_0_3 extends BaseModelMigration
{
    /**
     * Blocky runs as root, so what it reads or connects to no longer comes from free text: zone
     * $INCLUDE lines are dropped, resolv files outside the list directory are disabled, and Unix
     * socket addresses for Redis (other than the Redis plugin's) and dnstap are cleared, switching those off.
     * @param $model
     */
    public function run($model)
    {
        if (!($model instanceof Blocky)) {
            return;
        }

        $zone = (string)$model->general->customZone;
        if (Blocky::hasZoneInclude($zone)) {
            $model->general->customZone = preg_replace('/^\s*\$INCLUDE\b.*(\R|$)/mi', '', $zone);
        }

        foreach ($model->bootstrap->iterateItems() as $bootstrap) {
            if ((string)$bootstrap->type == 'resolvfile' && !Blocky::isListFile((string)$bootstrap->content)) {
                $bootstrap->enabled = '0';
            }
        }

        if (!Blocky::isAllowedRedisAddress((string)$model->redis->address)) {
            $model->redis->address = '';
            /* Redis cannot be required without an address */
            $model->redis->required = '0';
        }
        $sentinels = array_filter(explode(',', (string)$model->redis->sentinelAddresses), function ($address) {
            return !Blocky::isSocket(trim($address));
        });
        $model->redis->sentinelAddresses = implode(',', $sentinels);

        $target = $model->queryLog->target->getValue();
        if ((string)$model->queryLog->type == 'dnstap' && !Blocky::isDnstapTarget($target)) {
            $model->queryLog->target->applyDefault();
            $model->queryLog->type = 'none';
        }
    }
}
