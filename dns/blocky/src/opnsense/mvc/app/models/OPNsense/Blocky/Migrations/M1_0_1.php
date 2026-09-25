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
use OPNsense\Core\Config;

class M1_0_1 extends BaseModelMigration
{
    /**
     * The download caches moved to fixed directories: a path that was set turns caching on.
     * Files outside the list directory are no longer read, so entries naming one are disabled,
     * and secrets Blocky would read from a file outside the secrets directory are cleared.
     * @param $model
     */
    public function run($model)
    {
        if (!($model instanceof Blocky)) {
            return;
        }

        $src = Config::getInstance()->object()->OPNsense->blocky ?? null;
        if (!empty((string)($src->general->downloadCachePath ?? ''))) {
            $model->general->downloadCache = '1';
        }
        if (!empty((string)($src->hostsFile->downloadCachePath ?? ''))) {
            $model->hostsFile->downloadCache = '1';
        }

        foreach (['denylists', 'allowlists'] as $section) {
            foreach ($model->$section->iterateItems() as $item) {
                if (!Blocky::isAllowedFile((string)$item->source)) {
                    $item->enabled = '0';
                }
            }
        }
        $sources = array_filter(explode(',', (string)$model->hostsFile->sources), function ($source) {
            return Blocky::isAllowedFile(trim($source), Blocky::HOSTS_FILES);
        });
        $model->hostsFile->sources = implode(',', $sources);

        foreach (['redis.password', 'redis.sentinelPassword', 'queryLog.target'] as $ref) {
            $node = $model->getNodeByReference($ref);
            if (!Blocky::isAllowedSecret($node->getValue())) {
                $node->applyDefault();
                if ($ref == 'queryLog.target') {
                    /* these log types need a target, so the log is switched off rather than left invalid */
                    $model->queryLog->type = 'none';
                }
            }
        }
    }
}
