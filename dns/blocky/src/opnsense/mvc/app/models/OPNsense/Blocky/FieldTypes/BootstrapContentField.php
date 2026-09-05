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

namespace OPNsense\Blocky\FieldTypes;

use OPNsense\Base\FieldTypes\BaseField;
use OPNsense\Base\Validators\CallbackValidator;

/**
 * Class BootstrapContentField
 *
 * A bootstrap entry holds either a resolver or the path to a resolv.conf-style
 * file, decided by the sibling "type" field, so the content is validated per type.
 *
 * @package OPNsense\Blocky\FieldTypes
 */
class BootstrapContentField extends BaseField
{
    /**
     * @var bool marks if this is a data node or a container
     */
    protected $internalIsContainer = false;

    /**
     * {@inheritdoc}
     */
    public function getValidators()
    {
        $validators = parent::getValidators();

        if ($this->internalValue != null) {
            if ((string)$this->getParentNode()->type == 'resolvfile') {
                $validators[] = new CallbackValidator(["callback" => function ($data) {
                    if (!preg_match('/^\/[^\s\'"]*$/', (string)$data)) {
                        return [gettext('Enter an absolute path, e.g. /etc/resolv.conf.')];
                    }
                    return [];
                }
                ]);
            } else {
                $validators[] = new CallbackValidator(["callback" => function ($data) {
                    if (!preg_match('/^[^\s\'"]+$/', (string)$data)) {
                        return [gettext(
                            'Enter a resolver, e.g. 1.1.1.1, tcp+udp:1.1.1.1 or https://1.1.1.1/dns-query.'
                        )];
                    }
                    return [];
                }
                ]);
            }
        }

        return $validators;
    }
}
