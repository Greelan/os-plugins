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


namespace OPNsense\Backup;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

/**
 * Class S3Settings
 * @package OPNsense\Backup
 */
class S3Settings extends BaseModel
{
    /**
     * What an enabled backup needs. The secrets are write-only, so their stored values are read.
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);

        if ((string)$this->enabled != '1') {
            return $messages;
        }
        $required = [
            'endpoint' => gettext('Enter the S3 endpoint.'),
            'bucket' => gettext('Enter the bucket.'),
            'prefix' => gettext('Enter a folder for this firewall.'),
            'accessKey' => gettext('Enter the access key ID.'),
            'secretKey' => gettext('Enter the secret access key.'),
            'password' => gettext('Enter a password to encrypt the backups with; they are only sent encrypted.'),
        ];
        foreach ($required as $field => $message) {
            if ($this->$field->getValue() === '') {
                $messages->appendMessage(new Message($message, $field));
            }
        }

        return $messages;
    }
}
