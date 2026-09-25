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

use OPNsense\Core\Config;

/**
 * Configuration backups to S3-compatible object storage, signed with AWS Signature Version 4
 * and addressed path-style (https://endpoint/bucket/key), which every S3 service accepts.
 * @package OPNsense\Backup
 */
class S3 extends Base implements IBackupProvider
{
    /* the model's write-only fields, never sent back to the page */
    private const SECRETS = ['secretKey', 'password', 'passwordconfirm'];
    /* what the page gets in place of a saved secret, so its box shows dots; sent back, it keeps the secret */
    private const SAVED = '(saved)';
    /* names core gives backups: config-<microtime>[_<hrtime>].xml */
    private const BACKUP_NAME = '/^config-[0-9]+(\.[0-9]+)?(_[0-9]+)?\.xml$/';
    /* a hostile endpoint cannot keep a backup busy or fill memory */
    private const MAX_PAGES = 100;
    private const MAX_RESPONSE = 8 * 1024 * 1024;

    /* the most keys one DeleteObjects request takes */
    private const MAX_DELETE = 1000;

    /* one handle for the run, so requests share a connection */
    private $curl = null;

    private $model = null;

    public function __construct()
    {
        $this->model = new S3Settings();
    }

    /**
     * @inheritdoc
     */
    public function getConfigurationFields()
    {
        $fields = [
            [
                'name' => 'enabled',
                'type' => 'checkbox',
                'label' => gettext('Enable'),
            ],
            [
                'name' => 'endpoint',
                'type' => 'text',
                'label' => gettext('Endpoint'),
                'help' => gettext(
                    'Host name of the S3 service, optionally with a port, e.g. s3.eu-central-1.amazonaws.com,' .
                    ' s3.us-west-004.backblazeb2.com or ACCOUNT_ID.r2.cloudflarestorage.com. HTTPS is always ' .
                    'used.'
                ),
            ],
            [
                'name' => 'region',
                'type' => 'text',
                'label' => gettext('Region'),
                'help' => gettext('Region the bucket is in, e.g. us-east-1. Cloudflare R2 uses auto.'),
            ],
            [
                'name' => 'bucket',
                'type' => 'text',
                'label' => gettext('Bucket'),
                'help' => gettext('An existing bucket.'),
            ],
            [
                'name' => 'prefix',
                'type' => 'text',
                'label' => gettext('Folder'),
                'help' => gettext(
                    'Folder in the bucket for this firewall, e.g. backups/fw1. Use a different folder for each ' .
                    'firewall: backups in the folder beyond the backup count are deleted, whichever firewall ' .
                    'wrote them.'
                ),
            ],
            [
                'name' => 'accessKey',
                'type' => 'text',
                'label' => gettext('Access key ID'),
            ],
            [
                'name' => 'secretKey',
                'type' => 'password',
                'label' => gettext('Secret access key'),
                'help' => gettext(
                    'Never shown again: a saved key shows as dots, which leave it as it is. The key only ' .
                    'needs to list, write and delete objects in this bucket.'
                ),
            ],
            [
                'name' => 'backupcount',
                'type' => 'text',
                'label' => gettext('Backup Count'),
                'help' => gettext('How many backups to keep in the bucket. Older ones are deleted; 0 keeps them all.'),
            ],
            [
                'name' => 'password',
                'type' => 'password',
                'label' => gettext('Encrypt Password'),
                'help' => gettext(
                    'Backups are encrypted with this password before they are sent, and only it can restore ' .
                    'them, so keep a copy somewhere other than this firewall. Changing it does not re-encrypt ' .
                    'backups already sent; they still need the password they were made with. Never shown ' .
                    'again: a saved password shows as dots in both boxes, which leave it as it is.'
                ),
            ],
            [
                'name' => 'passwordconfirm',
                'type' => 'password',
                'label' => gettext('Confirm'),
            ],
        ];
        foreach ($fields as &$field) {
            if (in_array($field['name'], self::SECRETS)) {
                $name = $field['name'] == 'passwordconfirm' ? 'password' : $field['name'];
                $field['value'] = $this->model->$name->getValue() !== '' ? self::SAVED : '';
            } else {
                /* the page prints values unescaped, so they are escaped here */
                $field['value'] = htmlspecialchars(
                    (string)$this->model->getNodeByReference($field['name']),
                    ENT_QUOTES
                );
            }
        }
        return $fields;
    }

    /**
     * @inheritdoc
     */
    public function getName()
    {
        return gettext('S3');
    }

    /**
     * @inheritdoc
     */
    public function setConfiguration($conf)
    {
        foreach (self::SECRETS as $name) {
            if (($conf[$name] ?? '') === self::SAVED) {
                $conf[$name] = ''; /* untouched, so the write-only field keeps what it has */
            }
        }
        $this->setModelProperties($this->model, $conf);
        $messages = $this->validateModel($this->model);
        if (($conf['password'] ?? '') !== ($conf['passwordconfirm'] ?? '')) {
            $messages[] = gettext("The supplied 'Password' and 'Confirm' field values must match.");
        }
        if (empty($messages)) {
            $this->model->serializeToConfig();
            Config::getInstance()->save();
        }
        return $messages;
    }

    /**
     * @inheritdoc
     */
    public function isEnabled()
    {
        return (string)$this->model->enabled == '1';
    }

    /**
     * @inheritdoc
     */
    public function backup()
    {
        $cnf = Config::getInstance();
        if (!$this->isEnabled() || !$cnf->isValid()) {
            return [];
        }
        try {
            return $this->upload($cnf);
        } catch (\Throwable $e) {
            syslog(LOG_ERR, 's3-backup: ' . $e->getMessage());
            /* the page shows the reason; the nightly run carries on with the other providers */
            if (PHP_SAPI !== 'cli') {
                /* the page only catches Exception */
                throw $e instanceof \Exception ? $e : new \Exception($e->getMessage(), 0, $e);
            }
            return [];
        }
    }

    /**
     * Send the newest local backup unless the bucket has it, then apply the backup count.
     */
    private function upload($cnf)
    {
        /* settings can arrive without the page, e.g. in a restored config.xml, so check them all */
        foreach ($this->model->performValidation(true) as $message) {
            throw new \Exception(sprintf(gettext('The S3 settings are not valid: %s'), (string)$message));
        }

        /* newest first, as core orders them */
        $latest = $cnf->getBackups()[0] ?? null;
        if ($latest === null) {
            return [];
        }
        $name = basename($latest);
        if (!preg_match(self::BACKUP_NAME, $name)) {
            /* it would never show in the listing, so it would be sent again every time */
            throw new \Exception(sprintf(gettext('Unexpected backup name %s.'), $name));
        }

        $folder = $this->folder();
        $remote = $this->listBackups($folder);
        if (!in_array($name, $remote)) {
            $plain = @file_get_contents($latest);
            $data = $plain === false ? null : $this->encrypt($plain, $this->model->password->getValue());
            if ($data === null) {
                throw new \Exception(gettext('The backup could not be read and encrypted.'));
            }
            $this->request('PUT', $folder . $name, [], $data);
            syslog(LOG_NOTICE, 's3-backup: uploaded ' . $folder . $name);
            $remote[] = $name;
        }

        $keep = (int)$this->model->backupcount->getValue();
        usort($remote, function ($a, $b) {
            return [self::stamp($b), $b] <=> [self::stamp($a), $a];
        });
        /* the backup just sent stays even if the bucket holds names from a clock that ran ahead */
        $remote = array_merge([$name], array_values(array_diff($remote, [$name])));
        if ($keep > 0) {
            foreach (array_chunk(array_slice($remote, $keep), self::MAX_DELETE) as $old) {
                $this->delete($folder, $old);
            }
            $remote = array_slice($remote, 0, $keep);
        }

        return $remote;
    }

    /**
     * Remove backups in one DeleteObjects request; S3 answers 200 and lists any key it could not remove.
     * Services without DeleteObjects, e.g. Google Cloud Storage, get one DELETE per backup.
     */
    private function delete($folder, $names)
    {
        $body = '<?xml version="1.0" encoding="UTF-8"?><Delete><Quiet>true</Quiet>';
        foreach ($names as $name) {
            $body .= '<Object><Key>' . htmlspecialchars($folder . $name, ENT_XML1) . '</Key></Object>';
        }
        try {
            $response = $this->request('POST', '', ['delete' => ''], $body . '</Delete>');
        } catch (\Exception $e) {
            foreach ($names as $name) {
                $this->request('DELETE', $folder . $name);
                syslog(LOG_NOTICE, 's3-backup: removed ' . $folder . $name);
            }
            return;
        }
        $xml = $this->parse($response);
        foreach ($xml->Error ?? [] as $error) {
            $this->fail(sprintf(
                gettext('S3 could not remove %s: %s'),
                self::clean((string)$error->Key),
                self::clean((string)$error->Code . ': ' . (string)$error->Message)
            ));
        }
        foreach ($names as $name) {
            syslog(LOG_NOTICE, 's3-backup: removed ' . $folder . $name);
        }
    }

    /**
     * Timestamp a backup name carries, as core reads it.
     */
    private static function stamp($name)
    {
        return (float)substr($name, strlen('config-'), -strlen('.xml'));
    }

    /**
     * Key prefix for this firewall: the folder as entered, which is its alone.
     */
    private function folder()
    {
        return (string)$this->model->prefix . '/';
    }

    /**
     * Backup file names under a key prefix, following continuation tokens past 1000 keys.
     */
    private function listBackups($folder)
    {
        $names = [];
        $token = null;
        $seen = [];
        do {
            /* the delimiter keeps subfolders, e.g. other firewalls under this one's folder, out */
            $query = ['list-type' => '2', 'prefix' => $folder, 'delimiter' => '/'];
            if ($token !== null) {
                $query['continuation-token'] = $token;
            }
            $xml = $this->parse($this->request('GET', '', $query));
            foreach ($xml->Contents ?? [] as $object) {
                $name = substr((string)$object->Key, strlen($folder));
                /* core prints the names it gets back unescaped, so only backup names pass */
                if (preg_match(self::BACKUP_NAME, $name)) {
                    $names[] = $name;
                }
            }
            $token = (string)$xml->IsTruncated === 'true' ? (string)$xml->NextContinuationToken : null;
            if ($token === '') {
                $this->fail(gettext('S3 returned a partial bucket listing without a way to continue it.'));
            }
            if ($token !== null && (isset($seen[$token]) || count($seen) >= self::MAX_PAGES)) {
                $this->fail(gettext('S3 kept returning more of the bucket listing than a backup folder holds.'));
            }
            $seen[(string)$token] = true;
        } while (!empty($token));

        return $names;
    }

    /**
     * One signed request against the bucket; returns the response body or throws with S3's reason.
     */
    private function request($method, $key, $query = [], $body = '')
    {
        $host = (string)$this->model->endpoint;
        $region = (string)$this->model->region;
        $path = '/' . rawurlencode((string)$this->model->bucket);
        if ($key !== '') {
            $path .= '/' . implode('/', array_map('rawurlencode', explode('/', $key)));
        }
        ksort($query);
        $pairs = [];
        foreach ($query as $name => $value) {
            $pairs[] = rawurlencode($name) . '=' . rawurlencode($value);
        }
        $canonicalQuery = implode('&', $pairs);

        $stamp = gmdate('Ymd\THis\Z');
        $date = substr($stamp, 0, 8);
        $payload = hash('sha256', $body);
        $signed = 'host;x-amz-content-sha256;x-amz-date';
        $canonical = implode("\n", [
            $method, $path, $canonicalQuery,
            "host:{$host}\nx-amz-content-sha256:{$payload}\nx-amz-date:{$stamp}\n",
            $signed, $payload,
        ]);
        $scope = "{$date}/{$region}/s3/aws4_request";
        $toSign = "AWS4-HMAC-SHA256\n{$stamp}\n{$scope}\n" . hash('sha256', $canonical);
        $signingKey = 'AWS4' . $this->model->secretKey->getValue();
        foreach ([$date, $region, 's3', 'aws4_request'] as $part) {
            $signingKey = hash_hmac('sha256', $part, $signingKey, true);
        }
        $signature = hash_hmac('sha256', $toSign, $signingKey);

        $response = '';
        $tooLarge = false;
        $headers = [
            "Host: {$host}",
            "x-amz-content-sha256: {$payload}",
            "x-amz-date: {$stamp}",
            'Content-Type: application/octet-stream',
            'Authorization: AWS4-HMAC-SHA256 Credential=' . (string)$this->model->accessKey .
                "/{$scope}, SignedHeaders={$signed}, Signature={$signature}",
        ];
        if ($method == 'POST') {
            /* DeleteObjects requires it */
            $headers[] = 'Content-MD5: ' . base64_encode(md5($body, true));
        }
        $this->curl = $this->curl ?? curl_init();
        $curl = $this->curl;
        curl_reset($curl);
        curl_setopt_array($curl, [
            CURLOPT_URL => 'https://' . $host . $path . ($canonicalQuery !== '' ? '?' . $canonicalQuery : ''),
            CURLOPT_WRITEFUNCTION => function ($curl, $chunk) use (&$response, &$tooLarge) {
                if (strlen($response) + strlen($chunk) > self::MAX_RESPONSE) {
                    $tooLarge = true;
                    return 0; /* aborts the transfer */
                }
                $response .= $chunk;
                return strlen($chunk);
            },
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_TIMEOUT => 120,
            CURLOPT_HTTPHEADER => $headers,
        ]);
        if ($method == 'PUT' || $method == 'POST') {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        }
        $done = curl_exec($curl);
        $status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        $error = curl_error($curl);

        if ($tooLarge) {
            $this->fail(sprintf(gettext('%s sent a larger answer than S3 does.'), $host));
        }
        if ($done === false) {
            $this->fail(sprintf(gettext('Could not reach %s: %s'), $host, $error));
        }
        if ($status < 200 || $status >= 300) {
            /* only S3's own error code and message, never the raw body */
            $xml = @simplexml_load_string((string)$response, 'SimpleXMLElement', LIBXML_NONET);
            $reason = $xml !== false && isset($xml->Code)
                ? self::clean((string)$xml->Code . ': ' . (string)$xml->Message) : '';
            $this->fail(sprintf(gettext('S3 answered HTTP %d %s'), $status, $reason));
        }
        return (string)$response;
    }

    private function parse($body)
    {
        $xml = @simplexml_load_string($body, 'SimpleXMLElement', LIBXML_NONET);
        if ($xml === false) {
            $this->fail(gettext('S3 answered with something other than a bucket listing.'));
        }
        return $xml;
    }

    /**
     * Text from the endpoint as one short line, since it ends up in syslog and on the page.
     */
    private static function clean($text)
    {
        $text = trim(preg_replace('/[\x00-\x1f\x7f]+/', ' ', $text));
        return strlen($text) > 200 ? substr($text, 0, 200) . '...' : $text;
    }

    private function fail($message)
    {
        throw new \Exception($message);
    }
}
