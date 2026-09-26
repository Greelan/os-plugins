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

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;

/**
 * Class Notify
 * @package OPNsense\Notify
 */
class Notify extends BaseModel
{
    /**
     * Is an enabled channel subscribed to this event, as it happens or in its summary?
     */
    public function hasEvent($event)
    {
        if ((string)$this->general->enabled != '1') {
            return false;
        }
        foreach ($this->channels->iterateItems() as $channel) {
            if ((string)$channel->enabled != '1') {
                continue;
            }
            $events = explode(',', (string)$channel->events);
            if (!$channel->summary->isEqual('none')) {
                $events = array_merge($events, explode(',', (string)$channel->summaryEvents));
            }
            if (in_array($event, $events)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Does an enabled channel's summary include this section?
     */
    public function hasSummarySection($section)
    {
        if ((string)$this->general->enabled != '1') {
            return false;
        }
        foreach ($this->channels->iterateItems() as $channel) {
            if (
                (string)$channel->enabled == '1' && !$channel->summary->isEqual('none') &&
                in_array($section, explode(',', (string)$channel->summarySections))
            ) {
                return true;
            }
        }
        return false;
    }

    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        foreach ($this->channels->iterateItems() as $channel) {
            if (!$validateFullModel && !$channel->isFieldChanged()) {
                continue;
            }
            if ($channel->events->isEmpty() && $channel->summary->isEqual('none')) {
                $messages->appendMessage(new Message(
                    gettext('Choose events to send as they happen, or a summary.'),
                    $channel->__reference . '.events'
                ));
            }
            if (
                !$channel->summary->isEqual('none') &&
                $channel->summaryEvents->isEmpty() && $channel->summarySections->isEmpty()
            ) {
                $messages->appendMessage(new Message(
                    gettext('Choose summary events or sections, so the summary has something to report.'),
                    $channel->__reference . '.summarySections'
                ));
            }
        }
        return $messages;
    }
}
