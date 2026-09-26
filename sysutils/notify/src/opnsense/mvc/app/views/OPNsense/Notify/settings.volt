{#
 # Copyright (C) 2026 Greelan
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without modification,
 # are permitted provided that the following conditions are met:
 #
 # 1. Redistributions of source code must retain the above copyright notice,
 #    this list of conditions and the following disclaimer.
 #
 # 2. Redistributions in binary form must reproduce the above copyright notice,
 #    this list of conditions and the following disclaimer in the documentation
 #    and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 # INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 # AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 # AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 # OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 # SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 # INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 # CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 # ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 # POSSIBILITY OF SUCH DAMAGE.
 #}

<script>
    $( document ).ready(function() {
        mapDataToFormUI({'frm_general': "/api/notify/settings/get"}).done(function () {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            titlePrefixFields();
        });

        /* custom prefix text only applies to the custom option */
        function titlePrefixFields() {
            $("#row_notify\\.general\\.titleText").toggle($("#notify\\.general\\.titlePrefix").val() === 'custom');
        }
        $("#notify\\.general\\.titlePrefix").change(titlePrefixFields);

        /*
         * Service picker for the channel dialog: fields come from Apprise's own service
         * details, and the URL is composed and checked on save (SettingsController).
         */
        const dialogId = "{{ formGridChannel['edit_dialog_id'] }}";
        let appriseServices = null;
        let appriseLoaded = null;

        function appriseLoad() {
            if (appriseLoaded === null) {
                appriseLoaded = new $.Deferred();
                ajaxGet('/api/notify/service/services', {}, function (data) {
                    appriseServices = appriseDecode((data && data.services) || []);
                    appriseLoaded.resolve();
                });
            }
            return appriseLoaded;
        }

        function appriseDecode(value) {
            if (typeof value === 'string') {
                return htmlDecode(value);
            }
            if (Array.isArray(value)) {
                return value.map(appriseDecode);
            }
            if (value !== null && typeof value === 'object') {
                Object.keys(value).forEach(key => value[key] = appriseDecode(value[key]));
            }
            return value;
        }

        function appriseRow(id, label, control) {
            return $('<tr>').attr('id', 'row_' + id).addClass('apprise-row').append(
                $('<td>').append($('<div class="control-label">').append(
                    $('<i class="fa fa-info-circle fa-fw text-muted"></i>'), $('<b>').text(label))),
                $('<td>').append(control),
                $('<td>').append($('<span class="help-block">').attr('id', 'help_block_' + id))
            );
        }

        /* a button that shows or hides what is typed in a masked input */
        function appriseRevealButton($input) {
            return $('<span class="input-group-btn">').append($('<button type="button" class="btn btn-default">')
                .attr('title', "{{ lang._('Show or hide') }}")
                .append($('<i class="fa fa-eye">'))
                .on('click', function () {
                    const hidden = $input.attr('type') === 'password';
                    $input.attr('type', hidden ? 'text' : 'password');
                    $(this).find('i').toggleClass('fa-eye', !hidden).toggleClass('fa-eye-slash', hidden);
                }));
        }

        /* core renders the URL masked; it is worth seeing what an import just put there */
        function appriseRevealUrl() {
            const $input = $('#channel\\.url');
            if ($input.closest('.input-group').length) {
                return;
            }
            $input.wrap($('<div class="input-group">')).after(appriseRevealButton($input));
        }

        function appriseMarkChanged() {
            $('#apprise\\.changed').val('1');
        }

        function appriseRenderFields(serviceId, values, saved) {
            let set = false;
            $('#frm_' + dialogId + ' tr.apprise-field').remove();
            const service = (appriseServices || []).find(s => s.id === serviceId);
            $('#row_channel\\.url').toggle(serviceId === '__custom');
            $('#apprise_setup').empty();
            $('#apprise\\.__query').remove();
            if (service === undefined) {
                return;
            }
            $('#channel\\.url').val('');
            if (service.setup) {
                $('#apprise_setup').append($('<a target="_blank" rel="noopener noreferrer">')
                    .attr('href', service.setup).text("{{ lang._('Setup guide for %s') }}".replace('%s', service.name)));
            }
            /* advanced fields go last, below Saved URL, Events, Monit services and Summary */
            let $after = $('#row_apprise_service');
            let $afterExtra = $('#row_channel\\.summarySections');
            service.fields.forEach(function (field) {
                const id = 'apprise.' + field.key;
                const value = values[field.key] ?? field.default ?? '';
                let $control;
                if (field.type === 'choice') {
                    $control = $('<select class="form-control">').attr('id', id);
                    if (field.default === undefined) {
                        /* nothing to fall back on, so leaving it unset must stay possible */
                        $control.append($('<option value="">').text("{{ lang._('Not set') }}"));
                    }
                    field.values.forEach(v => $control.append($('<option>').val(v).text(v)));
                    $control.val(value || (field.default === undefined ? '' : field.values[0]));
                } else if (field.type === 'bool') {
                    $control = $('<input type="checkbox">').attr('id', id).prop('checked', ['1', 'yes', 'true'].includes(String(value).toLowerCase()));
                } else if (field.type === 'file') {
                    /* a key or template: the saved file is never sent back, so an empty box keeps it */
                    $control = $('<textarea class="form-control" rows="6" spellcheck="false" style="font-family: monospace;">')
                        .attr('id', id).val(value === 'stored' ? '' : value)
                        .attr('placeholder', saved.includes(field.key)
                            ? "{{ lang._('Saved, leave empty to keep') }}"
                            : (field.hint || "{{ lang._('Paste the file') }}"));
                } else {
                    $control = $('<input class="form-control">').attr('id', id)
                        .attr('type', field.private ? 'password' : 'text')
                        .attr('autocomplete', field.private ? 'new-password' : 'off').val(value);
                    if (field.private && value === '' && saved.includes(field.key)) {
                        $control.attr('placeholder', "{{ lang._('Saved, leave empty to keep') }}");
                    } else if (field.type === 'list') {
                        $control.attr('placeholder', "{{ lang._('Separate entries with commas') }}");
                    }
                    if (field.private) {
                        /* masked by default, but typing a webhook id blind is no fun */
                        $control = $('<div class="input-group">').append($control, appriseRevealButton($control));
                    }
                }
                if (field.clearable && saved.includes(field.key)) {
                    /* the saved value never reaches the page, so like core's Clear All it goes on save;
                       typing a new value instead replaces it */
                    const $flag = $('<input type="hidden" value="">').attr('id', 'apprise.__clear_' + field.key);
                    const $box = $control.find('input, textarea').addBack('input, textarea');
                    const $link = $('<a href="#" class="text-danger">');
                    const label = () => $link.empty().append($('<i class="fa fa-times-circle"></i>'), ' ',
                        $('<small>').text($flag.val() === '1' ? "{{ lang._('Undo') }}" : "{{ lang._('Remove') }}"));
                    label();
                    const mark = function (removing) {
                        $flag.val(removing ? '1' : '');
                        $box.attr('placeholder', removing
                            ? "{{ lang._('Removed when saved') }}" : "{{ lang._('Saved, leave empty to keep') }}");
                        label();
                        appriseMarkChanged();
                    };
                    $link.on('click', function (event) {
                        event.preventDefault();
                        $box.val('');
                        mark($flag.val() !== '1');
                    });
                    $box.on('input', function () {
                        if ($flag.val() === '1') {
                            mark(false);
                        }
                    });
                    $control = $('<div>').append($control, $flag, $('<div style="margin-top: 0.3em;">').append($link));
                }
                $control.find('input, select, textarea').addBack('input, select, textarea').on('input change', appriseMarkChanged);
                const $row = appriseRow(id, field.label, $control).addClass('apprise-field');
                if (field.basic) {
                    $after.after($row);
                    $after = $row;
                } else {
                    $row.attr('data-advanced', 'true');
                    /* a saved secret or file is never sent back, so its value here is empty */
                    if (saved.includes(field.key) || (value !== '' && String(value) !== String(field.default ?? ''))) {
                        set = true;
                    }
                    $afterExtra.after($row);
                    $afterExtra = $row;
                }
            });

            /* query parts no field covers, carried along untouched */
            $('#apprise_setup').after($('<input type="hidden" id="apprise.__query">').val(values.__query || ''));

            appriseAdvanced(set || (values.__query || '') !== '');
        }

        /* advanced mode follows the channel, not what the last dialog left behind */
        function appriseAdvanced(reveal) {
            const $toggle = $('#show_advanced_' + dialogId);
            if ($toggle.hasClass('fa-toggle-on') !== reveal) {
                $toggle.click();
            } else {
                $('#frm_' + dialogId).find('[data-advanced="true"]').toggle(reveal);
            }
        }

        function appriseDialog(payload) {
            const dfObj = new $.Deferred();
            appriseLoad().done(function () { appriseBuildDialog(payload); dfObj.resolve(); });
            return dfObj;
        }

        function appriseBuildDialog(payload) {
            const data = payload['frm_' + dialogId] || {};
            let apprise = appriseDecode(data.notify_apprise || {service: ''});
            $('#row_channel\\.service').hide();
            $('#frm_' + dialogId + ' tr.apprise-row').remove();

            const $select = $('<select id="apprise_service" class="selectpicker" data-live-search="true" data-width="100%" data-size="10">')
                .append($('<option value="">').text("{{ lang._('Select a service') }}"));
            (appriseServices || []).forEach(s => $select.append($('<option>').val(s.id).text(s.name)));
            $select.append($('<option value="__custom">').text("{{ lang._('Custom URL') }}"));
            const $cell = $('<div>').append($select, $('<input type="hidden" id="apprise.changed" value="">'),
                $('<div id="apprise_setup" style="margin-top: 0.5em;">'),
                $('<div id="apprise_note" class="text-warning" style="margin-top: 0.5em;">'));
            appriseRevealUrl();
            $('#row_channel\\.url').before(appriseRow('apprise_service', "{{ lang._('Service') }}", $cell))
                /* shown for Custom URL alone, so the advanced toggle must not claim it */
                .removeAttr('data-advanced');
            $select.val(apprise.service || '').selectpicker();
            $select.on('changed.bs.select', function () {
                appriseMarkChanged();
                appriseRenderFields($(this).val(), {}, []);
            });
            if (appriseImported !== null) {
                apprise = appriseImported;
                appriseImported = null;
                if (apprise.url) {
                    $('#channel\\.url').val(apprise.url);
                }
                appriseMarkChanged();
            }
            const chosen = apprise.service || (apprise.url || apprise.custom ? '__custom' : '');
            $select.val(chosen).selectpicker('refresh');
            $('#apprise_note').text(apprise.error || '');
            /* the stored URL is never sent back, so say what an empty box means */
            $('#channel\\.url').attr('placeholder', apprise.custom
                ? "{{ lang._('Saved, leave empty to keep') }}" : null);
            appriseRenderFields(chosen, apprise.fields || {}, apprise.saved || []);
            $('#row_channel\\.url').toggle(chosen === '__custom');

            monitFieldVisibility();
            $('#channel\\.events, #channel\\.summaryEvents, #channel\\.summary').off('changed.bs.select.notify')
                .on('changed.bs.select.notify', monitFieldVisibility);
            monitPlaceholder();
            $('#channel\\.monitServices').off('tokenize:tokens:change.notify')
                .on('tokenize:tokens:change.notify', monitPlaceholder);
        }

        /* set by the import dialog, applied when the add dialog renders */
        let appriseImported = null;

        function appriseImportDialog() {
            const $input = $('<input type="text" class="form-control">')
                .attr('placeholder', 'tgram://bottoken/chatid');
            const $message = $('<div class="text-danger" style="margin-top: 0.5em;">');
            BootstrapDialog.show({
                title: "{{ lang._('Create channel from a URL') }}",
                message: $('<div>').append(
                    $('<p>').text("{{ lang._('Paste an Apprise URL. Its service and fields are filled in for you; anything the fields cannot hold is kept as a custom URL.') }}"),
                    $input, $message,
                    $('<p style="margin-top: 1em;">').append(
                        $('<a target="_blank" rel="noopener noreferrer" href="https://appriseit.com/tools/url-builder/">')
                            .text("{{ lang._('Apprise URL builder') }}"),
                        $('<span>').text(" — "),
                        $('<a target="_blank" rel="noopener noreferrer" href="https://appriseit.com/services/">')
                            .text("{{ lang._('Apprise services') }}"))),
                buttons: [
                    {label: "{{ lang._('Cancel') }}", action: function (dlg) { dlg.close(); }},
                    {
                        label: "{{ lang._('Import') }}",
                        cssClass: 'btn-primary',
                        action: function (dlg) {
                            const url = $input.val().trim();
                            if (!url) {
                                return;
                            }
                            ajaxCall('/api/notify/service/import', {url: url}, function (data) {
                                if (data && data.service) {
                                    appriseImported = appriseDecode(data);
                                } else if (data && data.service === '') {
                                    /* the URL is as typed, only the answer is escaped */
                                    appriseImported = {service: '', url: url, error: htmlDecode(data.error || '')};
                                } else {
                                    $message.text((data && data.error) || "{{ lang._('The URL could not be read.') }}");
                                    return;
                                }
                                dlg.close();
                            });
                        }
                    }
                ],
                /* opening the next modal too early leaves the page unscrollable */
                onhidden: function () {
                    if (appriseImported !== null) {
                        $("#{{ formGridChannel['table_id'] }}").find('.command-add').first().click();
                    }
                }
            });
        }

        /* core hides the tokenizer's placeholder after loading values, so show it again */
        function monitPlaceholder() {
            const $tokenizer = $('#channel\\.monitServices').siblings('.tokenize');
            $tokenizer.find('li.placeholder').toggle($tokenizer.find('li.token').length === 0);
        }

        /* the Monit filter only means anything when the channel takes Monit alerts */
        function monitFieldVisibility() {
            const summary = $('#channel\\.summary').val() !== 'none';
            const events = ($('#channel\\.events').val() || [])
                .concat(summary ? ($('#channel\\.summaryEvents').val() || []) : []);
            $('#row_channel\\.monitServices').toggle(events.includes('monit'));
            $('#row_channel\\.summaryEvents, #row_channel\\.summarySections').toggle(summary);
        }

        let channelGrid = null;
        function initChannelGrid() {
            if (channelGrid !== null) {
                channelGrid.bootgrid('reload');
                return;
            }
            channelGrid = $("#{{ formGridChannel['table_id'] }}").UIBootgrid({
                search: '/api/notify/settings/searchChannel/',
                get: '/api/notify/settings/getChannel/',
                set: '/api/notify/settings/setChannel/',
                add: '/api/notify/settings/addChannel/',
                del: '/api/notify/settings/delChannel/',
                toggle: '/api/notify/settings/toggleChannel/',
                /* hooks live under options:, plain commands do not (opnsense_bootgrid.js) */
                options: {
                    onBeforeRenderDialog: appriseDialog
                },
                commands: {
                    test: {
                        method: function () {
                            const uuid = $(this).data("row-id") !== undefined ? $(this).data("row-id") : '';
                            const $icon = $(this).find('span');
                            $icon.removeClass('fa-paper-plane').addClass('fa-spinner fa-pulse');
                            ajaxCall('/api/notify/service/test/' + uuid, {}, function (data, status) {
                                $icon.removeClass('fa-spinner fa-pulse').addClass('fa-paper-plane');
                                if (data && data.status === 'ok') {
                                    BootstrapDialog.show({
                                        type: BootstrapDialog.TYPE_SUCCESS,
                                        title: "{{ lang._('Test notification') }}",
                                        message: "{{ lang._('The test notification was sent.') }}",
                                        buttons: [{label: "{{ lang._('Close') }}", action: function (dlg) { dlg.close(); }}]
                                    });
                                } else {
                                    BootstrapDialog.show({
                                        type: BootstrapDialog.TYPE_DANGER,
                                        title: "{{ lang._('Test notification') }}",
                                        message: $('<div>').text((data && data.message) || "{{ lang._('The test notification could not be sent.') }}"),
                                        buttons: [{label: "{{ lang._('Close') }}", action: function (dlg) { dlg.close(); }}]
                                    });
                                }
                            });
                        },
                        classname: 'fa fa-fw fa-paper-plane',
                        title: "{{ lang._('Send test notification') }}",
                        sequence: 10
                    },
                    summary: {
                        method: function () {
                            const uuid = $(this).data("row-id") !== undefined ? $(this).data("row-id") : '';
                            const $icon = $(this).find('span');
                            $icon.removeClass('fa-list-alt').addClass('fa-spinner fa-pulse');
                            ajaxCall('/api/notify/service/summary/' + uuid, {}, function (data, status) {
                                $icon.removeClass('fa-spinner fa-pulse').addClass('fa-list-alt');
                                const ok = data && data.status === 'ok';
                                BootstrapDialog.show({
                                    type: ok ? BootstrapDialog.TYPE_SUCCESS : BootstrapDialog.TYPE_DANGER,
                                    title: "{{ lang._('Summary') }}",
                                    message: ok ? "{{ lang._('The summary so far was sent. Its period carries on until the next scheduled summary.') }}"
                                                : $('<div>').text((data && data.message) || "{{ lang._('The summary could not be sent.') }}"),
                                    buttons: [{label: "{{ lang._('Close') }}", action: function (dlg) { dlg.close(); }}]
                                });
                            });
                        },
                        /* only for enabled channels that have a summary */
                        filter: function (cell) {
                            return cell.getData().enabled === '1' && cell.getData().summary !== 'none';
                        },
                        classname: 'fa fa-fw fa-list-alt',
                        title: "{{ lang._('Send summary so far') }}",
                        sequence: 11
                    }
                }
            });
        }

        $('#maintabs a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
            history.pushState(null, null, e.target.hash);
            if (e.target.hash === '#channels') {
                appriseLoad();
                initChannelGrid();
            } else if (e.target.hash === '#status') {
                loadStatus();
            }
        });
        function openTabFromHash() {
            if (window.location.hash != "") {
                $('#maintabs a[href="' + window.location.hash + '"]').click();
            }
        }
        openTabFromHash();
        /* the menu entries only change the hash when this page is already open */
        $(window).on('hashchange', openTabFromHash);

        function loadStatus() {
            ajaxGet('/api/notify/service/status', {}, function (data) {
                data = appriseDecode(data);
                if (!data || data.status === 'failed') {
                    $('#status_summary').text("{{ lang._('The status could not be read.') }}");
                    return;
                }
                const bits = [
                    data.enabled ? "{{ lang._('Enabled') }}" : "{{ lang._('Disabled') }}",
                    data.checked ? "{{ lang._('last check %s (%s ago)') }}".replace('%s', data.checked).replace('%s', data.age)
                                 : "{{ lang._('no check recorded yet') }}",
                    "{{ lang._('%s channel(s)') }}".replace('%s', data.channels),
                    (data.events || []).join(', ')
                ];
                $('#status_summary').text(bits.filter(Boolean).join(' - '));
                const $body = $('#status_queue tbody').empty();
                (data.queued || []).forEach(function (row) {
                    $body.append($('<tr>').append(
                        ['title', 'channel', 'event', 'age', 'tries', 'retry_in'].map(
                            key => $('<td>').text(row[key]))));
                });
                $('#status_empty').toggle((data.queued || []).length === 0);
            });
        }

        $("#status_refresh").click(loadStatus);
        $("#import_url").click(appriseImportDialog);

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function () {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/notify/settings/set", 'frm_general', function () {
                    dfObj.resolve();
                }, true, function () { dfObj.reject(); });
                return dfObj;
            }
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#general">{{ lang._('General') }}</a></li>
    <li><a data-toggle="tab" href="#channels">{{ lang._('Channels') }}</a></li>
    <li><a data-toggle="tab" href="#status">{{ lang._('Status') }}</a></li>
</ul>

<div class="tab-content content-box __mb">
    <div id="general" class="tab-pane fade in active">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
    </div>
    <div id="channels" class="tab-pane fade in">
        {{
            partial('layout_partials/base_bootgrid_table', formGridChannel + {
                'command_width': '170',
                'grid_commands': {
                    'import_url': {
                        'title': lang._('Create a channel from an Apprise URL'),
                        'class': 'btn btn-xs btn-default',
                        'icon_class': 'fa fa-fw fa-upload',
                        'data': {'toggle': 'tooltip'}
                    }
                }
            })
        }}
        <div style="padding: 10px;">
            {{ lang._('Each channel is one destination. Import an Apprise URL to fill in a channel, or add one and pick its service by hand. Save a channel, then use the paper plane button to send a test notification, or the list button to send the summary so far. Notifications that cannot be delivered are retried, less often each time, for up to 24 hours.') }}
        </div>
    </div>
    <div id="status" class="tab-pane fade in">
        <div style="padding: 10px;">
            <p id="status_summary">&nbsp;</p>
            <table class="table table-condensed" id="status_queue">
                <thead>
                    <tr>
                        <th>{{ lang._('Waiting to be sent') }}</th>
                        <th>{{ lang._('Channel') }}</th>
                        <th>{{ lang._('Event') }}</th>
                        <th>{{ lang._('Age') }}</th>
                        <th>{{ lang._('Attempts') }}</th>
                        <th>{{ lang._('Next attempt') }}</th>
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
            <p id="status_empty">{{ lang._('Nothing is waiting to be sent.') }}</p>
            <button class="btn btn-default" id="status_refresh" type="button">
                <i class="fa fa-refresh"></i> {{ lang._('Refresh') }}
            </button>
        </div>
    </div>
</div>

{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/notify/service/reconfigure'}) }}
{{ partial("layout_partials/base_dialog", ['fields': formDialogChannel, 'id': formGridChannel['edit_dialog_id'], 'label': lang._('Edit channel')]) }}
