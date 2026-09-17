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
                    appriseServices = (data && data.services) || [];
                    appriseLoaded.resolve();
                });
            }
            return appriseLoaded;
        }

        function appriseRow(id, label, control) {
            return $('<tr>').attr('id', 'row_' + id).addClass('apprise-row').append(
                $('<td>').append($('<div class="control-label">').append(
                    $('<i class="fa fa-info-circle fa-fw text-muted"></i>'), $('<b>').text(label))),
                $('<td>').append(control),
                $('<td>').append($('<span class="help-block">').attr('id', 'help_block_' + id))
            );
        }

        function appriseMarkChanged() {
            $('#apprise\\.changed').val('1');
        }

        function appriseRenderFields(serviceId, values, saved) {
            $('#frm_' + dialogId + ' tr.apprise-field').remove();
            const service = (appriseServices || []).find(s => s.id === serviceId);
            $('#row_channel\\.url').toggle(service === undefined);
            $('#apprise_setup').empty();
            if (service === undefined) {
                return;
            }
            $('#channel\\.url').val('');
            if (service.setup) {
                $('#apprise_setup').append($('<a target="_blank" rel="noopener noreferrer">')
                    .attr('href', service.setup).text("{{ lang._('Setup guide for %s') }}".replace('%s', service.name)));
            }
            let $after = $('#row_apprise_service');
            service.fields.forEach(function (field) {
                const id = 'apprise.' + field.key;
                const value = values[field.key] ?? field.default ?? '';
                let $control;
                if (field.type === 'choice') {
                    $control = $('<select class="form-control">').attr('id', id);
                    field.values.forEach(v => $control.append($('<option>').val(v).text(v)));
                    $control.val(value || field.values[0]);
                } else if (field.type === 'bool') {
                    $control = $('<input type="checkbox">').attr('id', id).prop('checked', ['1', 'yes', 'true'].includes(String(value).toLowerCase()));
                } else {
                    $control = $('<input class="form-control">').attr('id', id)
                        .attr('type', field.private ? 'password' : 'text')
                        .attr('autocomplete', field.private ? 'new-password' : 'off').val(field.private ? '' : value);
                    if (field.private && saved.includes(field.key)) {
                        $control.attr('placeholder', "{{ lang._('Saved, leave empty to keep') }}");
                    } else if (field.type === 'list') {
                        $control.attr('placeholder', "{{ lang._('Separate entries with commas') }}");
                    }
                    if (field.private) {
                        /* masked by default, but typing a webhook id blind is no fun */
                        const $show = $('<button type="button" class="btn btn-default">')
                            .attr('title', "{{ lang._('Show or hide') }}")
                            .append($('<i class="fa fa-eye">'))
                            .on('click', function () {
                                const hidden = $control.attr('type') === 'password';
                                $control.attr('type', hidden ? 'text' : 'password');
                                $(this).find('i').toggleClass('fa-eye', !hidden).toggleClass('fa-eye-slash', hidden);
                            });
                        $control = $('<div class="input-group">').append(
                            $control, $('<span class="input-group-btn">').append($show));
                    }
                }
                $control.find('input').addBack('input').on('input change', appriseMarkChanged);
                const $row = appriseRow(id, field.label, $control).addClass('apprise-field');
                $after.after($row);
                $after = $row;
            });

            /* anything Apprise takes after the "?", which the service fields do not cover */
            const $options = $('<input class="form-control" type="text">').attr('id', 'apprise.__query')
                .attr('placeholder', 'priority=high&format=markdown').val(values.__query || '')
                .on('input change', appriseMarkChanged);
            $after.after(appriseRow('apprise.__query', "{{ lang._('Options') }}", $options)
                .addClass('apprise-field'));
        }

        function appriseDialog(payload) {
            const dfObj = new $.Deferred();
            appriseLoad().done(function () { appriseBuildDialog(payload); dfObj.resolve(); });
            return dfObj;
        }

        function appriseBuildDialog(payload) {
            const data = payload['frm_' + dialogId] || {};
            const apprise = data.notify_apprise || {service: ''};
            $('#row_channel\\.service').hide();
            $('#frm_' + dialogId + ' tr.apprise-row').remove();

            const $select = $('<select id="apprise_service" class="selectpicker" data-live-search="true" data-width="100%" data-size="10">')
                .append($('<option value="">').text("{{ lang._('Custom URL') }}"));
            (appriseServices || []).forEach(s => $select.append($('<option>').val(s.id).text(s.name)));
            const $cell = $('<div>').append($select, $('<input type="hidden" id="apprise.changed" value="">'),
                $('<div id="apprise_setup" style="margin-top: 0.5em;">'));
            $('#row_channel\\.url').before(appriseRow('apprise_service', "{{ lang._('Service') }}", $cell));
            $select.val(apprise.service || '').selectpicker();
            $select.on('changed.bs.select', function () {
                appriseMarkChanged();
                appriseRenderFields($(this).val(), {}, []);
            });
            appriseRenderFields(apprise.service || '', apprise.fields || {}, apprise.saved || []);

            monitFieldVisibility();
            $('#channel\\.events').off('changed.bs.select.notify')
                .on('changed.bs.select.notify', monitFieldVisibility);
            monitPlaceholder();
            $('#channel\\.monitServices').off('tokenize:tokens:change.notify')
                .on('tokenize:tokens:change.notify', monitPlaceholder);
        }

        /* core hides the tokenizer's placeholder after loading values, so show it again */
        function monitPlaceholder() {
            const $tokenizer = $('#channel\\.monitServices').siblings('.tokenize');
            $tokenizer.find('li.placeholder').toggle($tokenizer.find('li.token').length === 0);
        }

        /* the Monit filter only means anything when the channel takes Monit alerts */
        function monitFieldVisibility() {
            const events = $('#channel\\.events').val() || [];
            $('#row_channel\\.monitServices').toggle(events.includes('monit'));
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
                    }
                }
            });
        }

        $('#maintabs a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
            history.pushState(null, null, e.target.hash);
            if (e.target.hash === '#channelstab') {
                appriseLoad();
                initChannelGrid();
            } else if (e.target.hash === '#statustab') {
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
    <li class="active"><a data-toggle="tab" href="#generaltab">{{ lang._('General') }}</a></li>
    <li><a data-toggle="tab" href="#channelstab">{{ lang._('Channels') }}</a></li>
    <li><a data-toggle="tab" href="#statustab">{{ lang._('Status') }}</a></li>
</ul>

<div class="tab-content content-box __mb">
    <div id="generaltab" class="tab-pane fade in active">
        {{ partial("layout_partials/base_form", ['fields': generalForm, 'id': 'frm_general']) }}
    </div>
    <div id="channelstab" class="tab-pane fade in">
        {{ partial('layout_partials/base_bootgrid_table', formGridChannel) }}
        <div style="padding: 10px;">
            {{ lang._('Each channel is one destination. Pick a service and fill in its fields, or choose Custom URL to enter an Apprise URL yourself. Save a channel, then use the paper plane button to send a test notification. Notifications that cannot be delivered are retried, less often each time, for up to 24 hours.') }}
        </div>
    </div>
    <div id="statustab" class="tab-pane fade in">
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
