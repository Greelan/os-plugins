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
        let data_get_map = {'frm_settings':"/api/blocky/settings/get"};
        mapDataToFormUI(data_get_map).done(function(){
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            updateServiceControlUI('blocky');
            certFields();
        });

        /* the file paths are an alternative to the trust store, so only one applies */
        function certFields() {
            const picked = $("#blocky\\.general\\.certificate").val() !== '';
            $("#row_blocky\\.general\\.certFile, #row_blocky\\.general\\.keyFile").toggle(!picked);
        }
        $("#blocky\\.general\\.certificate").change(certFields);
        $('[id*="show_advanced"]').click(() => setTimeout(certFields, 0));

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function() {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/blocky/settings/set", 'frm_settings', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
                return dfObj;
            },
            onAction: function(data, status) {
                updateServiceControlUI('blocky');
            }
        });

        function escapeHtml(text) {
            return $('<div>').text(htmlDecode(text)).html();
        }
        function renderList(title, items, cls) {
            if (!items || items.length === 0) {
                return '';
            }
            let html = '<div class="alert ' + cls + '"><strong>' + title + ':</strong><ul>';
            $.each(items, function (i, item) { html += '<li>' + escapeHtml(item) + '</li>'; });
            return html + '</ul></div>';
        }

        $("#importConfigBtn")
            .data('title', "{{ lang._('Import Blocky configuration') }}")
            .data('endpoint', '/api/blocky/settings/import')
            .SimpleFileUploadDlg({
                onAction: function (data, status) {
                    if (data && data['status'] === 'ok') {
                        let total = 0;
                        $.each(data['counts'] || {}, function (k, v) { total += v; });
                        let entries = total === 1
                            ? "{{ lang._('1 list entry') }}"
                            : "{{ lang._('%s list entries') }}".replace('%s', total);
                        let html = '<div class="alert alert-success">' +
                            "{{ lang._('Import successful. Review the settings and once satisfied apply them.') }}" +
                            ' (' + entries + ')</div>';
                        html += renderList("{{ lang._('Warnings') }}", data['warnings'], 'alert-warning');
                        html += renderList("{{ lang._('Skipped (unsupported)') }}", data['skipped'], 'alert-info');
                        $("#importResult").html(html);
                        mapDataToFormUI(data_get_map).done(function () {
                            formatTokenizersUI();
                            $('.selectpicker').selectpicker('refresh');
                        });
                    } else {
                        let html = '<div class="alert alert-danger">' + escapeHtml((data && data['message']) || "{{ lang._('Import failed.') }}") + '</div>';
                        html += renderList("{{ lang._('Validation errors') }}", data ? data['errors'] : [], 'alert-danger');
                        $("#importResult").html(html);
                    }
                }
            });
    });
</script>

<div class="content-box" style="padding-bottom: 1.5em;">
    {{ partial("layout_partials/base_form",['fields':generalForm,'id':'frm_settings'])}}
</div>

<div class="content-box" style="margin-top: 1.5em; padding: 1.5em;">
    <button class="btn btn-default" id="importConfigBtn" type="button">
        <i class="fa fa-upload"></i> {{ lang._('Import config.yml') }}
    </button>
    <div class="text-muted" style="margin-top: 0.5em;">
        {{ lang._('Import an existing Blocky config.yml. This replaces the current configuration: list entries are rebuilt and any setting not present in the file is reset to its default. Unsupported keys are reported and skipped. If the file is invalid nothing is changed. After a successful import, review the settings and then apply them.') }}
    </div>
    <div id="importResult" style="margin-top: 1em;"></div>
</div>

{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/blocky/service/reconfigure', 'data_service_widget': 'blocky'}) }}
