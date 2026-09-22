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
        mapDataToFormUI({'frm_upstreamsettings':"/api/blocky/settings/get"}).done(function(){
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            updateServiceControlUI('blocky');
        });

        $("#{{formGridUpstream['table_id']}}").UIBootgrid({
            search:'/api/blocky/settings/searchUpstream/',
            get:'/api/blocky/settings/getUpstream/',
            set:'/api/blocky/settings/setUpstream/',
            add:'/api/blocky/settings/addUpstream/',
            del:'/api/blocky/settings/delUpstream/',
            toggle:'/api/blocky/settings/toggleUpstream/'
        });
        $("#{{formGridBootstrap['table_id']}}").UIBootgrid({
            search:'/api/blocky/settings/searchBootstrap/',
            get:'/api/blocky/settings/getBootstrap/',
            set:'/api/blocky/settings/setBootstrap/',
            add:'/api/blocky/settings/addBootstrap/',
            del:'/api/blocky/settings/delBootstrap/',
            toggle:'/api/blocky/settings/toggleBootstrap/'
        });
        /* pinned addresses belong to a resolver, not to a resolv file */
        function bootstrapFields() {
            $("#row_bootstrap\\.ips").toggle($("#bootstrap\\.type").val() !== 'resolvfile');
        }
        $("#bootstrap\\.type").change(bootstrapFields);
        $('#{{ formGridBootstrap["edit_dialog_id"] }}').on('shown.bs.modal', bootstrapFields);

        $('#maintabs a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
            history.pushState(null, null, e.target.hash);
            if (e.target.hash === '#servers') {
                $("#{{formGridUpstream['table_id']}}").bootgrid('reload');
            } else if (e.target.hash === '#bootstrap') {
                $("#{{formGridBootstrap['table_id']}}").bootgrid('reload');
            }
        });

        function openTabFromHash() {
            if (window.location.hash != "") {
                $('#maintabs a[href="' + window.location.hash + '"]').click();
            }
        }
        openTabFromHash();
        /* help text links to a tab on this page only change the hash */
        $(window).on('hashchange', openTabFromHash);

        $("#reconfigureAct").SimpleActionButton({
            onPreAction: function() {
                const dfObj = new $.Deferred();
                saveFormToEndpoint("/api/blocky/settings/set", 'frm_upstreamsettings', function () {
                    dfObj.resolve();
                }, true, function () { dfObj.reject(); });
                return dfObj;
            },
            onAction: function(data, status) {
                updateServiceControlUI('blocky');
            }
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#settings">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#servers">{{ lang._('Servers') }}</a></li>
    <li><a data-toggle="tab" href="#bootstrap">{{ lang._('Bootstrap') }}</a></li>
</ul>

<div class="tab-content content-box __mb">
    <div id="settings" class="tab-pane fade in active">
        {{ partial("layout_partials/base_form",['fields':upstreamsForm,'id':'frm_upstreamsettings'])}}
    </div>
    <div id="servers" class="tab-pane fade in">
        {{ partial('layout_partials/base_bootgrid_table', formGridUpstream)}}
        <div style="padding: 10px;">
            {{ lang._('Resolvers Blocky forwards queries to. The "default" group applies to every client, so define at least one resolver there. To give specific clients their own resolvers, set the Upstream Group to a client selector - a client name (with * and [0-9] wildcards), an IP, or a CIDR. See the Resolver field for accepted server formats.') }}
        </div>
    </div>
    <div id="bootstrap" class="tab-pane fade in">
        {{ partial('layout_partials/base_bootgrid_table', formGridBootstrap)}}
        <div style="padding: 10px;">
            {{ lang._('Bootstrap resolvers look up the host names of upstream DNS servers and of deny/allow list download URLs, useful when no system DNS resolver is configured. Plain-IP resolvers need no pinned IPs; add pinned IPs only for an encrypted resolver given as a host name, so it can be reached without a prior lookup. A resolv file entry reads the name servers from a resolv.conf-style file instead. If empty, the operating system resolver is used.') }}
        </div>
    </div>
</div>

{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/blocky/service/reconfigure', 'data_service_widget': 'blocky'}) }}
{{ partial("layout_partials/base_dialog",['fields':formDialogUpstream,'id':formGridUpstream['edit_dialog_id'],'label':lang._('Edit upstream server')])}}
{{ partial("layout_partials/base_dialog",['fields':formDialogBootstrap,'id':formGridBootstrap['edit_dialog_id'],'label':lang._('Edit bootstrap resolver')])}}
