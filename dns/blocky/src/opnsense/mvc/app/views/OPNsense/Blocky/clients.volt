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
        mapDataToFormUI({'frm_clientlookupsettings':"/api/blocky/settings/get"}).done(function(){
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
            updateServiceControlUI('blocky');
        });
        $("#{{formGridClientgroup['table_id']}}").UIBootgrid({
            search:'/api/blocky/settings/searchClientgroup/',
            get:'/api/blocky/settings/getClientgroup/',
            set:'/api/blocky/settings/setClientgroup/',
            add:'/api/blocky/settings/addClientgroup/',
            del:'/api/blocky/settings/delClientgroup/',
            toggle:'/api/blocky/settings/toggleClientgroup/'
        });
        $("#{{formGridClientlookupclient['table_id']}}").UIBootgrid({
            search:'/api/blocky/settings/searchClientlookupclient/',
            get:'/api/blocky/settings/getClientlookupclient/',
            set:'/api/blocky/settings/setClientlookupclient/',
            add:'/api/blocky/settings/addClientlookupclient/',
            del:'/api/blocky/settings/delClientlookupclient/',
            toggle:'/api/blocky/settings/toggleClientlookupclient/'
        });
        $('#maintabs a[data-toggle="tab"]').on('shown.bs.tab', function (e) {
            history.pushState(null, null, e.target.hash);
            if (e.target.hash === '#clientgroupstab') {
                $("#{{formGridClientgroup['table_id']}}").bootgrid('reload');
            } else if (e.target.hash === '#clientnamestab') {
                $("#{{formGridClientlookupclient['table_id']}}").bootgrid('reload');
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
                saveFormToEndpoint("/api/blocky/settings/set", 'frm_clientlookupsettings', function () { dfObj.resolve(); }, true, function () { dfObj.reject(); });
                return dfObj;
            },
            onAction: function(data, status) {
                updateServiceControlUI('blocky');
            }
        });
    });
</script>

<ul class="nav nav-tabs" data-tabs="tabs" id="maintabs">
    <li class="active"><a data-toggle="tab" href="#settingstab">{{ lang._('Settings') }}</a></li>
    <li><a data-toggle="tab" href="#clientgroupstab">{{ lang._('Client Groups') }}</a></li>
    <li><a data-toggle="tab" href="#clientnamestab">{{ lang._('Client Names') }}</a></li>
</ul>

<div class="tab-content content-box __mb">
    <div id="settingstab" class="tab-pane fade in active">
        {{ partial("layout_partials/base_form",['fields':clientlookupForm,'id':'frm_clientlookupsettings'])}}
    </div>
    <div id="clientgroupstab" class="tab-pane fade in">
        {{ partial('layout_partials/base_bootgrid_table', formGridClientgroup)}}
        <div style="padding: 10px;">
            {{ lang._('Choose which list groups apply to which client. Match a client by name (wildcards * and [0-9]), IP address, FQDN, or CIDR subnet. Add a "default" entry to cover clients that match no other entry; a client with no matching entry (and no "default") is not filtered at all. %sDeny and allow lists%s take effect only for clients mapped to their group.') | format('<a href="/ui/blocky/settings/filterlists">', '</a>') }}
        </div>
    </div>
    <div id="clientnamestab" class="tab-pane fade in">
        {{ partial('layout_partials/base_bootgrid_table', formGridClientlookupclient)}}
        <div style="padding: 10px;">
            {{ lang._('Assign custom names to clients by IP address, for use in the client groups and in query logs. Useful when reverse DNS is unavailable or unreliable. This is independent of the reverse-DNS resolver configured on the %sSettings%s tab.') | format('<a href="/ui/blocky/settings/clients#settingstab">', '</a>') }}
        </div>
    </div>
</div>

{{ partial('layout_partials/base_apply_button', {'data_endpoint': '/api/blocky/service/reconfigure', 'data_service_widget': 'blocky'}) }}
{{ partial("layout_partials/base_dialog",['fields':formDialogClientgroup,'id':formGridClientgroup['edit_dialog_id'],'label':lang._('Edit client group')])}}
{{ partial("layout_partials/base_dialog",['fields':formDialogClientlookupclient,'id':formGridClientlookupclient['edit_dialog_id'],'label':lang._('Edit client name')])}}
