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
    /*
     * Write-only secrets never reach the page, so Remove, like core's Clear All, takes effect on
     * save, and typing a new value instead replaces the saved one. A removal is sent as the one
     * value nobody can type (SecretField::CLEAR), only for the moment the form is read.
     */
    function blockySecrets() {
        const pending = {};
        const input = ref => $('#' + $.escapeSelector('blocky.' + ref));
        const placeholder = removing => removing
            ? "{{ lang._('Removed when saved') }}" : "{{ lang._('Saved, leave empty to keep') }}";
        ajaxGet('/api/blocky/settings/secrets', {}, function (data) {
            $.each(data || {}, function (ref, saved) {
                const $input = input(ref);
                if (saved !== true || !$input.length) {
                    return;
                }
                const $link = $('<a href="#" class="text-danger">');
                const mark = function (removing) {
                    pending[ref] = removing;
                    $input.attr('placeholder', placeholder(removing));
                    $link.empty().append($('<i class="fa fa-times-circle"></i>'), ' ',
                        $('<small>').text(removing ? "{{ lang._('Undo') }}" : "{{ lang._('Remove') }}"));
                };
                mark(false);
                $link.on('click', function (event) {
                    event.preventDefault();
                    $input.val('');
                    mark(!pending[ref]);
                });
                $input.on('input', function () {
                    if (pending[ref]) {
                        mark(false);
                    }
                });
                $input.after($('<div class="blocky-secret" style="margin-top: 0.3em;">').append($link));
            });
        });
        return {
            /* save the form, sending pending removals, and forget them once saved */
            save: function (endpoint, formId, done, failed) {
                const marked = [];
                $.each(pending, function (ref, removing) {
                    if (removing && input(ref).val() === '') {
                        marked.push(input(ref).val('\0'));
                    }
                });
                saveFormToEndpoint(endpoint, formId, function () {
                    $.each(pending, function (ref, removing) {
                        if (removing) {
                            input(ref).attr('placeholder', '').siblings('.blocky-secret').remove();
                            delete pending[ref];
                        }
                    });
                    done();
                }, true, failed);
                marked.forEach($field => $field.val(''));
            }
        };
    }
</script>
