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
     * Write-only secrets never reach the page, so Clear Saved Value, like core's Clear All, takes effect on
     * save, and typing a new value instead replaces the saved one. A removal is sent as the one
     * value nobody can type (SecretField::CLEAR), only for the moment the form is read. An eye
     * inside the input shows what is being typed, e.g. a file: path or connection string. It is only
     * there while the input holds text, so it is not taken for a way to see a saved value; emptied,
     * the input is masked again.
     */
    function blockySecrets() {
        const pending = {};
        const input = ref => $('#' + $.escapeSelector('blocky.' + ref));
        const placeholder = removing => removing ? null : '********';
        /* offer to remove the secrets that hold a value, again after a save to show what was stored */
        const offer = () => ajaxGet('/api/blocky/settings/secrets', {}, function (data) {
            $.each(data || {}, function (ref, saved) {
                const $input = input(ref);
                if (!$input.length) {
                    return;
                }
                /* once, and not where core has an eye of its own */
                if (!$input.next('.form-control-feedback').length) {
                    const $eye = $('<span class="form-control-feedback text-muted hidden">')
                        .attr('title', "{{ lang._('Show or hide') }}")
                        /* the themes place it for a label above the input */
                        .css({top: 0, bottom: 0, height: 'auto', display: 'flex', 'align-items': 'center', 'justify-content': 'center', cursor: 'pointer'})
                        .append($('<i class="fa fa-eye"></i>'))
                        /* the caret stays in the input */
                        .on('mousedown', event => event.preventDefault())
                        .on('click', function () {
                            const hidden = $input.attr('type') === 'password';
                            $input.attr('type', hidden ? 'text' : 'password');
                            $eye.find('i').toggleClass('fa-eye', !hidden).toggleClass('fa-eye-slash', hidden);
                        });
                    let inline = null;
                    /* room for the eye inside the input, which keeps its size. It is made as the input is
                       clicked or focused, so a password manager places its own icon clear of the eye. */
                    const makeRoom = function () {
                        if (inline === null && $input.is(':visible')) {
                            const width = $input.outerWidth();
                            inline = {'width': $input[0].style.width, 'padding-right': $input[0].style.paddingRight};
                            $input.css('padding-right', parseFloat($input.css('padding-right')) + parseFloat($eye.css('width')));
                            $input.outerWidth(width).parent().css('width', width);
                        }
                    };
                    const freeRoom = function () {
                        if (inline !== null && $input.val() === '' && !$input.is(':focus')) {
                            $input.css(inline).parent().css('width', '');
                            inline = null;
                        }
                    };
                    /* setFormData() triggers change, as does code here that sets the value */
                    const sync = function () {
                        if ($input.val() === '') {
                            $input.attr('type', 'password');
                            $eye.addClass('hidden').find('i').addClass('fa-eye').removeClass('fa-eye-slash');
                            freeRoom();
                        } else {
                            makeRoom();
                            $eye.toggleClass('hidden', inline === null);
                        }
                    };
                    $input.wrap($('<div style="position: relative;">')).after($eye)
                        .on('mousedown focus', makeRoom).on('blur', freeRoom).on('input change', sync);
                    sync();
                }
                $input.off('input.blocky-secret').parent().siblings('.blocky-secret').remove();
                delete pending[ref];
                if (saved !== true) {
                    $input.attr('placeholder', null);
                    return;
                }
                /* never shown, also not right after it was typed and saved */
                $input.val('').change();
                const $link = $('<a href="#" class="text-danger">');
                const mark = function (removing) {
                    pending[ref] = removing;
                    $input.attr('placeholder', placeholder(removing));
                    $link.empty().append($('<i class="fa"></i>').addClass(removing ? 'fa-check-circle' : 'fa-times-circle'), ' ',
                        $('<small>').text(removing ? "{{ lang._('Keep Saved Value') }}" : "{{ lang._('Clear Saved Value') }}"));
                };
                mark(false);
                $link.on('click', function (event) {
                    event.preventDefault();
                    $input.val('').change();
                    mark(!pending[ref]);
                });
                $input.on('input.blocky-secret', function () {
                    if (pending[ref]) {
                        mark(false);
                    }
                });
                $input.parent().after($('<div class="blocky-secret" style="margin-top: 0.3em;">').append($link));
            });
        });
        offer();
        return {
            /* save the form, sending pending removals, then show what was stored */
            save: function (endpoint, formId, done, failed) {
                const marked = [];
                $.each(pending, function (ref, removing) {
                    if (removing && input(ref).val() === '') {
                        marked.push(input(ref).val('\0'));
                    }
                });
                saveFormToEndpoint(endpoint, formId, function () {
                    offer();
                    done();
                }, true, failed);
                marked.forEach($field => $field.val(''));
            }
        };
    }
</script>
