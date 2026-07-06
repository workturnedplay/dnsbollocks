(() => {
    "use strict";
    
    // --- Security & Extension Notices ---
    console.log(
        "%cⓘ [DNSbollocks Info]: The media block error directly above is harmless. " +
        "It occurs because extensions like NoScript inject layout placeholders into the page, " +
        "which our strict security policy safely rejects. No action is needed! Though if you want to change the source "+
        "replace \"media-src 'none'; \"+ with \"media-src 'self' data:; \"+ in the platform_windows.go file in function securityHeadersMiddleware.",
        "color: #0078d4; font-weight: bold; font-family: sans-serif; font-size: 11px;"
    );
    
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
    if (!csrfToken) {
        console.error('BUG: csrf-token meta tag missing or empty — all POST actions will be rejected server-side.');
    }
    
    // postAdminForm sends a POST with fields, injecting csrf_token automatically,
    // and treats redirect/opaqueredirect/2xx as success per this app's handler convention.
    async function postAdminForm(action, fields, errorPrefix) {
        const formData = new FormData();
        formData.append('csrf_token', csrfToken);
        
        for (const [key, value] of Object.entries(fields)) {
            formData.append(key, value);
        }
        
        let res;
        try {
            res = await fetch(action, { method: 'POST', body: formData, redirect: 'manual' });
        } catch (err) {
            console.error(errorPrefix + ' network error:', err);
            alert('A network error occurred: ' + errorPrefix);
            return false;
        }
        
        const isSuccessRedirect = res.status === 0 || res.status === 303 || res.type === 'opaqueredirect';
        if (!res.ok && !isSuccessRedirect) {
            const errMsg = await res.text();
            alert(errorPrefix + ':\n' + errMsg);
            return false;
        }
        
        return true;
    }
    
    // --- Filter highlight helpers ---
    // Operates directly on text nodes so it is safe even when sibling elements
    // (like <br> or <small>) are present, and survives staged-value updates that
    // change innerText without touching the DOM structure.
    function highlightTextNodes(element, terms) {
        if (!element) return;
        
        // Remove any existing highlights first so we start clean on every call.
        element.querySelectorAll('mark.filter-highlight').forEach(mark => {
            mark.replaceWith(document.createTextNode(mark.textContent));
        });
        element.normalize(); // merge adjacent text nodes created by the replacements
        
        if (terms.length === 0) return; // nothing to highlight — just clearing was the job
        
        const escaped = terms.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
        const regex = new RegExp('(' + escaped.join('|') + ')', 'gi');
        
        // Collect all text nodes under element up-front; modifying the DOM during
        // the TreeWalker traversal can confuse some browsers.
        const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null);
        const textNodes = [];
        let node;
        while ((node = walker.nextNode()) !== null) textNodes.push(node);
        
        textNodes.forEach(textNode => {
            const text = textNode.textContent;
            regex.lastIndex = 0;
            if (!regex.test(text)) { regex.lastIndex = 0; return; } // fast-path: no match
            regex.lastIndex = 0;
            
            const frag = document.createDocumentFragment();
            let lastIdx = 0;
            let match;
            while ((match = regex.exec(text)) !== null) {
                if (match.index > lastIdx) {
                    frag.appendChild(document.createTextNode(text.slice(lastIdx, match.index)));
                }
                const mark = document.createElement('mark');
                mark.className = 'filter-highlight';
                mark.textContent = match[1];
                frag.appendChild(mark);
                lastIdx = regex.lastIndex;
            }
            if (lastIdx < text.length) {
                frag.appendChild(document.createTextNode(text.slice(lastIdx)));
            }
            textNode.parentNode.replaceChild(frag, textNode);
        });
    }
    
    // Applies highlights to the three text targets in a config table row.
    // Pass terms=[] to clear all highlights on that row.
    function applyConfigRowHighlight(row, terms) {
        highlightTextNodes(row.querySelector('.config-key-text'), terms);
        highlightTextNodes(row.querySelector('.display-value'), terms);
        highlightTextNodes(row.querySelector('.config-field-desc'), terms);
    }
    
    // --- Client-Side Table Ordered-Substring Filter Logic ---
    function applyRulesFilter(clearingInteracted = false) {
        const filterInput = document.getElementById('rulesFilter');
        if (!filterInput) return;
        
        const raw = filterInput.value.trim().toLowerCase();
        sessionStorage.setItem('rulesTable_filter', raw);
        
        const terms = raw.split(/\s+/).filter(term => term.length > 0);
        const tbody = document.querySelector('#rulesTable tbody');
        if (!tbody) return;
        
        // Retrieve the item that gets a "free pass" to stay visible
        const lastInteracted = sessionStorage.getItem('rulesTable_lastInteracted');
        
        function matchesOrderedTerms(text, searchTerms) {
            let pos = 0;
            for (const term of searchTerms) {
                const found = text.indexOf(term, pos);
                if (found === -1) return false;
                pos = found + term.length;
            }
            return true;
        }
        
        Array.from(tbody.rows).forEach(row => {
            // Do not filter out or hide the inline edit row
            if (row.classList.contains('edit-row') || row.classList.contains('being-edited')) return;
            
            //You no longer need .trim() because HTML dataset attributes don't inherit layout whitespace.
            // NO MORE MAGIC INDEXES OR innerText DEPENDENCY:
            const pattern = row.dataset.rulePattern || "";
            const id = row.dataset.ruleId || "";
            const type = row.dataset.ruleType || "";
            
            // 2. Combine the actual data fields for filtering (ignoring UI button text!)
            // 2. Combine them using regular string concatenation
            // Joins them with spaces, completely avoiding backticks or string quotes
            const searchTargetText = [id, type, pattern].join(" ").toLowerCase();
            
            // 3. Evaluate the filter terms against our clean data string
            let isMatch = terms.length === 0 || matchesOrderedTerms(searchTargetText, terms);
            
            // FREE PASS: If this row is the one we just added/edited, force it to show!
            // 4. Free Pass logic (using our clean variable)
            if (lastInteracted) {
                if (lastInteracted.startsWith(" ")) {
                    // Added rule: ID was unknown, so it starts with a space.
                    // We check if the new row's string ENDS with our type and pattern.
                    if (searchTargetText.endsWith(lastInteracted)) {
                        isMatch = true;
                    }
                } else {
                    // Edited rule: ID was exact.
                    if (searchTargetText === lastInteracted) {
                        isMatch = true;
                    }
                }
            }
            
            row.style.display = isMatch ? '' : 'none';
        });
    }
    
    // --- Client-side ordered-substring filter, mirrors /rules and /response-blacklist ---
    function applyHostsFilter() {
        const filterInput = document.getElementById('hostsFilter');
        if (!filterInput) return;
        
        const raw = filterInput.value.trim().toLowerCase();
        sessionStorage.setItem('hostsTable_filter', raw);
        
        const terms = raw.split(/\s+/).filter(term => term.length > 0);
        const tbody = document.querySelector('#hostsTable tbody');
        if (!tbody) return;
        
        const lastInteracted = sessionStorage.getItem('hostsTable_lastInteracted');
        
        function matchesOrderedTerms(text, searchTerms) {
            let pos = 0;
            for (const term of searchTerms) {
                const found = text.indexOf(term, pos);
                if (found === -1) return false;
                pos = found + term.length;
            }
            return true;
        }
        
        Array.from(tbody.rows).forEach(row => {
            // Do not filter out the inline edit row
            if (row.classList.contains('edit-host-row') || row.classList.contains('being-edited')) return;
            
            const pattern = row.dataset.hostPattern || "";
            const ips = row.dataset.hostIps || "";
            const searchTargetText = [pattern, ips].join(" ").toLowerCase();
            
            let isMatch = terms.length === 0 || matchesOrderedTerms(searchTargetText, terms);
            
            // FREE PASS: keep the just-added/edited row visible even if it
            // doesn't currently match the filter text.
            if (lastInteracted && pattern.toLowerCase() === lastInteracted) {
                isMatch = true;
            }
            
            row.style.display = isMatch ? '' : 'none';
        });
    }
    
    // --- Client-side ordered-substring filter, mirrors /rules' filter ---
    function applyBlacklistFilter() {
        const filterInput = document.getElementById('blacklistFilter');
        if (!filterInput) return;
        
        const raw = filterInput.value.trim().toLowerCase();
        sessionStorage.setItem('blacklistTable_filter', raw);
        
        const terms = raw.split(/\s+/).filter(t => t.length > 0);
        const tbody = document.querySelector('#blacklistTable tbody');
        if (!tbody) return;
        
        const lastInteracted = sessionStorage.getItem('blacklistTable_lastInteracted');
        
        function matchesOrderedTerms(text, searchTerms) {
            let pos = 0;
            for (const term of searchTerms) {
                const found = text.indexOf(term, pos);
                if (found === -1) return false;
                pos = found + term.length;
            }
            return true;
        }
        
        Array.from(tbody.rows).forEach(row => {
            if (row.classList.contains('edit-row') || row.classList.contains('being-edited')) return;
            const cidr = (row.dataset.cidr || "").toLowerCase();
            
            let isMatch = terms.length === 0 || matchesOrderedTerms(cidr, terms);
            
            // Free Pass logic: ensures added/updated item remains fully visible
            if (lastInteracted && cidr === lastInteracted) {
                isMatch = true;
            }
            
            row.style.display = isMatch ? '' : 'none';
        });
    }
    
    // --- Client-side Config Filter Logic (with persistent storage and highlight) ---
    function applyConfigFilter() {
        const filterInput = document.getElementById('configFilter');
        if (!filterInput) return;
        
        const raw = filterInput.value.trim().toLowerCase();
        sessionStorage.setItem('configTable_filter', raw);
        
        const terms = raw.split(/\s+/).filter(t => t.length > 0);
        const tbody = document.querySelector('#configTable tbody');
        if (!tbody) return;
        
        Array.from(tbody.rows).forEach(row => {
            if (row.classList.contains('edit-row') || row.classList.contains('being-edited')) return;
            const key = (row.dataset.key || "").toLowerCase();
            const val = (row.dataset.original || "").toLowerCase();
            // Safely grab the text contents of the inline description field if it exists
            const descElem = row.querySelector('.config-field-desc');
            const desc = descElem ? descElem.textContent.toLowerCase() : "";
            
            // Include key, value, and description in the search text boundary
            const searchTarget = key + " " + val + " " + desc;
            
            const isMatch = terms.length === 0 || terms.every(term => searchTarget.includes(term));
            row.style.display = isMatch ? '' : 'none';
            
            // Apply or clear highlights in the three text targets.
            // Hidden rows also get their highlights cleared so stale marks don't
            // appear if the row later becomes visible due to a different filter term.
            applyConfigRowHighlight(row, isMatch ? terms : []);
        });
    }
    
    // --- Inline Cancel & Editing Clones ---
    function cancelEdit(id) {
        // 1. Find and remove the temporary edit row via the TR id
        const editRow = document.getElementById('editFormRow_' + id);
        if (editRow) editRow.remove();
        
        // 2. Find the original row using our clean layout ID hook
        const originalRow = document.getElementById('rule-row-' + id);
        if (originalRow) {
            originalRow.style.display = ''; // Bring it back into view!
            originalRow.removeAttribute('id'); // Clean up the temporary ID
            originalRow.classList.remove('being-edited');
        }
        // Re-apply the active filter now that editing has ended, so the row
        // is only shown if it still matches the current filter text.
        applyRulesFilter();
    }
    
    function editHost(btn) {
        // 0. Extract variables from the button itself
        const index = btn.dataset.index;
        const pat = btn.dataset.pattern;
        const ips = btn.dataset.ips;
        
        const row = document.getElementById('hostRow_' + index);
        row.style.display = 'none';
        row.classList.add('being-edited');
        
        // 1. Clone the template
        const tmpl = document.getElementById('editHostTemplate');
        const clone = tmpl.content.cloneNode(true);
        
        // 2. Track the row and form uniquely
        const editRow = clone.querySelector('tr');
        editRow.id = 'editHostRow_' + index;
        
        const form = clone.querySelector('.edit-host-form');
        const formId = 'editHostForm_' + index;
        form.id = formId;
        
        // 3. Populate inputs and link them to the form using the HTML5 'form' attribute
        // (Required because the inputs are inside table cells, not inside the <form> tag)
        const oldPatternInput = clone.querySelector('.edit-host-old-pattern');
        oldPatternInput.value = pat;
        oldPatternInput.setAttribute('form', formId);
        
        const patternInput = clone.querySelector('.edit-host-pattern');
        patternInput.value = pat;
        patternInput.setAttribute('form', formId);
        
        const ipsInput = clone.querySelector('.edit-host-ips');
        ipsInput.value = ips;
        ipsInput.setAttribute('form', formId);
        
        // 4. Save the new pattern and submit via AJAX
        form.addEventListener('submit', async function(eSubmit) {
            eSubmit.preventDefault();
            
            const newPattern = patternInput.value.trim().toLowerCase();
            sessionStorage.setItem('hostsTable_lastInteracted', newPattern);
            
            // Let the browser gather all form-linked inputs automatically!
            const fields = Object.fromEntries(new FormData(form));
            delete fields.csrf_token; 
            // Add the 'edit' flag that your backend expects
            fields.edit = '1';
            
            const success = await postAdminForm('/hosts', fields, 'Failed to save host edits');
            if (success) {
                location.reload();
            }
        });
        // 5. Setup cancel button
        clone.querySelector('.btn-cancel').addEventListener('click', () => cancelHostEdit(index), { once: true });
        // 6. Insert cleanly into the DOM
        row.after(clone);
    }
    
    function cancelHostEdit(index) {
        const editRow = document.getElementById('editHostRow_' + index);
        if (editRow) editRow.remove();
        const row = document.getElementById('hostRow_' + index);
        if (row) {
            row.style.display = '';
            row.classList.remove('being-edited');
        }
        // Re-apply the active filter now that editing has ended, so the row
        // is only shown if it still matches the current filter text.
        applyHostsFilter();
    }
    
    // --- Edit / Cancel for inline row editing ---
    function editBlacklist(btn) {
        const index = btn.dataset.index;
        const cidr = btn.dataset.cidr;
        
        const row = document.getElementById('blacklistRow_' + index);
        if (!row) return;
        row.style.display = 'none';
        row.classList.add('being-edited');
        
        const tmpl = document.getElementById('editBlacklistTemplate');
        const clone = tmpl.content.cloneNode(true);
        
        const editRow = clone.querySelector('tr');
        editRow.id = 'editBlacklistRow_' + index;
        
        const form = clone.querySelector('.edit-blacklist-form');
        const formId = 'editBlacklistForm_' + index;
        form.id = formId;
        
        const oldCidrInput = clone.querySelector('.edit-blacklist-old-cidr');
        oldCidrInput.value = cidr;
        oldCidrInput.setAttribute('form', formId);
        
        const cidrInput = clone.querySelector('.edit-blacklist-cidr');
        cidrInput.value = cidr;
        cidrInput.setAttribute('form', formId);
        
        // Save target CIDR signature and submit via AJAX
        form.addEventListener('submit', async function(eSubmit) {
            eSubmit.preventDefault();
            
            const newCidr = cidrInput.value.trim().toLowerCase();
            sessionStorage.setItem('blacklistTable_lastInteracted', newCidr);
            
            // Let the browser gather all form-linked inputs automatically!
            const fields = Object.fromEntries(new FormData(form));
            delete fields.csrf_token; // Our helper injects this automatically
            // Add the 'action' flag that your backend expects
            fields.action = 'edit';
            
            const success = await postAdminForm('/response-blacklist', fields, 'Failed to save blacklist edits');
            if (success) {
                location.reload();
            }
        });
        
        clone.querySelector('.btn-cancel').addEventListener('click', () => cancelBlacklistEdit(index), { once: true });
        row.after(clone);
    }
    
    function cancelBlacklistEdit(index) {
        const editRow = document.getElementById('editBlacklistRow_' + index);
        if (editRow) editRow.remove();
        const row = document.getElementById('blacklistRow_' + index);
        if (row) {
            row.style.display = '';
            row.classList.remove('being-edited'); 
        }
        // Discarding active inline changes cleanly respects and updates current active layout filter state
        applyBlacklistFilter();
    }
    
    const stagedChanges = {};
    
    function editConfig(key) {
        // Find existing items
        const row = document.getElementById('configRow_' + key);
        if (!row) return;
        
        // Cancel any existing inline edits to prevent duplicate row injection
        document.querySelectorAll('.config-cancel-btn').forEach(btn => btn.click());
        
        const type = row.dataset.type;
        const currentDisplay = row.querySelector('.display-value').innerText;
        //const isPwd = row.dataset.isPwd === 'true';
        //const options = row.dataset.options;
        
        // Capture the row's rendered height before hiding it so we can prevent
        // the edit row from being shorter (which causes a layout jump).
        // In HTML tables, setting `height` on a <tr> acts as min-height.
        // Fall back to 64px (the standard row height from CSS) if the row is
        // somehow unmeasurable (e.g., hidden by an active filter).
        const rowHeight = Math.max(64, row.getBoundingClientRect().height);
        
        row.style.display = 'none';
        row.classList.add('being-edited');
        
        // Setup Template
        const tmpl = document.getElementById('editConfigTemplate');
        const clone = tmpl.content.cloneNode(true);
        const editRow = clone.querySelector('tr');
        editRow.id = 'editConfigRow_' + key;
        
        // Lock the edit row so it cannot be shorter than the original row,
        // preventing any upward layout jump. It can still expand for textareas.
        editRow.style.height = rowHeight + 'px';
        
        // Populate key and safely carry over its description block
        const keyDisplay = editRow.querySelector('.edit-key-display');
        // Clone the inner span element to preserve existing filter highlight nodes
        const origKeyText = row.querySelector('.config-key-text');
        if (origKeyText) {
            keyDisplay.appendChild(origKeyText.cloneNode(true));
        } else {
            keyDisplay.textContent = key;
        }
        
        const origDesc = row.querySelector('.config-field-desc');
        if (origDesc) {
            keyDisplay.appendChild(document.createElement('br'));
            keyDisplay.appendChild(origDesc.cloneNode(true));
        }
        
        const container = editRow.querySelector('.edit-input-container');
        const hint = editRow.querySelector('.edit-type-hint');
        
        // Remove strict row height lock temporarily so textareas can expand
        editRow.style.height = 'auto';// Safe CSSOM assignment
        
        // Dynamically type the input control cleanly without inline string styles
        if (key === 'upstream_selection_mode') {
            container.innerHTML = `<select class="config-input w-100">
                                        <option value="fastest" ${currentDisplay === 'fastest' ? 'selected' : ''}>fastest</option>
                                        <option value="failover" ${currentDisplay === 'failover' ? 'selected' : ''}>failover</option>
                                        <option value="strict" ${currentDisplay === 'strict' ? 'selected' : ''}>strict</option>
                                       </select>`;
            hint.innerText = "Strategy for querying upstreams";
        } else if (key === 'console_log_level') {
            container.innerHTML = `<select class="config-input w-100">
                                        <option value="debug" ${currentDisplay === 'debug' ? 'selected' : ''}>debug</option>
                                        <option value="info" ${currentDisplay === 'info' ? 'selected' : ''}>info</option>
                                        <option value="warn" ${currentDisplay === 'warn' ? 'selected' : ''}>warn</option>
                                        <option value="error" ${currentDisplay === 'error' ? 'selected' : ''}>error</option>
                                       </select>`;
            hint.innerText = "Console output verbosity";
        } else if (key === 'block_mode') {
            container.innerHTML = `<select class="config-input w-100">
                                        <option value="nxdomain" ${currentDisplay === 'nxdomain' ? 'selected' : ''}>nxdomain</option>
                                        <option value="ip_block" ${currentDisplay === 'ip_block' ? 'selected' : ''}>ip_block</option>
                                        <option value="drop" ${currentDisplay === 'drop' ? 'selected' : ''}>drop</option>
                                       </select>`;
            hint.innerText = "Action taken when blocking queries";
        } else if (key === 'webui_password_hash') {
            container.innerHTML = `<input type="text" class="config-input monospace-code2" placeholder="Enter NEW password here...">`;
            hint.innerText = "Type a plaintext password (it will be hashed on save), don't prefix it with $2";
        } else if (type === 'bool') {
            const isTrue = currentDisplay === 'true';
            container.innerHTML = `<select class="config-input w-100">
                                        <option value="true" ${isTrue ? 'selected' : ''}>true</option>
                                        <option value="false" ${!isTrue ? 'selected' : ''}>false</option>
                                       </select>`;
            hint.innerText = "Boolean (true/false)";
        } else if (type === '[]string') {
            // Swap to textarea and format the current comma-string into 2xnewlines for easier editing and visually delimit each logical line (needed due to wrapping)
            const formattedDisplay = currentDisplay.split(',').map(s => s.trim()).join('\n\n');
            container.innerHTML = `<textarea class="config-input config-textarea">${formattedDisplay}</textarea>`;
            // Updated, highly reassuring hint text
            hint.innerText = "List (separate items with newlines or commas. Extra spaces, multiple commas, or empty lines are auto-cleaned.)";
        } else if (type === 'int') {
            container.innerHTML = `<input type="number" class="config-input w-100" value="${currentDisplay}">`;
            hint.innerText = "Integer value";
        } else {
            container.innerHTML = `<input type="text" class="config-input w-100" value="${currentDisplay}">`;
            hint.innerText = "FIXME: unhandled type '"+type+"', fallback to:String value";
        }
        
        // Re-apply the height lock now that we know whether it is a textarea or not.
        // For non-textarea types the edit row should match the original row height exactly
        // (neither shrink nor expand). For textarea types we allow expansion but still
        // enforce the original row height as the minimum.
        editRow.style.height = rowHeight + 'px';
        
        // Handle Cancel
        clone.querySelector('.config-cancel-btn').addEventListener('click', () => {
            editRow.remove();
            row.style.display = '';
            row.classList.remove('being-edited');
            applyConfigFilter();
        }, { once: true });
        
        // Handle Staging the change
        clone.querySelector('.config-stage-btn').addEventListener('click', () => {
            
            const rawVal = editRow.querySelector('.config-input').value;
            
            // Password confirmation logic!
            //&& rawVal !== '********' && rawVal !== currentDisplay) {
            if (isPwd && rawVal !== '' ) {
                const confirmPwd = prompt("Please confirm your new password by typing it again:");
                if (confirmPwd !== rawVal) {
                    alert("Passwords do not match. Staging cancelled.");
                    return; // Abort, FIXME: have to re-add listener for this Stage button!
                }
            }
            
            let parsedVal = rawVal;
            let displayVal = rawVal;
            
            if (type === 'int') {
                parsedVal = parseInt(rawVal, 10);
                if (isNaN(parsedVal)) { alert('Value must be a valid integer.'); return; }
                displayVal = parsedVal.toString();
            } else if (type === 'bool') {
                parsedVal = rawVal === 'true';
                displayVal = parsedVal.toString();
            } else if (type === '[]string') {
                // Split by newline OR comma to be flexible
                parsedVal = rawVal.split(/[\n,]+/).map(s => s.trim()).filter(s => s !== '');
                displayVal = parsedVal.join(', ');
            }
            
            // Save to object, modify UI, flag it
            stagedChanges[key] = parsedVal;
            row.querySelector('.display-value').innerText = displayVal;
            row.dataset.original = displayVal;
            row.classList.add('staged');
            row.classList.remove('being-edited'); 
            
            editRow.remove();
            row.style.display = '';
            
            applyConfigFilter();
            // Pop the banner
            updateBanner();
        }, { once: true });
        
        // Insert the edit row into the live DOM before any post-insertion adjustments.
        row.after(clone);
        
        // Post-insertion: auto-size the textarea now that it is in the DOM and
        // scrollHeight is measurable. This must happen after row.after(clone).
        if (type === '[]string') {
            const ta = editRow.querySelector('.config-input');
            if (ta && ta.tagName === 'TEXTAREA') {
                // Collapse to measure true content height, then expand to fit.
                ta.style.height = 'auto';
                const contentH = ta.scrollHeight;
                
                // The user may have previously resized a textarea on this page.
                // Apply the saved height if it is larger than the content height,
                // so the preference is honoured without hiding any content.
                const savedH = parseInt(sessionStorage.getItem('config_textarea_height') || '0', 10);
                const finalH = Math.max(contentH, savedH, 85); // 85px is the CSS minimum
                ta.style.height = finalH + 'px';
                
                // Prevent the user from dragging the textarea smaller than its
                // content; they can still make it bigger.
                ta.style.minHeight = Math.max(contentH, 85) + 'px';
                
                // Also update the edit row's height floor so the row matches the
                // (now potentially taller) textarea.
                editRow.style.height = Math.max(rowHeight, finalH + 12) + 'px'; // +12 for cell padding
                
                // Persist the height whenever the user finishes a resize drag.
                // offsetHeight reflects the actual rendered height including padding.
                ta.addEventListener('mouseup', () => {
                    const h = ta.offsetHeight;
                    if (h > 0) {
                        sessionStorage.setItem('config_textarea_height', String(h));
                    }
                });
                
                // Double left-click on the resize handle clears the saved user preference
                ta.addEventListener('dblclick', (e) => {
                    const rect = ta.getBoundingClientRect();
                    const clickX = e.clientX - rect.left;
                    const clickY = e.clientY - rect.top;
                    
                    // Check if the click happened inside a 20px square at the bottom-right corner
                    if (clickX >= rect.width - 20 && clickY >= rect.height - 20) {
                        if (confirm('Reset and stop remembering the custom textarea size?')) {
                            // Remove the preference completely
                            sessionStorage.removeItem('config_textarea_height');
                            
                            // Recalculate and snap layout back to natural content boundaries instantly
                            ta.style.height = 'auto';
                            const freshContentH = ta.scrollHeight;
                            const defaultH = Math.max(freshContentH, 85); // 85px is the CSS minimum
                            
                            ta.style.height = defaultH + 'px';
                            ta.style.minHeight = defaultH + 'px';
                            editRow.style.height = Math.max(rowHeight, defaultH + 12) + 'px'; // +12 for cell padding
                        }
                    }
                });
            }
        }
        
        editRow.querySelector('.config-input')?.focus();
    }
    
    function updateBanner() {
        const count = Object.keys(stagedChanges).length;
        const banner = document.getElementById('stagedChangesBanner');
        if (count > 0) {
            banner.style.display = 'block';
            document.getElementById('stagedCount').innerText = count;
        } else {
            banner.style.display = 'none';
        }
    }
    
    async function applyConfigChanges() {
        if (Object.keys(stagedChanges).length === 0) return;
        if (!confirm('Applying changes will overwrite config.json and gracefully restart listeners. Proceed?')) return;
        
        const success = await postAdminForm('/config', {
            'action': 'apply',
            'payload': JSON.stringify(stagedChanges)
        }, 'Failed to apply configuration');
        
        if (success) {
            location.reload();
        }
    }
    
    // --- Core Dynamic Initialization (DOMContentLoaded Closure Block) ---
    document.addEventListener('DOMContentLoaded', function() {
        
        // Consolidated Keyboard Handler ensuring typing and Escape contexts operate precisely
        document.addEventListener('keydown', function(e) {
            const activeTag = document.activeElement.tagName;
            const isTyping = activeTag === 'INPUT' || activeTag === 'SELECT' || activeTag === 'TEXTAREA';
            
            if (!isTyping) {
                const isF5 = e.key === 'F5';
                const isCtrlR = (e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'r';
                
                if (isF5 || isCtrlR) {
                    e.preventDefault(); // Stop Firefox from doing a POST-reload
                    //window.location.href = '/blocks'; // Perform a clean GET-reload instead
                    //window.location.href = window.location.pathname; // Clean GET-reload for the current page, this resets scroll position to top
                    window.location.reload(); // tells the browser's engine: "This is a refresh of the exact same context," which allows it to fire up its native scroll restoration feature and keep your position locked exactly where you left it!
                    return;
                }
                
                if (e.key === '/') {
                    const filterInput = document.querySelector('.table-filter-input');
                    if (filterInput) {
                        e.preventDefault();
                        filterInput.focus();
                        filterInput.select(); // Highlight existing text so they can immediately overwrite it
                    }
                }
            } else {
                if (e.key === 'Escape') {
                    const filterInput = document.querySelector('.table-filter-input');
                    if (filterInput && document.activeElement === filterInput) {
                        filterInput.blur();// Drops focus cleanly
                    }
                }
            }
        });
        
        // Global Rules Table Event Delegation (Interceptors for Edit and Delete Actions)
        document.addEventListener('click', function(e) {
            // 1. Check if the element clicked (or its nested contents) matches our class
            const editBtn = e.target.closest('.btn-edit');
            if (editBtn) {
                // 2. Safely grab the closest table row relative to the button
                const row = editBtn.closest('tr');
                
                // FIX: Stop if it's not a row, OR if it's not a Rules table row
                if (!row || !row.hasAttribute('data-rule-id')) return;
                
                e.preventDefault();
                
                // 3. Grab the data cleanly from the row dataset
                const id = row.dataset.ruleId;
                const typ = row.dataset.ruleType;
                const oldPattern = row.dataset.rulePattern;
                const enabled = row.dataset.ruleEnabled === 'true';
                
                // 4. Tag the original row with a unique layout ID so Cancel/Save can find it
                row.id = 'rule-row-' + id;
                row.style.display = 'none';
                row.classList.add('being-edited');
                
                // 1. Clone the template natively
                const tmpl = document.getElementById('editRuleTemplate');
                const clone = tmpl.content.cloneNode(true);
                
                // Add an ID to the <tr> to make cleanup easy
                clone.querySelector('tr').id = 'editFormRow_' + id;
                
                // 2. Grab references to the inputs in our clone
                const typeSelect = clone.querySelector('.edit-type');
                const idDisplay = clone.querySelector('.edit-id-display');
                const patternInput = clone.querySelector('.edit-pattern');
                const enabledCheck = clone.querySelector('.edit-enabled');
                const idInput = clone.querySelector('.edit-id-input');
                const form = clone.querySelector('.edit-form');
                const cancelBtn = clone.querySelector('.btn-cancel');
                
                // 3. Populate values securely as object properties (no string escaping needed)
                typeSelect.value = typ;
                idDisplay.textContent = id;
                idDisplay.title = id;
                patternInput.value = oldPattern;
                enabledCheck.checked = enabled;
                idInput.value = id;
                
                // 4. Setup Cancel action
                
                cancelBtn.addEventListener('click', () => cancelEdit(id), { once: true });
                // 5. Handle form submission
                form.addEventListener('submit', async function(eSubmit) {
                    eSubmit.preventDefault();
                    
                    const newPattern = patternInput.value.trim();
                    const enabledChecked = enabledCheck.checked; //uses the captured one from outside this is bugfix btw(says Gemini)
                    const newType = typeSelect.value;
                    
                    if (newPattern === '') { alert('newPattern cannot be empty'); return; }
                    
                    // --- SAVE THE NEW PATTERN AS LAST INTERACTED BEFORE RELOAD ---
                    const ruleSignature = [id, newType, newPattern].join(" ").toLowerCase();
                    sessionStorage.setItem('rulesTable_lastInteracted', ruleSignature);
                    
                    // --- DRY FETCH ---
                    const success = await postAdminForm('/rules', {
                        'id': id,
                        'pattern': newPattern,
                        'type': newType,
                        'enabled': enabledChecked ? 'true' : 'false'
                    }, 'Failed to save edits');
                    
                    if (success) {
                        location.reload();
                    }
                });
                
                // 6. Insert cleanly next to the original row
                row.after(clone);
            } // end of 'if editBtn'
            
            // --- DELETE BUTTON INTERCEPTOR ---
            const delBtn = e.target.closest('.btn-del');
            if (delBtn) {
                const row = delBtn.closest('tr');
                // FIX: Stop if it's not a row, OR if it's not a Rules table row
                if (!row || !row.hasAttribute('data-rule-id')) return;
                
                e.preventDefault(); // Stop native link/button submission
                
                const id = row.dataset.ruleId;
                const typ = row.dataset.ruleType;
                const pattern = row.dataset.rulePattern;
                
                // Native confirmation dialog
                if (!confirm('Delete rule: ' + pattern + '?')) return;
                
                // Clear out the free pass if we are deleting the item that had it
                const ruleSignature = [id, typ, pattern].join(" ").toLowerCase();
                if (sessionStorage.getItem('rulesTable_lastInteracted') === ruleSignature) {
                    sessionStorage.removeItem('rulesTable_lastInteracted');
                }
                
                // Submit in the background and reload cleanly
                const delForm = delBtn.closest('form');
                if (delForm) {
                    fetch(delForm.action, {
                        method: 'POST',
                        body: new FormData(delForm),
                        redirect: 'manual'
                    })
                    .then(async (res) => {
                        // If the response is OK (2xx) or a manual redirect (0, 303, or opaqueredirect), it's a success
                        const isSuccessRedirect = res.status === 0 || res.status === 303 || res.type === 'opaqueredirect';
                        if (!res.ok && !isSuccessRedirect) {
                            const errMsg = await res.text();
                            alert("Failed to delete rule:\n" + errMsg);
                            return; // Halt here, do NOT reload
                        }
                        location.reload();
                    })
                    .catch(err => {
                        console.error('Delete failed:', err);
                        alert('A network error occurred while deleting the rule.');
                    });
                }
            }
        }); // end of 'click' listener
        
        // Bind Rules filters on boot safely inside DOMContentLoaded
        const filterInput = document.getElementById('rulesFilter');
        if (filterInput) {
            filterInput.value = sessionStorage.getItem('rulesTable_filter') || '';
            // Typing clears the free pass so the table filters normally again
            filterInput.addEventListener('input', () => {
                sessionStorage.removeItem('rulesTable_lastInteracted');
                applyRulesFilter();
            });
            // Run IMMEDIATELY on boot load so the table stays filtered!
            applyRulesFilter();
        }
        // --- ADD RULE INTERCEPTOR ---
        const addForm = document.getElementById('addRuleForm');
        if (addForm) {
            addForm.addEventListener('submit', async function(e) {
                e.preventDefault(); // Stop native browser submission
                
                const patternInput = addForm.querySelector('[name="pattern"]');
                const typeSelect = addForm.querySelector('[name="type"]');
                if (!patternInput || !typeSelect) return;
                
                const pattern = patternInput.value.trim().toLowerCase();
                const type = typeSelect.value.toLowerCase();
                if (pattern === '') return;
                
                // Generate signature with an empty string for the missing ID
                const ruleSignature = ["", type, pattern].join(" ").toLowerCase();
                sessionStorage.setItem('rulesTable_lastInteracted', ruleSignature);
                
                // 1. Gather all inputs from the HTML form cleanly into an object
                const fields = Object.fromEntries(new FormData(addForm));
                // 2. Remove csrf_token from the object so postAdminForm doesn't duplicate it
                delete fields.csrf_token;
                
                // 3. Submit via our DRY helper function
                const success = await postAdminForm(addForm.action, fields, 'Failed to add rule');
                if (success) {
                    location.reload();
                }
            });
        }
        
        
        
        // ── Blocks page ───────────────────────────────────────────────────────────
        // Refresh button navigates to /blocks via GET, bypassing any cached POST state.
        const blocksRefreshBtn = document.querySelector('.js-blocks-refresh-btn');
        if (blocksRefreshBtn) {
            blocksRefreshBtn.addEventListener('click', () => {
                window.location.href = '/blocks';
            });
        }
        
        // ── Hosts page ────────────────────────────────────────────────────────────
        // Edit buttons: pass the button element to editHost() exactly as onclick="editHost(this)" did.
        // Direct binding is safe here because rows are server-rendered; none are added dynamically
        // without a full page reload, so every .js-host-edit button exists at DOMContentLoaded time.
        document.querySelectorAll('.js-host-edit').forEach(btn => {
            btn.addEventListener('click', () => editHost(btn));
        });
        
        // Delete forms: confirm, then conditionally clean the free-pass sessionStorage key.
        // Reading pattern from the hidden <input name="pattern"> already inside the form
        // avoids adding any new data attributes to the HTML.
        document.querySelectorAll('.js-host-delete-form').forEach(form => {
            form.addEventListener('submit', function(e) {
                if (!confirm('Delete local host override?')) {
                    e.preventDefault();
                    return;
                }
                const patternInput = form.querySelector('[name="pattern"]');
                if (!patternInput) {
                    // Defensive: form structure invariant violated; block submission rather
                    // than silently deleting without the sessionStorage cleanup.
                    console.error('js-host-delete-form: missing [name="pattern"] input');
                    e.preventDefault();
                    return;
                }
                const pattern = patternInput.value.toLowerCase();
                if (sessionStorage.getItem('hostsTable_lastInteracted') === pattern) {
                    sessionStorage.removeItem('hostsTable_lastInteracted');
                }
                // Fall through: browser performs the native POST submission.
            });
        });
        
        // --- ADD HOST FREE-PASS TRACKING ---
        // Records the pattern being added so the new row stays visible after
        // reload even if it doesn't currently match the active filter text.
        document.getElementById('addHostForm')?.addEventListener('submit', function() {
            const patternInput = this.querySelector('[name="pattern"]');
            if (patternInput) {
                sessionStorage.setItem('hostsTable_lastInteracted', patternInput.value.trim().toLowerCase());
            }
        });
        
        // Load filter value from persistent sessionStorage on page load
        const hostsFilterInput = document.getElementById('hostsFilter');
        if (hostsFilterInput) {
            hostsFilterInput.value = sessionStorage.getItem('hostsTable_filter') || '';
            hostsFilterInput.addEventListener('input', () => {
                sessionStorage.removeItem('hostsTable_lastInteracted');
                applyHostsFilter();
            });
            applyHostsFilter();
        }
        
        // ── Response-blacklist page ───────────────────────────────────────────────
        document.querySelectorAll('.js-blacklist-edit').forEach(btn => {
            btn.addEventListener('click', () => editBlacklist(btn));
        });
        
        // Note: the original onsubmit removed from sessionStorage *before* confirming,
        // meaning a cancel would still clear it. Fixed here: confirm first, clean after.
        document.querySelectorAll('.js-blacklist-delete-form').forEach(form => {
            form.addEventListener('submit', function(e) {
                const cidrInput = form.querySelector('[name="cidr"]');
                if (!cidrInput) {
                    console.error('js-blacklist-delete-form: missing [name="cidr"] input');
                    e.preventDefault();
                    return;
                }
                const cidr = cidrInput.value;
                if (!confirm('Remove ' + cidr + ' from blacklist?')) {
                    e.preventDefault();
                    return;
                }
                if (sessionStorage.getItem('blacklistTable_lastInteracted') === cidr.toLowerCase()) {
                    sessionStorage.removeItem('blacklistTable_lastInteracted');
                }
            });
        });
        
        // Load filter values from persistent sessionStorage on load tracking configuration
        const blacklistFilterInput = document.getElementById('blacklistFilter');
        if (blacklistFilterInput) {
            blacklistFilterInput.value = sessionStorage.getItem('blacklistTable_filter') || '';
            blacklistFilterInput.addEventListener('input', () => {
                sessionStorage.removeItem('blacklistTable_lastInteracted');
                applyBlacklistFilter();
            });
            applyBlacklistFilter();
        }
        
        // --- Existing "check for overlapping filters before add" validation ---
        document.getElementById('add-blacklist-form')?.addEventListener('submit', async function(e) {
            e.preventDefault(); // Stop form from auto-posting immediately
            
            const form = this;
            const cidrInput = form.querySelector('input[name="cidr"]');
            const cidrValue = cidrInput.value.trim().toLowerCase();
            
            if (!cidrValue) return;
            
            // Force persistent layout memory tracking hook prior to redirect submission triggers
            sessionStorage.setItem('blacklistTable_lastInteracted', cidrValue);
            try {
                const response = await fetch(`/response-blacklist/check?cidr=${encodeURIComponent(cidrValue)}`);
                if (response.ok) {
                    const data = await response.json();
                    
                    if (data.matches && data.matches.length > 0) {
                        // Double-ask user confirmation showing exact matching filters
                        const message = `This target is already covered or matched by these existing filters:\n• ` +
                        data.matches.join('\n• ') +
                        `\n\nDo you still want to add it as a separate redundant entry?`;
                        
                        if (!confirm(message)) {
                            return; // User clicked "Cancel" -> abort
                        }
                    }
                }
            } catch (err) {
                const msg = `Validation check failed (you must allow "fetch" (under "Custom") in NoScript Firefox extension).\n\n` +
                `Error details: ${err}\n\n` +
                `Would you like to bypass validation and add this entry anyway? (Note: It might be redundant if other filters already cover it.)`;
                
                // RESTORED DIAGNOSTIC LOG AND TELEMETRY STRINGS
                console.error(msg);
                // If user clicks "Cancel" (No), abort form submission.
                // If they click "OK" (Yes), execution drops below the try/catch and hits form.submit()
                
                if (!confirm(msg)) {
                    console.log("chose to NOT add it without validation, cidrValue=" + cidrValue);
                    return; 
                } else {
                    console.log("chose to add it without validation, cidrValue=" + cidrValue);
                }
            }
            
            form.submit(); // User clicked "OK" or check passed -> fire native submission
        });
        
        // ── Config page ───────────────────────────────────────────────────────────
        // Edit buttons: key lives on the row's data-key, not repeated on the button.
        document.querySelectorAll('.js-config-edit').forEach(btn => {
            btn.addEventListener('click', () => {
                const row = btn.closest('tr[data-key]');
                if (!row) {
                    // RESTORED STRUCTURAL DIAGNOSTIC WARNING
                    console.error('js-config-edit: could not find ancestor tr[data-key]');
                    return;
                }
                editConfig(row.dataset.key);
            });
        });
        
        const applyConfigBtn = document.getElementById('js-apply-config-btn');
        if (applyConfigBtn) {
            applyConfigBtn.addEventListener('click', applyConfigChanges);
        }
        
        const discardConfigBtn = document.getElementById('js-discard-config-btn');
        if (discardConfigBtn){
            discardConfigBtn.addEventListener('click', () => location.reload());
        }
        // Bind event listener and restore saved state on page load
        const configFilterInput = document.getElementById('configFilter');
        if (configFilterInput) {
            configFilterInput.value = sessionStorage.getItem('configTable_filter') || '';
            configFilterInput.addEventListener('input', applyConfigFilter);
            // Run immediately on page boot to apply the active filter
            applyConfigFilter();
        }
        
        // ── Logs page ─────────────────────────────────────────────────────────────
        // Clear button resets the q field and submits, matching the original
        // onclick="this.form.q.value=''; this.form.submit();" behavior exactly.
        const logsClearBtn = document.querySelector('.js-logs-clear-btn');
        if (logsClearBtn) {
            logsClearBtn.addEventListener('click', function() {
                const form = logsClearBtn.closest('form');
                if (!form) {
                    console.error('js-logs-clear-btn: not inside a <form>');
                    return;
                }
                const qInput = form.querySelector('[name="q"]');
                if (qInput) qInput.value = '';
                form.submit();
            });
        }
        
        // Clean up visual status notifications on browser refresh triggers
        //Because the messages are now in the URL (e.g., /blocks?success=Successfully...), if the user hits F5 a minute later, the URL will still contain that query string, and the success message will pop up again.
        // Clean URL query parameters so F5 doesn't re-trigger visual messages
        
        if (window.location.search.includes('success=') || window.location.search.includes('error=')) {
            window.history.replaceState({}, document.title, window.location.pathname);
        }
        
        
        // --- Generic Sorting Framework Initialization ---
        function setupTableSorting(tableId, storageKeyPrefix, postSortCallback) {
            const table = document.getElementById(tableId);
            if (!table) return;
            
            const tbody = table.querySelector('tbody');
            const headers = table.querySelectorAll('th.sortable');
            if (!tbody) return;
            
            // Store original row order to revert back to 'none'
            const originalRows = Array.from(tbody.rows);
            originalRows.forEach((row, i) => row.dataset.origIndex = i);
            
            function applySort(th, newDir) {
                const colIndex = parseInt(th.dataset.col);
                
                // 2. Save the new sorting state to sessionStorage so it survives page reloads
                sessionStorage.setItem(storageKeyPrefix + '_sortCol', colIndex);
                sessionStorage.setItem(storageKeyPrefix + '_sortDir', newDir);
                
                // Reset all headers
                headers.forEach(h => {
                    h.dataset.sortDir = 'none';
                    const icon = h.querySelector('.sort-icon');
                    if (icon) icon.textContent = '';
                });
                
                // Update clicked header
                th.dataset.sortDir = newDir;
                const icon = th.querySelector('.sort-icon');
                if (icon) {
                    if (newDir === 'asc') icon.textContent = '▲';
                    if (newDir === 'desc') icon.textContent = '▼';
                }
                
                let rowsArray = Array.from(tbody.rows);
                // Filter out custom inline edit rows and empty placeholder colspan messages
                rowsArray = rowsArray.filter(row => row.cells.length > colIndex && !row.querySelector('td[colspan]') && !row.classList.contains('edit-row') && !row.classList.contains('edit-host-row'));
                
                if (newDir === 'none') {
                    // Revert to original order
                    rowsArray.sort((a, b) => parseInt(a.dataset.origIndex) - parseInt(b.dataset.origIndex));
                } else {
                    // Sort ascending or descending
                    rowsArray.sort((a, b) => {
                        // FIX: Changed from innerText to textContent
                        let valA = a.cells[colIndex].textContent.trim().toLowerCase();
                        let valB = b.cells[colIndex].textContent.trim().toLowerCase();
                        
                        if (valA < valB) return newDir === 'asc' ? -1 : 1;
                        if (valA > valB) return newDir === 'asc' ? 1 : -1;
                        return 0;
                    });
                }
                
                // Append rows back to tbody in sorted order
                rowsArray.forEach(row => tbody.appendChild(row));
                // Re-apply filter immediately after sorting array structure changes
                // Re-apply filter immediately if applicable
                if (typeof postSortCallback === 'function') {
                    postSortCallback();
                }
            }
            
            headers.forEach(th => {
                th.dataset.sortDir = 'none'; // none, asc, desc
                th.addEventListener('click', () => {
                    // 1. Cancel any active inline edits so they don't break during sort
                    document.querySelectorAll('.btn-cancel').forEach(btn => btn.click());
                    const currentDir = th.dataset.sortDir;
                    const newDir = currentDir === 'none' ? 'asc' : currentDir === 'asc' ? 'desc' : 'none';
                    applySort(th, newDir);
                });
            });
            
            // Restore sort state on load WITHOUT a synthetic click / forced layout
            const savedCol = sessionStorage.getItem(storageKeyPrefix + '_sortCol');
            const savedDir = sessionStorage.getItem(storageKeyPrefix + '_sortDir');
            
            if (savedCol !== null && savedDir !== null && savedDir !== 'none') {
                const targetHeader = table.querySelector('th.sortable[data-col="' + savedCol + '"]');
                if (targetHeader) {
                    applySort(targetHeader, savedDir);
                }
            }
        }
        // Initialize table sorting states across views
        setupTableSorting('rulesTable', 'rulesTable', applyRulesFilter);
        setupTableSorting('hostsTable', 'hostsTable', applyHostsFilter);
        setupTableSorting('blacklistTable', 'blacklistTable', applyBlacklistFilter);
        setupTableSorting('configTable', 'configTable', applyConfigFilter);
    }); // end of domcontentloaded
})();