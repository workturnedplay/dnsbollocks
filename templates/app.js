(() => {
    "use strict";
    
    // --- UI State Storage Config ---
    // Change this to `localStorage` to persist UI states (like table sorting 
    // and textarea heights) across new tabs and browser restarts.
    // or keep using `sessionStorage`
    const uiStorage = localStorage;

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
    
    // Config field key names are injected by Go into data-* attributes on #configKeysData
    // (only present on the /config page). Falls back to empty strings on other pages so
    // CONFIG_KEYS is always safe to reference — editConfig is only called on /config anyway.
    // This ensures renaming a Config struct field + its json tag is the only change needed;
    // app.js never hard-codes json tag strings.
    const _cfgKeysEl = document.getElementById('configKeysData');
    // Optimistic-concurrency token: the mod-time of config.json at page-load
    // time. Sent back on Apply so the server can detect a stale page.
    // Falls back to '0' on pages that predate this feature or on non-config pages.
    const configVersion = _cfgKeysEl ? (_cfgKeysEl.dataset.configVersion || '0') : '0';
    // Mirrors the Go configFileName constant / wincoe.BackupFileExtension so this
    // confirmation dialog never goes stale if either changes.
    const configFileName = _cfgKeysEl ? (_cfgKeysEl.dataset.configFilename || 'config.json') : 'config.json';
    const configBackupExt = _cfgKeysEl ? (_cfgKeysEl.dataset.configBackupExt || '.bak') : '.bak';
    const CONFIG_KEYS = _cfgKeysEl ? {
        // JSON tag key names — used to identify which config row is being edited.
        upstreamSelectionMode: _cfgKeysEl.dataset.keyUpstreamSelectionMode || '',
        consoleLogLevel:       _cfgKeysEl.dataset.keyConsoleLogLevel       || '',
        blockMode:             _cfgKeysEl.dataset.keyBlockMode             || '',
        webuiPasswordHash:     _cfgKeysEl.dataset.keyWebuiPasswordHash     || '',
        // Valid option arrays for select-type fields.
        // Comma-separated from Go (all values are plain lowercase ASCII, no commas),
        // split here. An empty attribute produces [] → buildSelectElement falls back to
        // a plain text input so the field remains editable even if data is missing.
        optsUpstreamSelectionMode: (_cfgKeysEl.dataset.optsUpstreamSelectionMode || '').split(',').filter(Boolean),
        optsConsoleLogLevel:       (_cfgKeysEl.dataset.optsConsoleLogLevel       || '').split(',').filter(Boolean),
        optsBlockMode:             (_cfgKeysEl.dataset.optsBlockMode             || '').split(',').filter(Boolean),
    } : {
        //XXX: the following(or any) fallbacks to empty aren't needed because all are only used in /config
        // optsUpstreamSelectionMode: [],
        // optsConsoleLogLevel: [],
        // optsBlockMode: []
    };
    
    // --- Table-edit staging queue (rules / hosts / blacklist) ---
    // Works identically to the /config page staging system: Add, Edit, and Delete
    // actions are all queued locally and applied in a single Apply run, never
    // sent one-by-one. A staged "Add" that is itself edited or deleted again
    // before Apply is merged/removed in place (tracked via each row's
    // data-staged-client-id) rather than being queued as additional operations
    // referencing an identity the server doesn't know about yet.
    let stagedTableChanges = [];

    function updateTableBanner() {
        const count = stagedTableChanges.length;
        document.querySelectorAll('.staged-table-banner').forEach(banner => {
            banner.style.display = count > 0 ? 'block' : 'none';
            const countEl = banner.querySelector('.staged-table-count');
            if (countEl) countEl.textContent = count;
        });
    }

    // --- Filter Expression Parser ---
    function normalizeStr(str) {
        return str.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    }

    // generateClientId produces a short, session-unique token used to track a
    // staged "Add" entry (rule/host/blacklist) before it has a real server-assigned
    // identity, so a subsequent staged Edit/Delete of that same not-yet-applied
    // row can find and mutate/remove the correct stagedTableChanges entry instead
    // of sending a bogus reference to the server.
    function generateClientId() {
        return 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    }

    // normalizeIPListString parses a comma-separated IP list input (arbitrary
    // spacing) into a canonical "a, b, c" form so staged-edit comparisons against
    // the original baseline aren't fooled by cosmetic whitespace/comma differences.
    function normalizeIPListString(str) {
        return (str || '').split(',').map(s => s.trim()).filter(Boolean).join(', ');
    }

    // findStagedEntryIndex returns the index of an existing staged change in
    // stagedTableChanges matching url + a caller-supplied predicate over fields,
    // or -1 if none exists. Used so re-staging an edit to the same row updates
    // the queued change in place instead of piling up duplicate entries.
    function findStagedEntryIndex(url, predicate) {
        return stagedTableChanges.findIndex(c => c.url === url && predicate(c.fields));
    }

    // stageNewEntry generates a client-side id, queues a brand-new staged
    // "Add" entry, and returns the generated clientId so the caller can tag
    // the newly-built row element with it. Shared by the Rules/Hosts/
    // Blacklist "Add" form handlers.
    function stageNewEntry(url, fields) {
        const clientId = generateClientId();
        stagedTableChanges.push({ url: url, fields: fields, clientId: clientId });
        return clientId;
    }

    // removePlaceholderRow removes the "No X defined" <tr><td colspan> placeholder
    // row from tbody, if present — used when inserting the first staged Add row
    // into an otherwise-empty Hosts or Blacklist table.
    function removePlaceholderRow(tbody) {
        const placeholder = tbody.querySelector('td[colspan]');
        if (placeholder) placeholder.closest('tr').remove();
    }

    // mergeStagedAddFields updates an already-queued (not yet applied) "Add"
    // entry in stagedTableChanges in place with new field values — used when a
    // row that hasn't been sent to the server yet is edited again before Apply.
    function mergeStagedAddFields(clientId, newFieldValues) {
        const entry = stagedTableChanges.find(c => c.clientId === clientId);
        if (entry) {
            Object.assign(entry.fields, newFieldValues);
        }
    }

    // discardStagedEdit drops an already-queued staged Edit (if any) for a
    // persisted row and reverts the row's displayed values to their original
    // (pre-edit) baseline via applyDisplay. Shared by the Rules/Hosts/Blacklist
    // "Discard" button and by the no-op branch of reconcileStagedEdit.
    function discardStagedEdit(existingIdx, row, applyDisplay) {
        if (existingIdx !== -1) stagedTableChanges.splice(existingIdx, 1);
        applyDisplay();
        row.classList.remove('staged');
    }

    // reconcileStagedEdit implements the shared "merge this edit into an
    // already-queued staged edit for the same row, or drop the staged edit
    // entirely if the new values are identical to the row's original values
    // (no-op)" logic used by the Rules/Hosts/Blacklist inline Edit forms.
    //
    //   existingIdx  - index into stagedTableChanges of an already-queued edit
    //                  for this row, or -1
    //   isNoOp       - true if the new values exactly match the row's original values
    //   url          - the staged-change URL for a NEW queued entry (only used
    //                  when existingIdx === -1 and !isNoOp)
    //   fields       - the fields object to stage (only relevant when !isNoOp)
    //   row          - the <tr> whose 'staged' class should be toggled
    //   applyDisplay - () => void; updates the row's visible cells. Caller must
    //                  pass the ORIGINAL values when isNoOp is true, and the NEW
    //                  values otherwise.
    function reconcileStagedEdit(existingIdx, isNoOp, url, fields, row, applyDisplay) {
        if (isNoOp) {
            discardStagedEdit(existingIdx, row, applyDisplay);
            return;
        }
        if (existingIdx !== -1) {
            stagedTableChanges[existingIdx].fields = fields;
        } else {
            stagedTableChanges.push({ url: url, fields: fields });
        }
        applyDisplay();
        row.classList.add('staged');
    }

    // stageRowDeletion queues a Delete for an already-persisted (non-staged-add)
    // row: drops any stale queued Edit for the same identity, pushes the delete
    // entry, and (if the row element is available) marks it as staged-delete
    // (struck-through but still visible/undeletable) instead of removing it
    // from the DOM outright.
    function stageRowDeletion(url, staleEditIdx, deleteFields, row, restoreDisplay) {
        if (staleEditIdx !== -1) stagedTableChanges.splice(staleEditIdx, 1);
        stagedTableChanges.push({ url: url, fields: deleteFields });
        if (row) {
            restoreDisplay();
            row.classList.add('staged-delete', 'staged');
        }
    }

    // removeStagedAddRow discards a not-yet-applied "Add" entry (identified by
    // clientId) from stagedTableChanges and removes its row from the DOM.
    // Shared by the Rules/Hosts/Blacklist Delete and Discard controls for rows
    // that were never sent to the server.
    function removeStagedAddRow(clientId, row) {
        stagedTableChanges = stagedTableChanges.filter(c => c.clientId !== clientId);
        row.remove();
    }

    // undoStagedDeletion removes a previously staged Delete entry matching
    // predicate and restores the row's normal (non-struck-through) appearance.
    // Used by the Rules/Hosts/Blacklist "Undelete" controls.
    function undoStagedDeletion(row, predicate) {
        stagedTableChanges = stagedTableChanges.filter(c => !predicate(c));
        row.classList.remove('staged-delete', 'staged');
    }

    // buildRuleRowElement creates a <tr> for a staged (not yet applied) new rule,
    // matching the structure of server-rendered rows in the "rules" template so
    // filtering, sorting, and the existing Edit/Delete delegation all work on it
    // unmodified.
    function buildRuleRowElement(clientId, type, pattern, enabled) {
        const row = document.createElement('tr');
        row.dataset.ruleId = clientId;
        row.dataset.ruleType = type;
        row.dataset.rulePattern = pattern;
        row.dataset.ruleEnabled = enabled ? 'true' : 'false';
        row.dataset.stagedClientId = clientId;
        row.classList.add('staged-add', 'staged');

        const typeTd = document.createElement('td');
        typeTd.textContent = type;
        row.appendChild(typeTd);

        const idTd = document.createElement('td');
        idTd.textContent = '(pending)';
        idTd.title = '(pending \u2014 assigned on Apply)';
        row.appendChild(idTd);

        const patternTd = document.createElement('td');
        patternTd.textContent = pattern;
        patternTd.title = pattern;
        row.appendChild(patternTd);

        const enabledTd = document.createElement('td');
        const span = document.createElement('span');
        span.className = enabled ? 'tag-enabled' : 'tag-disabled';
        span.textContent = enabled ? 'Active' : 'Paused';
        enabledTd.appendChild(span);
        row.appendChild(enabledTd);

        const actionsTd = document.createElement('td');
        actionsTd.className = 'actions';
        const editBtn = document.createElement('button');
        editBtn.type = 'button';
        editBtn.className = 'btn-edit';
        editBtn.textContent = 'Edit';
        actionsTd.appendChild(editBtn);
        //actionsTd.appendChild(document.createTextNode(' ')); //a bit of horizontal gap
        const delBtn = document.createElement('button');
        delBtn.type = 'button';
        delBtn.className = 'btn-del';
        delBtn.textContent = 'Delete';
        actionsTd.appendChild(delBtn);
        row.appendChild(actionsTd);

        return row;
    } // end of buildRuleRowElement

    // applyRuleRowDisplay updates a rules-table row's dataset and visible cells
    // to reflect the given {type, pattern, enabled} values. Shared by the
    // optimistic post-Stage update and by baseline-restore (no-op stage / Discard).
    function applyRuleRowDisplay(row, type, pattern, enabled) {
        row.dataset.ruleType = type;
        row.dataset.rulePattern = pattern;
        row.dataset.ruleEnabled = enabled ? 'true' : 'false';
        row.cells[0].textContent = type;
        // cells[1] = ID, unchanged
        row.cells[2].textContent = pattern;
        row.cells[2].title = pattern;
        const enabledCell = row.cells[3];
        enabledCell.textContent = '';
        const enabledSpan = document.createElement('span');
        enabledSpan.className = enabled ? 'tag-enabled' : 'tag-disabled';
        enabledSpan.textContent = enabled ? 'Active' : 'Paused';
        enabledCell.appendChild(enabledSpan);
    }

    // buildHostRowElement creates a <tr> for a staged (not yet applied) new local
    // host override. Its Edit/Delete controls are wired directly here since,
    // unlike the rules table, hosts Edit/Delete are bound per-element rather than
    // via document-level delegation.
    function buildHostRowElement(clientId, pattern, ipsDisplay) {
        const row = document.createElement('tr');
        row.id = 'hostRow_' + clientId;
        row.dataset.hostPattern = pattern;
        row.dataset.hostIps = ipsDisplay;
        row.dataset.stagedClientId = clientId;
        row.classList.add('staged-add', 'staged');

        const patternTd = document.createElement('td');
        patternTd.textContent = pattern;
        patternTd.title = pattern;
        row.appendChild(patternTd);

        const ipsTd = document.createElement('td');
        ipsTd.textContent = ipsDisplay;
        ipsTd.title = ipsDisplay;
        row.appendChild(ipsTd);

        const actionsTd = document.createElement('td');
        actionsTd.className = 'actions';

        const editBtn = document.createElement('button');
        editBtn.type = 'button';
        editBtn.className = 'btn-edit js-host-edit';
        editBtn.textContent = 'Edit';
        editBtn.dataset.index = clientId;
        editBtn.dataset.pattern = pattern;
        editBtn.dataset.ips = ipsDisplay;
        editBtn.addEventListener('click', () => editHost(editBtn));
        actionsTd.appendChild(editBtn);

        //actionsTd.appendChild(document.createTextNode(' ')); //a bit of horizontal gap

        const delBtn = document.createElement('button');
        delBtn.type = 'button';
        delBtn.className = 'btn-del';
        delBtn.textContent = 'Delete';
        delBtn.addEventListener('click', () => {
            if (!confirm('Remove this not-yet-applied local host: ' + pattern + '?')) return;
            removeStagedAddRow(clientId, row);
            applyHostsFilter();
            updateTableBanner();
        });
        actionsTd.appendChild(delBtn);

        row.appendChild(actionsTd);
        return row;
    } // end of buildHostRowElement

    // applyHostRowDisplay updates a hosts-table row's dataset, visible cells, and
    // its Edit button's dataset to reflect the given pattern/ips. Shared by the
    // optimistic post-Stage update and by baseline-restore (no-op stage / Discard).
    function applyHostRowDisplay(row, pattern, ips) {
        row.dataset.hostPattern = pattern;
        row.dataset.hostIps = ips;
        row.cells[0].textContent = pattern;
        row.cells[0].title = pattern;
        row.cells[1].textContent = ips;
        row.cells[1].title = ips;

        const editBtnEl = row.querySelector('.js-host-edit');
        if (editBtnEl) {
            editBtnEl.dataset.pattern = pattern;
            editBtnEl.dataset.ips = ips;
        }
    }

    // buildBlacklistRowElement mirrors buildHostRowElement for the response-blacklist page.
    function buildBlacklistRowElement(clientId, cidr) {
        const row = document.createElement('tr');
        row.id = 'blacklistRow_' + clientId;
        row.dataset.cidr = cidr;
        row.dataset.stagedClientId = clientId;
        row.classList.add('staged-add', 'staged');

        const cidrTd = document.createElement('td');
        cidrTd.textContent = cidr;
        cidrTd.title = cidr;
        row.appendChild(cidrTd);

        const actionsTd = document.createElement('td');
        actionsTd.className = 'actions text-center';

        const editBtn = document.createElement('button');
        editBtn.type = 'button';
        editBtn.className = 'btn-edit js-blacklist-edit';
        editBtn.textContent = 'Edit';
        editBtn.dataset.index = clientId;
        editBtn.dataset.cidr = cidr;
        editBtn.addEventListener('click', () => editBlacklist(editBtn));
        actionsTd.appendChild(editBtn);

        //actionsTd.appendChild(document.createTextNode(' ')); //a bit of horizontal gap

        const delBtn = document.createElement('button');
        delBtn.type = 'button';
        delBtn.className = 'btn-del';
        delBtn.textContent = 'Delete';
        delBtn.addEventListener('click', () => {
            if (!confirm('Remove this not-yet-applied entry: ' + cidr + '?')) return;
            removeStagedAddRow(clientId, row);
            applyBlacklistFilter();
            updateTableBanner();
        });
        actionsTd.appendChild(delBtn);

        row.appendChild(actionsTd);
        return row;
    } //end of buildBlacklistRowElement

    // applyBlacklistRowDisplay updates a blacklist-table row's dataset, visible
    // cell, and its Edit button's dataset to reflect the given CIDR. Shared by
    // the optimistic post-Stage update and by baseline-restore (no-op stage /
    // Discard).
    function applyBlacklistRowDisplay(row, cidrVal) {
        row.dataset.cidr = cidrVal;
        row.cells[0].textContent = cidrVal;
        row.cells[0].title = cidrVal;

        const editBtnEl = row.querySelector('.js-blacklist-edit');
        if (editBtnEl) {
            editBtnEl.dataset.cidr = cidrVal;
        }
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
            alert('A network error occurred: ' + errorPrefix+"\nerr: "+err);
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

    // withApplyButtonBusy disables `button` and swaps in `busyLabel` for the
    // duration of the async `fn`, guarding against a second click firing a
    // duplicate request while the first is still in flight (e.g. a slow or
    // temporarily-firewalled backend after a restart). If `fn` resolves
    // truthy the caller is about to location.reload(), so the button is left
    // disabled/relabeled (the page is going away); otherwise it's restored so
    // the user can actually read the failure alert and retry.
    async function withApplyButtonBusy(button, busyLabel, fn) {
        if (button.disabled) return false; // already in flight; ignore extra clicks
        const originalText = button.textContent;
        button.disabled = true;
        button.textContent = busyLabel;
        let success = false;
        try {
            success = await fn();
        } finally {
            if (!success) {
                button.disabled = false;
                button.textContent = originalText;
            }
        }
        return success;
    }
    
    // postBlocksAction performs a background (AJAX) POST to /blocks for a
    // single Unblock/Re-block action, without navigating or reloading the
    // page. Unlike postAdminForm, failures are reported back to the caller
    // instead of via alert(), since this is used for small, frequent,
    // per-row actions where an inline status message is preferable to a
    // blocking dialog. The server recognizes the X-DNSBollocks-Ajax header
    // and responds with a plain status code instead of a redirect.
    async function postBlocksAction(domain, type, action) {
        const formData = new FormData();
        formData.append('csrf_token', csrfToken);
        formData.append('domain', domain);
        formData.append('type', type);
        formData.append('action', action);
        
        let res;
        try {
            res = await fetch('/blocks', {
                method: 'POST',
                body: formData,
                headers: { 'X-DNSBollocks-Ajax': '1' },
            });
        } catch (err) {
            return { ok: false, message: 'Network error: ' + err };
        }
        
        const bodyText = await res.text();
        if (res.ok) {
            return { ok: true, message: bodyText };
        }
        return { ok: false, message: bodyText || ('HTTP ' + res.status) };
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
    
    // --- Filter Expression Parser ---
    // Grammar: clause | clause | ...  where clause = term & term & ...
    //          and term = word word ... (ordered substring match)
    // Global NOT: !term (anywhere in the string, requires a space before it)
    // Examples: "foo | bar !baz" → (foo OR bar) AND NOT baz
    function matchesFilterExpression(text, rawFilter) {
        if (!rawFilter || rawFilter.length === 0) return true;
        
        const negativeTerms = [];
        let remainingFilter = rawFilter;

        // 1. Extract global negative terms (e.g., " !hugging")
        // Matches '!' at the start of the string or after a whitespace.
        remainingFilter = remainingFilter.replace(/(?:^|\s)!(\S+)/g, (match, term) => {
            negativeTerms.push(term);
            return ' '; // Replace with space to maintain separation for remaining tokens
        }).trim();

        // 2. Global Exclusion: If the text contains ANY of the negative terms, instantly reject.
        for (const neg of negativeTerms) {
            if (text.indexOf(neg) !== -1) {
                return false;
            }
        }

        // If the filter was ONLY negative terms (e.g., "!hugging") and it survived the check above, it's a match!
        if (remainingFilter.length === 0) return true;

        // 3. Continue with existing AND/OR logic on the remaining filter
        const orGroups = remainingFilter.split('|').map(s => s.trim()).filter(s => s.length > 0);
        if (orGroups.length === 0) return true;
        return orGroups.some(orGroup => {
            const andTerms = orGroup.split('&').map(s => s.trim()).filter(s => s.length > 0);
            if (andTerms.length === 0) return true;
            return andTerms.every(andTerm => {
                const words = andTerm.split(/\s+/).filter(w => w.length > 0);
                if (words.length === 0) return true;
                let pos = 0;
                for (const word of words) {
                    const found = text.indexOf(word, pos);
                    if (found === -1) return false;
                    pos = found + word.length;
                }
                return true;
            });
        });
    }

    // Collects all literal word tokens from a filter expression for highlight use.
    // Strips ! exclusions, | and & operators, then splits on whitespace.
    function extractHighlightTerms(rawFilter) {
        if (!rawFilter) return [];
        // Remove negative terms first so they don't trigger the yellow highlighter
        const cleanedFilter = rawFilter.replace(/(?:^|\s)!(\S+)/g, ' ');
        return cleanedFilter.replace(/[|&]/g, ' ').split(/\s+/).filter(t => t.length > 0);
    }

    // applyTableFilter is a shared, config-driven implementation of the
    // per-page filter functions (Rules/Hosts/Blacklist/Config). Behavior is
    // parameterized via opts so each page's quirks (staged-row visibility,
    // highlighting) are preserved exactly.
    //
    // opts:
    //   filterInputId    - id of the <input> holding the filter text
    //   storageKey       - uiStorage key used to persist the filter text
    //   tbodySelector    - CSS selector for the table's <tbody>
    //   editRowClasses   - array of class names identifying an inline-edit <tr>
    //                      to always skip (in addition to 'being-edited')
    //   getSearchText    - function(row) => string to match against (matching
    //                      is case-insensitive; lowercasing is handled here)
    //   alwaysShowStaged - if true, rows with class 'staged' are always shown
    //                      and skipped from matching (Rules/Hosts/Blacklist)
    //   highlightTerms   - optional function(row, terms) => void; if provided,
    //                      called on every non-skipped row with the matched
    //                      terms (or an empty array to clear) — used by /config
    function applyTableFilter(opts) {
        const filterInput = document.getElementById(opts.filterInputId);
        if (!filterInput) return;
        
        const raw = filterInput.value.trim().toLowerCase();
        const rawNorm = normalizeStr(raw);
        uiStorage.setItem(opts.storageKey, raw);
        
        const tbody = document.querySelector(opts.tbodySelector);
        if (!tbody) return;
        
        const terms = (opts.highlightTerms && raw.length > 0) ? extractHighlightTerms(raw) : [];
        
        Array.from(tbody.rows).forEach(row => {
            if (opts.editRowClasses.some(c => row.classList.contains(c)) || row.classList.contains('being-edited')) return;
            
            // Any row with a pending staged change (Add/Edit/Delete) must always
            // stay visible regardless of the current filter text, so the user
            // never loses track of what they've queued up.
            if (opts.alwaysShowStaged && row.classList.contains('staged')) {
                row.style.display = '';
                return;
            }
            
            const searchTargetText = normalizeStr(opts.getSearchText(row).toLowerCase());
            const isMatch = rawNorm.length === 0 || matchesFilterExpression(searchTargetText, rawNorm);
            row.style.display = isMatch ? '' : 'none';
            
            if (opts.highlightTerms) {
                opts.highlightTerms(row, isMatch ? terms : []);
            }
        });
    }
    
    // --- Client-Side Table Ordered-Substring Filter Logic ---
    function applyRulesFilter() {
        applyTableFilter({
            filterInputId: 'rulesFilter',
            storageKey: 'rulesTable_filter',
            tbodySelector: '#rulesTable tbody',
            editRowClasses: ['edit-row'],
            alwaysShowStaged: true,
            getSearchText: row => [row.dataset.ruleId || "", row.dataset.ruleType || "", row.dataset.rulePattern || ""].join(" "),
        });
    }
    
    // --- Client-side ordered-substring filter, mirrors /rules and /response-blacklist ---
    function applyHostsFilter() {
        applyTableFilter({
            filterInputId: 'hostsFilter',
            storageKey: 'hostsTable_filter',
            tbodySelector: '#hostsTable tbody',
            editRowClasses: ['edit-host-row'],
            alwaysShowStaged: true,
            getSearchText: row => [row.dataset.hostPattern || "", row.dataset.hostIps || ""].join(" "),
        });
    }
    
    // --- Client-side ordered-substring filter, mirrors /rules' filter ---
    function applyBlacklistFilter() {
        applyTableFilter({
            filterInputId: 'blacklistFilter',
            storageKey: 'blacklistTable_filter',
            tbodySelector: '#blacklistTable tbody',
            editRowClasses: ['edit-row'],
            alwaysShowStaged: true,
            getSearchText: row => row.dataset.cidr || "",
        });
    }
    
    // --- Client-side Config Filter Logic (with persistent storage and highlight) ---
    function applyConfigFilter() {
        applyTableFilter({
            filterInputId: 'configFilter',
            storageKey: 'configTable_filter',
            tbodySelector: '#configTable tbody',
            editRowClasses: ['edit-row'],
            alwaysShowStaged: false,
            getSearchText: row => {
                const key = row.dataset.key || "";
                const val = row.dataset.original || "";
                // Safely grab the text contents of the inline description field if it exists
                const descElem = row.querySelector('.config-field-desc');
                const desc = descElem ? descElem.textContent : "";
                return key + " " + val + " " + desc;
            },
            // Hidden rows also get their highlights cleared so stale marks don't
            // appear if the row later becomes visible due to a different filter term.
            highlightTerms: (row, terms) => applyConfigRowHighlight(row, terms),
        });
    }
    
    // --- Inline Cancel & Editing Clones ---
    
    // cancelInlineRowEdit removes the inline-edit <tr> (identified by editRowId)
    // and restores the original row (identified by rowId) to its normal,
    // non-edit-mode appearance, then re-applies the page's active filter.
    // resetRowId, if true, additionally strips the temporary 'id' attribute the
    // Rules table assigns to the original row while editing (Hosts/Blacklist
    // rows already have stable, permanent ids and don't need this).
    function cancelInlineRowEdit(editRowId, rowId, resetRowId, filterFn) {
        const editRow = document.getElementById(editRowId);
        if (editRow) editRow.remove();
        
        const row = document.getElementById(rowId);
        if (row) {
            row.style.display = '';
            row.classList.remove('being-edited');
            if (resetRowId) row.removeAttribute('id'); // Clean up the temporary ID
        }
        // Re-apply the active filter now that editing has ended, so the row
        // is only shown if it still matches the current filter text.
        filterFn();
    }
    
    function cancelEdit(id) {
        cancelInlineRowEdit('editFormRow_' + id, 'rule-row-' + id, true, applyRulesFilter);
    }
    
    // discardHostEdits drops any queued staged Edit for a persisted (non-add)
    // local host row and restores its displayed pattern/IPs to the original
    // baseline. Shared by the inline per-row Discard button and the Discard
    // button inside the Edit form.
    function discardHostEdits(row, origPattern, origIps) {
        const existingIdx = findStagedEntryIndex('/hosts', f => f.edit === '1' && f.old_pattern === origPattern);
        discardStagedEdit(existingIdx, row, () => applyHostRowDisplay(row, origPattern, origIps));
    }
    
    function editHost(btn) {
        // 0. Extract variables from the button itself
        const index = btn.dataset.index;
        const pat = btn.dataset.pattern;
        const ips = btn.dataset.ips;
        
        const row = document.getElementById('hostRow_' + index);
        const isStagedAdd = row.classList.contains('staged-add');
        const clientId = row.dataset.stagedClientId;
        const origPattern = row.dataset.origPattern;
        const origIps = row.dataset.origIps;
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
        // old_pattern must always be the TRUE original pattern (never mutated across
        // repeated Edit+Stage cycles), since that's the identity the live
        // server-side store still knows this entry by until Apply actually runs.
        const oldPatternInput = clone.querySelector('.edit-host-old-pattern');
        oldPatternInput.value = isStagedAdd ? pat : origPattern;
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
            const newIPs = ipsInput.value.trim();
            
            if (isStagedAdd) {
                // This row hasn't been sent to the server yet: merge the edit into
                // the still-pending Add entry instead of staging a separate Edit
                // that would reference a pattern the server doesn't know about yet.
                mergeStagedAddFields(clientId, { pattern: newPattern, ips: newIPs });
                applyHostRowDisplay(row, newPattern, newIPs);
                row.classList.add('staged');
            } else {
                // Same persisted host may be edited multiple times before Apply;
                // update the single queued edit in place instead of piling up one
                // staged entry per Edit+Stage cycle, and detect a full round-trip
                // back to the original values so we can drop the staged change.
                const existingIdx = findStagedEntryIndex('/hosts', f => f.edit === '1' && f.old_pattern === origPattern);
                
                //const isNoOp = newPattern === origPattern && normalizeIPListString(newIPs) === normalizeIPListString(origIps);
                
                // FIX: Compare newPattern against the Unicode display pattern (`pat`), not the Punycode `origPattern`.
                const isNoOp = newPattern === pat.toLowerCase() && normalizeIPListString(newIPs) === normalizeIPListString(origIps);

                const fields = { old_pattern: origPattern, pattern: newPattern, ips: newIPs, edit: '1' };
                const displayPattern = isNoOp ? origPattern : newPattern;
                const displayIPs = isNoOp ? origIps : newIPs;
                reconcileStagedEdit(existingIdx, isNoOp, '/hosts', fields, row, () => applyHostRowDisplay(row, displayPattern, displayIPs));
            }

            row.classList.remove('being-edited');
            row.style.display = '';

            editRow.remove();
            applyHostsFilter();
            updateTableBanner();
        });

        // 5. Setup cancel button
        clone.querySelector('.btn-cancel').addEventListener('click', () => cancelHostEdit(index), { once: true });
        
        // Discard: throw away every staged change for this row (however many
        // Edit+Stage cycles happened) and revert it to its original state.
        clone.querySelector('.btn-discard-row').addEventListener('click', () => {
            if (isStagedAdd) {
                if (!confirm('Discard this not-yet-applied local host entirely?')) return;
                removeStagedAddRow(clientId, row);
                editRow.remove();
            } else {
                if (!confirm('Discard all staged changes for this local host and revert it to its original state?')) return;
                discardHostEdits(row, origPattern, origIps);
                row.classList.remove('being-edited');
                row.style.display = '';
                editRow.remove();
            }
            applyHostsFilter();
            updateTableBanner();
        }, { once: true });
        
        // 6. Insert cleanly into the DOM
        row.after(clone);
    }
    
    function cancelHostEdit(index) {
        cancelInlineRowEdit('editHostRow_' + index, 'hostRow_' + index, false, applyHostsFilter);
    }
    
    // discardBlacklistEdits drops any queued staged Edit for a persisted
    // (non-add) blacklist row and restores its displayed CIDR to the
    // original baseline. Shared by the inline per-row Discard button and the
    // Discard button inside the Edit form.
    function discardBlacklistEdits(row, origCidr) {
        const existingIdx = findStagedEntryIndex('/response-blacklist', f => f.action === 'edit' && f.old_cidr === origCidr);
        discardStagedEdit(existingIdx, row, () => applyBlacklistRowDisplay(row, origCidr));
    }
    
    // --- Edit / Cancel for inline row editing ---
    function editBlacklist(btn) {
        const index = btn.dataset.index;
        const cidr = btn.dataset.cidr;
        
        const row = document.getElementById('blacklistRow_' + index);
        if (!row) return;
        const isStagedAdd = row.classList.contains('staged-add');
        const clientId = row.dataset.stagedClientId;
        const origCidr = row.dataset.origCidr;
        row.style.display = 'none';
        row.classList.add('being-edited');
        
        const tmpl = document.getElementById('editBlacklistTemplate');
        const clone = tmpl.content.cloneNode(true);
        
        const editRow = clone.querySelector('tr');
        editRow.id = 'editBlacklistRow_' + index;
        
        const form = clone.querySelector('.edit-blacklist-form');
        const formId = 'editBlacklistForm_' + index;
        form.id = formId;
        
        // old_cidr must always be the TRUE original CIDR (never mutated across
        // repeated Edit+Stage cycles), since that's the identity the live
        // server-side store still knows this entry by until Apply actually runs.
        const oldCidrInput = clone.querySelector('.edit-blacklist-old-cidr');
        oldCidrInput.value = isStagedAdd ? cidr : origCidr;
        oldCidrInput.setAttribute('form', formId);
        
        const cidrInput = clone.querySelector('.edit-blacklist-cidr');
        cidrInput.value = cidr;
        cidrInput.setAttribute('form', formId);
        
        // Save target CIDR signature and submit via AJAX
        form.addEventListener('submit', async function(eSubmit) {
            eSubmit.preventDefault();
            
            const newCidr = cidrInput.value.trim().toLowerCase();
            
            if (isStagedAdd) {
                // This row hasn't been sent to the server yet: merge the edit into
                // the still-pending Add entry instead of staging a separate Edit
                // that would reference a CIDR the server doesn't know about yet.
                mergeStagedAddFields(clientId, { cidr: newCidr });
                applyBlacklistRowDisplay(row, newCidr);
                row.classList.add('staged');
            } else {
                // Same persisted entry may be edited multiple times before Apply;
                // update the single queued edit in place instead of piling up one
                // staged entry per Edit+Stage cycle, and detect a full round-trip
                // back to the original value so we can drop the staged change.
                const existingIdx = findStagedEntryIndex('/response-blacklist', f => f.action === 'edit' && f.old_cidr === origCidr);
                const isNoOp = newCidr === origCidr;
                const fields = { old_cidr: origCidr, cidr: newCidr, action: 'edit' };
                const displayCidr = isNoOp ? origCidr : newCidr;
                reconcileStagedEdit(existingIdx, isNoOp, '/response-blacklist', fields, row, () => applyBlacklistRowDisplay(row, displayCidr));
            }

            row.classList.remove('being-edited');
            row.style.display = '';

            editRow.remove();
            applyBlacklistFilter();
            updateTableBanner();
        });
        
        clone.querySelector('.btn-cancel').addEventListener('click', () => cancelBlacklistEdit(index), { once: true });
        
        // Discard: throw away every staged change for this row (however many
        // Edit+Stage cycles happened) and revert it to its original state.
        clone.querySelector('.btn-discard-row').addEventListener('click', () => {
            if (isStagedAdd) {
                if (!confirm('Discard this not-yet-applied entry entirely?')) return;
                removeStagedAddRow(clientId, row);
                editRow.remove();
            } else {
                if (!confirm('Discard all staged changes for this entry and revert it to its original state?')) return;
                discardBlacklistEdits(row, origCidr);
                row.classList.remove('being-edited');
                row.style.display = '';
                editRow.remove();
            }
            applyBlacklistFilter();
            updateTableBanner();
        }, { once: true });
        
        row.after(clone);
    }
    
    function cancelBlacklistEdit(index) {
        cancelInlineRowEdit('editBlacklistRow_' + index, 'blacklistRow_' + index, false, applyBlacklistFilter);
    }
    
    const stagedChanges = {};
    
    // buildSelectElement creates a <select> DOM element for enum-type config fields.
    // options: string array from CONFIG_KEYS.opts* (injected by Go).
    // currentValue: the value currently stored in the config row (may not be in options
    //   if the config was written by a newer Go version or hand-edited).
    // Defense-in-depth: if options is empty (e.g. template failed to render), falls back
    //   to a plain text input so the field is still editable rather than silently broken.
    // Uses createElement/textContent throughout — no innerHTML, no string escaping needed.
    function buildSelectElement(options, currentValue) {
        if (!Array.isArray(options) || options.length === 0) {
            console.warn('buildSelectElement: empty or missing options list; falling back to plain text input. ' +
                'This likely means the Go template did not inject the expected data-opts-* attribute.');
            const input = document.createElement('input');
            input.type = 'text';
            input.className = 'config-input w-100';
            input.value = currentValue;
            return input;
        }

        const select = document.createElement('select');
        select.className = 'config-input w-100';

        // If the live value is not in the known enum (e.g. hand-edited config or written by a
        // newer Go version), prepend it as a clearly-labelled option so the user can see what
        // is stored and consciously pick a replacement. We never silently discard it.
        const isKnown = options.includes(currentValue);
        if (!isKnown && currentValue !== '') {
            const opt = document.createElement('option');
            opt.value = currentValue;           // .value = string, no HTML injection
            opt.selected = true;
            opt.textContent = currentValue + ' \u26A0 (current\u2014not in known list)';
            select.appendChild(opt);
        }
        for (const v of options) {
            const opt = document.createElement('option');
            opt.value = v;
            opt.selected = (v === currentValue);
            opt.textContent = v;
            select.appendChild(opt);
        }
        return select;
    }
    
    function editConfig(key) {
        // Find existing items
        const row = document.getElementById('configRow_' + key);
        if (!row) return;
        
        // Only cancel THIS row's own edit if one is somehow already open (guards
        // against duplicate row injection from a stale re-click); other rows'
        // in-progress edits are left alone, so multiple config fields can be
        // edited concurrently — matching /rules, /hosts, and /response-blacklist.
        const existingEditRow = document.getElementById('editConfigRow_' + key);
        if (existingEditRow) {
            existingEditRow.querySelector('.config-cancel-btn')?.click();
        }
        
        const type = row.dataset.type;
        const currentDisplay = row.querySelector('.display-value').innerText;
        const isPwd = row.dataset.isPwd === 'true';
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
        // All branches use createElement + .value/.textContent — no innerHTML, no string escaping.
        if (key === CONFIG_KEYS.upstreamSelectionMode) {
            // Option values come from Go's upstreamSelectionMode* constants via CONFIG_KEYS.
            container.appendChild(buildSelectElement(CONFIG_KEYS.optsUpstreamSelectionMode, currentDisplay));
            hint.innerText = "Strategy for querying upstreams";
        } else if (key === CONFIG_KEYS.consoleLogLevel) {
            // Option values come from Go's consoleLogLevel* constants via CONFIG_KEYS.
            container.appendChild(buildSelectElement(CONFIG_KEYS.optsConsoleLogLevel, currentDisplay));
            hint.innerText = "Console output verbosity";
        } else if (key === CONFIG_KEYS.blockMode) {
            // Option values come from Go's blockMode* constants via CONFIG_KEYS.
            container.appendChild(buildSelectElement(CONFIG_KEYS.optsBlockMode, currentDisplay));
            hint.innerText = "Action taken when blocking queries";
        } else if (key === CONFIG_KEYS.webuiPasswordHash) {
            // Both fields are type="password" (masked) rather than plain text,
            // and the confirmation is compared directly against this second
            // masked field instead of a native prompt() dialog -- prompt()
            // renders the typed confirmation in plain, unmasked text on
            // screen, visible to anyone looking at the display while it's typed.
            const pwdInput = document.createElement('input');
            pwdInput.type = 'password';
            pwdInput.autocomplete = 'new-password';
            pwdInput.className = 'config-input monospace-code2';
            pwdInput.placeholder = 'Enter NEW password here...';
            container.appendChild(pwdInput);

            const pwdConfirmInput = document.createElement('input');
            pwdConfirmInput.type = 'password';
            pwdConfirmInput.autocomplete = 'new-password';
            pwdConfirmInput.className = 'config-input-confirm monospace-code2';
            pwdConfirmInput.placeholder = 'Confirm new password...';
            pwdConfirmInput.style.marginTop = '6px';
            container.appendChild(pwdConfirmInput);

            hint.innerText = "Type a password (or paste a hash prefixed with $2) in both fields above; leave both empty to keep the current password.";
        } else if (type === 'bool') {
            const boolSelect = document.createElement('select');
            boolSelect.className = 'config-input w-100';
            const isTrue = currentDisplay === 'true';
            for (const val of ['true', 'false']) {
                const opt = document.createElement('option');
                opt.value = val;
                opt.selected = (val === 'true') ? isTrue : !isTrue;
                opt.textContent = val;
                boolSelect.appendChild(opt);
            }
            container.appendChild(boolSelect);
            hint.innerText = "Boolean (true/false)";
        } else if (type === '[]string') {
            // Swap to textarea and format the current comma-string into 2xnewlines for easier editing and visually delimit each logical line (needed due to wrapping)
            const listTA = document.createElement('textarea');
            listTA.className = 'config-input config-textarea';
            // .value assignment never interprets HTML — safe even if entries contain < > & etc.
            listTA.value = currentDisplay.split(',').map(s => s.trim()).join('\n\n');
            container.appendChild(listTA);
            // Updated, highly reassuring hint text
            hint.innerText = "List (separate items with newlines or commas. Extra spaces, multiple commas, or empty lines are auto-cleaned.)";
        } else if (type === 'int') {
            const numInput = document.createElement('input');
            numInput.type = 'number';
            numInput.className = 'config-input w-100';
            numInput.value = currentDisplay;
            container.appendChild(numInput);
            hint.innerText = "Integer value";
        } else {
            const textInput = document.createElement('input');
            textInput.type = 'text';
            textInput.className = 'config-input w-100';
            textInput.value = currentDisplay;
            container.appendChild(textInput);
            hint.innerText = "BUG: FIXME: unhandled type '"+type+"', fallback to:String value";
            //hint.innerText = "String value";
            
            // This branch should be unreachable: Go's getConfigFields() panics on unknown types.
            // If it is ever reached it means a new Config field type was added without updating
            // getConfigFields() — the console warning below will make that obvious.
            console.warn('BUG: editConfig: unexpected type for key', key, '(type:', type, ') — falling back to plain text input. Update getConfigFields() in Go and editConfig() in app.js.');
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
            
            // Password confirmation logic! Compared directly against a second
            // masked (type="password") input rather than a native prompt()
            // dialog, so the confirmation text is never shown in plaintext.
            if (isPwd && rawVal !== '') {
                const confirmInput = editRow.querySelector('.config-input-confirm');
                const confirmPwd = confirmInput ? confirmInput.value : '';
                if (confirmPwd !== rawVal) {
                    alert("Passwords do not match. Staging cancelled.");
                    return; // Abort, doneFIXME: have to re-add listener for this Stage button! ok i set once:false below
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
            
            // For the password field, an empty input means "keep existing hash" (the Go backend
            // substitutes the current hash when it receives an empty string). Keep the display
            // showing "********" so it's clear to the user that the password is unchanged,
            // rather than showing a blank cell that looks like the password was cleared.
            // currentDisplay is "********" (set by getConfigFields) so we reuse it here.
            if (isPwd && rawVal === '') {
                displayVal = currentDisplay;

                // If we already staged a new password, keep it instead of sending 
                // an empty string which would tell the backend to use the original unedited hash.
                if (stagedChanges[key] !== undefined) {
                    parsedVal = stagedChanges[key];
                }
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
        }, { once: false });// { once: false } is intentional:
        // • On validation failure (e.g. password mismatch → early return), the edit row
        //   stays in the DOM and the user must be able to click Stage again to retry.
        //   once:true would silently disable the button after the first failed attempt.
        // • On success, editRow.remove() destroys the button element from the DOM, so
        //   the listener is garbage-collected with it — no leak.
        // • No accumulation across Edit presses: editConfig() starts by clicking all
        //   .config-cancel-btn elements, removing any existing edit row before the new
        //   clone is inserted, so listeners are always on a fresh, short-lived element.
        
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
                
                // Per-field storage key: each []string config field remembers its
                // own custom textarea height independently, so resizing one field
                // (e.g. upstream_urls) doesn't clobber or get clobbered by another
                // (e.g. upstream_sni_hostnames) sharing a single global key.
                const textareaHeightKey = 'config_textarea_height_' + key;
                
                // The user may have previously resized a textarea on this page.
                // Apply the saved height if it is larger than the content height,
                // so the preference is honoured without hiding any content.
                const savedH = parseInt(uiStorage.getItem(textareaHeightKey) || '0', 10);
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
                        uiStorage.setItem(textareaHeightKey, String(h));
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
                            uiStorage.removeItem(textareaHeightKey);
                            
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
    
    async function applyConfigChanges(e) {
        if (Object.keys(stagedChanges).length === 0) return;
        if (!confirm('Applying changes will overwrite ' + configFileName + ' and gracefully restart listeners.\n\n' +
            'The existing ' + configFileName + ' will be safely backed up to ' + configFileName + configBackupExt + ' first.\n\nProceed?')) return;

        const success = await withApplyButtonBusy(e.currentTarget, 'Applying\u2026', () => postAdminForm('/config', {
            'action': 'apply',
            'payload': JSON.stringify(stagedChanges),
            'config_version': configVersion
        }, 'Failed to apply configuration'));
        
        if (success) {
            // CRITICAL: Clear the object to disarm the beforeunload listener before reloading!
            for (const key in stagedChanges) { delete stagedChanges[key]; }

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

        // Warn before navigating away while table edits are staged
        window.addEventListener('beforeunload', function(e) {
           const hasTableChanges = stagedTableChanges.length > 0;
            const hasConfigChanges = Object.keys(stagedChanges).length > 0;

            if (hasTableChanges || hasConfigChanges) {
                // Modern standard way to trigger the confirmation dialog
                e.preventDefault();
                
                e.returnValue = '' // says deprecated
                // Returning a string triggers the prompt in almost all browsers 
                // and completely bypasses the VS Code deprecation warning.
                return ''; 
            }
        });
        
        // Global Rules Table Event Delegation (Interceptors for Edit and Delete Actions)
        document.addEventListener('click', function(e) {
            // Table-staging Apply / Discard buttons
            if (e.target.closest('.js-discard-table-btn')) {
                if (!confirm('Discard all staged changes?')) return;
                stagedTableChanges = []; // Bypass the beforeunload block!
                location.reload();
                return;
            }
            if (e.target.closest('.js-apply-table-btn')) {
                const applyBtn = e.target.closest('.js-apply-table-btn');
                if (!confirm('Apply all staged changes?\n(a .bak file will be created with the old state)')) return;
                (async () => {
                    const success = await withApplyButtonBusy(applyBtn, 'Applying\u2026', () => {
                        const payload = JSON.stringify(stagedTableChanges);
                        return postAdminForm('/apply-tables', { payload: payload }, 'Failed to save staged changes\n(if using NoScript ensure "fetch" is allowed)');
                    });
                    if (success) {
                        stagedTableChanges = []; // Bypass the beforeunload block!
                        location.reload();
                    }
                })();
                return;
            }

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
                const isStagedAdd = row.classList.contains('staged-add');
                const clientId = row.dataset.stagedClientId;
                const origType = row.dataset.origType;
                const origPattern = row.dataset.origPattern;
                const origEnabled = row.dataset.origEnabled === 'true';
                
                // 4. Tag the original row with a unique layout ID so Cancel/Save can find it
                row.id = 'rule-row-' + id;
                row.style.display = 'none';
                row.classList.add('being-edited');
                
                // 1. Clone the template natively
                const tmpl = document.getElementById('editRuleTemplate');
                const clone = tmpl.content.cloneNode(true);
                
                // Add an ID to the <tr> to make cleanup easy
                const editRow = clone.querySelector('tr');
                editRow.id = 'editFormRow_' + id;
                
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
                idDisplay.textContent = isStagedAdd ? '(pending)' : id;
                idDisplay.title = isStagedAdd ? '(pending \u2014 assigned on Apply)' : id;
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
                    
                    if (isStagedAdd) {
                        // This row hasn't been sent to the server yet: merge the edit
                        // into the still-pending Add entry instead of staging a second,
                        // separate Edit that would reference a nonexistent rule ID.
                        mergeStagedAddFields(clientId, { pattern: newPattern, type: newType, enabled: enabledChecked ? 'true' : 'false' });
                        applyRuleRowDisplay(row, newType, newPattern, enabledChecked);
                        row.classList.add('staged');
                    } else {
                        // Same persisted rule may be edited multiple times before Apply;
                        // update the single queued edit in place instead of piling up
                        // one staged entry per Edit+Stage cycle. Also detect a full
                        // round-trip back to the original values so we can drop the
                        // staged change (and its banner-count contribution) entirely.
                        const existingIdx = findStagedEntryIndex('/rules', f => f.id === id && !f.delete);
                        const isNoOp = newType === origType && newPattern === origPattern &&
                            (enabledChecked ? 'true' : 'false') === (origEnabled ? 'true' : 'false');
                        const fields = { id: id, pattern: newPattern, type: newType, enabled: enabledChecked ? 'true' : 'false', edit: '1' };
                        const displayType = isNoOp ? origType : newType;
                        const displayPattern = isNoOp ? origPattern : newPattern;
                        const displayEnabled = isNoOp ? origEnabled : enabledChecked;
                        reconcileStagedEdit(existingIdx, isNoOp, '/rules', fields, row, () => applyRuleRowDisplay(row, displayType, displayPattern, displayEnabled));
                    }

                    row.classList.remove('being-edited');
                    row.style.display = '';

                    editRow.remove();
                    applyRulesFilter();
                    updateTableBanner();
                });
                
                // Discard: throw away every staged change (however many Edit+Stage
                // cycles happened) for this row and revert it to its original state.
                clone.querySelector('.btn-discard-row').addEventListener('click', () => {
                    if (isStagedAdd) {
                        if (!confirm('Discard this not-yet-applied rule entirely?')) return;
                        removeStagedAddRow(clientId, row);
                        editRow.remove();
                    } else {
                        if (!confirm('Discard all staged changes for this rule and revert it to its original state?')) return;
                        const existingIdx = findStagedEntryIndex('/rules', f => f.id === id && !f.delete);
                        discardStagedEdit(existingIdx, row, () => applyRuleRowDisplay(row, origType, origPattern, origEnabled));
                        row.classList.remove('being-edited');
                        row.style.display = '';
                        editRow.remove();
                    }
                    applyRulesFilter();
                    updateTableBanner();
                }, { once: true });
                
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

                if (row.classList.contains('staged-add')) {
                    // Never sent to the server: just drop the pending Add entry.
                    if (!confirm('Remove this not-yet-applied rule: ' + pattern + '?')) return;
                    removeStagedAddRow(row.dataset.stagedClientId, row);
                    applyRulesFilter();
                    updateTableBanner();
                    return;
                }
                
                // Native confirmation dialog
                if (!confirm('Delete rule: ' + pattern + '?')) return;
                
                // A pending Delete supersedes any queued Edit for the same rule;
                // drop it so we don't try to apply a stale edit right before
                // deleting. The delete itself must always reference the rule's
                // ORIGINAL type/ID, since the live server-side store doesn't know
                // about any not-yet-applied staged type change.
                const staleEditIdx = findStagedEntryIndex('/rules', f => f.id === id && !f.delete);
                const origType = row.dataset.origType;

                // Restore the row's displayed values to their pre-edit baseline (any
                // staged edit was just discarded above) and keep it visible — struck
                // through via CSS — instead of hiding it, so it can still be found
                // via the filter and Undeleted.
                stageRowDeletion('/rules', staleEditIdx, { 'delete': '1', 'id': id, 'type': origType }, row,
                    () => applyRuleRowDisplay(row, origType, row.dataset.origPattern, row.dataset.origEnabled === 'true'));

                applyRulesFilter();
                updateTableBanner();
            } // end of 'if delBtn'
            
            // --- UNDELETE BUTTON INTERCEPTOR ---
            const undelBtn = e.target.closest('.btn-undelete');
            if (undelBtn) {
                const row = undelBtn.closest('tr');
                if (row && row.hasAttribute('data-rule-id')) {
                    e.preventDefault();
                    const id = row.dataset.ruleId;
                    const origType = row.dataset.origType;
                    undoStagedDeletion(row, c => c.url === '/rules' && c.fields.delete === '1' && c.fields.id === id && c.fields.type === origType);
                    applyRulesFilter();
                    updateTableBanner();
                }//if
            } // end of 'if delBtn'
            
            // --- INLINE DISCARD BUTTON INTERCEPTOR (rules only; hosts/blacklist
            // wire their own '.js-host-discard'/'.js-blacklist-discard' listeners) ---
            const inlineDiscardBtn = e.target.closest('.inline-discard-btn');
            if (inlineDiscardBtn) {
                const row = inlineDiscardBtn.closest('tr');
                if (row && row.hasAttribute('data-rule-id') &&
                    row.classList.contains('staged') &&
                    !row.classList.contains('staged-add') &&
                    !row.classList.contains('staged-delete')) {
                    e.preventDefault();
                    if (!confirm('Discard all staged changes for this rule and revert it to its original state?')) return;
                    const id = row.dataset.ruleId;
                    const origType = row.dataset.origType;
                    const origPattern = row.dataset.origPattern;
                    const origEnabled = row.dataset.origEnabled === 'true';
                    const existingIdx = findStagedEntryIndex('/rules', f => f.id === id && !f.delete);
                    discardStagedEdit(existingIdx, row, () => applyRuleRowDisplay(row, origType, origPattern, origEnabled));
                    applyRulesFilter();
                    updateTableBanner();
                }
            } // end of 'if inlineDiscardBtn'
        }); // end of 'click' listener
        
        // Bind Rules filters on boot safely inside DOMContentLoaded
        const filterInput = document.getElementById('rulesFilter');
        if (filterInput) {
            filterInput.value = uiStorage.getItem('rulesTable_filter') || '';
            filterInput.addEventListener('input', () => {
                applyRulesFilter();
            });
            // Run IMMEDIATELY on boot load so the table stays filtered!
            applyRulesFilter();
        }
        // --- ADD RULE INTERCEPTOR ---
        const addForm = document.getElementById('addRuleForm');
        if (addForm) {
            addForm.addEventListener('submit', function(e) {
                e.preventDefault(); // Stop native browser submission
                if (stagedTableChanges.length > 0 && !confirm('You have staged changes. Continuing will discard them. Proceed?')) return;

                const patternInput = addForm.querySelector('[name="pattern"]');
                const typeSelect = addForm.querySelector('[name="type"]');
                const enabledCheckbox = addForm.querySelector('[name="enabled"]');
                if (!patternInput || !typeSelect) return;

                const pattern = patternInput.value.trim().toLowerCase();
                const type = typeSelect.value; // keep original case; matches dnsTypes option values
                if (pattern === '') return;
                const enabled = enabledCheckbox ? enabledCheckbox.checked : true;

                const alreadyStaged = findStagedEntryIndex('/rules', f => !f.id && !f.delete && f.type === type && f.pattern === pattern) !== -1;
                if (alreadyStaged) {
                    alert('A staged (not yet applied) rule with this type and pattern already exists.');
                    return;
                }

                const clientId = stageNewEntry('/rules', { pattern: pattern, type: type, enabled: enabled ? 'true' : 'false' });

                const row = buildRuleRowElement(clientId, type, pattern, enabled);
                const tbody = document.querySelector('#rulesTable tbody');
                if (tbody) {
                    tbody.insertBefore(row, tbody.firstChild); // newest first, mirrors server-side prepend
                }

                patternInput.value = '';
                if (enabledCheckbox) enabledCheckbox.checked = true;

                applyRulesFilter();
                updateTableBanner();
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
        
        // Unblock/Re-block buttons: submit in the background via fetch() instead
        // of a full page POST+redirect+reload, so several clicks in quick
        // succession each resolve independently without blocking on a full page
        // re-render. Falls back to a normal form submission (full page reload)
        // if JavaScript is disabled, since the underlying <form> is still real.
        document.querySelectorAll('.js-block-action-form').forEach(form => {
            form.addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const domain = form.querySelector('[name="domain"]').value;
                const type = form.querySelector('[name="type"]').value;
                const actionInput = form.querySelector('[name="action"]');
                const action = actionInput.value;
                const btn = form.querySelector('button[type="submit"]');
                const feedback = form.parentElement.querySelector('.block-action-feedback');
                
                if (btn.disabled) return; // already in flight; ignore rapid double-clicks
                
                const originalText = btn.textContent;
                const originalClass = btn.className;
                
                btn.disabled = true;
                btn.textContent = action === 'reblock' ? 'Re-blocking\u2026' : 'Unblocking\u2026';
                btn.classList.add('btn-action-pending');
                if (feedback) {
                    feedback.textContent = '';
                    feedback.className = 'block-action-feedback';
                }
                
                const result = await postBlocksAction(domain, type, action);
                
                if (result.ok) {
                    // Flip the form to perform the opposite action next time, and
                    // relabel the button to match — mirrors exactly what a full
                    // page reload would have shown.
                    if (action === 'unblock') {
                        actionInput.value = 'reblock';
                        btn.textContent = 'Re-block (Pause)';
                        btn.className = 'btn-cancel';
                    } else {
                        actionInput.value = 'unblock';
                        btn.textContent = 'Unblock ' + type;
                        btn.className = 'btn-edit';
                    }
                    btn.disabled = false;
                    if (feedback) {
                        feedback.textContent = '\u2713 ' + (result.message || 'Done');
                        feedback.classList.add('block-action-feedback-success');
                    }
                } else {
                    // Revert to the exact original button so the user can retry.
                    btn.disabled = false;
                    btn.textContent = originalText;
                    btn.className = originalClass;
                    if (feedback) {
                        feedback.textContent = 'Failed: ' + result.message;
                        feedback.classList.add('block-action-feedback-error');
                    }
                }
            });
        });
        
        // ── Hosts page ────────────────────────────────────────────────────────────
        // Edit buttons: pass the button element to editHost() exactly as onclick="editHost(this)" did.
        // Direct binding is safe here because rows are server-rendered; none are added dynamically
        // without a full page reload, so every .js-host-edit button exists at DOMContentLoaded time.
        document.querySelectorAll('.js-host-edit').forEach(btn => {
            btn.addEventListener('click', () => editHost(btn));
        });
        
        // Delete forms: confirm, then conditionally clean the free-pass uiStorage key.
        // Reading pattern from the hidden <input name="pattern"> already inside the form
        // avoids adding any new data attributes to the HTML.
        document.querySelectorAll('.js-host-delete-form').forEach(form => {
            form.addEventListener('submit', function(e) {
                e.preventDefault();

                const patternInput = form.querySelector('[name="pattern"]');
                if (!patternInput) {
                    console.error('js-host-delete-form: missing [name="pattern"] input');
                    return;
                }
                // This hidden field is server-rendered from the original pattern and
                // is never mutated by JS, so it's always the TRUE original identity —
                // exactly what the live server-side store still knows this entry by.
                const origPattern = patternInput.value.toLowerCase();

                if (!confirm('Delete local host override: ' + origPattern + '?')) {
                    return;
                }

                const row = form.closest('tr');

                // A pending Delete supersedes any queued Edit for the same host;
                // drop it so we don't try to apply a stale edit right before deleting.
                const staleEditIdx = findStagedEntryIndex('/hosts', f => f.edit === '1' && f.old_pattern === origPattern);

                // Restore the row's displayed values (any staged edit was just
                // discarded above) and keep it visible — struck through via CSS —
                // instead of hiding it, so it can still be found via the filter
                // and Undeleted.
                stageRowDeletion('/hosts', staleEditIdx, { delete: '1', pattern: origPattern }, row,
                    () => applyHostRowDisplay(row, origPattern, row.dataset.origIps));

                applyHostsFilter();
                updateTableBanner();
            });
        });
        
        document.querySelectorAll('.js-host-undelete').forEach(btn => {
            btn.addEventListener('click', () => {
                const index = btn.dataset.index;
                const row = document.getElementById('hostRow_' + index);
                if (!row) return;
                const origPattern = row.dataset.origPattern;
                undoStagedDeletion(row, c => c.url === '/hosts' && c.fields.delete === '1' && c.fields.pattern === origPattern);
                applyHostsFilter();
                updateTableBanner();
            });
        });
        
        // Inline Discard: revert a staged plain-edit row to its original
        // pattern/IPs directly, without first opening the Edit form.
        document.querySelectorAll('.js-host-discard').forEach(btn => {
            btn.addEventListener('click', () => {
                const index = btn.dataset.index;
                const row = document.getElementById('hostRow_' + index);
                if (!row || row.classList.contains('staged-add') || row.classList.contains('staged-delete')) return;
                if (!confirm('Discard all staged changes for this local host and revert it to its original state?')) return;
                discardHostEdits(row, row.dataset.origPattern, row.dataset.origIps);
                applyHostsFilter();
                updateTableBanner();
            });
        });
        
        // --- ADD HOST: stage instead of posting immediately ---
        document.getElementById('addHostForm')?.addEventListener('submit', function(e) {
            e.preventDefault();

            const patternInput = this.querySelector('[name="pattern"]');
            const ipsInput = this.querySelector('[name="ips"]');
            if (!patternInput || !ipsInput) return;

            const pattern = patternInput.value.trim().toLowerCase();
            const ips = ipsInput.value.trim();
            if (pattern === '' || ips === '') return;

            const alreadyStaged = findStagedEntryIndex('/hosts', f => !f.edit && !f.delete && f.pattern === pattern) !== -1;
            if (alreadyStaged) {
                alert('A staged (not yet applied) local host with this pattern already exists.');
                return;
            }

            const clientId = stageNewEntry('/hosts', { pattern: pattern, ips: ips });

            const tbody = document.querySelector('#hostsTable tbody');
            if (tbody) {
                removePlaceholderRow(tbody);
                tbody.appendChild(buildHostRowElement(clientId, pattern, ips));
            }

            patternInput.value = '';
            ipsInput.value = '';

            applyHostsFilter();
            updateTableBanner();
        });
        
        // Load filter value from persistent uiStorage on page load
        const hostsFilterInput = document.getElementById('hostsFilter');
        if (hostsFilterInput) {
            hostsFilterInput.value = uiStorage.getItem('hostsTable_filter') || '';
            hostsFilterInput.addEventListener('input', () => {
                applyHostsFilter();
            });
            applyHostsFilter();
        }
        
        // ── Response-blacklist page ───────────────────────────────────────────────
        document.querySelectorAll('.js-blacklist-edit').forEach(btn => {
            btn.addEventListener('click', () => editBlacklist(btn));
        });
        
        document.querySelectorAll('.js-blacklist-delete-form').forEach(form => {
            form.addEventListener('submit', function(e) {
                e.preventDefault();

                const cidrInput = form.querySelector('[name="cidr"]');
                if (!cidrInput) {
                    console.error('js-blacklist-delete-form: missing [name="cidr"] input');
                    return;
                }
                // This hidden field is server-rendered from the original CIDR and is
                // never mutated by JS, so it's always the TRUE original identity.
                const origCidr = cidrInput.value;
                if (!confirm('Remove ' + origCidr + ' from blacklist?')) {
                    return;
                }

                const row = form.closest('tr');

                // A pending Delete supersedes any queued Edit for the same entry;
                // drop it so we don't try to apply a stale edit right before deleting.
                const staleEditIdx = findStagedEntryIndex('/response-blacklist', f => f.action === 'edit' && f.old_cidr === origCidr);

                // Restore the row's displayed value (any staged edit was just
                // discarded above) and keep it visible — struck through via CSS —
                // instead of hiding it, so it can still be found via the filter
                // and Undeleted.
                stageRowDeletion('/response-blacklist', staleEditIdx, { action: 'delete', cidr: origCidr }, row,
                    () => applyBlacklistRowDisplay(row, origCidr));

                applyBlacklistFilter();
                updateTableBanner();
            });
        });
        
        document.querySelectorAll('.js-blacklist-undelete').forEach(btn => {
            btn.addEventListener('click', () => {
                const index = btn.dataset.index;
                const row = document.getElementById('blacklistRow_' + index);
                if (!row) return;
                const origCidr = row.dataset.origCidr;
                undoStagedDeletion(row, c => c.url === '/response-blacklist' && c.fields.action === 'delete' && c.fields.cidr === origCidr);
                applyBlacklistFilter();
                updateTableBanner();
            });
        });
        
        // Inline Discard: revert a staged plain-edit row to its original
        // CIDR directly, without first opening the Edit form.
        document.querySelectorAll('.js-blacklist-discard').forEach(btn => {
            btn.addEventListener('click', () => {
                const index = btn.dataset.index;
                const row = document.getElementById('blacklistRow_' + index);
                if (!row || row.classList.contains('staged-add') || row.classList.contains('staged-delete')) return;
                if (!confirm('Discard all staged changes for this entry and revert it to its original state?')) return;
                discardBlacklistEdits(row, row.dataset.origCidr);
                applyBlacklistFilter();
                updateTableBanner();
            });
        });
        
        // Load filter values from persistent uiStorage on load tracking configuration
        const blacklistFilterInput = document.getElementById('blacklistFilter');
        if (blacklistFilterInput) {
            blacklistFilterInput.value = uiStorage.getItem('blacklistTable_filter') || '';
            blacklistFilterInput.addEventListener('input', () => {
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

            const alreadyStaged = findStagedEntryIndex('/response-blacklist', f => f.action === 'add' && f.cidr === cidrValue) !== -1;
            if (alreadyStaged) {
                alert('A staged (not yet applied) blacklist entry with this CIDR already exists.');
                return;
            }
            
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
                console.error('Blacklist overlap validation check failed:', err);

                const msg = `Validation check failed (you must allow "fetch" (under "Custom") in NoScript Firefox extension).\n\n` +
                `Error details: ${err}\n\n` +
                `Would you like to bypass validation and add this entry anyway? (Note: It might be redundant if other filters already cover it.)`;
                
                // If user clicks "Cancel" (No), abort form submission.
                // If they click "OK" (Yes), execution drops below the try/catch and hits form.submit()
                
                if (!confirm(msg)) {
                    console.log("chose to NOT add it without validation, cidrValue=" + cidrValue);
                    return; 
                } else {
                    console.log("chose to add it without validation, cidrValue=" + cidrValue);
                }
            }
            
            const clientId = stageNewEntry('/response-blacklist', { action: 'add', cidr: cidrValue });

            const tbody = document.querySelector('#blacklistTable tbody');
            if (tbody) {
                removePlaceholderRow(tbody);
                tbody.insertBefore(buildBlacklistRowElement(clientId, cidrValue), tbody.firstChild);
            }

            cidrInput.value = '';

            applyBlacklistFilter();
            updateTableBanner();
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
        
        // Inline Discard: revert a single staged config field back to its
        // true pristine (server-rendered) value directly, without opening
        // the Edit form and without touching any other staged field.
        document.querySelectorAll('.js-config-discard').forEach(btn => {
            btn.addEventListener('click', () => {
                const row = btn.closest('tr[data-key]');
                if (!row) {
                    console.error('js-config-discard: could not find ancestor tr[data-key]');
                    return;
                }
                const key = row.dataset.key;
                if (stagedChanges[key] === undefined) return; // nothing staged; shouldn't be visible anyway
                if (!confirm('Discard the staged change for "' + key + '" and revert it to its original value?')) return;
                
                delete stagedChanges[key];
                const trueOriginal = row.dataset.trueOriginal;
                row.querySelector('.display-value').innerText = trueOriginal;
                row.dataset.original = trueOriginal;
                row.classList.remove('staged');
                
                applyConfigFilter();
                updateBanner();
            });
        });
        
        const applyConfigBtn = document.getElementById('js-apply-config-btn');
        if (applyConfigBtn) {
            applyConfigBtn.addEventListener('click', applyConfigChanges);
        }
        
        const discardConfigBtn = document.getElementById('js-discard-config-btn');
        if (discardConfigBtn){
            discardConfigBtn.addEventListener('click', () => {
                if (confirm('Discard all staged config changes?')) {
                    // Empty the staged changes object safely, else beforeunload will prevent reload!
                    for (const key in stagedChanges) { delete stagedChanges[key]; }
                    location.reload();
                }
            });
        }
        // Bind event listener and restore saved state on page load
        const configFilterInput = document.getElementById('configFilter');
        if (configFilterInput) {
            configFilterInput.value = uiStorage.getItem('configTable_filter') || '';
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
                
                // 2. Save the new sorting state to uiStorage so it survives page reloads
                uiStorage.setItem(storageKeyPrefix + '_sortCol', colIndex);
                uiStorage.setItem(storageKeyPrefix + '_sortDir', newDir);
                
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
            const savedCol = uiStorage.getItem(storageKeyPrefix + '_sortCol');
            const savedDir = uiStorage.getItem(storageKeyPrefix + '_sortDir');
            
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