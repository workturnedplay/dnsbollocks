(() => {
    "use strict";
    
    // --- UI State Storage Config ---
    // Change this to `localStorage` to persist UI states (like table sorting 
    // and textarea heights) across new tabs and browser restarts.
    // UI preferences should never be able to prevent the admin interface from
    // initializing. Browsers may deny Web Storage in hardened/private contexts.
    function createSafeStorage(storageName) {
        try {
            const storage = window[storageName];
            const probeKey = '__dnsbollocks_storage_probe__';

            storage.setItem(probeKey, '1');
            storage.removeItem(probeKey);

            return {
                getItem(key) {
                    try {
                        return storage.getItem(key);
                    } catch (err) {
                        console.warn(`Failed to read ${storageName}:`, err);
                        return null;
                    }
                },
                setItem(key, value) {
                    try {
                        storage.setItem(key, value);
                        return true;
                    } catch (err) {
                        console.warn(`Failed to write ${storageName}:`, err);
                        return false;
                    }
                },
                removeItem(key) {
                    try {
                        storage.removeItem(key);
                    } catch (err) {
                        console.warn(`Failed to remove ${storageName} item:`, err);
                    }
                },
            };
        } catch (err) {
            console.warn(`${storageName} is unavailable:`, err);
            return {
                getItem() {
                    return null;
                },
                setItem() {
                    return false;
                },
                removeItem() {},
            };
        }
    }

    const uiStorage = createSafeStorage('localStorage');
    const stagedStorage = createSafeStorage('sessionStorage');

    // --- Security & Extension Notices ---
    //FIXME: this doesn't seem to appear anymore, unclear what and when I've change something!:
    console.log(
        "%cⓘ [DNSbollocks Info]: The media block error directly above(FIXME: if it even appears anymore!) is harmless. " +
        "It occurs because extensions like NoScript inject layout placeholders into the page, " +
        "which our strict security policy safely rejects. No action is needed! Though if you want to change the source "+
        "replace \"media-src 'none'; \"+ with \"media-src 'self' data:; \"+ in the platform_windows.go file in function securityHeadersMiddleware.",
        "color: #0078d4; font-weight: bold; font-family: sans-serif; font-size: 11px;"
    );
    
    let csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || '';
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
        webuiAuthSessionMode:  _cfgKeysEl.dataset.keyWebuiAuthSessionMode  || '',
        // Valid option arrays for select-type fields.
        // Comma-separated from Go (all values are plain lowercase ASCII, no commas),
        // split here. An empty attribute produces [] → buildSelectElement falls back to
        // a plain text input so the field remains editable even if data is missing.
        optsUpstreamSelectionMode: (_cfgKeysEl.dataset.optsUpstreamSelectionMode || '').split(',').filter(Boolean),
        optsConsoleLogLevel:       (_cfgKeysEl.dataset.optsConsoleLogLevel       || '').split(',').filter(Boolean),
        optsBlockMode:             (_cfgKeysEl.dataset.optsBlockMode             || '').split(',').filter(Boolean),
        optsWebUIAuthSessionMode:  (_cfgKeysEl.dataset.optsWebuiAuthSessionMode  || '').split(',').filter(Boolean),
    } : {
        //XXX: the following(or any) fallbacks to empty aren't needed because all are only used in /config
        // optsUpstreamSelectionMode: [],
        // optsConsoleLogLevel: [],
        // optsBlockMode: []
    };

    const tableVersionElement = document.getElementById('tableVersionData');

    // Not frozen: applyStagedTableChanges()'s updateTableVersions() helper
    // updates these in place after a partial (422) batch-apply, so a
    // subsequent reload's staged-change restore matches the server's actual
    // post-mutation state instead of the stale versions captured at page load.
    const tableVersions = {
        rules: tableVersionElement?.dataset.rulesVersion || '0',
        hosts: tableVersionElement?.dataset.hostsVersion || '0',
        blacklist: tableVersionElement?.dataset.blacklistVersion || '0',
        query_blocklist: tableVersionElement?.dataset.queryBlocklistVersion || '0',
    };

    const tablePageKey = location.pathname;

    // Per-page storage key for the /logs, /logs_queries, and /logs_queries_simple
    // search filter (see the "Logs page: remember the filter text" block in the
    // DOMContentLoaded handler below) — keyed by pathname so each of the three
    // log pages remembers its own filter independently.
    const logsFilterStorageKey = 'logs_filter_' + tablePageKey;
    const logsRotatedStorageKey = 'logs_rotated_' + tablePageKey;
    const logsMaxRotStorageKey = 'logs_maxrot_' + tablePageKey;

    const ADMIN_FETCH_TIMEOUT_MS = 30_000;
    const ADMIN_CHECK_FETCH_TIMEOUT_MS = 10_000;

    const STAGED_STORAGE_VERSION = 1;
    const MAX_STORED_STAGED_CHANGES = 10_000;
    const stagedStorageKey = `dnsbollocks:staged:${tablePageKey}`;

    function isPlainObject(value) {
        return value !== null &&
            typeof value === 'object' &&
            Object.getPrototypeOf(value) === Object.prototype;
    }

    function isValidStoredChange(change) {
        if (!isPlainObject(change)) return false;
        if (
            change.url !== '/rules' &&
            change.url !== '/hosts' &&
            change.url !== '/response-blacklist' &&
            change.url !== '/query-blocklist'
        ) {
            return false;
        }
        if (typeof change.clientId !== 'string' || !change.clientId) return false;
        if (!isPlainObject(change.fields)) return false;

        return Object.entries(change.fields).every(([key, value]) => (
            typeof key === 'string' &&
            key.length > 0 &&
            key.length <= 64 &&
            typeof value === 'string' &&
            value.length <= 65_536
        ));
    }

    // storagePersistenceWarningEl lazily holds a DOM banner warning the user
    // that staged changes can no longer be saved to sessionStorage (e.g.
    // quota exceeded or storage unavailable), so a page refresh/crash/close
    // would lose them even though they're still safely queued in memory for
    // this tab. Built once on first failure and shown/hidden afterward;
    // resets naturally on every full page (re)load since this is a fresh
    // script run.
    let storagePersistenceWarningEl = null;

    function ensureStoragePersistenceWarningEl() {
        if (storagePersistenceWarningEl) return storagePersistenceWarningEl;
        const el = document.createElement('div');
        el.className = 'alert-error storage-persistence-warning';
        el.setAttribute('role', 'alert');
        el.hidden = true;

        const strong = document.createElement('strong');
        strong.textContent = 'Warning:';
        el.appendChild(strong);
        el.appendChild(document.createTextNode(
            ' Staged changes could not be saved to this browser tab\'s storage ' +
            '(quota exceeded or storage unavailable). They still exist in memory and can ' +
            'still be applied, but will be LOST if you reload, close, or navigate away from ' +
            'this tab before clicking "Apply & Reload". Consider applying soon, or staging fewer changes at once.'
        ));

        const container = document.querySelector('.container');
        const h1 = container ? container.querySelector('h1') : null;
        if (h1) {
            h1.after(el);
        } else if (container) {
            container.insertBefore(el, container.firstChild);
        } else {
            document.body.insertBefore(el, document.body.firstChild);
        }
        storagePersistenceWarningEl = el;
        return el;
    }

    function setStoragePersistenceWarningVisible(visible) {
        // Avoid creating the (hidden) element at all if we've never needed to
        // show it — keeps the common, healthy-storage case free of DOM churn.
        if (!visible && !storagePersistenceWarningEl) return;
        ensureStoragePersistenceWarningEl().hidden = !visible;
    }

    function persistStagedTableChanges() {
        if (stagedTableChanges.length === 0) {
            stagedStorage.removeItem(stagedStorageKey);
            setStoragePersistenceWarningVisible(false);
            return;
        }

        const record = {
            schema: STAGED_STORAGE_VERSION,
            pathname: tablePageKey,
            versions: tableVersions,
            changes: stagedTableChanges,
        };

        let persisted = false;
        try {
            persisted = stagedStorage.setItem(stagedStorageKey, JSON.stringify(record));
        } catch (err) {
            // Defensive: stagedTableChanges entries are always plain
            // string-keyed/valued objects (see isValidStoredChange), so
            // JSON.stringify should never throw here in practice, but treat
            // it exactly like a storage-write failure if it somehow does.
            console.error('Failed to serialize staged changes for storage:', err);
            persisted = false;
        }
        setStoragePersistenceWarningVisible(!persisted);
    }

    function loadStoredStagedTableChanges() {
        const raw = stagedStorage.getItem(stagedStorageKey);
        if (!raw) return null;

        let record;
        try {
            record = JSON.parse(raw);
        } catch {
            stagedStorage.removeItem(stagedStorageKey);
            return null;
        }

        if (
            !isPlainObject(record) ||
            record.schema !== STAGED_STORAGE_VERSION ||
            record.pathname !== tablePageKey ||
            !isPlainObject(record.versions) ||
            !Array.isArray(record.changes) ||
            record.changes.length === 0 ||
            record.changes.length > MAX_STORED_STAGED_CHANGES ||
            !record.changes.every(isValidStoredChange)
        ) {
            stagedStorage.removeItem(stagedStorageKey);
            return null;
        }

        // Only the version(s) of the table(s) actually touched by these
        // staged changes need to still match — an unrelated table changing
        // in another tab (e.g. rules edited while this page only ever staged
        // host changes) must not discard an otherwise still-valid restore.
        const versionKeyForUrl = {
            '/rules': 'rules',
            '/hosts': 'hosts',
            '/response-blacklist': 'blacklist',
            '/query-blocklist': 'query_blocklist',
        };
        const touchedVersionKeys = new Set(
            record.changes.map(change => versionKeyForUrl[change.url])
        );
        const versionsMatch = [...touchedVersionKeys].every(
            key => record.versions[key] === tableVersions[key]
        );

        if (!versionsMatch) {
            stagedStorage.removeItem(stagedStorageKey);
            return null;
        }

        return record.changes;
    }

    function createTimeoutSignal(timeoutMs) {
        const controller = new AbortController();
        const timer = window.setTimeout(() => {
            controller.abort(new DOMException('Request timed out', 'TimeoutError'));
        }, timeoutMs);

        return {
            signal: controller.signal,
            cancel() {
                window.clearTimeout(timer);
            },
        };
    }

    async function fetchWithTimeout(url, options = {}, timeoutMs = ADMIN_FETCH_TIMEOUT_MS) {
        const timeout = createTimeoutSignal(timeoutMs);

        try {
            return await fetch(url, {
                ...options,
                signal: timeout.signal,
            });
        } catch (err) {
            if (timeout.signal.aborted) {
                throw new Error(`Request timed out after ${timeoutMs / 1000} seconds`, {
                    cause: err,
                });
            }
            throw err;
        } finally {
            timeout.cancel();
        }
    }
    
    // --- Table-edit staging queue (rules / hosts / blacklist) ---
    // Works identically to the /config page staging system: Add, Edit, and Delete
    // actions are all queued locally and applied in a single Apply run, never
    // sent one-by-one. A staged "Add" that is itself edited or deleted again
    // before Apply is merged/removed in place (tracked via each row's
    // data-staged-client-id) rather than being queued as additional operations
    // referencing an identity the server doesn't know about yet.
    let stagedTableChanges = [];

    // suppressUnloadWarning disables the beforeunload "unsaved changes"
    // confirmation for exactly one upcoming navigation. Only ever set right
    // before a reload we trigger ourselves after already persisting/applying
    // staged state and telling the user via alert() — never for a manual
    // user-initiated refresh (F5/Ctrl+R), which must keep warning normally.
    let suppressUnloadWarning = false;

    // reloadPageBypassingUnsavedWarning triggers a full page reload while
    // suppressing the native "leave site?" prompt for that one navigation.
    // Resets automatically on the next page load since this is a fresh
    // script run each time.
    function reloadPageBypassingUnsavedWarning() {
        suppressUnloadWarning = true;
        location.reload();
    }

    function updateTableBanner() {
        const count = stagedTableChanges.length;
        document.querySelectorAll('.staged-table-banner').forEach(banner => {
            // banner.style.display = count > 0 ? 'block' : 'none';
            banner.hidden = count === 0;
            
            const countEl = banner.querySelector('.staged-table-count');
            if (countEl) countEl.textContent = count;
            
            const applyButton = banner.querySelector('.js-apply-table-btn');
            if (applyButton) applyButton.disabled = count === 0;
        });

        persistStagedTableChanges();
    }

    // --- Filter Expression Parser ---
    function normalizeStr(str) {
        return str.normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    }

    // debounce wraps fn so that rapid repeated calls (e.g. one per keystroke
    // while typing into a filter box) only actually invoke fn once, after
    // `wait` ms of silence since the last call. Used on the filter inputs so
    // a fast typist doesn't force a full DOM highlight-rebuild (see
    // highlightTextNodes) on every single keystroke.
    function debounce(fn, wait) {
        let timer = null;
        return function debounced(...args) {
            if (timer !== null) clearTimeout(timer);
            timer = setTimeout(() => {
                timer = null;
                fn.apply(this, args);
            }, wait);
        };
    }

    let fallbackClientIdCounter = 0;

    // generateClientId produces a short, session-unique token used to track a
    // staged "Add" entry (rule/host/blacklist) before it has a real server-assigned
    // identity, so a subsequent staged Edit/Delete of that same not-yet-applied
    // row can find and mutate/remove the correct stagedTableChanges entry instead
    // of sending a bogus reference to the server.
    // function generateClientId() {
    //     return 'c' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
    // }
    function generateClientId() {
        for (let attempt = 0; attempt < 10; attempt++) {
            let id;

            if (typeof crypto?.randomUUID === 'function') {
                id = `c-${crypto.randomUUID()}`;
            } else {
                fallbackClientIdCounter++;
                id = [
                    'c',
                    Date.now().toString(36),
                    fallbackClientIdCounter.toString(36),
                    Math.random().toString(36).slice(2),
                ].join('-');
            }

            if (!stagedTableChanges.some(change => change.clientId === id)) {
                return id;
            }
        }

        throw new Error('Unable to generate a unique staged-change client ID');
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
        stagedTableChanges.push({ url, fields, clientId });
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
            stagedTableChanges.push({ url: url, fields: fields, clientId: generateClientId() });
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
        stagedTableChanges.push({ url: url, fields: deleteFields, clientId: generateClientId() });
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

    // --- Column identity, order, and DOM reconciliation ---
    // Every data table uses stable semantic column ids (data-col-id) on
    // <col>, <th>, and <td> elements. Visual order is independent of those
    // ids: drag-reorder mutates DOM order of colgroup/thead/tbody cells,
    // while sort / filter / row display / resize all resolve cells by id.
    // The Actions column is always pinned last and is never draggable.

    const TABLE_DEFAULT_COL_ORDER = Object.freeze({
        rulesTable: Object.freeze(['type', 'id', 'pattern', 'enabled', 'modified', 'actions']),
        hostsTable: Object.freeze(['pattern', 'ips', 'enabled', 'modified', 'actions']),
        blacklistTable: Object.freeze(['cidr', 'enabled', 'modified', 'actions']),
        queryBlocklistTable: Object.freeze(['category', 'id', 'pattern', 'enabled', 'modified', 'actions']),
        configTable: Object.freeze(['key', 'value', 'modified', 'actions']),
    });

    function cellByColId(row, colId) {
        if (!row || !colId) return null;
        return row.querySelector(':scope > td[data-col-id="' + colId + '"]');
    }

    function getColumnOrderFromDOM(table) {
        const headerRow = table && table.querySelector('thead tr');
        if (!headerRow) return [];
        return Array.from(headerRow.children)
            .map(th => th.dataset.colId)
            .filter(Boolean);
    }

    function colOrderStorageKey(storageKeyPrefix) {
        return 'colorder_' + storageKeyPrefix;
    }

    function loadColumnOrder(storageKeyPrefix, defaultOrder) {
        const raw = uiStorage.getItem(colOrderStorageKey(storageKeyPrefix));
        if (!raw) return null;
        let order;
        try {
            order = JSON.parse(raw);
        } catch {
            return null;
        }
        if (!Array.isArray(order) || order.length === 0) return null;
        if (!order.every(id => typeof id === 'string' && id.length > 0)) return null;
        // Validate: same multiset as default (no unknown / missing ids).
        if (order.length !== defaultOrder.length) return null;
        const expected = new Set(defaultOrder);
        if (!order.every(id => expected.has(id))) return null;
        if (new Set(order).size !== order.length) return null;
        // Actions is always forced last regardless of what was stored.
        const withoutActions = order.filter(id => id !== 'actions');
        if (expected.has('actions')) withoutActions.push('actions');
        return withoutActions;
    }

    function persistColumnOrder(storageKeyPrefix, order) {
        uiStorage.setItem(colOrderStorageKey(storageKeyPrefix), JSON.stringify(order));
    }

    // alignRowCellsToOrder reorders a single <tr>'s <td> children to match
    // the given col-id sequence. Cells without data-col-id (e.g. colspan
    // placeholders) are left at the end untouched. Missing ids are skipped.
    function alignRowCellsToOrder(row, order) {
        if (!row || !order || order.length === 0) return;
        if (row.querySelector('td[colspan]')) return;
        const byId = new Map();
        Array.from(row.children).forEach(td => {
            if (td.dataset && td.dataset.colId) byId.set(td.dataset.colId, td);
        });
        order.forEach(id => {
            const cell = byId.get(id);
            if (cell) row.appendChild(cell);
        });
    }

    // applyColumnOrderToTable reorders <col>, <th>, and every data-row <td>
    // so visual order matches `order`. Call after load and after every drag
    // drop. Does not touch widths (those are keyed by col-id separately).
    function applyColumnOrderToTable(table, order) {
        if (!table || !order || order.length === 0) return;
        const colgroup = table.querySelector('colgroup');
        const headerRow = table.querySelector('thead tr');
        if (!colgroup || !headerRow) return;

        const colsById = new Map();
        Array.from(colgroup.children).forEach(col => {
            if (col.dataset && col.dataset.colId) colsById.set(col.dataset.colId, col);
        });
        const thsById = new Map();
        Array.from(headerRow.children).forEach(th => {
            if (th.dataset && th.dataset.colId) thsById.set(th.dataset.colId, th);
        });

        order.forEach(id => {
            const col = colsById.get(id);
            if (col) colgroup.appendChild(col);
            const th = thsById.get(id);
            if (th) headerRow.appendChild(th);
        });

        const tbody = table.querySelector('tbody');
        if (tbody) {
            Array.from(tbody.rows).forEach(row => alignRowCellsToOrder(row, order));
        }
    }

    // ensureRowMatchesTableOrder aligns a newly built or template-cloned
    // row to the table's current visual column order before insertion.
    function ensureRowMatchesTableOrder(row, table) {
        if (!row || !table) return;
        alignRowCellsToOrder(row, getColumnOrderFromDOM(table));
    }

    // buildRuleRowElement creates a <tr> for a staged (not yet applied) new rule,
    // matching the structure of server-rendered rows in the "rules" template so
    // filtering, sorting, and the existing Edit/Delete delegation all work on it
    // unmodified. Cells carry stable data-col-id so reorder/sort/display stay
    // correct regardless of visual column order.
    function buildRuleRowElement(clientId, type, pattern, enabled) {
        const row = document.createElement('tr');
        row.dataset.ruleId = clientId;
        row.dataset.ruleType = type;
        row.dataset.rulePattern = pattern;
        row.dataset.ruleEnabled = enabled ? 'true' : 'false';
        row.dataset.stagedClientId = clientId;
        row.classList.add('staged-add', 'staged');

        const typeTd = document.createElement('td');
        typeTd.dataset.colId = 'type';
        typeTd.textContent = type;
        row.appendChild(typeTd);

        const idTd = document.createElement('td');
        idTd.dataset.colId = 'id';
        idTd.textContent = '(pending)';
        idTd.title = '(pending \u2014 assigned on Apply)';
        row.appendChild(idTd);

        const patternTd = document.createElement('td');
        patternTd.dataset.colId = 'pattern';
        patternTd.textContent = pattern;
        patternTd.title = pattern;
        row.appendChild(patternTd);

        const enabledTd = document.createElement('td');
        enabledTd.dataset.colId = 'enabled';
        const span = document.createElement('span');
        span.className = enabled ? 'tag-enabled' : 'tag-disabled';
        span.textContent = enabled ? 'Active' : 'Paused';
        enabledTd.appendChild(span);
        row.appendChild(enabledTd);

        const modifiedTd = document.createElement('td');
        modifiedTd.dataset.colId = 'modified';
        modifiedTd.className = 'text-muted';
        modifiedTd.textContent = '(pending)';
        modifiedTd.title = '(pending \u2014 set on Apply)';
        row.appendChild(modifiedTd);

        const actionsTd = document.createElement('td');
        actionsTd.dataset.colId = 'actions';
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
    // Cells are resolved by stable col-id so display stays correct after reorder.
    function applyRuleRowDisplay(row, type, pattern, enabled) {
        row.dataset.ruleType = type;
        row.dataset.rulePattern = pattern;
        row.dataset.ruleEnabled = enabled ? 'true' : 'false';
        const typeCell = cellByColId(row, 'type');
        if (typeCell) typeCell.textContent = type;
        // id cell is left unchanged
        const patternCell = cellByColId(row, 'pattern');
        if (patternCell) {
            patternCell.textContent = pattern;
            patternCell.title = pattern;
        }
        const enabledCell = cellByColId(row, 'enabled');
        if (enabledCell) {
            enabledCell.textContent = '';
            const enabledSpan = document.createElement('span');
            enabledSpan.className = enabled ? 'tag-enabled' : 'tag-disabled';
            enabledSpan.textContent = enabled ? 'Active' : 'Paused';
            enabledCell.appendChild(enabledSpan);
        }
    }

    // buildQueryBlockRowElement creates a <tr> for a staged (not yet applied) new
    // query-blocklist rule. Its Edit/Delete controls are wired directly here
    // (not via Rules' document-level delegation), since these rows share the
    // .btn-edit/.btn-del classes with Rules' delegated handler and direct
    // binding avoids the two handlers fighting over the same click — mirrors
    // buildHostRowElement's identical approach below.
    function buildQueryBlockRowElement(clientId, category, pattern, enabled) {
        const row = document.createElement('tr');
        row.id = 'qbRow_' + clientId;
        row.dataset.qbId = clientId;
        row.dataset.qbCategory = category;
        row.dataset.qbPattern = pattern;
        row.dataset.qbEnabled = enabled ? 'true' : 'false';
        row.dataset.stagedClientId = clientId;
        row.classList.add('staged-add', 'staged');

        const categoryTd = document.createElement('td');
        categoryTd.dataset.colId = 'category';
        categoryTd.textContent = category;
        row.appendChild(categoryTd);

        const idTd = document.createElement('td');
        idTd.dataset.colId = 'id';
        idTd.textContent = '(pending)';
        idTd.title = '(pending \u2014 assigned on Apply)';
        row.appendChild(idTd);

        const patternTd = document.createElement('td');
        patternTd.dataset.colId = 'pattern';
        patternTd.textContent = pattern;
        patternTd.title = pattern;
        row.appendChild(patternTd);

        const enabledTd = document.createElement('td');
        enabledTd.dataset.colId = 'enabled';
        const span = document.createElement('span');
        span.className = enabled ? 'tag-enabled' : 'tag-disabled';
        span.textContent = enabled ? 'Active' : 'Paused';
        enabledTd.appendChild(span);
        row.appendChild(enabledTd);

        const modifiedTd = document.createElement('td');
        modifiedTd.dataset.colId = 'modified';
        modifiedTd.className = 'text-muted';
        modifiedTd.textContent = '(pending)';
        modifiedTd.title = '(pending \u2014 set on Apply)';
        row.appendChild(modifiedTd);

        const actionsTd = document.createElement('td');
        actionsTd.dataset.colId = 'actions';
        actionsTd.className = 'actions';

        const editBtn = document.createElement('button');
        editBtn.type = 'button';
        editBtn.className = 'btn-edit js-qb-edit';
        editBtn.textContent = 'Edit';
        editBtn.dataset.id = clientId;
        editBtn.dataset.category = category;
        editBtn.dataset.pattern = pattern;
        editBtn.dataset.enabled = enabled ? 'true' : 'false';
        editBtn.addEventListener('click', () => editQueryBlock(editBtn));
        actionsTd.appendChild(editBtn);

        const delBtn = document.createElement('button');
        delBtn.type = 'button';
        delBtn.className = 'btn-del';
        delBtn.textContent = 'Delete';
        delBtn.addEventListener('click', () => {
            if (!confirm('Remove this not-yet-applied query-blocklist rule: ' + pattern + '?')) return;
            removeStagedAddRow(clientId, row);
            applyQueryBlocklistFilter();
            updateTableBanner();
        });
        actionsTd.appendChild(delBtn);

        row.appendChild(actionsTd);
        return row;
    } // end of buildQueryBlockRowElement

    // applyQueryBlockRowDisplay updates a query-blocklist-table row's dataset,
    // visible cells, and its Edit button's dataset to reflect the given
    // {category, pattern, enabled} values. Shared by the optimistic post-Stage
    // update and by baseline-restore (no-op stage / Discard).
    function applyQueryBlockRowDisplay(row, category, pattern, enabled) {
        row.dataset.qbCategory = category;
        row.dataset.qbPattern = pattern;
        row.dataset.qbEnabled = enabled ? 'true' : 'false';
        const categoryCell = cellByColId(row, 'category');
        if (categoryCell) categoryCell.textContent = category;
        // id cell is left unchanged
        const patternCell = cellByColId(row, 'pattern');
        if (patternCell) {
            patternCell.textContent = pattern;
            patternCell.title = pattern;
        }
        const enabledCell = cellByColId(row, 'enabled');
        if (enabledCell) {
            enabledCell.textContent = '';
            const enabledSpan = document.createElement('span');
            enabledSpan.className = enabled ? 'tag-enabled' : 'tag-disabled';
            enabledSpan.textContent = enabled ? 'Active' : 'Paused';
            enabledCell.appendChild(enabledSpan);
        }

        const editBtnEl = row.querySelector('.js-qb-edit');
        if (editBtnEl) {
            editBtnEl.dataset.category = category;
            editBtnEl.dataset.pattern = pattern;
            editBtnEl.dataset.enabled = enabled ? 'true' : 'false';
        }
    }

    // discardQueryBlockEdits drops any queued staged Edit for a persisted
    // (non-add) query-blocklist rule (matched by its stable id) and restores
    // its displayed category/pattern/enabled state to the original baseline.
    // Shared by the inline per-row Discard button and the Discard button
    // inside the Edit form.
    function discardQueryBlockEdits(row, id, origCategory, origPattern, origEnabled) {
        const existingIdx = findStagedEntryIndex('/query-blocklist', f => f.edit === '1' && f.id === id);
        discardStagedEdit(existingIdx, row, () => applyQueryBlockRowDisplay(row, origCategory, origPattern, origEnabled));
    }

    // editQueryBlock opens the inline edit row for a query-blocklist rule.
    function editQueryBlock(btn) {
        const id = btn.dataset.id;
        const category = btn.dataset.category;
        const pattern = btn.dataset.pattern;
        const enabled = btn.dataset.enabled === 'true';

        const row = document.getElementById('qbRow_' + id);
        if (!row) return;
        const isStagedAdd = row.classList.contains('staged-add');
        const clientId = row.dataset.stagedClientId;
        const origCategory = row.dataset.origCategory;
        const origPattern = row.dataset.origPattern;
        const origEnabled = row.dataset.origEnabled === 'true';

        row.hidden = true;
        row.classList.add('being-edited');

        const tmpl = document.getElementById('editQueryBlockTemplate');
        const clone = tmpl.content.cloneNode(true);

        const editRow = clone.querySelector('tr');
        editRow.id = 'editQBRow_' + id;

        const form = clone.querySelector('.edit-qb-form');
        const formId = 'editQBForm_' + id;
        form.id = formId;

        const categorySelect = clone.querySelector('.edit-qb-category');
        categorySelect.setAttribute('form', formId);
        categorySelect.setAttribute('aria-label', 'Query-blocklist category');
        categorySelect.value = category;

        const idDisplay = clone.querySelector('.edit-id-display');
        idDisplay.textContent = isStagedAdd ? '(pending)' : id;
        idDisplay.title = isStagedAdd ? '(pending \u2014 assigned on Apply)' : id;

        const patternInput = clone.querySelector('.edit-qb-pattern');
        patternInput.setAttribute('form', formId);
        patternInput.setAttribute('aria-label', 'Query-blocklist pattern');
        patternInput.value = pattern;

        const enabledCheck = clone.querySelector('.edit-qb-enabled');
        enabledCheck.setAttribute('form', formId);
        enabledCheck.setAttribute('aria-label', 'Enabled');
        enabledCheck.checked = enabled;

        const idInput = clone.querySelector('.edit-qb-id-input');
        idInput.value = id;
        idInput.setAttribute('form', formId);

        clone.querySelector('.btn-cancel').addEventListener('click', () => cancelQueryBlockEdit(id), { once: true });

        form.addEventListener('submit', async function(eSubmit) {
            eSubmit.preventDefault();

            const newPattern = patternInput.value.trim();
            const enabledChecked = enabledCheck.checked;
            const newCategory = categorySelect.value;

            if (newPattern === '') { alert('pattern cannot be empty'); return; }

            if (isStagedAdd) {
                mergeStagedAddFields(clientId, { pattern: newPattern, category: newCategory, enabled: enabledChecked ? 'true' : 'false' });
                applyQueryBlockRowDisplay(row, newCategory, newPattern, enabledChecked);
                row.classList.add('staged');
            } else {
                const existingIdx = findStagedEntryIndex('/query-blocklist', f => f.edit === '1' && f.id === id);
                const isNoOp = newCategory === origCategory && newPattern === origPattern &&
                    (enabledChecked ? 'true' : 'false') === (origEnabled ? 'true' : 'false');
                const fields = { edit: '1', id: id, category: newCategory, pattern: newPattern, enabled: enabledChecked ? 'true' : 'false' };
                const displayCategory = isNoOp ? origCategory : newCategory;
                const displayPattern = isNoOp ? origPattern : newPattern;
                const displayEnabled = isNoOp ? origEnabled : enabledChecked;
                reconcileStagedEdit(existingIdx, isNoOp, '/query-blocklist', fields, row, () => applyQueryBlockRowDisplay(row, displayCategory, displayPattern, displayEnabled));
            }

            row.classList.remove('being-edited');
            row.hidden = false;

            editRow.remove();
            applyQueryBlocklistFilter();
            updateTableBanner();
        });

        clone.querySelector('.btn-discard-row').addEventListener('click', () => {
            if (isStagedAdd) {
                if (!confirm('Discard this not-yet-applied query-blocklist rule entirely?')) return;
                removeStagedAddRow(clientId, row);
                editRow.remove();
            } else {
                if (!confirm('Discard all staged changes for this query-blocklist rule and revert it to its original state?')) return;
                discardQueryBlockEdits(row, id, origCategory, origPattern, origEnabled);
                row.classList.remove('being-edited');
                row.hidden = false;
                editRow.remove();
            }
            applyQueryBlocklistFilter();
            updateTableBanner();
        }, { once: true });

        ensureRowMatchesTableOrder(editRow, document.getElementById('queryBlocklistTable'));
        row.after(clone);
    }

    function cancelQueryBlockEdit(id) {
        cancelInlineRowEdit('editQBRow_' + id, 'qbRow_' + id, false, applyQueryBlocklistFilter);
    }

    // buildHostRowElement creates a <tr> for a staged (not yet applied) new local
    // host override. Its Edit/Delete controls are wired directly here since,
    // unlike the rules table, hosts Edit/Delete are bound per-element rather than
    // via document-level delegation.
    function buildHostRowElement(clientId, pattern, ipsDisplay, enabled) {
        const row = document.createElement('tr');
        row.id = 'hostRow_' + clientId;
        row.dataset.hostPattern = pattern;
        row.dataset.hostIps = ipsDisplay;
        row.dataset.hostEnabled = enabled ? 'true' : 'false';
        row.dataset.stagedClientId = clientId;
        row.classList.add('staged-add', 'staged');

        const patternTd = document.createElement('td');
        patternTd.dataset.colId = 'pattern';
        patternTd.textContent = pattern;
        patternTd.title = pattern;
        row.appendChild(patternTd);

        const ipsTd = document.createElement('td');
        ipsTd.dataset.colId = 'ips';
        ipsTd.textContent = ipsDisplay;
        ipsTd.title = ipsDisplay;
        row.appendChild(ipsTd);

        const enabledTd = document.createElement('td');
        enabledTd.dataset.colId = 'enabled';
        const enabledSpanEl = document.createElement('span');
        enabledSpanEl.className = enabled ? 'tag-enabled' : 'tag-disabled';
        enabledSpanEl.textContent = enabled ? 'Active' : 'Paused';
        enabledTd.appendChild(enabledSpanEl);
        row.appendChild(enabledTd);

        const modifiedTd = document.createElement('td');
        modifiedTd.dataset.colId = 'modified';
        modifiedTd.className = 'text-muted';
        modifiedTd.textContent = '(pending)';
        modifiedTd.title = '(pending \u2014 set on Apply)';
        row.appendChild(modifiedTd);

        const actionsTd = document.createElement('td');
        actionsTd.dataset.colId = 'actions';
        actionsTd.className = 'actions';

        const editBtn = document.createElement('button');
        editBtn.type = 'button';
        editBtn.className = 'btn-edit js-host-edit';
        editBtn.textContent = 'Edit';
        editBtn.dataset.index = clientId;
        editBtn.dataset.pattern = pattern;
        editBtn.dataset.ips = ipsDisplay;
        editBtn.dataset.enabled = enabled ? 'true' : 'false';
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
    function applyHostRowDisplay(row, pattern, ips, enabled) {
        row.dataset.hostPattern = pattern;
        row.dataset.hostIps = ips;
        row.dataset.hostEnabled = enabled ? 'true' : 'false';
        const patternCell = cellByColId(row, 'pattern');
        if (patternCell) {
            patternCell.textContent = pattern;
            patternCell.title = pattern;
        }
        const ipsCell = cellByColId(row, 'ips');
        if (ipsCell) {
            ipsCell.textContent = ips;
            ipsCell.title = ips;
        }
        const enabledCell = cellByColId(row, 'enabled');
        if (enabledCell) {
            enabledCell.textContent = '';
            const enabledSpanEl = document.createElement('span');
            enabledSpanEl.className = enabled ? 'tag-enabled' : 'tag-disabled';
            enabledSpanEl.textContent = enabled ? 'Active' : 'Paused';
            enabledCell.appendChild(enabledSpanEl);
        }

        const editBtnEl = row.querySelector('.js-host-edit');
        if (editBtnEl) {
            editBtnEl.dataset.pattern = pattern;
            editBtnEl.dataset.ips = ips;
            editBtnEl.dataset.enabled = enabled ? 'true' : 'false';
        }
    }

    // buildBlacklistRowElement mirrors buildHostRowElement for the response-blacklist page.
    function buildBlacklistRowElement(clientId, cidr, enabled) {
        const row = document.createElement('tr');
        row.id = 'blacklistRow_' + clientId;
        row.dataset.cidr = cidr;
        row.dataset.enabled = enabled ? 'true' : 'false';
        row.dataset.stagedClientId = clientId;
        row.classList.add('staged-add', 'staged');

        const cidrTd = document.createElement('td');
        cidrTd.dataset.colId = 'cidr';
        cidrTd.textContent = cidr;
        cidrTd.title = cidr;
        row.appendChild(cidrTd);

        const enabledTd = document.createElement('td');
        enabledTd.dataset.colId = 'enabled';
        const enabledSpanEl = document.createElement('span');
        enabledSpanEl.className = enabled ? 'tag-enabled' : 'tag-disabled';
        enabledSpanEl.textContent = enabled ? 'Active' : 'Paused';
        enabledTd.appendChild(enabledSpanEl);
        row.appendChild(enabledTd);

        const modifiedTd = document.createElement('td');
        modifiedTd.dataset.colId = 'modified';
        modifiedTd.className = 'text-muted';
        modifiedTd.textContent = '(pending)';
        modifiedTd.title = '(pending \u2014 set on Apply)';
        row.appendChild(modifiedTd);

        const actionsTd = document.createElement('td');
        actionsTd.dataset.colId = 'actions';
        actionsTd.className = 'actions text-center';

        const editBtn = document.createElement('button');
        editBtn.type = 'button';
        editBtn.className = 'btn-edit js-blacklist-edit';
        editBtn.textContent = 'Edit';
        editBtn.dataset.index = clientId;
        editBtn.dataset.cidr = cidr;
        editBtn.dataset.enabled = enabled ? 'true' : 'false';
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
    function applyBlacklistRowDisplay(row, cidrVal, enabled) {
        row.dataset.cidr = cidrVal;
        row.dataset.enabled = enabled ? 'true' : 'false';
        const cidrCell = cellByColId(row, 'cidr');
        if (cidrCell) {
            cidrCell.textContent = cidrVal;
            cidrCell.title = cidrVal;
        }
        const enabledCell = cellByColId(row, 'enabled');
        if (enabledCell) {
            enabledCell.textContent = '';
            const enabledSpanEl = document.createElement('span');
            enabledSpanEl.className = enabled ? 'tag-enabled' : 'tag-disabled';
            enabledSpanEl.textContent = enabled ? 'Active' : 'Paused';
            enabledCell.appendChild(enabledSpanEl);
        }

        const editBtnEl = row.querySelector('.js-blacklist-edit');
        if (editBtnEl) {
            editBtnEl.dataset.cidr = cidrVal;
            editBtnEl.dataset.enabled = enabled ? 'true' : 'false';
        }
    }

    let csrfRefreshPromise = null;

    async function refreshCSRFToken() {
        if (csrfRefreshPromise) {
            return csrfRefreshPromise;
        }

        csrfRefreshPromise = (async () => {
            const response = await fetchWithTimeout(
                '/csrf-token',
                {
                    method: 'GET',
                    credentials: 'same-origin',
                    headers: {
                        Accept: 'application/json',
                    },
                    cache: 'no-store',
                },
                ADMIN_CHECK_FETCH_TIMEOUT_MS
            );

            if (!response.ok) {
                throw new Error(`CSRF refresh failed with HTTP ${response.status}`);
            }

            const contentType = response.headers.get('Content-Type') || '';
            if (!contentType.includes('application/json')) {
                throw new Error('CSRF refresh returned a non-JSON response');
            }

            const body = await response.json();
            if (!body || typeof body.csrf_token !== 'string' || !body.csrf_token) {
                throw new Error('CSRF refresh response did not contain a token');
            }

            csrfToken = body.csrf_token;

            const meta = document.querySelector('meta[name="csrf-token"]');
            if (meta) meta.content = csrfToken;

            return csrfToken;
        })();

        try {
            return await csrfRefreshPromise;
        } finally {
            csrfRefreshPromise = null;
        }
    }

    // // postAdminForm sends a POST with fields, injecting csrf_token automatically,
    // // and treats redirect/opaqueredirect/2xx as success per this app's handler convention.
    // async function postAdminForm(action, fields, errorPrefix, isRetry = false) {
    //     const formData = new FormData();
    //     formData.append('csrf_token', csrfToken);
        
    //     for (const [key, value] of Object.entries(fields)) {
    //         formData.append(key, value);
    //     }
        
    //     let res;
    //     try {
    //         res = await fetchWithTimeout(action, { method: 'POST', body: formData, redirect: 'manual' });
    //     } catch (err) {
    //         console.error(errorPrefix + ' network error:', err);
    //         alert('A network error occurred: ' + errorPrefix+"\nerr: "+err);
    //         return false;
    //     }
        
    //     const isSuccessRedirect = res.status === 303 || res.type === 'opaqueredirect';
    //     if (!res.ok && !isSuccessRedirect) {
    //         const errMsg = await res.text();

    //         // --- CSRF Auto-Recovery ---
    //         if (
    //             res.status === 403 &&
    //             res.headers.get('X-DNSbollocks-Error') === 'csrf' &&
    //             !isRetry
    //         ) {
    //             console.log("CSRF token invalid/expired. Attempting to fetch a new token and retry...");
    //             try {
    //                 const tokenRes = await fetch(window.location.pathname);
    //                 if (tokenRes.ok) {
    //                     const html = await tokenRes.text();
    //                     const match = html.match(/<meta name="csrf-token" content="([^"]+)">/);
    //                     if (match && match[1]) {
    //                         csrfToken = match[1];
    //                         console.log("Successfully obtained new CSRF token. Retrying request...");
    //                         const meta = document.querySelector('meta[name="csrf-token"]');
    //                         if (meta) meta.content = csrfToken;
    //                         return await postAdminForm(action, fields, errorPrefix, true);
    //                     }
    //                 }
    //             } catch (e) {
    //                 console.error("Failed to recover CSRF token:", e);
    //             }
    //         }
            
    //         alert(errorPrefix + ':\n' + errMsg);
    //         return false;
    //     }
        
    //     return true;
    // }

    
    async function postAdminForm(action, fields, errorPrefix) {
        let result;
        try {
            result = await sendAdminForm(action, fields);
        } catch (err) {
            console.error(errorPrefix + ' network error:', err);
            alert('A network error occurred: ' + errorPrefix + "\nerr: " + err);
            return false;
        }

        const { response: res, redirectSuccess } = result;

        if (res.ok || redirectSuccess) {
            return true;
        }

        const errMsg = await res.text();

        alert(errorPrefix + ':\n' + errMsg);
        return false;
    }
    async function sendAdminForm(
        action,
        fields,
        {
            allowRedirectSuccess = true,
            retryCSRF = true,
            timeoutMs = ADMIN_FETCH_TIMEOUT_MS,
        } = {}
    ) {
        const body = new URLSearchParams({
            ...fields,
            csrf_token: csrfToken,
        });

        const response = await fetchWithTimeout(
            action,
            {
                method: 'POST',
                credentials: 'same-origin',
                redirect: 'manual',
                cache: 'no-store',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                    Accept: 'application/json, text/plain;q=0.9, */*;q=0.1',
                },
                body,
            },
            timeoutMs
        );

        if (retryCSRF && response.status === 403 &&
            response.headers.get('X-DNSbollocks-Error') === 'csrf') {
            console.log("CSRF token invalid/expired. Attempting to fetch a new token and retry...");
            if (await refreshCSRFToken()) {
                console.log("Successfully obtained new CSRF token. Retrying request...");
                return sendAdminForm(action, fields, {
                    allowRedirectSuccess,
                    retryCSRF: false,
                    timeoutMs,
                });
            }
        }

        const redirectSuccess =
            allowRedirectSuccess &&
            (response.status === 303 || response.type === 'opaqueredirect');

        return { response, redirectSuccess };
    }
    // updateTableVersions adopts the server's authoritative post-mutation
    // generation numbers onto the page's working copy of tableVersions, so a
    // subsequent persistStagedTableChanges() records what the server is
    // actually at. Without this, reloading after a partial (422) batch
    // failure would make loadStoredStagedTableChanges()'s version-match
    // check fail on the very next load, silently discarding the remaining
    // still-valid staged changes.
    function updateTableVersions(serverVersions) {
        if (!serverVersions) return;
        if (typeof serverVersions.rules === 'string') tableVersions.rules = serverVersions.rules;
        if (typeof serverVersions.hosts === 'string') tableVersions.hosts = serverVersions.hosts;
        if (typeof serverVersions.blacklist === 'string') tableVersions.blacklist = serverVersions.blacklist;
        if (typeof serverVersions.query_blocklist === 'string') tableVersions.query_blocklist = serverVersions.query_blocklist;
    }

    async function applyStagedTableChanges() {
        const payload = JSON.stringify({
            versions: tableVersions,
            changes: stagedTableChanges.map(change => ({
                url: change.url,
                fields: change.fields,
                client_id: change.clientId,
            })),
        });

        let result;
        try {
            result = await sendAdminForm('/apply-tables', { payload }, { allowRedirectSuccess: false });
        } catch (err) {
            console.error('Failed to save staged changes:', err);
            alert('Failed to save staged changes:\n' + (err instanceof Error ? err.message : String(err)));
            return false;
        }

        const { response: res } = result;
        const contentType = res.headers.get('Content-Type') || '';
        // Read the body exactly once as text, then attempt JSON.parse on it.
        // Calling res.json() and later (conditionally) res.text() on the same
        // Response throws "body stream already read" on the second call —
        // that was reachable here whenever a JSON response's `error` field
        // was falsy/missing and execution fell through to the text fallback,
        // silently swallowing the real failure reason.
        const rawBody = await res.text();
        let body = null;
        if (contentType.includes('application/json')) {
            try {
                body = JSON.parse(rawBody);
            } catch (err) {
                console.error('Failed to parse /apply-tables JSON response:', err);
            }
        }

        if (res.status === 409) {
            alert(body?.error || rawBody || 'The table changed since this page was loaded. Reload before applying again.');
            return false;
        }

        if (res.status === 422) {
            const appliedIds = new Set(body?.applied_client_ids || []);
            stagedTableChanges = stagedTableChanges.filter(change => !appliedIds.has(change.clientId));
            // Adopt the server's authoritative post-mutation versions before
            // persisting, so the reload below's restore-matching succeeds for
            // the remaining, still-staged changes instead of discarding them.
            updateTableVersions(body?.versions);
            updateTableBanner(); // also persists the trimmed staged list

            alert(
                `Applied ${appliedIds.size} staged change(s), but some entries failed.\n` +
                `The failed entries remain staged. Reloading to refresh the table...`
            );

            reloadPageBypassingUnsavedWarning();
            return false;
        }

        if (!res.ok) {
            if (body?.persistence_failed) {
                // Every change in the batch was applied to the server's live,
                // in-memory state (appliedIds reflects exactly that), but
                // saving it to disk failed. Treat this like a 422: drop the
                // applied entries from the staged queue, adopt the server's
                // now-bumped versions, and reload — otherwise the client would
                // keep showing these changes as "unsaved" even though they're
                // already live, and any retry would be rejected as a stale
                // version conflict.
                const appliedIds = new Set(body?.applied_client_ids || []);
                stagedTableChanges = stagedTableChanges.filter(change => !appliedIds.has(change.clientId));
                updateTableVersions(body?.versions);
                updateTableBanner();

                alert(
                    `${appliedIds.size} staged change(s) were applied on the running server, but could ` +
                    `NOT be saved to disk, so they may be lost if the server restarts before the next ` +
                    `successful save.\nServer error: ${body?.error || rawBody || ('HTTP ' + res.status)}\n` +
                    `Reloading to refresh the table...`
                );

                reloadPageBypassingUnsavedWarning();
                return false;
            }

            alert(body?.error || rawBody || `HTTP ${res.status}`);
            return false;
        }

        stagedTableChanges = [];
        stagedStorage.removeItem(stagedStorageKey);
        updateTableBanner();
        reloadPageBypassingUnsavedWarning();
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
    async function postBlocksAction(domain, type, action, id, isRetry = false) {
        const formData = new FormData();
        formData.append('csrf_token', csrfToken);
        formData.append('domain', domain);
        formData.append('type', type);
        formData.append('action', action);
        if (id) {
            formData.append('id', id);
        }
        
        let res;
        try {
            res = await fetchWithTimeout('/blocks', {
                method: 'POST',
                body: formData,
                headers: { 'X-DNSBollocks-Ajax': '1' },
            });
        } catch (err) {
            return { ok: false, message: 'Network error: ' + err };
        }
        
        const bodyText = await res.text();

        // --- CSRF Auto-Recovery ---
        if (!res.ok && res.status === 403 &&
            res.headers.get('X-DNSbollocks-Error') === 'csrf' &&
            !isRetry) {
            console.log("CSRF token invalid/expired in blocks AJAX. Attempting recovery...");
            if (await refreshCSRFToken()) {
                console.log("Successfully obtained new CSRF token. Retrying request...");
                return await postBlocksAction(domain, type, action, id, true);
            }
        }
        
        if (res.ok) {
            return { ok: true, message: bodyText };
        }
        return { ok: false, message: bodyText || ('HTTP ' + res.status) };
    }
    
    // --- Filter highlight helpers ---
    // Highlights matches using the same case-insensitive, NFD/accent-insensitive
    // normalization used by matchesFilterExpression(), while preserving the
    // original text (and its original casing) in the DOM. normalizedIndexMap
    // maps every normalized UTF-16 code unit back to the original UTF-16 range
    // it came from.
    function highlightTextNodes(element, terms) {
        if (!element) return;

        // Remove existing highlights first so every invocation starts from the
        // original text representation.
        element.querySelectorAll('mark.filter-highlight').forEach(mark => {
            mark.replaceWith(document.createTextNode(mark.textContent));
        });
        element.normalize();

        if (terms.length === 0) return;

        const normalizedWithMap = (text) => {
            let normalized = '';
            const mapStart = [];
            const mapEnd = [];

            for (let i = 0; i < text.length;) {
                const codePoint = text.codePointAt(i);
                const originalEnd = i + (codePoint > 0xFFFF ? 2 : 1);
                // Strip combining diacritical marks AND lowercase, the same
                // way normalizeStr()+toLowerCase() do for filter terms below,
                // so this stays in sync with matchesFilterExpression()'s
                // matching and with the case-insensitive substring match the
                // Go backend uses for /logs* pages (renderLogPage's
                // strings.Contains(strings.ToLower(line), searchLower)) —
                // otherwise a term spanning where an accented character used
                // to be (e.g. "fe123" matching "café123"), or one that only
                // differs in case (e.g. "login" matching "Login"), is found
                // by the filter but silently fails to highlight here.
                const segment = normalizeStr(text.slice(i, originalEnd).toLowerCase());

                normalized += segment;

                for (let j = 0; j < segment.length; j++) {
                    mapStart.push(i);
                    mapEnd.push(originalEnd);
                }

                i = originalEnd;
            }

            return { normalized, mapStart, mapEnd };
        };

        const normalizedTerms = terms
            .map(term => normalizeStr(term.toLowerCase()))
            .filter(term => term.length > 0);

        if (normalizedTerms.length === 0) return;

        const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT, null);
        const textNodes = [];
        let node;

        while ((node = walker.nextNode()) !== null) {
            textNodes.push(node);
        }

        textNodes.forEach(textNode => {
            const text = textNode.textContent;
            const { normalized, mapStart, mapEnd } = normalizedWithMap(text);

            const matches = [];

            for (const term of normalizedTerms) {
                let searchFrom = 0;

                while (searchFrom < normalized.length) {
                    const index = normalized.indexOf(term, searchFrom);
                    if (index === -1) break;

                    const normalizedEnd = index + term.length;

                    matches.push({
                        start: mapStart[index],
                        end: mapEnd[normalizedEnd - 1],
                    });

                    // Advance by at least one normalized code unit so an
                    // overlapping occurrence cannot cause an infinite loop.
                    searchFrom = index + Math.max(term.length, 1);
                }
            }

            if (matches.length === 0) return;

            // Merge overlapping/adjacent matches so multiple terms cannot
            // produce nested <mark> elements or duplicate text.
            matches.sort((a, b) => a.start - b.start || b.end - a.end);

            const merged = [];
            for (const match of matches) {
                const last = merged[merged.length - 1];

                if (!last || match.start > last.end) {
                    merged.push({ ...match });
                } else if (match.end > last.end) {
                    last.end = match.end;
                }
            }

            const frag = document.createDocumentFragment();
            let lastIdx = 0;

            for (const match of merged) {
                if (match.start > lastIdx) {
                    frag.appendChild(document.createTextNode(text.slice(lastIdx, match.start)));
                }

                const mark = document.createElement('mark');
                mark.className = 'filter-highlight';
                mark.textContent = text.slice(match.start, match.end);
                frag.appendChild(mark);

                lastIdx = match.end;
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
                // Filtering only ever toggles .filtered-out, never the `hidden`
                // attribute — `hidden` is reserved for edit-mode row-swapping
                // and component visibility (banners), so the two mechanisms
                // can never fight over the same row.
                row.classList.remove('filtered-out');
                return;
            }
            
            const searchTargetText = normalizeStr(opts.getSearchText(row).toLowerCase());
            const isMatch = rawNorm.length === 0 || matchesFilterExpression(searchTargetText, rawNorm);
            row.classList.toggle('filtered-out', !isMatch);
            
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
            // Highlight Type / ID / Pattern by stable col-id (order-independent).
            highlightTerms: (row, terms) => {
                ['type', 'id', 'pattern'].forEach(id => {
                    const cell = cellByColId(row, id);
                    if (cell) highlightTextNodes(cell, terms);
                });
            }
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
            // Highlight Pattern / IPs by stable col-id (order-independent).
            highlightTerms: (row, terms) => {
                ['pattern', 'ips'].forEach(id => {
                    const cell = cellByColId(row, id);
                    if (cell) highlightTextNodes(cell, terms);
                });
            }
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
            // Highlight CIDR by stable col-id (order-independent).
            highlightTerms: (row, terms) => {
                const cell = cellByColId(row, 'cidr');
                if (cell) highlightTextNodes(cell, terms);
            }
        });
    }
    
    // --- Client-side ordered-substring filter, mirrors /rules' filter ---
    function applyQueryBlocklistFilter() {
        applyTableFilter({
            filterInputId: 'queryBlocklistFilter',
            storageKey: 'queryBlocklistTable_filter',
            tbodySelector: '#queryBlocklistTable tbody',
            editRowClasses: ['edit-row'],
            alwaysShowStaged: true,
            getSearchText: row => [row.dataset.qbId || "", row.dataset.qbCategory || "", row.dataset.qbPattern || ""].join(" "),
            // Highlight Category / ID / Pattern by stable col-id (order-independent).
            highlightTerms: (row, terms) => {
                ['category', 'id', 'pattern'].forEach(id => {
                    const cell = cellByColId(row, id);
                    if (cell) highlightTextNodes(cell, terms);
                });
            }
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
            // row.style.display = '';
            row.hidden = false;
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
    function discardHostEdits(row, origPattern, origIps, origEnabled) {
        const existingIdx = findStagedEntryIndex('/hosts', f => f.edit === '1' && f.old_pattern === origPattern);
        discardStagedEdit(existingIdx, row, () => applyHostRowDisplay(row, origPattern, origIps, origEnabled));
    }
    
    function editHost(btn) {
        // 0. Extract variables from the button itself
        const index = btn.dataset.index;
        const pat = btn.dataset.pattern;
        const ips = btn.dataset.ips;
        const enabled = btn.dataset.enabled === 'true';
        
        const row = document.getElementById('hostRow_' + index);
        const isStagedAdd = row.classList.contains('staged-add');
        const clientId = row.dataset.stagedClientId;
        const origPattern = row.dataset.origPattern;
        const origIps = row.dataset.origIps;
        const origEnabled = row.dataset.origEnabled === 'true';
        // row.style.display = 'none';
        row.hidden = true;
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
        patternInput.setAttribute('aria-label', 'Host pattern');
        
        const ipsInput = clone.querySelector('.edit-host-ips');
        ipsInput.value = ips;
        ipsInput.setAttribute('form', formId);
        ipsInput.setAttribute('aria-label', 'Host IP addresses');

        const enabledCheck = clone.querySelector('.edit-host-enabled');
        enabledCheck.setAttribute('form', formId);
        enabledCheck.setAttribute('aria-label', 'Enabled');
        enabledCheck.checked = enabled;
        
        // 4. Save the new pattern and submit via AJAX
        form.addEventListener('submit', async function(eSubmit) {
            eSubmit.preventDefault();
            
            const newPattern = patternInput.value.trim().toLowerCase();
            const newIPs = ipsInput.value.trim();
            const enabledChecked = enabledCheck.checked;
            
            if (isStagedAdd) {
                // This row hasn't been sent to the server yet: merge the edit into
                // the still-pending Add entry instead of staging a separate Edit
                // that would reference a pattern the server doesn't know about yet.
                mergeStagedAddFields(clientId, { pattern: newPattern, ips: newIPs, enabled: enabledChecked ? 'true' : 'false' });
                applyHostRowDisplay(row, newPattern, newIPs, enabledChecked);
                row.classList.add('staged');
            } else {
                // Same persisted host may be edited multiple times before Apply;
                // update the single queued edit in place instead of piling up one
                // staged entry per Edit+Stage cycle, and detect a full round-trip
                // back to the original values so we can drop the staged change.
                const existingIdx = findStagedEntryIndex('/hosts', f => f.edit === '1' && f.old_pattern === origPattern);
                
                //const isNoOp = newPattern === origPattern && normalizeIPListString(newIPs) === normalizeIPListString(origIps);
                
                // FIX: Compare newPattern against the Unicode display pattern (`pat`), not the Punycode `origPattern`.
                const isNoOp = newPattern === pat.toLowerCase() && normalizeIPListString(newIPs) === normalizeIPListString(origIps) &&
                    (enabledChecked ? 'true' : 'false') === (origEnabled ? 'true' : 'false');

                const fields = { old_pattern: origPattern, pattern: newPattern, ips: newIPs, enabled: enabledChecked ? 'true' : 'false', edit: '1' };
                const displayPattern = isNoOp ? origPattern : newPattern;
                const displayIPs = isNoOp ? origIps : newIPs;
                const displayEnabled = isNoOp ? origEnabled : enabledChecked;
                reconcileStagedEdit(existingIdx, isNoOp, '/hosts', fields, row, () => applyHostRowDisplay(row, displayPattern, displayIPs, displayEnabled));
            }

            row.classList.remove('being-edited');
            // row.style.display = '';
            row.hidden = false;

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
                discardHostEdits(row, origPattern, origIps, origEnabled);
                row.classList.remove('being-edited');
                // row.style.display = '';
                row.hidden = false;
                editRow.remove();
            }
            applyHostsFilter();
            updateTableBanner();
        }, { once: true });
        
        // 6. Insert cleanly into the DOM (cells aligned to current column order)
        ensureRowMatchesTableOrder(editRow, document.getElementById('hostsTable'));
        row.after(clone);
    }
    
    function cancelHostEdit(index) {
        cancelInlineRowEdit('editHostRow_' + index, 'hostRow_' + index, false, applyHostsFilter);
    }
    
    // discardBlacklistEdits drops any queued staged Edit for a persisted
    // (non-add) blacklist row and restores its displayed CIDR to the
    // original baseline. Shared by the inline per-row Discard button and the
    // Discard button inside the Edit form.
    function discardBlacklistEdits(row, origCidr, origEnabled) {
        const existingIdx = findStagedEntryIndex('/response-blacklist', f => f.action === 'edit' && f.old_cidr === origCidr);
        discardStagedEdit(existingIdx, row, () => applyBlacklistRowDisplay(row, origCidr, origEnabled));
    }
    
    // --- Edit / Cancel for inline row editing ---
    function editBlacklist(btn) {
        const index = btn.dataset.index;
        const cidr = btn.dataset.cidr;
        const enabled = btn.dataset.enabled === 'true';
        
        const row = document.getElementById('blacklistRow_' + index);
        if (!row) return;
        const isStagedAdd = row.classList.contains('staged-add');
        const clientId = row.dataset.stagedClientId;
        const origCidr = row.dataset.origCidr;
        const origEnabled = row.dataset.origEnabled === 'true';
        // row.style.display = 'none';
        row.hidden = true;
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
        cidrInput.setAttribute('aria-label', 'Blacklisted IP or CIDR');

        const enabledCheck = clone.querySelector('.edit-blacklist-enabled');
        enabledCheck.setAttribute('form', formId);
        enabledCheck.setAttribute('aria-label', 'Enabled');
        enabledCheck.checked = enabled;
        
        // Save target CIDR signature and submit via AJAX
        form.addEventListener('submit', async function(eSubmit) {
            eSubmit.preventDefault();
            
            const newCidr = cidrInput.value.trim().toLowerCase();
            const enabledChecked = enabledCheck.checked;
            
            if (isStagedAdd) {
                // This row hasn't been sent to the server yet: merge the edit into
                // the still-pending Add entry instead of staging a separate Edit
                // that would reference a CIDR the server doesn't know about yet.
                mergeStagedAddFields(clientId, { cidr: newCidr, enabled: enabledChecked ? 'true' : 'false' });
                applyBlacklistRowDisplay(row, newCidr, enabledChecked);
                row.classList.add('staged');
            } else {
                // Same persisted entry may be edited multiple times before Apply;
                // update the single queued edit in place instead of piling up one
                // staged entry per Edit+Stage cycle, and detect a full round-trip
                // back to the original value so we can drop the staged change.
                const existingIdx = findStagedEntryIndex('/response-blacklist', f => f.action === 'edit' && f.old_cidr === origCidr);
                const isNoOp = newCidr === origCidr && (enabledChecked ? 'true' : 'false') === (origEnabled ? 'true' : 'false');
                const fields = { old_cidr: origCidr, cidr: newCidr, enabled: enabledChecked ? 'true' : 'false', action: 'edit' };
                const displayCidr = isNoOp ? origCidr : newCidr;
                const displayEnabled = isNoOp ? origEnabled : enabledChecked;
                reconcileStagedEdit(existingIdx, isNoOp, '/response-blacklist', fields, row, () => applyBlacklistRowDisplay(row, displayCidr, displayEnabled));
            }

            row.classList.remove('being-edited');
            // row.style.display = '';
            row.hidden = false;

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
                discardBlacklistEdits(row, origCidr, origEnabled);
                row.classList.remove('being-edited');
                // row.style.display = '';
                row.hidden = false;
                editRow.remove();
            }
            applyBlacklistFilter();
            updateTableBanner();
        }, { once: true });
        
        ensureRowMatchesTableOrder(editRow, document.getElementById('blacklistTable'));
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
    function buildSelectElement(options, currentValue, ariaLabel) {
        if (!Array.isArray(options) || options.length === 0) {
            console.warn('buildSelectElement: empty or missing options list; falling back to plain text input. ' +
                'This likely means the Go template did not inject the expected data-opts-* attribute.');
            const input = document.createElement('input');
            input.type = 'text';
            input.className = 'config-input w-100';
            input.value = currentValue;
            if (ariaLabel) input.setAttribute('aria-label', ariaLabel);
            return input;
        }

        const select = document.createElement('select');
        select.className = 'config-input w-100';
        if (ariaLabel) select.setAttribute('aria-label', ariaLabel);

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
        
        // row.style.display = 'none';
        row.hidden = true;
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
            container.appendChild(buildSelectElement(CONFIG_KEYS.optsUpstreamSelectionMode, currentDisplay, key + ' value'));
            hint.innerText = "Strategy for querying upstreams";
        } else if (key === CONFIG_KEYS.consoleLogLevel) {
            // Option values come from Go's consoleLogLevel* constants via CONFIG_KEYS.
            container.appendChild(buildSelectElement(CONFIG_KEYS.optsConsoleLogLevel, currentDisplay, key + ' value'));
            hint.innerText = "Console output verbosity";
        } else if (key === CONFIG_KEYS.blockMode) {
            // Option values come from Go's blockMode* constants via CONFIG_KEYS.
            container.appendChild(buildSelectElement(CONFIG_KEYS.optsBlockMode, currentDisplay, key + ' value'));
            hint.innerText = "Action taken when blocking queries";
        } else if (key === CONFIG_KEYS.webuiAuthSessionMode) {
            // Option values come from Go's webUIAuthSessionMode* constants via CONFIG_KEYS.
            container.appendChild(buildSelectElement(CONFIG_KEYS.optsWebUIAuthSessionMode, currentDisplay, key + ' value'));
            hint.innerText = "How the WebUI forces Basic-Auth clients to periodically re-authenticate";
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
            pwdInput.setAttribute('aria-label', 'New password for ' + key);
            container.appendChild(pwdInput);

            const pwdConfirmInput = document.createElement('input');
            pwdConfirmInput.type = 'password';
            pwdConfirmInput.autocomplete = 'new-password';
            pwdConfirmInput.className = 'config-input-confirm monospace-code2';
            pwdConfirmInput.placeholder = 'Confirm new password...';
            pwdConfirmInput.style.marginTop = '6px';
            pwdConfirmInput.setAttribute('aria-label', 'Confirm new password for ' + key);
            container.appendChild(pwdConfirmInput);

            hint.innerText = "Type a password (or paste a hash prefixed with $2) in both fields above; leave both empty to keep the current password.";
        } else if (type === 'bool') {
            const boolSelect = document.createElement('select');
            boolSelect.className = 'config-input w-100';
            boolSelect.setAttribute('aria-label', key + ' value');
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
            // Swap to textarea...
            const listTA = document.createElement('textarea');
            listTA.className = 'config-input config-textarea';
            listTA.setAttribute('aria-label', key + ' value');

            // Use the server-provided JSON representation rather than parsing
            // the human-readable comma-separated display value. Commas are
            // valid inside strings (e.g. URLs), so splitting currentDisplay
            // would be lossy.
            let listValue;
            try {
                listValue = JSON.parse(row.dataset.listJson || '[]');
            } catch (err) {
                console.error('BUG: invalid JSON representation for []string config field', key, err);
                listValue = [];
            }

            if (!Array.isArray(listValue) || !listValue.every(v => typeof v === 'string')) {
                console.error('BUG: server supplied a non-string-array value for []string config field', key);
                listValue = [];
            }

            listTA.value = JSON.stringify(listValue, null, 2);
            container.appendChild(listTA);
            hint.innerText = "JSON array of strings. This preserves commas, empty strings, and other characters inside list items.";
        } else if (type === 'int') {
            const numInput = document.createElement('input');
            numInput.type = 'number';
            numInput.className = 'config-input w-100';
            numInput.setAttribute('aria-label', key + ' value');
            numInput.value = currentDisplay;
            container.appendChild(numInput);
            hint.innerText = "Integer value";
        } else if (type === 'string') {
            const textInput = document.createElement('input');
            textInput.type = 'text';
            textInput.className = 'config-input w-100';
            textInput.setAttribute('aria-label', key + ' value');
            textInput.value = currentDisplay;
            container.appendChild(textInput);
            hint.innerText = "String value";
        } else {
            const textInput = document.createElement('input');
            textInput.type = 'text';
            textInput.className = 'config-input w-100';
            textInput.setAttribute('aria-label', key + ' value');
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
            // row.style.display = '';
            row.hidden = false;
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
                const integerText = rawVal.trim();

                if (integerText === '') {
                    alert('Value must be a valid integer.');
                    return;
                }

                const numericValue = Number(integerText);

                // Number.isSafeInteger (not just isInteger) rejects values beyond
                // +/-(2^53-1): JavaScript's Number type cannot represent every
                // 64-bit Go int exactly above that threshold, so isInteger alone
                // would let e.g. 9007199254740993 silently arrive at the server
                // as 9007199254740992.
                if (!Number.isSafeInteger(numericValue)) {
                    alert('Value must be a valid whole number that fits safely in a JavaScript number (magnitude below 2^53).');
                    return;
                }

                parsedVal = numericValue;
                displayVal = parsedVal.toString();
            } else if (type === 'bool') {
                parsedVal = rawVal === 'true';
                displayVal = parsedVal.toString();
            } else if (type === '[]string') {
                try {
                    parsedVal = JSON.parse(rawVal);
                } catch (err) {
                    alert('Value must be a valid JSON array of strings.');
                    return;
                }

                if (!Array.isArray(parsedVal) || !parsedVal.every(v => typeof v === 'string')) {
                    alert('Value must be a JSON array of strings.');
                    return;
                }

                displayVal = parsedVal.join(', ');
            }
            
            // For the password field, an empty input means "keep existing hash" (the Go backend
            // substitutes the current hash when it receives an empty string). Keep the display
            // showing "********" so it's clear to the user that the password is unchanged,
            // rather than showing a blank cell that looks like the password was cleared.
            // currentDisplay is "********" (set by getConfigFields) so we reuse it here.
            if (isPwd) { // && rawVal === '') {
                if (rawVal === '') {
                    displayVal = currentDisplay;

                    // If we already staged a new password, keep it instead of sending 
                    // an empty string which would tell the backend to use the original unedited hash.
                    if (stagedChanges[key] !== undefined) {
                        parsedVal = stagedChanges[key];
                    }
                } else {
                    // Never expose a newly staged password in the config table or in
                    // data-original, which is also used as the filter/search value.
                    // currentDisplay is the server-provided masked value ("********").
                    displayVal = currentDisplay;
                }
            }
            
            // Save to object, modify UI, flag it
            stagedChanges[key] = parsedVal;
            row.querySelector('.display-value').innerText = displayVal;
            row.dataset.original = displayVal;
            if (type === '[]string') {
                // Keep the JSON-backed value in sync with what was just staged,
                // so re-opening Edit on this row before Apply shows the staged
                // list instead of silently reverting to the pristine server value.
                row.dataset.listJson = JSON.stringify(parsedVal);
            }
            row.classList.add('staged');
            row.classList.remove('being-edited'); 
            
            editRow.remove();
            // row.style.display = '';
            row.hidden = false;
            
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
        
        // Align cells to current visual column order, then insert before any
        // post-insertion measurements (textarea auto-size needs a live row).
        ensureRowMatchesTableOrder(editRow, document.getElementById('configTable'));
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
        // Use the `hidden` attribute (matching updateTableBanner's approach
        // for the Rules/Hosts/Blacklist staged-table banners) instead of an
        // inline style, so the banner's default HTML state and its
        // JS-driven state can never disagree — this is what was leaving
        // "Unsaved Changes! 0 modification(s)" visible on first load and
        // after Discard All (which reloads the page without ever calling
        // this function).
        banner.hidden = count === 0;
        document.getElementById('stagedCount').innerText = count;
        const applyBtn = document.getElementById('js-apply-config-btn');
        if (applyBtn) applyBtn.disabled = count === 0;
    }
    
    async function applyConfigChanges(e) {
        if (Object.keys(stagedChanges).length === 0) return;
        if (!confirm('Applying changes will overwrite ' + configFileName + ' and gracefully restart listeners.\n\n' +
            'The existing ' + configFileName + ' will be safely backed up to ' + configFileName + configBackupExt + ' first.\n\nProceed?')) return;

        const success = await withApplyButtonBusy(e.currentTarget, 'Applying\u2026', () => postAdminForm(
          '/config', {
            'action': 'apply',
            'payload': JSON.stringify(stagedChanges),
            'config_version': configVersion
        }, 'Failed to apply configuration'));
        
        if (success) {
            // Clear the object to disarm the beforeunload listener before reloading!
            for (const key in stagedChanges) { delete stagedChanges[key]; }

            reloadPageBypassingUnsavedWarning();
        }
    }
    
    // --- Column resize (drag) + double-click auto-fit, applied generically to
    // every sortable data table (Rules/Hosts/Blacklist/Query-Blocklist/Config).
    // Hybrid percentage resizing keeps every row summing to 100% width
    // (matching the existing `table-layout: fixed` + percentage <col> approach),
    // so resizing never requires horizontal scrolling or changes to the overall
    // table width:
    //   - Normal drag / double-click: the resized column takes the full delta;
    //     the opposite delta is redistributed proportionally across every
    //     column to its right (avoids crushing only the immediate neighbour).
    //   - Shift-drag: classic adjacent-only trade with the single right-hand
    //     neighbour (precise two-column adjustment).
    // Preferences persist per table via uiStorage (localStorage).

    const COL_RESIZE_MIN_PCT = 4;

    function getColWidthPct(col) {
        const match = /^([\d.]+)%$/.exec(col.style.width || '');
        return match ? parseFloat(match[1]) : 0;
    }

    function colWidthsStorageKey(storageKeyPrefix) {
        return 'colwidths_' + storageKeyPrefix;
    }

    // Widths are persisted as { colId: pct, ... } so they survive column
    // reorder. Legacy array-by-index payloads (from before col-id support)
    // are accepted once, mapped via the table's *current* DOM order, and
    // rewritten in the new format on the next persist.
    function persistColumnWidths(storageKeyPrefix, cols) {
        const widths = {};
        cols.forEach(col => {
            const id = col.dataset && col.dataset.colId;
            if (!id) return;
            widths[id] = getColWidthPct(col);
        });
        uiStorage.setItem(colWidthsStorageKey(storageKeyPrefix), JSON.stringify(widths));
    }

    function loadColumnWidthsMap(storageKeyPrefix, cols) {
        const raw = uiStorage.getItem(colWidthsStorageKey(storageKeyPrefix));
        if (!raw) return null;
        let parsed;
        try {
            parsed = JSON.parse(raw);
        } catch {
            return null;
        }
        // New format: object keyed by col-id.
        if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
            const ids = cols.map(c => c.dataset && c.dataset.colId).filter(Boolean);
            if (ids.length === 0) return null;
            if (!ids.every(id => typeof parsed[id] === 'number' && Number.isFinite(parsed[id]) && parsed[id] > 0)) {
                return null;
            }
            return parsed;
        }
        // Legacy format: array parallel to current DOM col order.
        if (Array.isArray(parsed) && parsed.length === cols.length &&
            parsed.every(w => typeof w === 'number' && Number.isFinite(w) && w > 0)) {
            const map = {};
            cols.forEach((col, i) => {
                const id = col.dataset && col.dataset.colId;
                if (id) map[id] = parsed[i];
            });
            return Object.keys(map).length === cols.length ? map : null;
        }
        return null;
    }

    // initializeColumnWidths bakes each column's effective width into an
    // explicit inline percentage on its <col> element: either a previously
    // saved user preference (keyed by stable col-id), or (on first run) the
    // width the browser is already rendering via the CSS .col-NN classes —
    // so subsequent resize math always has a concrete, consistent starting
    // point without changing how the table looks by default.
    function initializeColumnWidths(table, cols, ths, storageKeyPrefix) {
        const saved = loadColumnWidthsMap(storageKeyPrefix, cols);
        if (saved) {
            cols.forEach(col => {
                const id = col.dataset && col.dataset.colId;
                if (id && saved[id] != null) col.style.width = saved[id] + '%';
            });
            return;
        }
        const tableWidthPx = table.getBoundingClientRect().width;
        if (tableWidthPx <= 0) return;
        ths.forEach((th, i) => {
            const pct = (th.getBoundingClientRect().width / tableWidthPx) * 100;
            cols[i].style.width = pct.toFixed(3) + '%';
        });
    }

    let colResizeMeasureCtx = null;

    // measureTextWidthPx returns the pixel width `text` would render at,
    // using the font of a real cell from `table` so the measurement matches
    // on-screen rendering as closely as practical, without touching layout.
    function measureTextWidthPx(table, text) {
        if (!colResizeMeasureCtx) {
            colResizeMeasureCtx = document.createElement('canvas').getContext('2d');
        }
        const sample = table.querySelector('tbody td') || table.querySelector('thead th');
        if (sample) {
            const style = window.getComputedStyle(sample);
            colResizeMeasureCtx.font = `${style.fontWeight} ${style.fontSize} ${style.fontFamily}`;
        }
        return colResizeMeasureCtx.measureText(text || '').width;
    }

    // applyColumnWidthChange sets cols[index] toward targetPct, taking the
    // opposite delta either from the single right-hand neighbour (adjacentMode)
    // or proportionally from every column to the right. Min-width clamps are
    // enforced; any residual caused by clamping is absorbed so the row always
    // sums to 100%. Returns false if the change cannot be applied without
    // violating COL_RESIZE_MIN_PCT on the resized column itself.
    function applyColumnWidthChange(cols, index, targetPct, adjacentMode) {
        const n = cols.length;
        if (index < 0 || index >= n - 1) return false;

        const start = cols.map(getColWidthPct);
        const rightIndices = [];
        if (adjacentMode) {
            rightIndices.push(index + 1);
        } else {
            for (let i = index + 1; i < n; i++) rightIndices.push(i);
        }

        const rightStartSum = rightIndices.reduce((s, i) => s + start[i], 0);
        if (rightStartSum <= 0) return false;

        // Hard upper bound: leave at least MIN for every column that will
        // give up space (prevents the left column from swallowing the table).
        const maxLeft = 100 - (n - 1) * COL_RESIZE_MIN_PCT;
        let newLeft = Math.max(COL_RESIZE_MIN_PCT, Math.min(targetPct, maxLeft));
        const actualDelta = newLeft - start[index];

        const newWidths = start.slice();
        newWidths[index] = newLeft;

        let distributed = 0;
        for (const i of rightIndices) {
            const share = start[i] / rightStartSum;
            let w = start[i] - actualDelta * share;
            if (w < COL_RESIZE_MIN_PCT) w = COL_RESIZE_MIN_PCT;
            newWidths[i] = w;
            distributed += w;
        }

        // Clamping on the right-hand side can leave a residual. Absorb it into
        // the resized column so the percentages still sum to 100%.
        const residual = (rightStartSum - actualDelta) - distributed;
        newWidths[index] += residual;
        if (newWidths[index] < COL_RESIZE_MIN_PCT) return false;

        // Final floating-point normalisation onto the last column.
        const total = newWidths.reduce((s, w) => s + w, 0);
        if (Math.abs(total - 100) > 0.001) {
            newWidths[n - 1] += 100 - total;
            if (newWidths[n - 1] < COL_RESIZE_MIN_PCT) return false;
        }

        for (let i = 0; i < n; i++) {
            cols[i].style.width = newWidths[i].toFixed(3) + '%';
        }
        return true;
    }

    // autoFitColumn sets column `index`'s width to fit the widest content
    // currently displayed in it (header text plus every body row). Uses the
    // same proportional redistribution as a normal (non-Shift) drag so
    // double-click behaviour matches the primary resize mode. Body cells are
    // resolved by the header's stable data-col-id so auto-fit survives reorder.
    function autoFitColumn(table, cols, ths, index, storageKeyPrefix) {
        const colId = ths[index] && ths[index].dataset.colId;
        let maxWidthPx = measureTextWidthPx(table, ths[index].textContent);
        const tbody = table.querySelector('tbody');
        if (tbody) {
            for (const row of tbody.rows) {
                const cell = colId ? cellByColId(row, colId) : row.cells[index];
                if (!cell) continue;
                const w = measureTextWidthPx(table, cell.textContent);
                if (w > maxWidthPx) maxWidthPx = w;
            }
        }

        const tableWidthPx = table.getBoundingClientRect().width;
        if (tableWidthPx <= 0) return;

        const CELL_PADDING_PX = 34; // approximate cell left+right padding plus breathing room
        const desiredPct = ((maxWidthPx + CELL_PADDING_PX) / tableWidthPx) * 100;

        if (applyColumnWidthChange(cols, index, desiredPct, /*adjacentMode=*/false)) {
            persistColumnWidths(storageKeyPrefix, cols);
        }
    }

    function startColumnResize(e, handle, table, cols, index, storageKeyPrefix) {
        if (typeof e.button === 'number' && e.button !== 0) return; // primary button/touch only
        e.preventDefault();

        const tableWidthPx = table.getBoundingClientRect().width;
        if (tableWidthPx <= 0) return;

        try {
            handle.setPointerCapture(e.pointerId);
        } catch (err) {
            console.warn('Column resize: setPointerCapture failed, drag may not track outside the handle:', err);
        }

        // Capture the modifier at pointerdown so the mode cannot flip mid-drag
        // if the user presses/releases Shift while moving.
        const adjacentMode = e.shiftKey;
        const startX = e.clientX;
        const startLeftPct = getColWidthPct(cols[index]);

        function onPointerMove(moveEvent) {
            const deltaPct = ((moveEvent.clientX - startX) / tableWidthPx) * 100;
            applyColumnWidthChange(cols, index, startLeftPct + deltaPct, adjacentMode);
        }

        function finish() {
            handle.removeEventListener('pointermove', onPointerMove);
            handle.removeEventListener('pointerup', finish);
            handle.removeEventListener('pointercancel', finish);
            document.body.classList.remove('col-resizing');
            try {
                handle.releasePointerCapture(e.pointerId);
            } catch {
                // Already released (e.g. pointercancel) — nothing to do.
            }
            persistColumnWidths(storageKeyPrefix, cols);
        }

        handle.addEventListener('pointermove', onPointerMove);
        handle.addEventListener('pointerup', finish, { once: true });
        handle.addEventListener('pointercancel', finish, { once: true });
        document.body.classList.add('col-resizing');
    }

    // liveColState reads the current colgroup/th order from the live DOM so
    // resize/auto-fit keep working after column drag-reorder (indices change).
    function liveColState(table) {
        const colgroup = table.querySelector('colgroup');
        const headerRow = table.querySelector('thead tr');
        if (!colgroup || !headerRow) return null;
        const cols = Array.from(colgroup.children);
        const ths = Array.from(headerRow.children);
        if (cols.length !== ths.length || cols.length < 2) return null;
        return { cols, ths };
    }

    // rewireColumnResizeHandles strips any previous resize handles and
    // attaches fresh ones bound to the *current* visual indices. Called on
    // initial setup and after every successful column reorder.
    function rewireColumnResizeHandles(table, storageKeyPrefix) {
        const state = liveColState(table);
        if (!state) return;
        const { cols, ths } = state;

        ths.forEach(th => {
            th.classList.remove('resizable-col');
            th.querySelectorAll('.col-resize-handle').forEach(h => h.remove());
        });

        for (let i = 0; i < ths.length - 1; i++) {
            const th = ths[i];
            th.classList.add('resizable-col');

            const handle = document.createElement('span');
            handle.className = 'col-resize-handle';
            handle.setAttribute('aria-hidden', 'true');
            handle.title = 'Drag to resize (Shift+drag = adjacent only) \u2014 double-click to fit content';
            th.appendChild(handle);

            // Resolve index/cols from live DOM at event time so reorder cannot
            // leave a stale closure pointing at the wrong column.
            handle.addEventListener('pointerdown', (e) => {
                const live = liveColState(table);
                if (!live) return;
                const idx = live.ths.indexOf(th);
                if (idx < 0 || idx >= live.cols.length - 1) return;
                startColumnResize(e, handle, table, live.cols, idx, storageKeyPrefix);
            });
            handle.addEventListener('dblclick', (e) => {
                e.preventDefault();
                e.stopPropagation();
                const live = liveColState(table);
                if (!live) return;
                const idx = live.ths.indexOf(th);
                if (idx < 0 || idx >= live.cols.length - 1) return;
                autoFitColumn(table, live.cols, live.ths, idx, storageKeyPrefix);
            });
        }
    }

    // setupColumnResizing wires hybrid drag-to-resize and double-click-to-
    // auto-fit onto every column border of `tableId` except the very last
    // (there is nothing to its right to trade width with). storageKeyPrefix
    // scopes the persisted widths to this specific table, mirroring
    // setupTableSorting's identical pattern.
    function setupColumnResizing(tableId, storageKeyPrefix) {
        const table = document.getElementById(tableId);
        if (!table) return;
        const state = liveColState(table);
        if (!state) return;

        initializeColumnWidths(table, state.cols, state.ths, storageKeyPrefix);
        rewireColumnResizeHandles(table, storageKeyPrefix);
    }

    // setupColumnReorder enables drag-to-reorder of data columns (Actions
    // stays pinned last). Order is persisted per table under colorder_*.
    // Dropping a column reorders <col>, <th>, and every row's <td> cells by
    // stable data-col-id, then rewires resize handles to the new indices.
    function setupColumnReorder(tableId, storageKeyPrefix) {
        const table = document.getElementById(tableId);
        if (!table) return;
        const headerRow = table.querySelector('thead tr');
        if (!headerRow) return;

        const defaultOrder = TABLE_DEFAULT_COL_ORDER[tableId];
        if (!defaultOrder) return;

        // Apply any previously saved order before wiring interaction.
        const savedOrder = loadColumnOrder(storageKeyPrefix, defaultOrder);
        if (savedOrder) {
            applyColumnOrderToTable(table, savedOrder);
        }

        Array.from(headerRow.children).forEach(th => {
            const colId = th.dataset.colId;
            if (!colId || colId === 'actions') return;
            th.classList.add('col-draggable');
            th.setAttribute('draggable', 'true');
            th.title = (th.title ? th.title + ' — ' : '') + 'Drag header to reorder columns';
        });

        let dragColId = null;

        headerRow.addEventListener('dragstart', (e) => {
            const th = e.target.closest('th');
            if (!th || !headerRow.contains(th)) return;
            // Resize handle and sort button must never start a column drag —
            // those controls own their own pointer interactions.
            if (e.target.closest('.col-resize-handle') || e.target.closest('.sort-button')) {
                e.preventDefault();
                return;
            }
            const colId = th.dataset.colId;
            if (!colId || colId === 'actions') {
                e.preventDefault();
                return;
            }
            dragColId = colId;
            th.classList.add('col-dragging');
            try {
                e.dataTransfer.effectAllowed = 'move';
                e.dataTransfer.setData('text/plain', colId);
            } catch {
                // Some browsers throw on setData during certain gesture paths.
            }
        });

        headerRow.addEventListener('dragend', () => {
            dragColId = null;
            headerRow.querySelectorAll('.col-dragging, .col-drop-target').forEach(el => {
                el.classList.remove('col-dragging', 'col-drop-target');
            });
        });

        headerRow.addEventListener('dragover', (e) => {
            if (!dragColId) return;
            const th = e.target.closest('th');
            if (!th || !headerRow.contains(th)) return;
            const targetId = th.dataset.colId;
            if (!targetId || targetId === 'actions' || targetId === dragColId) return;
            e.preventDefault();
            try { e.dataTransfer.dropEffect = 'move'; } catch { /* ignore */ }
            headerRow.querySelectorAll('.col-drop-target').forEach(el => el.classList.remove('col-drop-target'));
            th.classList.add('col-drop-target');
        });

        headerRow.addEventListener('dragleave', (e) => {
            const th = e.target.closest('th');
            if (th) th.classList.remove('col-drop-target');
        });

        headerRow.addEventListener('drop', (e) => {
            e.preventDefault();
            const th = e.target.closest('th');
            headerRow.querySelectorAll('.col-drop-target').forEach(el => el.classList.remove('col-drop-target'));
            if (!dragColId || !th || !headerRow.contains(th)) return;
            const targetId = th.dataset.colId;
            if (!targetId || targetId === 'actions' || targetId === dragColId) return;

            const current = getColumnOrderFromDOM(table);
            const fromIdx = current.indexOf(dragColId);
            const toIdx = current.indexOf(targetId);
            if (fromIdx < 0 || toIdx < 0 || fromIdx === toIdx) return;

            const next = current.slice();
            next.splice(fromIdx, 1);
            next.splice(toIdx, 0, dragColId);
            // Force Actions last if present.
            const withoutActions = next.filter(id => id !== 'actions');
            if (current.includes('actions')) withoutActions.push('actions');

            // Cancel any open inline edits before reshuffling cells under them.
            document.querySelectorAll('.btn-cancel').forEach(btn => btn.click());

            applyColumnOrderToTable(table, withoutActions);
            persistColumnOrder(storageKeyPrefix, withoutActions);
            rewireColumnResizeHandles(table, storageKeyPrefix);
            dragColId = null;
        });
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
            // Programmatic reloads triggered via reloadPageBypassingUnsavedWarning()
            // (after we've already persisted/communicated the outcome to the
            // user, e.g. post-apply or post-discard) must never re-trigger this
            // native "leave site?" prompt.
            if (suppressUnloadWarning) return;

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
                stagedStorage.removeItem(stagedStorageKey);
                reloadPageBypassingUnsavedWarning();
                return;
            }
            if (e.target.closest('.js-apply-table-btn')) {
                const applyBtn = e.target.closest('.js-apply-table-btn');
                if (!confirm('Apply all staged changes?\n(a .bak file will be created with the old state)')) return;
                // applyStagedTableChanges() already handles every outcome on its
                // own: it clears stagedTableChanges, clears sessionStorage,
                // updates the banner, and reloads on full success; on a 409
                // (version conflict) it leaves everything untouched so the user
                // can manually refresh; on a 422 (partial failure) it filters
                // out only the entries that succeeded, re-persists the rest,
                // and deliberately does NOT reload, so the surviving staged
                // entries aren't wiped out from under the user. Don't
                // second-guess that here with an unconditional clear+reload.
                withApplyButtonBusy(applyBtn, 'Applying\u2026', () => applyStagedTableChanges())
                    .catch(err => console.error('Unexpected error while applying staged changes:', err));
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
                // row.style.display = 'none';
                row.hidden = true;
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
                typeSelect.setAttribute('aria-label', 'DNS record type');
                typeSelect.value = typ;
                idDisplay.textContent = isStagedAdd ? '(pending)' : id;
                idDisplay.title = isStagedAdd ? '(pending \u2014 assigned on Apply)' : id;
                patternInput.setAttribute('aria-label', 'Rule pattern');
                patternInput.value = oldPattern;
                enabledCheck.setAttribute('aria-label', 'Enabled');
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
                    // row.style.display = '';
                    row.hidden = false;

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
                        // row.style.display = '';
                        row.hidden = false;
                        editRow.remove();
                    }
                    applyRulesFilter();
                    updateTableBanner();
                }, { once: true });
                
                // 6. Insert cleanly next to the original row (cells match column order)
                ensureRowMatchesTableOrder(editRow, document.getElementById('rulesTable'));
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
            filterInput.addEventListener('input', debounce(() => {
                applyRulesFilter();
            }, 120));
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
                    ensureRowMatchesTableOrder(row, document.getElementById('rulesTable'));
                    tbody.insertBefore(row, tbody.firstChild); // newest first, mirrors server-side prepend
                }

                patternInput.value = '';
                if (enabledCheckbox) enabledCheckbox.checked = true;

                applyRulesFilter();
                updateTableBanner();
            });
        }
        
        // ── Query Blocklist page ────
        document.querySelectorAll('.js-qb-edit').forEach(btn => {
            btn.addEventListener('click', () => editQueryBlock(btn));
        });

        document.querySelectorAll('.js-qb-delete-form').forEach(form => {
            form.addEventListener('submit', function(e) {
                e.preventDefault();

                const idInput = form.querySelector('[name="id"]');
                const categoryInput = form.querySelector('[name="category"]');
                if (!idInput || !categoryInput) {
                    console.error('js-qb-delete-form: missing [name="id"] or [name="category"] input');
                    return;
                }
                const id = idInput.value;
                const origCategory = categoryInput.value;

                const row = form.closest('tr');
                const pattern = row ? row.dataset.origPattern : '';

                if (!confirm('Delete query-blocklist rule: ' + (pattern || id) + '?')) {
                    return;
                }

                // A pending Delete supersedes any queued Edit for the same rule;
                // drop it so we don't try to apply a stale edit right before deleting.
                const staleEditIdx = findStagedEntryIndex('/query-blocklist', f => f.edit === '1' && f.id === id);

                // Restore the row's displayed values (any staged edit was just
                // discarded above) and keep it visible — struck through via CSS —
                // instead of hiding it, so it can still be found via the filter
                // and Undeleted.
                stageRowDeletion('/query-blocklist', staleEditIdx, { delete: '1', id: id, category: origCategory }, row,
                    () => applyQueryBlockRowDisplay(row, row.dataset.origCategory, row.dataset.origPattern, row.dataset.origEnabled === 'true'));

                applyQueryBlocklistFilter();
                updateTableBanner();
            });
        });

        document.querySelectorAll('.js-qb-undelete').forEach(btn => {
            btn.addEventListener('click', () => {
                const id = btn.dataset.id;
                const row = document.getElementById('qbRow_' + id);
                if (!row) return;
                const origCategory = row.dataset.origCategory;
                undoStagedDeletion(row, c => c.url === '/query-blocklist' && c.fields.delete === '1' && c.fields.id === id && c.fields.category === origCategory);
                applyQueryBlocklistFilter();
                updateTableBanner();
            });
        });

        // Inline Discard: revert a staged plain-edit row to its original
        // category/pattern/enabled directly, without first opening the Edit form.
        document.querySelectorAll('.js-qb-discard').forEach(btn => {
            btn.addEventListener('click', () => {
                const id = btn.dataset.id;
                const row = document.getElementById('qbRow_' + id);
                if (!row || row.classList.contains('staged-add') || row.classList.contains('staged-delete')) return;
                if (!confirm('Discard all staged changes for this query-blocklist rule and revert it to its original state?')) return;
                discardQueryBlockEdits(row, id, row.dataset.origCategory, row.dataset.origPattern, row.dataset.origEnabled === 'true');
                applyQueryBlocklistFilter();
                updateTableBanner();
            });
        });

        // --- ADD QUERY-BLOCKLIST RULE: stage instead of posting immediately ---
        const addQueryBlockForm = document.getElementById('addQueryBlockForm');
        if (addQueryBlockForm) {
            addQueryBlockForm.addEventListener('submit', function(e) {
                e.preventDefault();

                const patternInput = addQueryBlockForm.querySelector('[name="pattern"]');
                const categorySelect = addQueryBlockForm.querySelector('[name="category"]');
                const enabledCheckbox = addQueryBlockForm.querySelector('[name="enabled"]');
                if (!patternInput || !categorySelect) return;

                const pattern = patternInput.value.trim().toLowerCase();
                const category = categorySelect.value;
                if (pattern === '') return;
                const enabled = enabledCheckbox ? enabledCheckbox.checked : true;

                const alreadyStaged = findStagedEntryIndex('/query-blocklist', f => !f.id && !f.delete && f.category === category && f.pattern === pattern) !== -1;
                if (alreadyStaged) {
                    alert('A staged (not yet applied) query-blocklist rule with this category and pattern already exists.');
                    return;
                }

                const clientId = stageNewEntry('/query-blocklist', { pattern: pattern, category: category, enabled: enabled ? 'true' : 'false' });

                const tbody = document.querySelector('#queryBlocklistTable tbody');
                if (tbody) {
                    removePlaceholderRow(tbody);
                    const newRow = buildQueryBlockRowElement(clientId, category, pattern, enabled);
                    ensureRowMatchesTableOrder(newRow, document.getElementById('queryBlocklistTable'));
                    tbody.insertBefore(newRow, tbody.firstChild);
                }

                patternInput.value = '';
                if (enabledCheckbox) enabledCheckbox.checked = true;

                applyQueryBlocklistFilter();
                updateTableBanner();
            });
        }

        // Load filter value from persistent uiStorage on page load
        const queryBlocklistFilterInput = document.getElementById('queryBlocklistFilter');
        if (queryBlocklistFilterInput) {
            queryBlocklistFilterInput.value = uiStorage.getItem('queryBlocklistTable_filter') || '';
            queryBlocklistFilterInput.addEventListener('input', debounce(() => {
                applyQueryBlocklistFilter();
            }, 120));
            applyQueryBlocklistFilter();
        }
        
        // ── Blocks page ─────────────
        // Refresh button(s) navigate to /blocks via GET, bypassing any cached POST
        // state. There can be up to two of these now (one per section — Recent
        // Blocks and, outside whitelist_mode, Recent Allows).
        document.querySelectorAll('.js-blocks-refresh-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                window.location.href = '/blocks';
            });
        });
        
        // Clear Shown Blocks/Allows: grey the button while the request is in
        // flight (matching withApplyButtonBusy's pattern used elsewhere) so a
        // slow or temporarily-firewalled backend can't be double-submitted by a
        // second click, and un-grey it again on failure so the user can retry.
        // There can be up to two of these forms now — see the refresh-button
        // comment above — each with its own "action" (clear / clear_allowed).
        document.querySelectorAll('.js-blocks-clear-form').forEach(blocksClearForm => {
            blocksClearForm.addEventListener('submit', function(e) {
                e.preventDefault();
                const actionValue = blocksClearForm.querySelector('[name="action"]').value;
                const noun = actionValue === 'clear_allowed' ? 'allows' : 'blocks';
                if (!confirm('Clear all currently shown ' + noun + '?\n\n(New ' + noun + ' that occurred since you loaded the page will be kept safely.)')) {
                    return;
                }
                const btn = blocksClearForm.querySelector('button[type="submit"]');
                (async () => {
                    const success = await withApplyButtonBusy(btn, 'Clearing\u2026', () => postAdminForm(
                        blocksClearForm.getAttribute('action'),// this is '/blocks'
                        {
                            action: actionValue,
                            cutoff: blocksClearForm.querySelector('[name="cutoff"]').value,
                        },
                        'Failed to clear shown ' + noun
                    ));
                    if (success) {
                        location.reload();
                    }
                })();
            });
        });
        
        // Unblock/Re-block buttons: submit in the background via fetchWithTimeout() instead
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
                const idInput = form.querySelector('[name="id"]');
                const id = idInput ? idInput.value : '';
                const btn = form.querySelector('button[type="submit"]');
                const feedback = form.parentElement.querySelector('.block-action-feedback');
                
                if (btn.disabled) return; // already in flight; ignore rapid double-clicks
                
                const originalText = btn.textContent;
                const originalClass = btn.className;
                
                btn.disabled = true;
                btn.textContent = action === 'disable_qb_local_rule' ? 'Disabling…' :
                    action === 'block_qb_local' ? 'Blocking…' :
                    action === 'reblock' ? 'Re-blocking…' : 'Unblocking…';
                btn.classList.add('btn-action-pending');
                if (feedback) {
                    feedback.textContent = '';
                    feedback.className = 'block-action-feedback';
                }
                
                const result = await postBlocksAction(domain, type, action, id);
                
                if (result.ok) {
                    // Flip the form to perform the opposite action next time, and
                    // relabel the button to match — mirrors exactly what a full
                    // page reload would have shown.
                    if (action === 'unblock') {
                        actionInput.value = 'reblock';
                        btn.textContent = 'Re-block (Pause) [Whitelist]';
                        btn.className = 'btn-cancel';
                    } else if (action === 'reblock') {
                        actionInput.value = 'unblock';
                        btn.textContent = 'Unblock ' + type + ' [Whitelist]';
                        btn.className = 'btn-edit';
                    } else if (action === 'unblock_qb') {
                        actionInput.value = 'reblock_qb';
                        btn.textContent = 'Re-block (Pause) [Query Blocklist, External]';
                        btn.className = 'btn-cancel';
                    } else if (action === 'reblock_qb') {
                        actionInput.value = 'unblock_qb';
                        btn.textContent = 'Unblock [Query Blocklist, External]';
                        btn.className = 'btn-edit';
                    } else if (action === 'disable_qb_local_rule') {
                        // One-directional from /blocks: re-enabling happens on
                        // /query-blocklist, so there's no "undo" toggle here —
                        // just remove the control once it's done its job.
                        form.remove();
                    } else if (action === 'block_qb_local') {
                        // We don't have the newly created/enabled rule's ID
                        // here (needed to build the corresponding "Unblock
                        // (Pause)" toggle, which targets a rule by ID via
                        // disable_qb_local_rule), so just reload to pick up
                        // the fresh server-side state instead of guessing.
                        location.reload();
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
        
        // ── Hosts page ──────────────
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
                    () => applyHostRowDisplay(row, origPattern, row.dataset.origIps, row.dataset.origEnabled === 'true'));

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
                discardHostEdits(row, row.dataset.origPattern, row.dataset.origIps, row.dataset.origEnabled === 'true');
                applyHostsFilter();
                updateTableBanner();
            });
        });
        
        // --- ADD HOST: stage instead of posting immediately ---
        document.getElementById('addHostForm')?.addEventListener('submit', function(e) {
            e.preventDefault();

            const patternInput = this.querySelector('[name="pattern"]');
            const ipsInput = this.querySelector('[name="ips"]');
            const enabledCheckbox = this.querySelector('[name="enabled"]');
            if (!patternInput || !ipsInput) return;

            const pattern = patternInput.value.trim().toLowerCase();
            const ips = ipsInput.value.trim();
            if (pattern === '' || ips === '') return;
            const enabled = enabledCheckbox ? enabledCheckbox.checked : true;

            const alreadyStaged = findStagedEntryIndex('/hosts', f => !f.edit && !f.delete && f.pattern === pattern) !== -1;
            if (alreadyStaged) {
                alert('A staged (not yet applied) local host with this pattern already exists.');
                return;
            }

            const clientId = stageNewEntry('/hosts', { pattern: pattern, ips: ips, enabled: enabled ? 'true' : 'false' });

            const tbody = document.querySelector('#hostsTable tbody');
            if (tbody) {
                removePlaceholderRow(tbody);
                const newRow = buildHostRowElement(clientId, pattern, ips, enabled);
                ensureRowMatchesTableOrder(newRow, document.getElementById('hostsTable'));
                tbody.appendChild(newRow);
            }

            patternInput.value = '';
            ipsInput.value = '';
            if (enabledCheckbox) enabledCheckbox.checked = true;

            applyHostsFilter();
            updateTableBanner();
        });
        
        // Load filter value from persistent uiStorage on page load
        const hostsFilterInput = document.getElementById('hostsFilter');
        if (hostsFilterInput) {
            hostsFilterInput.value = uiStorage.getItem('hostsTable_filter') || '';
            hostsFilterInput.addEventListener('input', debounce(() => {
                applyHostsFilter();
            }, 120));
            applyHostsFilter();
        }
        
        // ── Response-blacklist page ─
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
                    () => applyBlacklistRowDisplay(row, origCidr, row.dataset.origEnabled === 'true'));

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
                discardBlacklistEdits(row, row.dataset.origCidr, row.dataset.origEnabled === 'true');
                applyBlacklistFilter();
                updateTableBanner();
            });
        });
        
        // Load filter values from persistent uiStorage on load tracking configuration
        const blacklistFilterInput = document.getElementById('blacklistFilter');
        if (blacklistFilterInput) {
            blacklistFilterInput.value = uiStorage.getItem('blacklistTable_filter') || '';
            blacklistFilterInput.addEventListener('input', debounce(() => {
                applyBlacklistFilter();
            }, 120));
            applyBlacklistFilter();
        }
        
        // --- Existing "check for overlapping filters before add" validation ---
        document.getElementById('add-blacklist-form')?.addEventListener('submit', async function(e) {
            e.preventDefault(); // Stop form from auto-posting immediately
            const form = this;
            const cidrInput = form.querySelector('input[name="cidr"]');
            const enabledCheckbox = form.querySelector('input[name="enabled"]');
            const cidrValue = cidrInput.value.trim().toLowerCase();
            const enabled = enabledCheckbox ? enabledCheckbox.checked : true;
            
            if (!cidrValue) return;

            const alreadyStaged = findStagedEntryIndex('/response-blacklist', f => f.action === 'add' && f.cidr === cidrValue) !== -1;
            if (alreadyStaged) {
                alert('A staged (not yet applied) blacklist entry with this CIDR already exists.');
                return;
            }
            
            try {
                const response = await fetchWithTimeout(
                    `/response-blacklist/check?cidr=${encodeURIComponent(cidrValue)}`,
                    {},
                    ADMIN_CHECK_FETCH_TIMEOUT_MS
                );

                let data = null;
                try {
                    data = await response.json();
                } catch (parseErr) {
                    console.error('Blacklist overlap check returned a non-JSON response:', parseErr);
                }

                if (!response.ok) {
                    alert(
                        (data && data.error) ||
                        `The blacklist overlap check rejected this input (HTTP ${response.status}).\n\nThe entry was not staged.`
                    );
                    return;
                }

                if (data && data.matches && data.matches.length > 0) {
                    // Double-ask user confirmation showing exact matching filters
                    const message = `This target is already covered or matched by these existing filters:\n• ` +
                    data.matches.join('\n• ') +
                    `\n\nDo you still want to add it as a separate redundant entry?`;
                    
                    if (!confirm(message)) {
                        return; // User clicked "Cancel" -> abort
                    }
                }
            } catch (err) {
                // Genuine network/timeout/protocol failure (not a server-side
                // validation rejection, which is handled above via !response.ok).
                // Deliberately conservative: never offer a "continue anyway"
                // bypass here, since this catch covers everything from a
                // browser-extension block to auth expiry to a 5xx to a code
                // bug, and those warrant different handling than a simple retry.
                console.error('Blacklist overlap validation check failed:', err);
                const message = err instanceof Error ? err.message : String(err);
                alert(
                    'The blacklist overlap check could not be completed (network error, timeout, or the request was blocked by browser/extension policy).\n\n' +
                    message +
                    '\n\nThe entry was not staged. Retry after resolving the error.'
                );
                return;
            }
            
            const clientId = stageNewEntry('/response-blacklist', { action: 'add', cidr: cidrValue, enabled: enabled ? 'true' : 'false' });

            const tbody = document.querySelector('#blacklistTable tbody');
            if (tbody) {
                removePlaceholderRow(tbody);
                const newRow = buildBlacklistRowElement(clientId, cidrValue, enabled);
                ensureRowMatchesTableOrder(newRow, document.getElementById('blacklistTable'));
                tbody.insertBefore(newRow, tbody.firstChild);
            }

            cidrInput.value = '';
            if (enabledCheckbox) enabledCheckbox.checked = true;

            applyBlacklistFilter();
            updateTableBanner();
        });
        
        // ── Config page ─────────────
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
                if (row.dataset.type === '[]string') {
                    row.dataset.listJson = row.dataset.trueListJson;
                }
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
                    reloadPageBypassingUnsavedWarning();
                }
            });
        }
        // Bind event listener and restore saved state on page load
        const configFilterInput = document.getElementById('configFilter');
        if (configFilterInput) {
            configFilterInput.value = uiStorage.getItem('configTable_filter') || '';
            configFilterInput.addEventListener('input', debounce(applyConfigFilter, 120));
            // Run immediately on page boot to apply the active filter
            applyConfigFilter();
        }
        
        // ── Stats page: Shutdown ───
        const shutdownForm = document.querySelector('.js-shutdown-form');
        if (shutdownForm) {
            shutdownForm.addEventListener('submit', function(e) {
                e.preventDefault();
                if (!confirm('Really shut down the dnsbollocks server now? All DNS resolution will stop until it is manually restarted.')) {
                    return;
                }
                (async () => {
                    try {
                        const result = await sendAdminForm('/shutdown', { confirm: 'yes' }, { allowRedirectSuccess: false });
                        if (result.response.ok) {
                            alert('Shutdown initiated. The server will stop shortly.');
                        } else {
                            const errMsg = await result.response.text();
                            alert('Failed to shut down:\n' + errMsg);
                        }
                    } catch (err) {
                        // A network-level failure here (connection reset, timeout) is
                        // ambiguous, not a clear failure: shutdownHandler writes and
                        // flushes its 200 response, then waits 500ms before actually
                        // exiting, specifically to let the response reach the client
                        // first — but if the listener itself tears down mid-flight the
                        // fetch can still fail even though shutdown genuinely succeeded.
                        // Don't alarm the user with a scary "network error" for exactly
                        // what they just asked to happen.
                        console.warn('Shutdown request did not complete cleanly (this can be normal if the server already stopped):', err);
                        alert('Shutdown request sent. If the server does not respond, it likely already stopped.');
                    }
                })();
            });
        }

        // ── Control page: Reload Config / Clear DNS Cache ──
        const controlReloadForm = document.querySelector('.js-control-reload-form');
        if (controlReloadForm) {
            controlReloadForm.addEventListener('submit', function(e) {
                if (!confirm('Reload configuration now? This re-reads config.json and the dependent rule/host/blocklist files, and may briefly rebind listeners if their settings changed.')) {
                    e.preventDefault();
                }
            });
        }

        const controlClearCacheForm = document.querySelector('.js-control-clear-cache-form');
        if (controlClearCacheForm) {
            controlClearCacheForm.addEventListener('submit', function(e) {
                if (!confirm('Clear the DNS cache now? All cached responses will be dropped immediately.')) {
                    e.preventDefault();
                }
            });
        }
        
        // ── Logs page ───────────────
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
                uiStorage.removeItem(logsFilterStorageKey);
                form.submit();
            });
        }
        
        // Clean up visual status notifications on browser refresh triggers
        //Because the messages are now in the URL (e.g., /blocks?success=Successfully...), if the user hits F5 a minute later, the URL will still contain that query string, and the success message will pop up again.
        // Clean URL query parameters so F5 doesn't re-trigger visual messages
        
        if (window.location.search.includes('success=') || window.location.search.includes('error=')) {
            window.history.replaceState({}, document.title, window.location.pathname);
        }
        
        function cssEscapeAttrValue(value) {
            const s = String(value ?? '');
            if (window.CSS && typeof CSS.escape === 'function') {
                return CSS.escape(s);
            }
            // Fallback for older browsers: good enough for our stored patterns/CIDs.
            return s.replace(/["\\]/g, '\\$&');
        }

        function findRulesRowById(id) {
            return document.querySelector(
                `#rulesTable tbody tr[data-rule-id="${cssEscapeAttrValue(id)}"]`
            );
        }

        function findHostsRowByOriginalPattern(pattern) {
            return document.querySelector(
                `#hostsTable tbody tr[data-orig-pattern="${cssEscapeAttrValue(pattern)}"]`
            );
        }

        function findBlacklistRowByOriginalCidr(cidr) {
            return document.querySelector(
                `#blacklistTable tbody tr[data-orig-cidr="${cssEscapeAttrValue(cidr)}"]`
            );
        }

        function findQueryBlockRowById(id) {
            return document.getElementById('qbRow_' + id);
        }

        function renderStagedRuleChange(change) {
            const fields = change?.fields || {};
            const tbody = document.querySelector('#rulesTable tbody');
            if (!tbody) return;

            // Staged add: no server-side ID yet, so recreate the row from scratch.
            if (!fields.id && !fields.delete && !fields.edit) {
                const type = fields.type || 'A';
                const pattern = fields.pattern || '';
                const enabled = fields.enabled !== 'false';
                const newRow = buildRuleRowElement(change.clientId, type, pattern, enabled);
                ensureRowMatchesTableOrder(newRow, document.getElementById('rulesTable'));
                tbody.insertBefore(newRow, tbody.firstChild);
                return;
            }

            const row = findRulesRowById(fields.id || '');
            if (!row) {
                console.warn('renderStagedRuleChange: could not find row for restored change', change);
                return;
            }

            if (fields.delete === '1') {
                // Staged delete: restore the original visible values, then strike through.
                applyRuleRowDisplay(
                    row,
                    row.dataset.origType,
                    row.dataset.origPattern,
                    row.dataset.origEnabled === 'true'
                );
                row.classList.remove('staged-add');
                row.classList.add('staged-delete', 'staged');
                return;
            }

            // Staged edit: apply the staged values directly to the existing row.
            const type = fields.type || row.dataset.origType;
            const pattern = fields.pattern || row.dataset.origPattern;
            const enabled = fields.enabled === 'true';

            applyRuleRowDisplay(row, type, pattern, enabled);
            row.classList.add('staged');
        }

        function renderStagedHostChange(change) {
            const fields = change?.fields || {};
            const tbody = document.querySelector('#hostsTable tbody');
            if (!tbody) return;

            // Staged add: create a brand-new row.
            if (!fields.old_pattern && !fields.edit && !fields.delete) {
                const pattern = fields.pattern || '';
                const ips = fields.ips || '';
                const enabled = fields.enabled !== 'false';
                const newRow = buildHostRowElement(change.clientId, pattern, ips, enabled);
                ensureRowMatchesTableOrder(newRow, document.getElementById('hostsTable'));
                tbody.appendChild(newRow);
                return;
            }

            const origPattern = fields.old_pattern || fields.pattern || '';
            const row = findHostsRowByOriginalPattern(origPattern);
            if (!row) {
                console.warn('renderStagedHostChange: could not find row for restored change', change);
                return;
            }

            if (fields.delete === '1') {
                applyHostRowDisplay(row, row.dataset.origPattern, row.dataset.origIps, row.dataset.origEnabled === 'true');
                row.classList.remove('staged-add');
                row.classList.add('staged-delete', 'staged');
                return;
            }

            // Staged edit of an existing row.
            const pattern = fields.pattern || row.dataset.origPattern;
            const ips = fields.ips || row.dataset.origIps;
            const enabled = fields.enabled === 'true';

            applyHostRowDisplay(row, pattern, ips, enabled);
            row.classList.add('staged');
        }

        function renderStagedBlacklistChange(change) {
            const fields = change?.fields || {};
            const tbody = document.querySelector('#blacklistTable tbody');
            if (!tbody) return;

            // Staged add.
            if (fields.action === 'add') {
                const cidr = fields.cidr || '';
                const enabled = fields.enabled !== 'false';
                const newRow = buildBlacklistRowElement(change.clientId, cidr, enabled);
                ensureRowMatchesTableOrder(newRow, document.getElementById('blacklistTable'));
                tbody.insertBefore(newRow, tbody.firstChild);
                return;
            }

            const origCidr = fields.old_cidr || fields.cidr || '';
            const row = findBlacklistRowByOriginalCidr(origCidr);
            if (!row) {
                console.warn('renderStagedBlacklistChange: could not find row for restored change', change);
                return;
            }

            if (fields.action === 'delete') {
                applyBlacklistRowDisplay(row, row.dataset.origCidr, row.dataset.origEnabled === 'true');
                row.classList.remove('staged-add');
                row.classList.add('staged-delete', 'staged');
                return;
            }

            // Staged edit.
            if (fields.action === 'edit') {
                const cidr = fields.cidr || row.dataset.origCidr;
                const enabled = fields.enabled === 'true';
                applyBlacklistRowDisplay(row, cidr, enabled);
                row.classList.add('staged');
                return;
            }

            console.warn('renderStagedBlacklistChange: unrecognized restored change', change);
        }

        function renderStagedQueryBlockChange(change) {
            const fields = change?.fields || {};
            const tbody = document.querySelector('#queryBlocklistTable tbody');
            if (!tbody) return;

            // Staged add: no server-side ID yet, so recreate the row from scratch.
            if (!fields.id && !fields.delete && !fields.edit) {
                const category = fields.category || 'block';
                const pattern = fields.pattern || '';
                const enabled = fields.enabled !== 'false';
                const newRow = buildQueryBlockRowElement(change.clientId, category, pattern, enabled);
                ensureRowMatchesTableOrder(newRow, document.getElementById('queryBlocklistTable'));
                tbody.insertBefore(newRow, tbody.firstChild);
                return;
            }

            const row = findQueryBlockRowById(fields.id || '');
            if (!row) {
                console.warn('renderStagedQueryBlockChange: could not find row for restored change', change);
                return;
            }

            if (fields.delete === '1') {
                // Staged delete: restore the original visible values, then strike through.
                applyQueryBlockRowDisplay(
                    row,
                    row.dataset.origCategory,
                    row.dataset.origPattern,
                    row.dataset.origEnabled === 'true'
                );
                row.classList.remove('staged-add');
                row.classList.add('staged-delete', 'staged');
                return;
            }

            // Staged edit: apply the staged values directly to the existing row.
            const category = fields.category || row.dataset.origCategory;
            const pattern = fields.pattern || row.dataset.origPattern;
            const enabled = fields.enabled === 'true';

            applyQueryBlockRowDisplay(row, category, pattern, enabled);
            row.classList.add('staged');
        }
        
        function renderStoredStagedChange(change) {
            switch (change.url) {
                case '/rules':
                    renderStagedRuleChange(change);
                    break;
                case '/hosts':
                    renderStagedHostChange(change);
                    break;
                case '/response-blacklist':
                    renderStagedBlacklistChange(change);
                    break;
                case '/query-blocklist':
                    renderStagedQueryBlockChange(change);
                    break;
                default:
                    throw new Error(`Unsupported staged-change URL: ${change.url}`);
            }
        }

        const restoredChanges = loadStoredStagedTableChanges();
        if (restoredChanges) {
            if (confirm(`Restore ${restoredChanges.length} staged change(s) from this tab's previous session?`)) {
                stagedTableChanges = restoredChanges;
                for (const change of stagedTableChanges) {
                    renderStoredStagedChange(change);
                }
                // A restored staged EDIT of an existing row only updates that
                // row's display and adds the 'staged' class — it never touches
                // .filtered-out. If that row was hidden by a filter restored
                // earlier in this same DOMContentLoaded pass (before this
                // restore ran), it would otherwise stay invisible even though
                // it's now staged and must always be shown. Re-running the
                // filters clears .filtered-out on every staged row via the
                // alwaysShowStaged branch above.
                applyRulesFilter();
                applyHostsFilter();
                applyBlacklistFilter();
                applyQueryBlocklistFilter();
                updateTableBanner();
            } else {
                stagedStorage.removeItem(stagedStorageKey);
            }
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
                // Prefer stable col-id; fall back to legacy numeric data-col for
                // any header that has not yet been annotated.
                const colId = th.dataset.colId || null;
                const legacyIndex = th.dataset.col != null ? parseInt(th.dataset.col, 10) : NaN;

                // Persist by col-id so sort survives column reorder. Legacy
                // numeric values are still accepted on restore (see below).
                if (colId) {
                    uiStorage.setItem(storageKeyPrefix + '_sortCol', colId);
                } else if (Number.isFinite(legacyIndex)) {
                    uiStorage.setItem(storageKeyPrefix + '_sortCol', String(legacyIndex));
                }
                uiStorage.setItem(storageKeyPrefix + '_sortDir', newDir);

                // Reset all headers
                headers.forEach(h => {
                    h.setAttribute('aria-sort', 'none');
                    h.dataset.sortDir = 'none';
                    const icon = h.querySelector('.sort-icon');
                    if (icon) icon.textContent = '';
                });

                // Update clicked header
                th.dataset.sortDir = newDir;
                th.setAttribute(
                    'aria-sort',
                    newDir === 'asc' ? 'ascending' :
                    newDir === 'desc' ? 'descending' :
                    'none'
                );
                const icon = th.querySelector('.sort-icon');
                if (icon) {
                    if (newDir === 'asc') icon.textContent = '▲';
                    if (newDir === 'desc') icon.textContent = '▼';
                }

                let rowsArray = Array.from(tbody.rows);
                // Filter out custom inline edit rows and empty placeholder colspan messages
                rowsArray = rowsArray.filter(row =>
                    !row.querySelector('td[colspan]') &&
                    !row.classList.contains('edit-row') &&
                    !row.classList.contains('edit-host-row') &&
                    (colId ? !!cellByColId(row, colId) : row.cells.length > legacyIndex)
                );

                if (newDir === 'none') {
                    // Revert to original order
                    rowsArray.sort((a, b) => parseInt(a.dataset.origIndex) - parseInt(b.dataset.origIndex));
                } else {
                    // Sort ascending or descending using the cell for this col-id
                    rowsArray.sort((a, b) => {
                        const cellA = colId ? cellByColId(a, colId) : a.cells[legacyIndex];
                        const cellB = colId ? cellByColId(b, colId) : b.cells[legacyIndex];
                        const valA = (cellA ? cellA.textContent : '').trim().toLowerCase();
                        const valB = (cellB ? cellB.textContent : '').trim().toLowerCase();

                        if (valA < valB) return newDir === 'asc' ? -1 : 1;
                        if (valA > valB) return newDir === 'asc' ? 1 : -1;
                        return 0;
                    });
                }

                // Append rows back to tbody in sorted order
                rowsArray.forEach(row => tbody.appendChild(row));
                // Re-apply filter immediately if applicable
                if (typeof postSortCallback === 'function') {
                    postSortCallback();
                }
            }

            headers.forEach(th => {
                const button = th.querySelector('.sort-button');
                if (!button) return;
                th.dataset.sortDir = 'none'; // none, asc, desc
                th.setAttribute('aria-sort', 'none');// none, asc, desc
                button.addEventListener('click', () => {
                    // 1. Cancel any active inline edits so they don't break during sort
                    document.querySelectorAll('.btn-cancel').forEach(btn => btn.click());
                    const currentDir = th.dataset.sortDir;
                    const newDir = currentDir === 'none' ? 'asc' : currentDir === 'asc' ? 'desc' : 'none';
                    applySort(th, newDir);
                });
            });

            // Restore sort state on load WITHOUT a synthetic click / forced layout.
            // Accept both new col-id strings and legacy numeric data-col values.
            const savedCol = uiStorage.getItem(storageKeyPrefix + '_sortCol');
            const savedDir = uiStorage.getItem(storageKeyPrefix + '_sortDir');

            if (savedCol !== null && savedDir !== null && savedDir !== 'none') {
                let targetHeader = table.querySelector('th.sortable[data-col-id="' + savedCol + '"]');
                if (!targetHeader && /^\d+$/.test(savedCol)) {
                    targetHeader = table.querySelector('th.sortable[data-col="' + savedCol + '"]');
                }
                if (targetHeader) {
                    applySort(targetHeader, savedDir);
                }
            }
        }
        // Column reorder must run before sort/resize so saved visual order is
        // applied (and resize handles wired against the final DOM indices).
        setupColumnReorder('rulesTable', 'rulesTable');
        setupColumnReorder('hostsTable', 'hostsTable');
        setupColumnReorder('blacklistTable', 'blacklistTable');
        setupColumnReorder('queryBlocklistTable', 'queryBlocklistTable');
        setupColumnReorder('configTable', 'configTable');

        // Initialize table sorting states across views
        setupTableSorting('rulesTable', 'rulesTable', applyRulesFilter);
        setupTableSorting('hostsTable', 'hostsTable', applyHostsFilter);
        setupTableSorting('blacklistTable', 'blacklistTable', applyBlacklistFilter);
        setupTableSorting('queryBlocklistTable', 'queryBlocklistTable', applyQueryBlocklistFilter);
        setupTableSorting('configTable', 'configTable', applyConfigFilter);

        // Initialize column resizing (drag + double-click auto-fit) across the
        // same set of tables. Run after reorder + sorting/filtering so any
        // filter-driven layout has already settled before we measure widths.
        setupColumnResizing('rulesTable', 'rulesTable');
        setupColumnResizing('hostsTable', 'hostsTable');
        setupColumnResizing('blacklistTable', 'blacklistTable');
        setupColumnResizing('queryBlocklistTable', 'queryBlocklistTable');
        setupColumnResizing('configTable', 'configTable');

        // --- Apply Log Highlighting on Load ---
        // Highlight the filter as a SINGLE term (not split on whitespace),
        // mirroring renderLogPage's exact substring match in Go
        // (strings.Contains(strings.ToLower(line), searchLower) in
        // platform_windows.go) rather than the table pages' word/AND/OR/NOT
        // filter language. highlightTextNodes() now matches case-insensitively
        // (see its own doc comment), so a filter typed as "login" correctly
        // highlights "Login" in the displayed log text too.
        const logsSearchInput = document.getElementById('logsSearchQuery');
        const logOutputPre = document.querySelector('.log-output-pre');

        // ── Logs page: remember the filter text across navigating to another
        // WebUI page and back, mirroring the table pages' persisted filters.
        // /logs, /logs_queries, and /logs_queries_simple each get their own
        // remembered value (see logsFilterStorageKey, keyed by pathname).
        if (logsSearchInput) {
            const logsRotatedCheckbox = document.getElementById('logsIncludeRotated');
            const logsMaxRotInput = document.getElementById('logsMaxRotations');

            if (new URLSearchParams(location.search).has('q')) {
                // A query string was explicitly supplied for this load (even an
                // empty one, e.g. right after the Clear button) — honor it as the
                // current filter and remember it (plus the rotated-logs settings)
                // for the next visit to this page.
                uiStorage.setItem(logsFilterStorageKey, logsSearchInput.value);
                if (logsRotatedCheckbox) uiStorage.setItem(logsRotatedStorageKey, logsRotatedCheckbox.checked ? '1' : '0');
                if (logsMaxRotInput) uiStorage.setItem(logsMaxRotStorageKey, logsMaxRotInput.value);
            } else {
                // No filter was requested for this specific page load; restore
                // whatever was last remembered for this log page, if anything.
                const savedLogsFilter = uiStorage.getItem(logsFilterStorageKey);
                const savedLogsRotated = uiStorage.getItem(logsRotatedStorageKey);
                const savedLogsMaxRot = uiStorage.getItem(logsMaxRotStorageKey);
                if (savedLogsFilter || savedLogsRotated || savedLogsMaxRot) {
                    const restoreParams = new URLSearchParams();
                    restoreParams.set('q', savedLogsFilter || '');
                    if (savedLogsRotated === '1') restoreParams.set('rotated', '1');
                    if (savedLogsMaxRot) restoreParams.set('maxrot', savedLogsMaxRot);
                    location.replace(location.pathname + '?' + restoreParams.toString());
                    return; // Navigating away; nothing else on this page matters now.
                }
            }

            // HTMLFormElement.submit() (used by the Clear button above) does not
            // fire the 'submit' event, so this only covers the normal Filter
            // button / Enter-key submission path — which is exactly right, since
            // Clear already removes the stored filter value itself (rotated/maxrot
            // settings are deliberately left untouched by Clear).
            const logsForm = logsSearchInput.closest('form');
            if (logsForm) {
                logsForm.addEventListener('submit', () => {
                    uiStorage.setItem(logsFilterStorageKey, logsSearchInput.value);
                    if (logsRotatedCheckbox) uiStorage.setItem(logsRotatedStorageKey, logsRotatedCheckbox.checked ? '1' : '0');
                    if (logsMaxRotInput) uiStorage.setItem(logsMaxRotStorageKey, logsMaxRotInput.value);
                });
            }
        }

        if (logsSearchInput && logOutputPre) {
            const query = logsSearchInput.value.trim();
            if (query) {
                highlightTextNodes(logOutputPre, [query]);
            }
        }
    }); // end of domcontentloaded
})();