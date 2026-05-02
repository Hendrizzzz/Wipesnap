import {
    PHONE_ACCOUNT_STATES,
    PHONE_DRAFT_LIMITS,
    SAFE_PRESET_PATCH_LIMITS,
    SANITIZED_PRESET_SNAPSHOT_LIMITS,
    addExistingSnapshotItemToPreset,
    addSnapshotBrowserTabToPreset,
    clearSnapshotEditorFromState,
    createAccountIntention,
    createBrowserProfileSlot,
    createBrowserTab,
    createDesiredAppPlaceholder,
    createDraftInState,
    createPhonePlannerState,
    deleteDraftFromState,
    duplicateDraftInState,
    exportSafePresetPatchJson,
    importSnapshotIntoPlannerState,
    moveSnapshotPresetInState,
    moveSnapshotPresetItemInState,
    removeSnapshotItemFromPreset,
    selectSnapshotPresetInState,
    updateSnapshotEditorSelection,
    updateSnapshotNewBrowserItem,
    updateSnapshotPresetFields,
    updateSnapshotPresetItem,
    exportCloudDraftJson,
    validateDraftForExport,
    validateSafePresetPatchForExport
} from './phonePlannerCore.js'
import {
    loadPhonePlannerState,
    savePhonePlannerState
} from './phonePlannerStorage.js'
import { createPhonePlannerFirebaseRestApp } from './phonePlannerFirebaseRest.js'
import {
    PHONE_PLANNER_CLOUD_PROVIDER_IDS,
    loadPhonePlannerCloudProviderConfig
} from './phonePlannerCloudProvider.js'
import { createPhonePlannerCloudflareRestApp } from './phonePlannerCloudflareRest.js'
import {
    createIndexedDbAdapter,
    createPhonePlannerCloudStorage
} from './phonePlannerCloudStorage.js'
import {
    claimHostedPlannerDeviceSession,
    downloadLatestHostedPlannerSnapshot,
    requestHostedPlannerEnrollment,
    uploadHostedPlannerSafePatch
} from './phonePlannerCloudWorkflow.js'
import {
    claimCloudflareHostedPlannerDeviceSession,
    requestCloudflareHostedPlannerEnrollment
} from './phonePlannerCloudflareWorkflow.js'

let state = loadPhonePlannerState()
let statusMessage = state.loadError || 'Saved locally on this browser.'
let errorMessage = ''
let lastExportJson = ''
let snapshotImportText = ''
let newSnapshotTabDraft = {
    url: 'https://aistudio.google.com/',
    label: 'AI Studio',
    notes: '',
    enabled: true,
    accountIntentionId: '',
    profileIntentionId: ''
}
let cloudState = {
    status: 'loading',
    message: 'Loading staging cloud config.',
    error: '',
    busy: '',
    provider: 'disabled',
    config: null,
    authClient: null,
    cloudflareClient: null,
    functionsClient: null,
    firestoreClient: null,
    storage: null,
    auth: { signedIn: false, uid: '', email: '', metadataOnly: true },
    email: '',
    password: '',
    deviceId: '',
    requestId: '',
    pairingChallengeDisplay: '',
    keyGrantId: '',
    lastSnapshotRevisionId: '',
    lastPatchRevisionId: '',
    syncKeyActive: false
}

const root = document.getElementById('app')

if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./service-worker.js').catch(() => {})
}

function selectedDraft() {
    return state.drafts.find(draft => draft.draftId === state.selectedDraftId) || null
}

function snapshotEditor() {
    return state.snapshotEditor || null
}

function selectedSnapshotPreset() {
    const editor = snapshotEditor()
    if (!editor) return null
    return editor.presets.find(preset => preset.id === editor.selectedPresetId) ||
        [...editor.presets].sort((a, b) => Number(a.order || 0) - Number(b.order || 0))[0] ||
        null
}

function createElement(tag, attrs = {}, children = []) {
    const element = document.createElement(tag)
    for (const [key, value] of Object.entries(attrs)) {
        if (key === 'className') {
            element.className = value
        } else if (key === 'text') {
            element.textContent = value
        } else if (key === 'value') {
            element.value = value
        } else if (key === 'checked') {
            element.checked = !!value
        } else if (key === 'disabled') {
            element.disabled = !!value
        } else if (key === 'dataset') {
            for (const [dataKey, dataValue] of Object.entries(value || {})) {
                element.dataset[dataKey] = dataValue
            }
        } else if (key.startsWith('on') && typeof value === 'function') {
            element.addEventListener(key.slice(2).toLowerCase(), value)
        } else if (value !== false && value != null) {
            element.setAttribute(key, String(value))
        }
    }

    const childList = Array.isArray(children) ? children : [children]
    for (const child of childList) {
        if (child == null) continue
        if (typeof child === 'string') {
            element.appendChild(document.createTextNode(child))
        } else {
            element.appendChild(child)
        }
    }
    return element
}

function fieldLabel(text, child, hint = '') {
    return createElement('label', { className: 'field' }, [
        createElement('span', { className: 'field-label', text }),
        child,
        hint ? createElement('small', { text: hint }) : null
    ])
}

function textInput({ label, value, maxLength, placeholder = '', onInput, hint = '', type = 'text', inputMode = '' }) {
    return fieldLabel(label, createElement('input', {
        type,
        value: value || '',
        maxLength,
        placeholder,
        inputMode,
        onInput: event => onInput(event.target.value)
    }), hint)
}

function textArea({ label, value, maxLength, placeholder = '', rows = 3, onInput, hint = '' }) {
    return fieldLabel(label, createElement('textarea', {
        value: value || '',
        maxLength,
        placeholder,
        rows,
        onInput: event => onInput(event.target.value)
    }), hint)
}

function selectInput({ label, value, options, onChange, hint = '' }) {
    const select = createElement('select', {
        value: value || '',
        onChange: event => onChange(event.target.value)
    }, options.map(option => createElement('option', {
        value: option.value,
        text: option.label
    })))
    select.value = value || ''
    return fieldLabel(label, select, hint)
}

function checkboxInput({ label, checked, onChange }) {
    return createElement('label', { className: 'check-row' }, [
        createElement('input', {
            type: 'checkbox',
            checked,
            onChange: event => onChange(event.target.checked)
        }),
        createElement('span', { text: label })
    ])
}

function button(text, className, onClick, disabled = false) {
    return createElement('button', { className, onClick, disabled, text })
}

function commitSnapshotOperation(operation, message) {
    try {
        commitState(operation(state), message)
    } catch (err) {
        errorMessage = err?.message || 'Snapshot edit failed.'
        renderStatus()
    }
}

function sortedByOrder(items) {
    return [...items].map((item, index) => ({ item, index }))
        .sort((a, b) => Number(a.item.order || 0) - Number(b.item.order || 0) || a.index - b.index)
        .map(({ item }) => item)
}

function snapshotItemLookup(editor, itemId) {
    const snapshotItem = editor.snapshot.availableItems.find(item => item.id === itemId)
    if (snapshotItem) return snapshotItem
    const newItem = editor.newBrowserItems.find(item => item.id === itemId)
    if (!newItem) return null
    return {
        id: newItem.id,
        type: 'browser-tab',
        label: newItem.label || newItem.url,
        status: newItem.enabled === false ? 'disabled' : 'available',
        source: 'phone-patch',
        url: newItem.url,
        metadataOnly: true
    }
}

function snapshotAccounts(editor) {
    return editor.snapshot.availableItems.filter(item => item.type === 'account-intention')
}

function snapshotProfiles(editor) {
    return editor.snapshot.availableItems.filter(item => item.type === 'profile-intention')
}

function optionsForSnapshotAccounts(editor) {
    return [
        { value: '', label: 'No account intention' },
        ...snapshotAccounts(editor).map(item => ({ value: item.id, label: item.label || item.id }))
    ]
}

function optionsForSnapshotProfiles(editor) {
    return [
        { value: '', label: 'No profile intention' },
        ...snapshotProfiles(editor).map(item => ({ value: item.id, label: item.label || item.id }))
    ]
}

function optionsForSnapshotPresets(editor) {
    return [
        { value: '', label: 'No preset selected' },
        ...sortedByOrder(editor.presets).map(preset => ({ value: preset.id, label: preset.name || preset.id }))
    ]
}

function itemTypeLabel(type) {
    return {
        'browser-tab': 'Browser tab',
        'desktop-app': 'Desktop app',
        'host-folder': 'Folder',
        'account-intention': 'Account',
        'profile-intention': 'Profile'
    }[type] || type
}

function itemStatusClass(status) {
    if (status === 'available') return 'tag ok'
    if (status === 'disabled') return 'tag muted'
    if (status === 'redacted' || status === 'broken') return 'tag warn'
    return 'tag'
}

function safeIdNode(id) {
    return createElement('code', { text: id || '' })
}

function saveCurrent(message = 'Saved locally on this browser.', options = {}) {
    try {
        state = savePhonePlannerState(state, options)
        statusMessage = message
        errorMessage = ''
    } catch (err) {
        errorMessage = err?.message || 'Could not save local draft.'
    }
    renderStatus()
}

function commitState(nextState, message, options = {}) {
    state = nextState
    saveCurrent(message, options)
    render()
}

function mutateSelectedDraft(mutator, { rerender = false, message = 'Saved locally on this browser.' } = {}) {
    const draft = selectedDraft()
    if (!draft) return
    try {
        mutator(draft)
    } catch (err) {
        errorMessage = err?.message || 'Draft edit failed.'
        renderStatus()
        return
    }
    draft.updatedAt = Date.now()
    saveCurrent(message)
    if (rerender) render()
}

function optionsForProfiles(draft) {
    return [
        { value: '', label: 'No profile intention' },
        ...draft.browserProfileSlots.map(profile => ({
            value: profile.id,
            label: profile.label || profile.id
        }))
    ]
}

function optionsForAccounts(draft) {
    return [
        { value: '', label: 'No account intention' },
        ...draft.accountSlots.map(account => ({
            value: account.id,
            label: account.label || account.id
        }))
    ]
}

function loadSnapshotJsonText(text) {
    try {
        const nextState = importSnapshotIntoPlannerState(state, text)
        snapshotImportText = ''
        commitState(nextState, 'Loaded sanitized snapshot.')
    } catch (err) {
        errorMessage = err?.message || 'Snapshot JSON could not be loaded.'
        renderStatus()
    }
}

function readSnapshotFile(file) {
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
        snapshotImportText = String(reader.result || '')
        loadSnapshotJsonText(snapshotImportText)
    }
    reader.onerror = () => {
        errorMessage = 'Snapshot file could not be read.'
        renderStatus()
    }
    reader.readAsText(file)
}

function safeCloudError(error) {
    const text = String(error?.message || 'Hosted cloud action failed.').replace(/[\u0000-\u001F\u007F]/g, ' ').trim()
    if (!text || /token|secret|private|syncRootKey|rootKeyMaterial|ciphertext|vault\.json|BrowserProfile|AppData[\\/]|[A-Za-z]:[\\/]|\\\\|cap_[A-Za-z0-9_-]{4,128}/i.test(text)) {
        return 'Hosted cloud action failed.'
    }
    return text.length > 140 ? `${text.slice(0, 137).trim()}...` : text
}

function refreshCloudAuthState() {
    cloudState.auth = cloudState.authClient?.getSafeAuthState
        ? cloudState.authClient.getSafeAuthState()
        : { signedIn: false, uid: '', email: '', metadataOnly: true }
}

function isCloudflareCloudProvider() {
    return cloudState.provider === PHONE_PLANNER_CLOUD_PROVIDER_IDS.cloudflare
}

function requireCloudRuntime() {
    if (!cloudState.authClient || !cloudState.functionsClient || !cloudState.firestoreClient || !cloudState.storage) {
        throw new Error('Hosted staging cloud is not configured.')
    }
    return {
        authClient: cloudState.authClient,
        cloudflareClient: cloudState.cloudflareClient,
        functionsClient: cloudState.functionsClient,
        firestoreClient: cloudState.firestoreClient,
        storage: cloudState.storage
    }
}

async function runHostedCloudAction(actionName, action) {
    if (cloudState.busy) return
    cloudState.busy = actionName
    cloudState.error = ''
    render()
    try {
        const result = await action(requireCloudRuntime())
        refreshCloudAuthState()
        cloudState.message = cloudMessageForResult(actionName, result)
        cloudState.status = 'ready'
        return result
    } catch (err) {
        cloudState.error = safeCloudError(err)
        return null
    } finally {
        cloudState.busy = ''
        render()
    }
}

function cloudMessageForResult(actionName, result) {
    if (actionName === 'sign-in') return 'Signed in to staging cloud.'
    if (actionName === 'create-user') return 'Created staging auth user.'
    if (actionName === 'anonymous-auth') return 'Signed in anonymously to staging cloud.'
    if (actionName === 'request-enrollment') return 'Phone enrollment request uploaded.'
    if (actionName === 'claim-session') return 'Device session claimed and sync key activated.'
    if (actionName === 'download-snapshot') return `Downloaded sanitized snapshot ${result?.revisionId || ''}`.trim()
    if (actionName === 'upload-patch') return `Uploaded encrypted safe patch ${result?.patchRevisionId || ''}`.trim()
    return 'Hosted cloud action complete.'
}

async function signInHostedCloud(createUser = false) {
    await runHostedCloudAction(createUser ? 'create-user' : 'sign-in', async ({ authClient }) => {
        if (isCloudflareCloudProvider()) {
            const ownerUid = cloudState.email.trim()
            if (!ownerUid) throw new Error('Owner uid is required.')
            const result = await authClient.activateOwnerUid(ownerUid)
            cloudState.password = ''
            return result
        }
        const email = cloudState.email.trim()
        const password = cloudState.password
        if (!email || !password) throw new Error('Email and password are required.')
        const result = createUser
            ? await authClient.createUserWithEmailAndPassword(email, password)
            : await authClient.signInWithEmailAndPassword(email, password)
        cloudState.password = ''
        return result
    })
}

async function signInHostedCloudAnonymously() {
    await runHostedCloudAction('anonymous-auth', async ({ authClient }) => authClient.signInAnonymously())
}

async function requestHostedCloudEnrollment() {
    await runHostedCloudAction('request-enrollment', async ({ authClient, cloudflareClient, functionsClient, storage }) => {
        const result = isCloudflareCloudProvider()
            ? await requestCloudflareHostedPlannerEnrollment({
                authClient,
                cloudflareClient,
                storage
            })
            : await requestHostedPlannerEnrollment({
                authClient,
                functionsClient,
                storage
            })
        cloudState.deviceId = result.deviceId
        cloudState.requestId = result.requestId
        cloudState.keyGrantId = result.keyGrantId
        cloudState.pairingChallengeDisplay = result.pairingChallengeDisplay
        return result
    })
}

async function claimHostedCloudSession() {
    await runHostedCloudAction('claim-session', async ({ authClient, cloudflareClient, functionsClient, firestoreClient, storage }) => {
        const deviceId = (cloudState.deviceId || cloudState.requestId).trim()
        if (!deviceId) throw new Error('A phone enrollment request id is required.')
        const result = isCloudflareCloudProvider()
            ? await claimCloudflareHostedPlannerDeviceSession({
                authClient,
                cloudflareClient,
                storage,
                deviceId
            })
            : await claimHostedPlannerDeviceSession({
                authClient,
                functionsClient,
                firestoreClient,
                storage,
                deviceId
            })
        cloudState.deviceId = result.deviceId
        cloudState.keyGrantId = result.keyGrantId
        cloudState.syncKeyActive = result.syncKeyActive === true
        return result
    })
}

async function downloadHostedCloudSnapshot() {
    await runHostedCloudAction('download-snapshot', async ({ firestoreClient, storage }) => {
        const result = await downloadLatestHostedPlannerSnapshot({
            firestoreClient,
            storage
        })
        const nextState = importSnapshotIntoPlannerState(state, result.snapshot, {
            authorDeviceId: cloudState.deviceId || result.sourceDeviceId
        })
        state = savePhonePlannerState(nextState)
        cloudState.lastSnapshotRevisionId = result.revisionId
        return result
    })
}

async function uploadHostedCloudPatch() {
    await runHostedCloudAction('upload-patch', async ({ functionsClient, storage }) => {
        const editor = snapshotEditor()
        if (!editor) throw new Error('Load a sanitized snapshot before uploading a safe patch.')
        const result = await uploadHostedPlannerSafePatch({
            functionsClient,
            storage,
            editor
        })
        cloudState.lastPatchRevisionId = result.patchRevisionId
        return result
    })
}

async function initializeHostedCloud() {
    try {
        const selectedProvider = await loadPhonePlannerCloudProviderConfig()
        const storage = createPhonePlannerCloudStorage({
            indexedDbAdapter: createIndexedDbAdapter()
        })
        const restApp = selectedProvider.provider === PHONE_PLANNER_CLOUD_PROVIDER_IDS.cloudflare
            ? createPhonePlannerCloudflareRestApp({ config: selectedProvider.config, storage })
            : createPhonePlannerFirebaseRestApp({ config: selectedProvider.config })
        cloudState = {
            ...cloudState,
            status: 'ready',
            message: 'Staging cloud ready.',
            provider: selectedProvider.provider,
            config: selectedProvider.config,
            authClient: restApp.authClient,
            cloudflareClient: restApp.cloudflareClient || null,
            functionsClient: restApp.functionsClient,
            firestoreClient: restApp.firestoreClient,
            storage
        }
        refreshCloudAuthState()
    } catch (err) {
        cloudState = {
            ...cloudState,
            status: 'unavailable',
            error: safeCloudError(err),
            message: 'Hosted staging cloud is unavailable.'
        }
    }
    render()
}

function exportSnapshotPatch({ download = true } = {}) {
    const editor = snapshotEditor()
    if (!editor) return
    try {
        const json = exportSafePresetPatchJson(editor)
        state.snapshotEditor.lastExportJson = json
        state = savePhonePlannerState(state)
        statusMessage = 'Exported validated safe preset patch JSON.'
        errorMessage = ''
        if (download) downloadPatchJson(editor, json)
    } catch (err) {
        errorMessage = err?.message || 'Safe preset patch cannot be exported.'
    }
    render()
}

function renderStatus() {
    const node = document.getElementById('status-line')
    if (!node) return
    node.className = errorMessage ? 'status error' : 'status'
    node.textContent = errorMessage || statusMessage
}

function renderHeader() {
    return createElement('header', { className: 'app-header' }, [
        createElement('div', {}, [
            createElement('p', { className: 'eyebrow', text: 'Wipesnap Phone Planner' }),
            createElement('h1', { text: 'Phone Preset Editor' }),
            createElement('p', {
                className: 'subhead',
                text: 'Snapshot edits stay in this browser until you export a safe patch. Account and profile choices are intentions only, not credentials or copied sessions.'
            })
        ]),
        createElement('div', { className: 'offline-pill', text: 'Offline local' })
    ])
}

function renderHostedCloudPanel(editor) {
    const ready = cloudState.status === 'ready'
    const signedIn = cloudState.auth?.signedIn === true
    const busy = !!cloudState.busy
    const cloudflareProvider = isCloudflareCloudProvider()
    const canClaim = ready && signedIn && !!(cloudState.deviceId || cloudState.requestId)
    const cloudStatus = cloudState.error || cloudState.message
    return createElement('section', { className: `panel wide hosted-cloud ${cloudState.error ? 'blocked' : ''}` }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Hosted Staging Cloud' }),
            createElement('span', { text: ready ? (signedIn ? (cloudflareProvider ? 'owner set' : 'signed in') : 'auth required') : cloudState.status })
        ]),
        createElement('p', {
            className: `helper ${cloudState.error ? 'cloud-error' : ''}`,
            text: cloudStatus
        }),
        createElement('div', { className: 'grid two' }, [
            textInput({
                label: cloudflareProvider ? 'Owner UID' : 'Email',
                value: cloudState.email,
                maxLength: 160,
                type: cloudflareProvider ? 'text' : 'email',
                onInput: value => { cloudState.email = value }
            }),
            cloudflareProvider ? null : textInput({
                label: 'Password',
                value: cloudState.password,
                maxLength: 256,
                type: 'password',
                onInput: value => { cloudState.password = value }
            })
        ]),
        createElement('div', { className: 'toolbar-actions' }, [
            button(
                busy && cloudState.busy === 'sign-in' ? (cloudflareProvider ? 'Setting Owner' : 'Signing In') : (cloudflareProvider ? 'Set Owner' : 'Sign In'),
                'btn primary',
                () => signInHostedCloud(false),
                !ready || busy
            ),
            cloudflareProvider ? null : button(busy && cloudState.busy === 'create-user' ? 'Creating' : 'Create User', 'btn', () => signInHostedCloud(true), !ready || busy),
            !cloudflareProvider && cloudState.config?.allowAnonymousAuth
                ? button(busy && cloudState.busy === 'anonymous-auth' ? 'Signing In' : 'Anonymous', 'btn', () => signInHostedCloudAnonymously(), !ready || busy)
                : null
        ]),
        createElement('div', { className: 'grid two cloud-session-grid' }, [
            textInput({
                label: 'Request ID',
                value: cloudState.requestId || cloudState.deviceId,
                maxLength: 96,
                placeholder: 'dev_...',
                onInput: value => {
                    cloudState.requestId = value
                    cloudState.deviceId = value
                }
            }),
            textInput({
                label: 'Pairing Challenge',
                value: cloudState.pairingChallengeDisplay,
                maxLength: 128,
                onInput: value => { cloudState.pairingChallengeDisplay = value },
                hint: cloudState.keyGrantId ? `grant ${cloudState.keyGrantId}` : ''
            })
        ]),
        createElement('div', { className: 'toolbar-actions' }, [
            button(busy && cloudState.busy === 'request-enrollment' ? 'Requesting' : 'Request Enrollment', 'btn primary', () => requestHostedCloudEnrollment(), !ready || !signedIn || busy),
            button(busy && cloudState.busy === 'claim-session' ? 'Claiming' : 'Claim Session', 'btn', () => claimHostedCloudSession(), !canClaim || busy),
            button(busy && cloudState.busy === 'download-snapshot' ? 'Downloading' : 'Download Snapshot', 'btn', () => downloadHostedCloudSnapshot(), !ready || !signedIn || busy || !cloudState.syncKeyActive),
            button(busy && cloudState.busy === 'upload-patch' ? 'Uploading' : 'Upload Patch', 'btn', () => uploadHostedCloudPatch(), !ready || !signedIn || busy || !cloudState.syncKeyActive || !editor)
        ]),
        createElement('div', { className: 'cloud-meta-line' }, [
            createElement('span', { text: cloudState.auth?.email || cloudState.auth?.uid || 'not signed in' }),
            createElement('span', { text: cloudflareProvider ? 'cloudflare disabled staging' : 'firebase staging' }),
            cloudState.lastSnapshotRevisionId ? createElement('span', { text: `snapshot ${cloudState.lastSnapshotRevisionId}` }) : null,
            cloudState.lastPatchRevisionId ? createElement('span', { text: `patch ${cloudState.lastPatchRevisionId}` }) : null
        ])
    ])
}

function renderSnapshotImportPanel(editor) {
    return createElement('section', { className: 'panel wide snapshot-import' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Sanitized Snapshot' }),
            createElement('span', {
                text: editor ? `revision ${editor.snapshot.revisionId}` : `${SANITIZED_PRESET_SNAPSHOT_LIMITS.maxSnapshotJsonBytes / 1024} KB max`
            })
        ]),
        createElement('div', { className: 'grid two' }, [
            textArea({
                label: 'Paste snapshot JSON',
                value: snapshotImportText,
                maxLength: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxSnapshotJsonBytes,
                rows: 6,
                placeholder: 'Paste a Phase 18 sanitized snapshot JSON export.',
                onInput: value => { snapshotImportText = value }
            }),
            fieldLabel('Load snapshot file', createElement('input', {
                type: 'file',
                accept: 'application/json,.json',
                onChange: event => readSnapshotFile(event.target.files?.[0] || null)
            }), editor ? `Loaded ${editor.snapshot.presets.length} presets and ${editor.snapshot.availableItems.length} safe items.` : '')
        ]),
        createElement('div', { className: 'toolbar-actions' }, [
            button('Load Snapshot JSON', 'btn primary', () => loadSnapshotJsonText(snapshotImportText), !snapshotImportText.trim()),
            button('Clear Snapshot', 'btn danger', () => {
                if (!editor) return
                if (!window.confirm('Clear the loaded sanitized snapshot from this browser?')) return
                commitSnapshotOperation(next => clearSnapshotEditorFromState(next), 'Cleared sanitized snapshot.')
            }, !editor)
        ])
    ])
}

function renderSnapshotPresetPicker(editor, preset) {
    const ordered = sortedByOrder(editor.presets)
    const select = createElement('select', {
        value: editor.selectedPresetId,
        onChange: event => {
            commitSnapshotOperation(
                next => selectSnapshotPresetInState(next, event.target.value),
                'Selected snapshot preset.'
            )
        }
    }, ordered.map(item => createElement('option', {
        value: item.id,
        text: item.name || item.id
    })))
    select.value = editor.selectedPresetId

    return createElement('section', { className: 'toolbar-panel snapshot-toolbar' }, [
        createElement('div', { className: 'draft-select' }, [
            createElement('span', { className: 'field-label', text: 'Preset' }),
            select,
            createElement('div', { className: 'safe-id-line' }, [safeIdNode(preset?.id || '')])
        ]),
        createElement('div', { className: 'toolbar-actions' }, [
            button('Up', 'btn', () => {
                if (!preset) return
                commitSnapshotOperation(next => moveSnapshotPresetInState(next, preset.id, -1), 'Updated preset order.')
            }, !preset || ordered[0]?.id === preset.id),
            button('Down', 'btn', () => {
                if (!preset) return
                commitSnapshotOperation(next => moveSnapshotPresetInState(next, preset.id, 1), 'Updated preset order.')
            }, !preset || ordered[ordered.length - 1]?.id === preset.id)
        ])
    ])
}

function renderSnapshotPresetDetails(editor, preset) {
    if (!preset) {
        return createElement('section', { className: 'panel' }, [
            createElement('h2', { text: 'No Preset Loaded' })
        ])
    }
    return createElement('section', { className: 'panel' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Preset Metadata' }),
            createElement('span', { text: preset.enabled === false ? 'disabled' : 'enabled' })
        ]),
        createElement('div', { className: 'grid two' }, [
            textInput({
                label: 'Preset name',
                value: preset.name,
                maxLength: SAFE_PRESET_PATCH_LIMITS.maxPresetNameLength,
                onInput: value => commitSnapshotOperation(
                    next => updateSnapshotPresetFields(next, preset.id, { name: value }),
                    'Updated preset name.'
                )
            }),
            checkboxInput({
                label: 'Enabled preset',
                checked: preset.enabled !== false,
                onChange: value => commitSnapshotOperation(
                    next => updateSnapshotPresetFields(next, preset.id, { enabled: value }),
                    'Updated preset enabled state.'
                )
            })
        ]),
        createElement('div', { className: 'grid two' }, [
            selectInput({
                label: 'Default preset',
                value: editor.selection.defaultPresetId || '',
                options: optionsForSnapshotPresets(editor),
                onChange: value => commitSnapshotOperation(
                    next => updateSnapshotEditorSelection(next, { defaultPresetId: value || null }),
                    'Updated default preset metadata.'
                )
            }),
            selectInput({
                label: 'Next preset',
                value: editor.selection.nextPresetId || '',
                options: optionsForSnapshotPresets(editor),
                onChange: value => commitSnapshotOperation(
                    next => updateSnapshotEditorSelection(next, { nextPresetId: value || null }),
                    'Updated next preset metadata.'
                )
            })
        ])
    ])
}

function renderSnapshotPresetItems(editor, preset) {
    const orderedRefs = preset ? sortedByOrder(preset.itemRefs) : []
    return createElement('section', { className: 'panel wide' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Preset Items' }),
            createElement('span', { text: `${orderedRefs.length}/${SAFE_PRESET_PATCH_LIMITS.maxPresetItemRefs}` })
        ]),
        createElement('div', { className: 'item-list' }, orderedRefs.map((ref, index) => renderSnapshotPresetItem(editor, preset, ref, index, orderedRefs)))
    ])
}

function renderSnapshotPresetItem(editor, preset, ref, index, orderedRefs) {
    const item = snapshotItemLookup(editor, ref.itemId)
    const isBrowser = item?.type === 'browser-tab'
    const newBrowserItem = editor.newBrowserItems.find(candidate => candidate.id === ref.itemId) || null
    return createElement('article', { className: 'item snapshot-item' }, [
        createElement('div', { className: 'item-topline' }, [
            createElement('div', {}, [
                createElement('strong', { text: item?.label || ref.itemId }),
                createElement('div', { className: 'item-meta' }, [
                    createElement('span', { className: 'tag', text: itemTypeLabel(item?.type || 'unknown') }),
                    createElement('span', { className: itemStatusClass(item?.status || 'available'), text: item?.status || 'available' }),
                    safeIdNode(ref.itemId)
                ])
            ]),
            createElement('div', { className: 'inline-actions' }, [
                button('Up', 'btn tiny', () => commitSnapshotOperation(
                    next => moveSnapshotPresetItemInState(next, preset.id, ref.itemId, -1),
                    'Updated item order.'
                ), index === 0),
                button('Down', 'btn tiny', () => commitSnapshotOperation(
                    next => moveSnapshotPresetItemInState(next, preset.id, ref.itemId, 1),
                    'Updated item order.'
                ), index === orderedRefs.length - 1)
            ])
        ]),
        newBrowserItem ? renderNewBrowserItemFields(newBrowserItem) : null,
        isBrowser ? createElement('div', { className: 'grid two' }, [
            selectInput({
                label: 'Account intention',
                value: ref.accountIntentionId || newBrowserItem?.accountIntentionId || '',
                options: optionsForSnapshotAccounts(editor),
                onChange: value => commitSnapshotOperation(
                    next => updateSnapshotPresetItem(next, preset.id, ref.itemId, { accountIntentionId: value }),
                    'Updated browser account intention.'
                )
            }),
            selectInput({
                label: 'Profile intention',
                value: ref.profileIntentionId || newBrowserItem?.profileIntentionId || '',
                options: optionsForSnapshotProfiles(editor),
                onChange: value => commitSnapshotOperation(
                    next => updateSnapshotPresetItem(next, preset.id, ref.itemId, { profileIntentionId: value }),
                    'Updated browser profile intention.'
                )
            })
        ]) : null,
        createElement('div', { className: 'item-footer' }, [
            checkboxInput({
                label: 'Enabled item',
                checked: ref.enabled !== false,
                onChange: value => commitSnapshotOperation(
                    next => updateSnapshotPresetItem(next, preset.id, ref.itemId, { enabled: value }),
                    'Updated preset item enabled state.'
                )
            }),
            button('Remove item', 'btn danger small', () => commitSnapshotOperation(
                next => removeSnapshotItemFromPreset(next, preset.id, ref.itemId),
                'Removed preset item.'
            ))
        ])
    ])
}

function renderNewBrowserItemFields(item) {
    return createElement('div', { className: 'new-tab-fields' }, [
        createElement('div', { className: 'grid two' }, [
            textInput({
                label: 'URL',
                value: item.url,
                maxLength: SAFE_PRESET_PATCH_LIMITS.maxBrowserTabUrlLength,
                onInput: value => commitSnapshotOperation(
                    next => updateSnapshotNewBrowserItem(next, item.id, { url: value }),
                    'Updated new browser tab URL.'
                )
            }),
            textInput({
                label: 'Label',
                value: item.label,
                maxLength: SAFE_PRESET_PATCH_LIMITS.maxBrowserTabLabelLength,
                onInput: value => commitSnapshotOperation(
                    next => updateSnapshotNewBrowserItem(next, item.id, { label: value }),
                    'Updated new browser tab label.'
                )
            })
        ]),
        textArea({
            label: 'Notes',
            value: item.notes,
            maxLength: SAFE_PRESET_PATCH_LIMITS.maxBrowserTabNotesLength,
            rows: 2,
            onInput: value => commitSnapshotOperation(
                next => updateSnapshotNewBrowserItem(next, item.id, { notes: value }),
                'Updated new browser tab notes.'
            )
        })
    ])
}

function renderAvailableSnapshotItems(editor, preset) {
    const existingIds = new Set((preset?.itemRefs || []).map(ref => ref.itemId))
    const items = editor.snapshot.availableItems
    return createElement('section', { className: 'panel' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Available Safe Items' }),
            createElement('span', { text: `${items.length}/${SANITIZED_PRESET_SNAPSHOT_LIMITS.maxAvailableItems}` })
        ]),
        createElement('div', { className: 'item-list compact-list' }, items.map(item => createElement('article', { className: 'item available-item' }, [
            createElement('div', {}, [
                createElement('strong', { text: item.label }),
                createElement('div', { className: 'item-meta' }, [
                    createElement('span', { className: 'tag', text: itemTypeLabel(item.type) }),
                    createElement('span', { className: itemStatusClass(item.status), text: item.status }),
                    safeIdNode(item.id)
                ])
            ]),
            button('Add', 'btn tiny', () => {
                if (!preset) return
                commitSnapshotOperation(
                    next => addExistingSnapshotItemToPreset(next, preset.id, item.id),
                    'Added safe item id to preset.'
                )
            }, !preset || existingIds.has(item.id))
        ])))
    ])
}

function renderAddSnapshotBrowserTab(editor, preset) {
    return createElement('section', { className: 'panel' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'New Public Browser Tab' }),
            createElement('span', { text: `${editor.newBrowserItems.length}/${SAFE_PRESET_PATCH_LIMITS.maxNewBrowserItems}` })
        ]),
        textInput({
            label: 'URL',
            value: newSnapshotTabDraft.url,
            maxLength: SAFE_PRESET_PATCH_LIMITS.maxBrowserTabUrlLength,
            placeholder: 'https://aistudio.google.com/',
            onInput: value => { newSnapshotTabDraft.url = value }
        }),
        textInput({
            label: 'Label',
            value: newSnapshotTabDraft.label,
            maxLength: SAFE_PRESET_PATCH_LIMITS.maxBrowserTabLabelLength,
            onInput: value => { newSnapshotTabDraft.label = value }
        }),
        createElement('div', { className: 'grid two' }, [
            selectInput({
                label: 'Account intention',
                value: newSnapshotTabDraft.accountIntentionId,
                options: optionsForSnapshotAccounts(editor),
                onChange: value => { newSnapshotTabDraft.accountIntentionId = value }
            }),
            selectInput({
                label: 'Profile intention',
                value: newSnapshotTabDraft.profileIntentionId,
                options: optionsForSnapshotProfiles(editor),
                onChange: value => { newSnapshotTabDraft.profileIntentionId = value }
            })
        ]),
        textArea({
            label: 'Notes',
            value: newSnapshotTabDraft.notes,
            maxLength: SAFE_PRESET_PATCH_LIMITS.maxBrowserTabNotesLength,
            rows: 2,
            onInput: value => { newSnapshotTabDraft.notes = value }
        }),
        createElement('div', { className: 'item-footer' }, [
            checkboxInput({
                label: 'Enabled tab',
                checked: newSnapshotTabDraft.enabled !== false,
                onChange: value => { newSnapshotTabDraft.enabled = value }
            }),
            button('Add Browser Tab', 'btn primary small', () => {
                if (!preset) return
                commitSnapshotOperation(
                    next => addSnapshotBrowserTabToPreset(next, preset.id, newSnapshotTabDraft),
                    'Added new safe browser tab.'
                )
            }, !preset || editor.newBrowserItems.length >= SAFE_PRESET_PATCH_LIMITS.maxNewBrowserItems)
        ])
    ])
}

function renderSnapshotExportPanel(editor) {
    const validation = validateSafePresetPatchForExport(editor)
    const message = validation.valid
        ? 'Ready to export as a Phase 19 safe preset patch.'
        : validation.errors[0]
    return createElement('section', { className: `panel export-panel ${validation.valid ? '' : 'blocked'}` }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Safe Patch Export' }),
            createElement('span', { text: validation.valid ? 'valid' : 'blocked' })
        ]),
        createElement('p', { className: 'helper', text: message }),
        createElement('div', { className: 'export-actions' }, [
            button('Export Patch JSON', 'btn primary', () => exportSnapshotPatch(), !validation.valid),
            button('Preview Patch JSON', 'btn', () => exportSnapshotPatch({ download: false }), !validation.valid)
        ]),
        createElement('textarea', {
            className: 'export-json',
            readonly: true,
            rows: 10,
            value: editor.lastExportJson || ''
        })
    ])
}

function renderSnapshotEditor(editor) {
    if (!editor) {
        return createElement('main', { className: 'planner-grid' }, [
            renderHostedCloudPanel(null),
            renderSnapshotImportPanel(null)
        ])
    }
    const preset = selectedSnapshotPreset()
    return createElement('main', { className: 'planner-grid' }, [
        renderHostedCloudPanel(editor),
        renderSnapshotImportPanel(editor),
        renderSnapshotPresetPicker(editor, preset),
        renderSnapshotPresetDetails(editor, preset),
        renderAddSnapshotBrowserTab(editor, preset),
        renderSnapshotPresetItems(editor, preset),
        renderAvailableSnapshotItems(editor, preset),
        renderSnapshotExportPanel(editor)
    ])
}

function renderDraftPicker(draft) {
    const select = createElement('select', {
        value: state.selectedDraftId,
        onChange: event => {
            state.selectedDraftId = event.target.value
            saveCurrent('Selected draft saved locally.')
            render()
        }
    }, state.drafts.map(item => createElement('option', {
        value: item.draftId,
        text: item.name || item.draftId
    })))
    select.value = state.selectedDraftId

    return createElement('section', { className: 'toolbar-panel' }, [
        createElement('div', { className: 'draft-select' }, [
            createElement('span', { className: 'field-label', text: 'Draft' }),
            select
        ]),
        createElement('div', { className: 'toolbar-actions' }, [
            button('New', 'btn primary', () => {
                try {
                    commitState(createDraftInState(state, { name: 'Untitled Draft' }), 'Created local draft.')
                } catch (err) {
                    errorMessage = err.message
                    renderStatus()
                }
            }, state.drafts.length >= PHONE_DRAFT_LIMITS.maxActiveDraftsPerUser),
            button('Duplicate', 'btn', () => {
                if (!draft) return
                try {
                    commitState(duplicateDraftInState(state, draft.draftId), 'Duplicated local draft.')
                } catch (err) {
                    errorMessage = err.message
                    renderStatus()
                }
            }, !draft || state.drafts.length >= PHONE_DRAFT_LIMITS.maxActiveDraftsPerUser),
            button('Delete', 'btn danger', () => {
                if (!draft) return
                if (!window.confirm(`Delete "${draft.name || 'this draft'}" from this browser?`)) return
                commitState(deleteDraftFromState(state, draft.draftId, { createIfEmpty: false }), 'Deleted local draft.', { createIfEmpty: false })
            }, !draft)
        ])
    ])
}

function renderDraftDetails(draft) {
    return createElement('section', { className: 'panel' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Draft Details' }),
            createElement('span', { text: `${state.drafts.length}/${PHONE_DRAFT_LIMITS.maxActiveDraftsPerUser} drafts` })
        ]),
        createElement('div', { className: 'grid two' }, [
            textInput({
                label: 'Draft name',
                value: draft.name,
                maxLength: PHONE_DRAFT_LIMITS.maxDraftNameLength,
                onInput: value => mutateSelectedDraft(next => { next.name = value })
            }),
            checkboxInput({
                label: 'Default draft',
                checked: draft.isDefault,
                onChange: value => mutateSelectedDraft(next => { next.isDefault = value })
            })
        ]),
        textArea({
            label: 'Notes',
            value: draft.notes,
            maxLength: PHONE_DRAFT_LIMITS.maxDraftNotesLength,
            rows: 4,
            placeholder: 'Local planning notes only. Do not enter passwords, tokens, paths, scripts, or recovery codes.',
            onInput: value => mutateSelectedDraft(next => { next.notes = value })
        })
    ])
}

function renderProfileSection(draft) {
    return createElement('section', { className: 'panel' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Browser Profile Intentions' }),
            createElement('span', { text: `${draft.browserProfileSlots.length}/${PHONE_DRAFT_LIMITS.maxBrowserProfileSlots}` })
        ]),
        createElement('p', {
            className: 'helper',
            text: 'Profile slots are labels for desktop verification later. They do not create browser profiles from the phone.'
        }),
        button('Add profile slot', 'btn small', () => {
            mutateSelectedDraft(next => {
                if (next.browserProfileSlots.length >= PHONE_DRAFT_LIMITS.maxBrowserProfileSlots) throw new Error('Profile slot limit reached.')
                next.browserProfileSlots.push(createBrowserProfileSlot({ label: `Profile ${next.browserProfileSlots.length + 1}` }))
            }, { rerender: true, message: 'Added profile intention.' })
        }, draft.browserProfileSlots.length >= PHONE_DRAFT_LIMITS.maxBrowserProfileSlots),
        createElement('div', { className: 'item-list' }, draft.browserProfileSlots.map(profile => renderProfileItem(draft, profile)))
    ])
}

function renderProfileItem(draft, profile) {
    return createElement('article', { className: 'item' }, [
        createElement('div', { className: 'grid two' }, [
            textInput({
                label: 'Profile label',
                value: profile.label,
                maxLength: PHONE_DRAFT_LIMITS.maxBrowserProfileSlotLabelLength,
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.browserProfileSlots.find(slot => slot.id === profile.id)
                    if (item) item.label = value
                })
            }),
            fieldLabel('Provider', createElement('input', { value: 'google', disabled: true }))
        ]),
        button('Remove profile', 'btn danger small', () => {
            mutateSelectedDraft(next => {
                next.browserProfileSlots = next.browserProfileSlots.filter(slot => slot.id !== profile.id)
                for (const account of next.accountSlots) {
                    if (account.profileSlotId === profile.id) account.profileSlotId = ''
                }
                for (const tab of next.browserTabs) {
                    if (tab.profileSlotId === profile.id) tab.profileSlotId = ''
                }
            }, { rerender: true, message: 'Removed profile intention.' })
        })
    ])
}

function renderAccountSection(draft) {
    return createElement('section', { className: 'panel' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Google Account Intentions' }),
            createElement('span', { text: `${draft.accountSlots.length}/${PHONE_DRAFT_LIMITS.maxAccountIntentions}` })
        ]),
        createElement('p', {
            className: 'helper',
            text: 'Use these as planning labels. Wipesnap will still need the desktop browser to verify sign-in later.'
        }),
        button('Add account intention', 'btn small', () => {
            mutateSelectedDraft(next => {
                if (next.accountSlots.length >= PHONE_DRAFT_LIMITS.maxAccountIntentions) throw new Error('Account intention limit reached.')
                next.accountSlots.push(createAccountIntention({
                    label: `Google ${next.accountSlots.length + 1}`,
                    profileSlotId: next.browserProfileSlots[0]?.id || '',
                    state: 'needs-check'
                }))
            }, { rerender: true, message: 'Added account intention.' })
        }, draft.accountSlots.length >= PHONE_DRAFT_LIMITS.maxAccountIntentions),
        createElement('div', { className: 'item-list' }, draft.accountSlots.map(account => renderAccountItem(draft, account)))
    ])
}

function renderAccountItem(draft, account) {
    return createElement('article', { className: 'item' }, [
        createElement('div', { className: 'grid two' }, [
            textInput({
                label: 'Label',
                value: account.label,
                maxLength: PHONE_DRAFT_LIMITS.maxAccountIntentionLabelLength,
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.accountSlots.find(slot => slot.id === account.id)
                    if (item) item.label = value
                })
            }),
            textInput({
                label: 'Identifier hint',
                value: account.identifierHint,
                maxLength: PHONE_DRAFT_LIMITS.maxAccountIdentifierHintLength,
                placeholder: 'optional masked email',
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.accountSlots.find(slot => slot.id === account.id)
                    if (item) item.identifierHint = value
                })
            })
        ]),
        createElement('div', { className: 'grid two' }, [
            selectInput({
                label: 'State',
                value: account.state,
                options: PHONE_ACCOUNT_STATES.map(value => ({ value, label: value })),
                onChange: value => mutateSelectedDraft(next => {
                    const item = next.accountSlots.find(slot => slot.id === account.id)
                    if (item) item.state = value
                }, { rerender: true })
            }),
            selectInput({
                label: 'Profile intention',
                value: account.profileSlotId,
                options: optionsForProfiles(draft),
                onChange: value => mutateSelectedDraft(next => {
                    const item = next.accountSlots.find(slot => slot.id === account.id)
                    if (item) item.profileSlotId = value
                }, { rerender: true })
            })
        ]),
        button('Remove account', 'btn danger small', () => {
            mutateSelectedDraft(next => {
                next.accountSlots = next.accountSlots.filter(slot => slot.id !== account.id)
                for (const tab of next.browserTabs) {
                    if (tab.accountSlotId === account.id) tab.accountSlotId = ''
                }
            }, { rerender: true, message: 'Removed account intention.' })
        })
    ])
}

function renderTabsSection(draft) {
    const orderedTabs = [...draft.browserTabs].sort((a, b) => Number(a.order || 0) - Number(b.order || 0))
    return createElement('section', { className: 'panel wide' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Browser Tabs' }),
            createElement('span', { text: `${draft.browserTabs.length}/${PHONE_DRAFT_LIMITS.maxBrowserTabs}` })
        ]),
        button('Add AI Studio tab', 'btn small', () => {
            mutateSelectedDraft(next => {
                if (next.browserTabs.length >= PHONE_DRAFT_LIMITS.maxBrowserTabs) throw new Error('Browser tab limit reached.')
                next.browserTabs.push(createBrowserTab({
                    order: next.browserTabs.length,
                    accountSlotId: next.accountSlots[0]?.id || '',
                    profileSlotId: next.browserProfileSlots[0]?.id || ''
                }))
            }, { rerender: true, message: 'Added browser tab.' })
        }, draft.browserTabs.length >= PHONE_DRAFT_LIMITS.maxBrowserTabs),
        createElement('div', { className: 'item-list' }, orderedTabs.map(tab => renderTabItem(draft, tab, orderedTabs)))
    ])
}

function moveTab(tabId, direction) {
    mutateSelectedDraft(next => {
        const ordered = [...next.browserTabs].sort((a, b) => Number(a.order || 0) - Number(b.order || 0))
        const index = ordered.findIndex(tab => tab.id === tabId)
        const other = ordered[index + direction]
        if (!other) return
        const tab = ordered[index]
        const order = tab.order
        tab.order = other.order
        other.order = order
    }, { rerender: true, message: 'Updated tab order.' })
}

function renderTabItem(draft, tab, orderedTabs) {
    const position = orderedTabs.findIndex(item => item.id === tab.id)
    return createElement('article', { className: 'item tab-item' }, [
        createElement('div', { className: 'item-topline' }, [
            createElement('strong', { text: `Tab ${position + 1}` }),
            createElement('div', { className: 'inline-actions' }, [
                button('Up', 'btn tiny', () => moveTab(tab.id, -1), position === 0),
                button('Down', 'btn tiny', () => moveTab(tab.id, 1), position === orderedTabs.length - 1)
            ])
        ]),
        createElement('div', { className: 'grid two' }, [
            textInput({
                label: 'URL',
                value: tab.url,
                maxLength: PHONE_DRAFT_LIMITS.maxBrowserTabUrlLength,
                placeholder: 'https://aistudio.google.com/',
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.browserTabs.find(candidate => candidate.id === tab.id)
                    if (item) item.url = value
                })
            }),
            textInput({
                label: 'Label',
                value: tab.label,
                maxLength: PHONE_DRAFT_LIMITS.maxBrowserTabLabelLength,
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.browserTabs.find(candidate => candidate.id === tab.id)
                    if (item) item.label = value
                })
            })
        ]),
        createElement('div', { className: 'grid three' }, [
            textInput({
                label: 'Order',
                value: String(tab.order ?? 0),
                maxLength: 4,
                inputMode: 'numeric',
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.browserTabs.find(candidate => candidate.id === tab.id)
                    if (item) item.order = Math.max(0, Number.parseInt(value, 10) || 0)
                })
            }),
            selectInput({
                label: 'Account',
                value: tab.accountSlotId,
                options: optionsForAccounts(draft),
                onChange: value => mutateSelectedDraft(next => {
                    const item = next.browserTabs.find(candidate => candidate.id === tab.id)
                    if (item) item.accountSlotId = value
                }, { rerender: true })
            }),
            selectInput({
                label: 'Profile',
                value: tab.profileSlotId,
                options: optionsForProfiles(draft),
                onChange: value => mutateSelectedDraft(next => {
                    const item = next.browserTabs.find(candidate => candidate.id === tab.id)
                    if (item) item.profileSlotId = value
                }, { rerender: true })
            })
        ]),
        textArea({
            label: 'Tab notes',
            value: tab.notes,
            maxLength: PHONE_DRAFT_LIMITS.maxBrowserTabNotesLength,
            rows: 2,
            onInput: value => mutateSelectedDraft(next => {
                const item = next.browserTabs.find(candidate => candidate.id === tab.id)
                if (item) item.notes = value
            })
        }),
        createElement('div', { className: 'item-footer' }, [
            checkboxInput({
                label: 'Enabled',
                checked: tab.enabled !== false,
                onChange: value => mutateSelectedDraft(next => {
                    const item = next.browserTabs.find(candidate => candidate.id === tab.id)
                    if (item) item.enabled = value
                })
            }),
            button('Remove tab', 'btn danger small', () => {
                mutateSelectedDraft(next => {
                    next.browserTabs = next.browserTabs.filter(candidate => candidate.id !== tab.id)
                    next.browserTabs.forEach((candidate, index) => { candidate.order = index })
                }, { rerender: true, message: 'Removed browser tab.' })
            })
        ])
    ])
}

function renderAppsSection(draft) {
    return createElement('section', { className: 'panel' }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Desired Desktop Apps' }),
            createElement('span', { text: `${draft.desiredApps.length}/${PHONE_DRAFT_LIMITS.maxDesiredApps}` })
        ]),
        createElement('p', {
            className: 'helper',
            text: 'Add app names only. These export as unresolved placeholders and cannot launch until resolved on desktop.'
        }),
        button('Add app placeholder', 'btn small', () => {
            mutateSelectedDraft(next => {
                if (next.desiredApps.length >= PHONE_DRAFT_LIMITS.maxDesiredApps) throw new Error('Desired app limit reached.')
                next.desiredApps.push(createDesiredAppPlaceholder({ name: `App ${next.desiredApps.length + 1}` }))
            }, { rerender: true, message: 'Added desired app placeholder.' })
        }, draft.desiredApps.length >= PHONE_DRAFT_LIMITS.maxDesiredApps),
        createElement('div', { className: 'item-list' }, draft.desiredApps.map(app => renderDesiredAppItem(app)))
    ])
}

function renderDesiredAppItem(app) {
    return createElement('article', { className: 'item' }, [
        createElement('div', { className: 'grid two' }, [
            textInput({
                label: 'Name',
                value: app.name,
                maxLength: PHONE_DRAFT_LIMITS.maxDesiredAppNameLength,
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.desiredApps.find(candidate => candidate.id === app.id)
                    if (item) item.name = value
                })
            }),
            textInput({
                label: 'Label',
                value: app.label,
                maxLength: PHONE_DRAFT_LIMITS.maxDesiredAppLabelLength,
                onInput: value => mutateSelectedDraft(next => {
                    const item = next.desiredApps.find(candidate => candidate.id === app.id)
                    if (item) item.label = value
                })
            })
        ]),
        textArea({
            label: 'Notes',
            value: app.notes,
            maxLength: PHONE_DRAFT_LIMITS.maxDesiredAppNotesLength,
            rows: 2,
            onInput: value => mutateSelectedDraft(next => {
                const item = next.desiredApps.find(candidate => candidate.id === app.id)
                if (item) item.notes = value
            })
        }),
        createElement('div', { className: 'item-footer' }, [
            checkboxInput({
                label: 'Enabled placeholder',
                checked: app.enabled !== false,
                onChange: value => mutateSelectedDraft(next => {
                    const item = next.desiredApps.find(candidate => candidate.id === app.id)
                    if (item) item.enabled = value
                })
            }),
            button('Remove app', 'btn danger small', () => {
                mutateSelectedDraft(next => {
                    next.desiredApps = next.desiredApps.filter(candidate => candidate.id !== app.id)
                }, { rerender: true, message: 'Removed desired app placeholder.' })
            })
        ])
    ])
}

function safeFileName(name) {
    const safe = String(name || 'wipesnap-draft')
        .trim()
        .replace(/[^A-Za-z0-9._-]+/g, '-')
        .replace(/^-+|-+$/g, '')
        .slice(0, 80)
    return safe || 'wipesnap-draft'
}

function downloadJson(draft, json) {
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${safeFileName(draft.name)}.wipesnap-draft.json`
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
}

function downloadPatchJson(editor, json) {
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const preset = selectedSnapshotPreset()
    const link = document.createElement('a')
    link.href = url
    link.download = `${safeFileName(preset?.name || editor.patchId)}.wipesnap-preset-patch.json`
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
}

function exportSelectedDraft({ download = true } = {}) {
    const draft = selectedDraft()
    if (!draft) return
    try {
        const json = exportCloudDraftJson(draft)
        lastExportJson = json
        statusMessage = 'Exported validated draft JSON.'
        errorMessage = ''
        if (download) downloadJson(draft, json)
    } catch (err) {
        errorMessage = err?.message || 'Draft cannot be exported.'
    }
    render()
}

function renderExportPanel(draft) {
    const validation = validateDraftForExport(draft)
    const message = validation.valid
        ? 'Ready to export. Phase 15 desktop validation should accept this JSON.'
        : validation.errors[0]
    return createElement('section', { className: `panel export-panel ${validation.valid ? '' : 'blocked'}` }, [
        createElement('div', { className: 'section-head' }, [
            createElement('h2', { text: 'Export' }),
            createElement('span', { text: validation.valid ? 'valid' : 'blocked' })
        ]),
        createElement('p', { className: 'helper', text: message }),
        createElement('div', { className: 'export-actions' }, [
            button('Export JSON', 'btn primary', () => exportSelectedDraft(), !validation.valid),
            button('Preview JSON', 'btn', () => exportSelectedDraft({ download: false }), !validation.valid)
        ]),
        createElement('textarea', {
            className: 'export-json',
            readonly: true,
            rows: 10,
            value: lastExportJson || ''
        })
    ])
}

function renderEmptyState() {
    return createElement('main', { className: 'empty-state' }, [
        createElement('h2', { text: 'No local drafts' }),
        createElement('p', { text: 'Create a draft to start planning tabs, account intentions, profile intentions, and app placeholders.' }),
        button('Create draft', 'btn primary', () => {
            commitState(createPhonePlannerState(), 'Created local draft.')
        })
    ])
}

function render() {
    root.textContent = ''
    const draft = selectedDraft()
    const editor = snapshotEditor()
    root.appendChild(renderHeader())
    root.appendChild(createElement('div', { id: 'status-line', className: 'status', text: errorMessage || statusMessage }))
    root.appendChild(renderSnapshotEditor(editor))
    if (!draft) {
        root.appendChild(renderEmptyState())
        renderStatus()
        return
    }

    root.appendChild(createElement('div', { className: 'legacy-head' }, [
        createElement('p', { className: 'eyebrow', text: 'Legacy Local Drafts' }),
        createElement('h2', { text: 'Local Draft Planner' })
    ]))
    root.appendChild(createElement('main', { className: 'planner-grid' }, [
        renderDraftPicker(draft),
        renderDraftDetails(draft),
        renderProfileSection(draft),
        renderAccountSection(draft),
        renderTabsSection(draft),
        renderAppsSection(draft),
        renderExportPanel(draft)
    ]))
    renderStatus()
}

render()
initializeHostedCloud()
