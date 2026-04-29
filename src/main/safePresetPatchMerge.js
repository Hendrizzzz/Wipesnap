import { createHash } from 'crypto'
import { validateCloudDraft } from './cloudDraftSchema.js'
import {
    SAFE_PRESET_PATCH_IMPORT_PLAN_VERSION,
    planSafePresetPatchImport
} from './safePresetPatch.js'
import {
    SANITIZED_PRESET_SNAPSHOT_KIND,
    SANITIZED_PRESET_SNAPSHOT_LIMITS,
    SANITIZED_PRESET_SNAPSHOT_SCHEMA_VERSION
} from './sanitizedPresetSnapshot.js'
import { WORKSPACE_CAPABILITY_VAULT_KEY } from './workspaceCapabilityMigration.js'
import {
    SAFE_PRESET_METADATA_VERSION,
    WORKSPACE_SAFE_PRESET_METADATA_KEY
} from './safePresetMetadata.js'

export const SAFE_PRESET_PATCH_MERGE_RESULT_VERSION = 1

const MAX_TIMESTAMP = 8_640_000_000_000_000
const SAFE_ID_PATTERN = /^[A-Za-z][A-Za-z0-9_-]+$/
const CAPABILITY_ID_PATTERN = /\bcap_[a-f0-9]{32,64}\b/i
const RAW_ACCOUNT_SLOT_ID_PATTERN = /\bacct_[a-f0-9]{32,64}\b/i

const TOP_LEVEL_PLAN_KEYS = new Set([
    'success',
    'importPlanVersion',
    'source',
    'schemaVersion',
    'patchId',
    'patchRevisionId',
    'baseSnapshotRevisionId',
    'authorDeviceId',
    'createdAt',
    'updatedAt',
    'snapshot',
    'selection',
    'newBrowserItems',
    'presetPlans',
    'sideEffects',
    'planned',
    'warnings'
])
const PLAN_SNAPSHOT_KEYS = new Set(['snapshotId', 'revisionId', 'sourceDeviceId'])
const PLAN_SELECTION_KEYS = new Set([
    'defaultPresetId',
    'nextPresetId',
    'metadataOnly',
    'selectionKind',
    'authorizesLaunch'
])
const PLAN_BROWSER_ITEM_KEYS = new Set([
    'id',
    'type',
    'source',
    'url',
    'label',
    'notes',
    'enabled',
    'accountIntentionId',
    'profileIntentionId',
    'metadataOnly',
    'createsCapability',
    'createsDesktopAppAuthority',
    'createsHostFolderAuthority',
    'launchable'
])
const PLAN_PRESET_KEYS = new Set([
    'presetId',
    'previous',
    'next',
    'changes',
    'metadataOnly',
    'createsCapability',
    'createsDesktopAppAuthority',
    'createsHostFolderAuthority',
    'writesVault',
    'launches'
])
const PLAN_PRESET_STATE_KEYS = new Set(['name', 'order', 'enabled', 'itemRefs'])
const PLAN_PREVIOUS_REF_KEYS = new Set([
    'id',
    'itemId',
    'order',
    'enabled',
    'accountIntentionId',
    'profileIntentionId',
    'metadataOnly'
])
const PLAN_NEXT_REF_KEYS = new Set([
    'itemId',
    'itemType',
    'itemSource',
    'label',
    'order',
    'enabled',
    'accountIntentionId',
    'profileIntentionId',
    'metadataOnly',
    'existingSnapshotItem',
    'newBrowserItem',
    'createsCapability',
    'createsDesktopAppAuthority',
    'createsHostFolderAuthority',
    'launchable'
])
const PLAN_CHANGE_KEYS = new Set(['name', 'order', 'enabled', 'itemRefs'])
const PLAN_SIDE_EFFECT_KEYS = new Set([
    'writesVault',
    'writesCapabilityVault',
    'createsCapability',
    'createsAccountSlots',
    'createsBrowserProfiles',
    'launches'
])
const PLAN_PLANNED_KEYS = new Set(['presets', 'newBrowserItems', 'selectionMetadata'])

const SNAPSHOT_TOP_LEVEL_KEYS = new Set([
    'product',
    'kind',
    'schemaVersion',
    'snapshotId',
    'revisionId',
    'baseRevisionId',
    'sourceDeviceId',
    'timestamp',
    'limits',
    'selection',
    'presets',
    'availableItems'
])
const SNAPSHOT_SELECTION_KEYS = new Set(['defaultPresetId', 'nextPresetId', 'metadataOnly', 'selectionKind'])
const SNAPSHOT_PRESET_KEYS = new Set(['id', 'name', 'order', 'enabled', 'itemRefs'])
const SNAPSHOT_REF_KEYS = new Set([
    'id',
    'itemId',
    'order',
    'enabled',
    'accountIntentionId',
    'profileIntentionId',
    'metadataOnly'
])
const SNAPSHOT_ITEM_KEYS = new Set([
    'id',
    'type',
    'label',
    'status',
    'source',
    'url',
    'provider',
    'identifierHint',
    'state',
    'metadataOnly'
])
const SNAPSHOT_ITEM_TYPES = new Set([
    'browser-tab',
    'desktop-app',
    'host-folder',
    'account-intention',
    'profile-intention'
])
const SNAPSHOT_ITEM_STATUSES = new Set(['available', 'disabled', 'redacted', 'broken'])
const SNAPSHOT_ITEM_SOURCES = new Set(['browser', 'desktop', 'account', 'profile'])
const PLAN_ITEM_SOURCES = new Set([...SNAPSHOT_ITEM_SOURCES, 'phone-patch'])

const SECRET_FIELD_MARKERS = [
    'password',
    'passcode',
    'backupcode',
    'cookie',
    'oauth',
    'refreshtoken',
    'accesstoken',
    'idtoken',
    'token',
    'credential',
    'secret',
    'pin',
    'fastboot',
    'hiddenmaster'
]
const AUTHORITY_FIELD_MARKERS = [
    'vault',
    'capability',
    'executable',
    'exepath',
    'sourcepath',
    'importpath',
    'datapath',
    'apppath',
    'appdata',
    'browserprofile',
    'path',
    'command',
    'script',
    'registry',
    'process',
    'pid',
    'shell',
    'session',
    'rawbrowser',
    'launch',
    'args',
    'userargs',
    'manifest',
    'storage',
    'shortcut'
]

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function requireObject(value, fieldName) {
    if (!isPlainObject(value)) fail(`${fieldName} must be an object.`)
    return value
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function normalizedKey(value) {
    return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '')
}

function looksLikeForbiddenField(key) {
    const normalized = normalizedKey(key)
    return SECRET_FIELD_MARKERS.some(marker => normalized.includes(marker)) ||
        AUTHORITY_FIELD_MARKERS.some(marker => normalized.includes(marker))
}

function rejectUnknownKeys(value, allowedKeys, fieldName) {
    for (const key of Object.keys(value || {})) {
        if (allowedKeys.has(key)) continue
        if (looksLikeForbiddenField(key)) {
            fail(`${fieldName}.${key} is not accepted because safe preset merge data cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material.`)
        }
        fail(`${fieldName}.${key} is not accepted.`)
    }
}

function looksLikeSecretString(value) {
    return /\b(?:password|passcode|backup\s*code|cookie|oauth|refresh[_\s-]*token|access[_\s-]*token|id[_\s-]*token|token|credential|secret|pin|fastboot|hidden[_\s-]*master)\b\s*[:=]/i.test(value) ||
        /\bbearer\s+[A-Za-z0-9._~+/-]{16,}/i.test(value) ||
        /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/i.test(value) ||
        /\bAIza[A-Za-z0-9_-]{20,}\b/.test(value) ||
        /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/.test(value) ||
        /(?:^|[^a-f0-9])[a-f0-9]{40,}(?:$|[^a-f0-9])/i.test(value)
}

function looksLikeWindowsPathString(value) {
    return /(?:^|[\s"'([{])(?:[A-Za-z]:[\\/]|\\\\|\[USB\][\\/])/i.test(value) ||
        /\b(?:vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile)\b/i.test(value) ||
        /\bAppData[\\/]/i.test(value)
}

function looksLikeRegistryString(value) {
    return /\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKEY_CURRENT_CONFIG)\b/i.test(value) ||
        /\b(?:HKLM|HKCU|HKCR|HKU|HKCC)[\\:]/i.test(value)
}

function looksLikeProcessSelector(value) {
    return /\b(?:pid|process\s*id)\s*[:=]?\s*\d{2,}\b/i.test(value)
}

function looksLikeShellCommand(value) {
    return /(?:^|[\s"'([{])(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regedit|reg|schtasks|taskkill|start)\s+(?:\/|-\w|&|\||<|>)/i.test(value) ||
        /[;&|`><]\s*(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|reg|taskkill)\b/i.test(value)
}

function looksLikeExecutableReference(value) {
    const fileReference = String.raw`(?:^|[\s"'([{\\/])[^\\/\s"'([{@:]+\.(?:exe|bat|cmd|ps1|vbs|lnk|scr|msi)(?=$|[\s"'\])},.;:!?])`
    return new RegExp(fileReference, 'i').test(value)
}

function looksLikeManifestOrStorageReference(value) {
    return /\b(?:manifest|storage)\s*(?:id)?\s*[:=]/i.test(value) ||
        /\b(?:manifestId|storageId)\b/i.test(value)
}

function hasDangerousStringMaterial(value) {
    return looksLikeSecretString(value) ||
        looksLikeWindowsPathString(value) ||
        looksLikeRegistryString(value) ||
        looksLikeProcessSelector(value) ||
        looksLikeShellCommand(value) ||
        looksLikeExecutableReference(value) ||
        looksLikeManifestOrStorageReference(value) ||
        CAPABILITY_ID_PATTERN.test(value) ||
        RAW_ACCOUNT_SLOT_ID_PATTERN.test(value)
}

function normalizeString(value, fieldName, {
    required = false,
    max = 256,
    multiline = false,
    rejectDangerous = true
} = {}) {
    if (value == null) {
        if (required) fail(`${fieldName} is required.`)
        return ''
    }
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    if (value.includes('\0')) fail(`${fieldName} contains an invalid null byte.`)
    let text = value.normalize('NFC').replace(/\r\n?/g, '\n')
    const controlPattern = multiline
        ? /[\u0000-\u0009\u000B\u000C\u000E-\u001F\u007F]/
        : /[\u0000-\u001F\u007F]/
    if (controlPattern.test(text)) fail(`${fieldName} contains unsupported control characters.`)
    text = text.trim()
    if (required && !text) fail(`${fieldName} is required.`)
    if (!required && !text) return ''
    if (text.length > max) fail(`${fieldName} is too long.`)
    if (rejectDangerous && hasDangerousStringMaterial(text)) {
        fail(`${fieldName} contains forbidden safe preset merge material.`)
    }
    return text
}

function normalizeTimestamp(value, fieldName) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > MAX_TIMESTAMP) {
        fail(`${fieldName} must be a non-negative timestamp.`)
    }
    return Math.floor(value)
}

function normalizeBoolean(value, fieldName, defaultValue = false) {
    if (value == null) return defaultValue
    if (typeof value !== 'boolean') fail(`${fieldName} must be a boolean.`)
    return value
}

function requireTrue(value, fieldName) {
    if (value !== true) fail(`${fieldName} must be true.`)
    return true
}

function requireFalse(value, fieldName) {
    if (value !== false) fail(`${fieldName} must be false.`)
    return false
}

function normalizeOrder(value, fieldName) {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${fieldName} must be a non-negative integer.`)
    return value
}

function normalizeCount(value, fieldName) {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${fieldName} must be a non-negative integer.`)
    return value
}

function normalizeArray(value, fieldName, max, { required = false } = {}) {
    if (value == null) {
        if (required) fail(`${fieldName} is required.`)
        return []
    }
    if (!Array.isArray(value)) fail(`${fieldName} must be an array.`)
    if (value.length > max) fail(`${fieldName} cannot contain more than ${max} items.`)
    return value
}

function normalizeSafeId(value, fieldName, prefixes, { nullable = false, required = true } = {}) {
    if (value == null || value === '') {
        if (nullable) return null
        if (required) fail(`${fieldName} is required.`)
        return ''
    }
    const id = normalizeString(value, fieldName, {
        required: true,
        max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength,
        rejectDangerous: false
    })
    if (!SAFE_ID_PATTERN.test(id)) fail(`${fieldName} must be a safe id.`)
    if (CAPABILITY_ID_PATTERN.test(id)) fail(`${fieldName} cannot use a launch capability id shape.`)
    if (RAW_ACCOUNT_SLOT_ID_PATTERN.test(id)) fail(`${fieldName} cannot use a raw account slot id shape.`)
    if (prefixes && !prefixes.some(prefix => id.startsWith(prefix))) {
        fail(`${fieldName} must use an allowed safe id prefix.`)
    }
    return id
}

function normalizeOptionalIntentionId(value, fieldName, prefix) {
    if (value == null || value === '') return ''
    return normalizeSafeId(value, fieldName, [prefix], { required: false })
}

function normalizePublicBrowserUrl(value, fieldName) {
    try {
        const draft = validateCloudDraft({
            product: 'wipesnap',
            schemaVersion: 1,
            draftId: 'safe_patch_merge_url_check',
            revisionId: 'safe_patch_merge_url_check_rev',
            baseRevisionId: null,
            authorDeviceId: 'safe_patch_merge_url_check_device',
            name: 'Safe Patch Merge URL Check',
            notes: '',
            isDefault: false,
            accountSlots: [],
            browserProfileSlots: [],
            browserTabs: [{
                id: 'safe_patch_merge_url_check_tab',
                url: value,
                order: 0,
                label: '',
                notes: '',
                enabled: true,
                accountSlotId: '',
                profileSlotId: ''
            }],
            desiredApps: [],
            createdAt: 1,
            updatedAt: 1
        })
        return draft.browserTabs[0].url
    } catch (_) {
        fail(`${fieldName} is not an accepted public browser URL.`)
    }
}

function canonicalize(value) {
    if (Array.isArray(value)) return value.map(canonicalize)
    if (isPlainObject(value)) {
        const next = {}
        for (const key of Object.keys(value).sort()) next[key] = canonicalize(value[key])
        return next
    }
    return value === undefined ? null : value
}

function deterministicRefId({ presetId, itemId, order, index }) {
    const digest = createHash('sha256')
        .update('wipesnap.phase22.preset-ref.v1\0')
        .update(JSON.stringify({ presetId, itemId, order, index }))
        .digest('base64url')
        .slice(0, 32)
    return `pref_${digest}`
}

function indexById(items) {
    const map = new Map()
    for (const item of items || []) map.set(item.id, item)
    return map
}

function addUnique(seen, value, fieldName) {
    if (seen.has(value)) fail(`${fieldName} contains a duplicate id.`)
    seen.add(value)
}

function conflict(code, message, extra = {}) {
    return { code, message, ...extra }
}

function sideEffectsNone({ writesVault = false } = {}) {
    return {
        writesVault,
        writesCapabilityVault: false,
        createsCapability: false,
        createsDesktopAppAuthority: false,
        createsHostFolderAuthority: false,
        createsAccountSlots: false,
        createsBrowserProfiles: false,
        launches: false
    }
}

function baseResult(status, extra = {}) {
    return {
        success: status === 'merged',
        status,
        mergeResultVersion: SAFE_PRESET_PATCH_MERGE_RESULT_VERSION,
        appliedChanges: [],
        skipped: [],
        conflicts: [],
        sideEffects: sideEffectsNone(),
        ...extra
    }
}

function requireUnlockedCallerContext(context) {
    const value = requireObject(context, 'safe preset patch merge caller context')
    if (value.unlocked !== true) fail('Safe preset patch merge requires an explicit unlocked caller context.')
    if (value.vaultBacked !== true) fail('Safe preset patch merge requires an explicit vault-backed caller context.')
    if (value.authority !== 'desktop-main') fail('Safe preset patch merge requires desktop-main caller authority.')
}

function normalizeSnapshotSelection(value) {
    const selection = requireObject(value, 'sanitized snapshot.selection')
    rejectUnknownKeys(selection, SNAPSHOT_SELECTION_KEYS, 'sanitized snapshot.selection')
    if (selection.metadataOnly !== true) fail('sanitized snapshot.selection.metadataOnly must be true.')
    if (selection.selectionKind !== 'metadata-only') fail('sanitized snapshot.selection.selectionKind must be metadata-only.')
    return {
        defaultPresetId: normalizeSafeId(selection.defaultPresetId, 'sanitized snapshot.selection.defaultPresetId', ['preset_'], {
            nullable: true,
            required: false
        }),
        nextPresetId: normalizeSafeId(selection.nextPresetId, 'sanitized snapshot.selection.nextPresetId', ['preset_'], {
            nullable: true,
            required: false
        }),
        metadataOnly: true,
        selectionKind: 'metadata-only'
    }
}

function normalizeSnapshotAvailableItem(value, index) {
    const fieldName = `sanitized snapshot.availableItems[${index}]`
    const item = requireObject(value, fieldName)
    rejectUnknownKeys(item, SNAPSHOT_ITEM_KEYS, fieldName)
    const type = normalizeString(item.type, `${fieldName}.type`, { required: true, max: 40, rejectDangerous: false })
    if (!SNAPSHOT_ITEM_TYPES.has(type)) fail(`${fieldName}.type is invalid.`)
    const source = normalizeString(item.source, `${fieldName}.source`, { required: true, max: 40, rejectDangerous: false })
    if (!SNAPSHOT_ITEM_SOURCES.has(source)) fail(`${fieldName}.source is invalid.`)
    const status = normalizeString(item.status, `${fieldName}.status`, { required: true, max: 40, rejectDangerous: false })
    if (!SNAPSHOT_ITEM_STATUSES.has(status)) fail(`${fieldName}.status is invalid.`)
    const idPrefixes = type === 'account-intention'
        ? ['accti_']
        : type === 'profile-intention'
            ? ['profi_']
            : type === 'browser-tab'
                ? ['item_', 'patch_item_']
                : ['item_']
    const next = {
        id: normalizeSafeId(item.id, `${fieldName}.id`, idPrefixes),
        type,
        label: normalizeString(item.label, `${fieldName}.label`, {
            required: true,
            max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxItemLabelLength
        }),
        status,
        source
    }
    if (item.url != null) {
        if (type !== 'browser-tab') fail(`${fieldName}.url is only allowed on browser-tab items.`)
        next.url = normalizePublicBrowserUrl(item.url, `${fieldName}.url`)
        if (next.url !== item.url) fail(`${fieldName}.url must already be normalized.`)
    }
    if (item.provider != null) {
        next.provider = normalizeString(item.provider, `${fieldName}.provider`, {
            required: true,
            max: 40,
            rejectDangerous: false
        }).toLowerCase()
    }
    if (item.identifierHint != null) {
        next.identifierHint = normalizeString(item.identifierHint, `${fieldName}.identifierHint`, {
            max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxAccountIdentifierHintLength
        })
    }
    if (item.state != null) {
        next.state = normalizeString(item.state, `${fieldName}.state`, { required: true, max: 80, rejectDangerous: false })
    }
    if (item.metadataOnly === true) next.metadataOnly = true
    return next
}

function normalizeSnapshotRef(value, index, presetIndex) {
    const fieldName = `sanitized snapshot.presets[${presetIndex}].itemRefs[${index}]`
    const ref = requireObject(value, fieldName)
    rejectUnknownKeys(ref, SNAPSHOT_REF_KEYS, fieldName)
    if (ref.metadataOnly !== true) fail(`${fieldName}.metadataOnly must be true.`)
    const next = {
        id: normalizeSafeId(ref.id, `${fieldName}.id`, ['pref_']),
        itemId: normalizeSafeId(ref.itemId, `${fieldName}.itemId`, ['item_', 'accti_', 'profi_', 'patch_item_']),
        order: normalizeOrder(ref.order, `${fieldName}.order`),
        enabled: normalizeBoolean(ref.enabled, `${fieldName}.enabled`),
        metadataOnly: true
    }
    const accountIntentionId = normalizeOptionalIntentionId(ref.accountIntentionId, `${fieldName}.accountIntentionId`, 'accti_')
    const profileIntentionId = normalizeOptionalIntentionId(ref.profileIntentionId, `${fieldName}.profileIntentionId`, 'profi_')
    if (accountIntentionId) next.accountIntentionId = accountIntentionId
    if (profileIntentionId) next.profileIntentionId = profileIntentionId
    return next
}

function normalizeSnapshotPreset(value, index) {
    const fieldName = `sanitized snapshot.presets[${index}]`
    const preset = requireObject(value, fieldName)
    rejectUnknownKeys(preset, SNAPSHOT_PRESET_KEYS, fieldName)
    const itemRefs = normalizeArray(
        preset.itemRefs,
        `${fieldName}.itemRefs`,
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetItemRefs,
        { required: true }
    ).map((ref, refIndex) => normalizeSnapshotRef(ref, refIndex, index))
    const refIds = new Set()
    const itemIds = new Set()
    for (const ref of itemRefs) {
        addUnique(refIds, ref.id, `${fieldName}.itemRefs`)
        addUnique(itemIds, ref.itemId, `${fieldName}.itemRefs`)
    }
    return {
        id: normalizeSafeId(preset.id, `${fieldName}.id`, ['preset_']),
        name: normalizeString(preset.name, `${fieldName}.name`, {
            required: true,
            max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetNameLength
        }),
        order: normalizeOrder(preset.order, `${fieldName}.order`),
        enabled: normalizeBoolean(preset.enabled, `${fieldName}.enabled`),
        itemRefs
    }
}

function normalizeCurrentSnapshot(input) {
    const snapshot = requireObject(input, 'sanitized snapshot')
    rejectUnknownKeys(snapshot, SNAPSHOT_TOP_LEVEL_KEYS, 'sanitized snapshot')
    const product = normalizeString(snapshot.product, 'sanitized snapshot.product', {
        required: true,
        max: 40,
        rejectDangerous: false
    }).toLowerCase()
    if (product !== 'wipesnap') fail('sanitized snapshot.product is not supported.')
    if (snapshot.kind !== SANITIZED_PRESET_SNAPSHOT_KIND) fail('sanitized snapshot.kind is not supported.')
    if (snapshot.schemaVersion !== SANITIZED_PRESET_SNAPSHOT_SCHEMA_VERSION) {
        fail('sanitized snapshot.schemaVersion is not supported.')
    }
    const availableItems = normalizeArray(
        snapshot.availableItems,
        'sanitized snapshot.availableItems',
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxAvailableItems,
        { required: true }
    ).map(normalizeSnapshotAvailableItem)
    const itemIds = new Set()
    for (const item of availableItems) addUnique(itemIds, item.id, 'sanitized snapshot.availableItems')
    const presets = normalizeArray(
        snapshot.presets,
        'sanitized snapshot.presets',
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresets,
        { required: true }
    ).map(normalizeSnapshotPreset)
    const presetIds = new Set()
    for (const preset of presets) {
        addUnique(presetIds, preset.id, 'sanitized snapshot.presets')
        for (const ref of preset.itemRefs) {
            if (!itemIds.has(ref.itemId)) fail('sanitized snapshot preset item reference points at an unknown safe item.')
        }
    }
    return {
        product,
        kind: SANITIZED_PRESET_SNAPSHOT_KIND,
        schemaVersion: SANITIZED_PRESET_SNAPSHOT_SCHEMA_VERSION,
        snapshotId: normalizeSafeId(snapshot.snapshotId, 'sanitized snapshot.snapshotId', ['snap_']),
        revisionId: normalizeSafeId(snapshot.revisionId, 'sanitized snapshot.revisionId', ['srev_']),
        baseRevisionId: normalizeSafeId(snapshot.baseRevisionId, 'sanitized snapshot.baseRevisionId', ['srev_'], {
            nullable: true,
            required: false
        }),
        sourceDeviceId: normalizeSafeId(snapshot.sourceDeviceId, 'sanitized snapshot.sourceDeviceId', ['dev_']),
        timestamp: normalizeTimestamp(snapshot.timestamp, 'sanitized snapshot.timestamp'),
        limits: { ...SANITIZED_PRESET_SNAPSHOT_LIMITS },
        selection: normalizeSnapshotSelection(snapshot.selection),
        presets,
        availableItems
    }
}

function normalizePreviousRef(value, index, fieldName) {
    const ref = requireObject(value, `${fieldName}[${index}]`)
    rejectUnknownKeys(ref, PLAN_PREVIOUS_REF_KEYS, `${fieldName}[${index}]`)
    if (ref.metadataOnly !== true) fail(`${fieldName}[${index}].metadataOnly must be true.`)
    const next = {
        id: normalizeSafeId(ref.id, `${fieldName}[${index}].id`, ['pref_']),
        itemId: normalizeSafeId(ref.itemId, `${fieldName}[${index}].itemId`, ['item_', 'accti_', 'profi_', 'patch_item_']),
        order: normalizeOrder(ref.order, `${fieldName}[${index}].order`),
        enabled: normalizeBoolean(ref.enabled, `${fieldName}[${index}].enabled`),
        metadataOnly: true
    }
    const accountIntentionId = normalizeOptionalIntentionId(ref.accountIntentionId, `${fieldName}[${index}].accountIntentionId`, 'accti_')
    const profileIntentionId = normalizeOptionalIntentionId(ref.profileIntentionId, `${fieldName}[${index}].profileIntentionId`, 'profi_')
    if (accountIntentionId) next.accountIntentionId = accountIntentionId
    if (profileIntentionId) next.profileIntentionId = profileIntentionId
    return next
}

function normalizeNextRef(value, index, fieldName) {
    const ref = requireObject(value, `${fieldName}[${index}]`)
    rejectUnknownKeys(ref, PLAN_NEXT_REF_KEYS, `${fieldName}[${index}]`)
    if (!SNAPSHOT_ITEM_TYPES.has(ref.itemType)) fail(`${fieldName}[${index}].itemType is invalid.`)
    if (!PLAN_ITEM_SOURCES.has(ref.itemSource)) fail(`${fieldName}[${index}].itemSource is invalid.`)
    return {
        itemId: normalizeSafeId(ref.itemId, `${fieldName}[${index}].itemId`, ['item_', 'accti_', 'profi_', 'patch_item_']),
        itemType: ref.itemType,
        itemSource: ref.itemSource,
        label: normalizeString(ref.label, `${fieldName}[${index}].label`, {
            max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxItemLabelLength
        }),
        order: normalizeOrder(ref.order, `${fieldName}[${index}].order`),
        enabled: normalizeBoolean(ref.enabled, `${fieldName}[${index}].enabled`),
        accountIntentionId: normalizeOptionalIntentionId(ref.accountIntentionId, `${fieldName}[${index}].accountIntentionId`, 'accti_'),
        profileIntentionId: normalizeOptionalIntentionId(ref.profileIntentionId, `${fieldName}[${index}].profileIntentionId`, 'profi_'),
        metadataOnly: requireTrue(ref.metadataOnly, `${fieldName}[${index}].metadataOnly`),
        existingSnapshotItem: normalizeBoolean(ref.existingSnapshotItem, `${fieldName}[${index}].existingSnapshotItem`),
        newBrowserItem: normalizeBoolean(ref.newBrowserItem, `${fieldName}[${index}].newBrowserItem`),
        createsCapability: requireFalse(ref.createsCapability, `${fieldName}[${index}].createsCapability`),
        createsDesktopAppAuthority: requireFalse(ref.createsDesktopAppAuthority, `${fieldName}[${index}].createsDesktopAppAuthority`),
        createsHostFolderAuthority: requireFalse(ref.createsHostFolderAuthority, `${fieldName}[${index}].createsHostFolderAuthority`),
        launchable: requireFalse(ref.launchable, `${fieldName}[${index}].launchable`)
    }
}

function normalizePresetState(value, fieldName, refNormalizer) {
    const state = requireObject(value, fieldName)
    rejectUnknownKeys(state, PLAN_PRESET_STATE_KEYS, fieldName)
    return {
        name: normalizeString(state.name, `${fieldName}.name`, {
            required: true,
            max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetNameLength
        }),
        order: normalizeOrder(state.order, `${fieldName}.order`),
        enabled: normalizeBoolean(state.enabled, `${fieldName}.enabled`),
        itemRefs: normalizeArray(
            state.itemRefs,
            `${fieldName}.itemRefs`,
            SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetItemRefs,
            { required: true }
        ).map((ref, index) => refNormalizer(ref, index, `${fieldName}.itemRefs`))
    }
}

function normalizePlanChanges(value, fieldName) {
    const changes = requireObject(value, fieldName)
    rejectUnknownKeys(changes, PLAN_CHANGE_KEYS, fieldName)
    return {
        name: normalizeBoolean(changes.name, `${fieldName}.name`),
        order: normalizeBoolean(changes.order, `${fieldName}.order`),
        enabled: normalizeBoolean(changes.enabled, `${fieldName}.enabled`),
        itemRefs: normalizeBoolean(changes.itemRefs, `${fieldName}.itemRefs`)
    }
}

function normalizePlanBrowserItem(value, index) {
    const fieldName = `safe preset patch import plan.newBrowserItems[${index}]`
    const item = requireObject(value, fieldName)
    rejectUnknownKeys(item, PLAN_BROWSER_ITEM_KEYS, fieldName)
    if (item.type !== 'browser-tab') fail(`${fieldName}.type must be browser-tab.`)
    if (item.source !== 'phone-patch') fail(`${fieldName}.source must be phone-patch.`)
    return {
        id: normalizeSafeId(item.id, `${fieldName}.id`, ['patch_item_']),
        type: 'browser-tab',
        source: 'phone-patch',
        url: normalizePublicBrowserUrl(item.url, `${fieldName}.url`),
        label: normalizeString(item.label, `${fieldName}.label`, {
            max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxItemLabelLength
        }),
        notes: normalizeString(item.notes, `${fieldName}.notes`, {
            max: 500,
            multiline: true
        }),
        enabled: normalizeBoolean(item.enabled, `${fieldName}.enabled`, true),
        accountIntentionId: normalizeOptionalIntentionId(item.accountIntentionId, `${fieldName}.accountIntentionId`, 'accti_'),
        profileIntentionId: normalizeOptionalIntentionId(item.profileIntentionId, `${fieldName}.profileIntentionId`, 'profi_'),
        metadataOnly: requireTrue(item.metadataOnly, `${fieldName}.metadataOnly`),
        createsCapability: requireFalse(item.createsCapability, `${fieldName}.createsCapability`),
        createsDesktopAppAuthority: requireFalse(item.createsDesktopAppAuthority, `${fieldName}.createsDesktopAppAuthority`),
        createsHostFolderAuthority: requireFalse(item.createsHostFolderAuthority, `${fieldName}.createsHostFolderAuthority`),
        launchable: requireFalse(item.launchable, `${fieldName}.launchable`)
    }
}

function normalizePlanSelection(value) {
    if (value == null) return null
    const fieldName = 'safe preset patch import plan.selection'
    const selection = requireObject(value, fieldName)
    rejectUnknownKeys(selection, PLAN_SELECTION_KEYS, fieldName)
    return {
        defaultPresetId: normalizeSafeId(selection.defaultPresetId, `${fieldName}.defaultPresetId`, ['preset_'], {
            nullable: true,
            required: false
        }),
        nextPresetId: normalizeSafeId(selection.nextPresetId, `${fieldName}.nextPresetId`, ['preset_'], {
            nullable: true,
            required: false
        }),
        metadataOnly: requireTrue(selection.metadataOnly, `${fieldName}.metadataOnly`),
        selectionKind: selection.selectionKind === 'metadata-only'
            ? 'metadata-only'
            : fail(`${fieldName}.selectionKind must be metadata-only.`),
        authorizesLaunch: requireFalse(selection.authorizesLaunch, `${fieldName}.authorizesLaunch`)
    }
}

function normalizePlanPreset(value, index) {
    const fieldName = `safe preset patch import plan.presetPlans[${index}]`
    const preset = requireObject(value, fieldName)
    rejectUnknownKeys(preset, PLAN_PRESET_KEYS, fieldName)
    return {
        presetId: normalizeSafeId(preset.presetId, `${fieldName}.presetId`, ['preset_']),
        previous: normalizePresetState(preset.previous, `${fieldName}.previous`, normalizePreviousRef),
        next: normalizePresetState(preset.next, `${fieldName}.next`, normalizeNextRef),
        changes: normalizePlanChanges(preset.changes, `${fieldName}.changes`),
        metadataOnly: requireTrue(preset.metadataOnly, `${fieldName}.metadataOnly`),
        createsCapability: requireFalse(preset.createsCapability, `${fieldName}.createsCapability`),
        createsDesktopAppAuthority: requireFalse(preset.createsDesktopAppAuthority, `${fieldName}.createsDesktopAppAuthority`),
        createsHostFolderAuthority: requireFalse(preset.createsHostFolderAuthority, `${fieldName}.createsHostFolderAuthority`),
        writesVault: requireFalse(preset.writesVault, `${fieldName}.writesVault`),
        launches: requireFalse(preset.launches, `${fieldName}.launches`)
    }
}

function normalizePlanSideEffects(value) {
    const sideEffects = requireObject(value, 'safe preset patch import plan.sideEffects')
    rejectUnknownKeys(sideEffects, PLAN_SIDE_EFFECT_KEYS, 'safe preset patch import plan.sideEffects')
    return {
        writesVault: requireFalse(sideEffects.writesVault, 'safe preset patch import plan.sideEffects.writesVault'),
        writesCapabilityVault: requireFalse(sideEffects.writesCapabilityVault, 'safe preset patch import plan.sideEffects.writesCapabilityVault'),
        createsCapability: requireFalse(sideEffects.createsCapability, 'safe preset patch import plan.sideEffects.createsCapability'),
        createsAccountSlots: requireFalse(sideEffects.createsAccountSlots, 'safe preset patch import plan.sideEffects.createsAccountSlots'),
        createsBrowserProfiles: requireFalse(sideEffects.createsBrowserProfiles, 'safe preset patch import plan.sideEffects.createsBrowserProfiles'),
        launches: requireFalse(sideEffects.launches, 'safe preset patch import plan.sideEffects.launches')
    }
}

function normalizePlanPlanned(value) {
    const planned = requireObject(value, 'safe preset patch import plan.planned')
    rejectUnknownKeys(planned, PLAN_PLANNED_KEYS, 'safe preset patch import plan.planned')
    return {
        presets: normalizeCount(planned.presets, 'safe preset patch import plan.planned.presets'),
        newBrowserItems: normalizeCount(planned.newBrowserItems, 'safe preset patch import plan.planned.newBrowserItems'),
        selectionMetadata: normalizeCount(planned.selectionMetadata, 'safe preset patch import plan.planned.selectionMetadata')
    }
}

function normalizeImportPlan(input) {
    const plan = requireObject(input, 'safe preset patch import plan')
    rejectUnknownKeys(plan, TOP_LEVEL_PLAN_KEYS, 'safe preset patch import plan')
    if (plan.success !== true) fail('safe preset patch import plan.success must be true.')
    if (plan.importPlanVersion !== SAFE_PRESET_PATCH_IMPORT_PLAN_VERSION) {
        fail('safe preset patch import plan version is not supported.')
    }
    if (plan.source !== 'safe-preset-patch') fail('safe preset patch import plan.source is not supported.')

    const snapshot = requireObject(plan.snapshot, 'safe preset patch import plan.snapshot')
    rejectUnknownKeys(snapshot, PLAN_SNAPSHOT_KEYS, 'safe preset patch import plan.snapshot')
    const presetPlans = normalizeArray(
        plan.presetPlans,
        'safe preset patch import plan.presetPlans',
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresets,
        { required: true }
    ).map(normalizePlanPreset)
    const newBrowserItems = normalizeArray(
        plan.newBrowserItems,
        'safe preset patch import plan.newBrowserItems',
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxBrowserItems,
        { required: true }
    ).map(normalizePlanBrowserItem)
    const warnings = normalizeArray(plan.warnings, 'safe preset patch import plan.warnings', 32)
        .map((warning, index) => normalizeString(warning, `safe preset patch import plan.warnings[${index}]`, {
            max: 300
        }))
    const seenPresets = new Set()
    for (const preset of presetPlans) addUnique(seenPresets, preset.presetId, 'safe preset patch import plan.presetPlans')
    const seenNewItems = new Set()
    for (const item of newBrowserItems) addUnique(seenNewItems, item.id, 'safe preset patch import plan.newBrowserItems')
    return {
        success: true,
        importPlanVersion: SAFE_PRESET_PATCH_IMPORT_PLAN_VERSION,
        source: 'safe-preset-patch',
        schemaVersion: normalizeCount(plan.schemaVersion, 'safe preset patch import plan.schemaVersion'),
        patchId: normalizeSafeId(plan.patchId, 'safe preset patch import plan.patchId', ['patch_']),
        patchRevisionId: normalizeSafeId(plan.patchRevisionId, 'safe preset patch import plan.patchRevisionId', ['patchrev_']),
        baseSnapshotRevisionId: normalizeSafeId(plan.baseSnapshotRevisionId, 'safe preset patch import plan.baseSnapshotRevisionId', ['srev_']),
        authorDeviceId: normalizeSafeId(plan.authorDeviceId, 'safe preset patch import plan.authorDeviceId', ['dev_']),
        createdAt: normalizeTimestamp(plan.createdAt, 'safe preset patch import plan.createdAt'),
        updatedAt: normalizeTimestamp(plan.updatedAt, 'safe preset patch import plan.updatedAt'),
        snapshot: {
            snapshotId: normalizeSafeId(snapshot.snapshotId, 'safe preset patch import plan.snapshot.snapshotId', ['snap_']),
            revisionId: normalizeSafeId(snapshot.revisionId, 'safe preset patch import plan.snapshot.revisionId', ['srev_']),
            sourceDeviceId: normalizeSafeId(snapshot.sourceDeviceId, 'safe preset patch import plan.snapshot.sourceDeviceId', ['dev_'])
        },
        selection: normalizePlanSelection(plan.selection),
        newBrowserItems,
        presetPlans,
        sideEffects: normalizePlanSideEffects(plan.sideEffects),
        planned: normalizePlanPlanned(plan.planned),
        warnings
    }
}

function comparePresetPrevious(previous, snapshotPreset) {
    return JSON.stringify(canonicalize(previous)) === JSON.stringify(canonicalize({
        name: snapshotPreset.name,
        order: snapshotPreset.order,
        enabled: snapshotPreset.enabled,
        itemRefs: snapshotPreset.itemRefs
    }))
}

function validatePlanAgainstSnapshot(plan, snapshot) {
    const conflicts = []
    const snapshotPresetById = indexById(snapshot.presets)
    const snapshotItemById = indexById(snapshot.availableItems)
    const newBrowserById = indexById(plan.newBrowserItems)
    const accountIds = new Set(snapshot.availableItems.filter(item => item.type === 'account-intention').map(item => item.id))
    const profileIds = new Set(snapshot.availableItems.filter(item => item.type === 'profile-intention').map(item => item.id))
    const newBrowserRefCounts = new Map(plan.newBrowserItems.map(item => [item.id, 0]))

    if (plan.baseSnapshotRevisionId !== snapshot.revisionId) {
        conflicts.push(conflict('stale-base', 'Patch base revision does not match the current sanitized snapshot revision.', {
            expectedRevisionId: snapshot.revisionId,
            actualRevisionId: plan.baseSnapshotRevisionId
        }))
    }
    if (plan.snapshot.revisionId !== snapshot.revisionId) {
        conflicts.push(conflict('snapshot-mismatch', 'Import plan was not built for the current sanitized snapshot revision.', {
            expectedRevisionId: snapshot.revisionId,
            actualRevisionId: plan.snapshot.revisionId
        }))
    }

    for (const item of plan.newBrowserItems) {
        if (snapshotItemById.has(item.id)) {
            conflicts.push(conflict('duplicate-new-browser-id', 'New browser item id already exists in the current sanitized snapshot.', {
                itemId: item.id
            }))
        }
        if (item.accountIntentionId && !accountIds.has(item.accountIntentionId)) {
            conflicts.push(conflict('unknown-account-intention', 'New browser item references an unknown account intention.', {
                itemId: item.id,
                accountIntentionId: item.accountIntentionId
            }))
        }
        if (item.profileIntentionId && !profileIds.has(item.profileIntentionId)) {
            conflicts.push(conflict('unknown-profile-intention', 'New browser item references an unknown profile intention.', {
                itemId: item.id,
                profileIntentionId: item.profileIntentionId
            }))
        }
    }

    if (plan.selection?.defaultPresetId && !snapshotPresetById.has(plan.selection.defaultPresetId)) {
        conflicts.push(conflict('unknown-default-preset', 'Default preset selection references an unknown preset.', {
            presetId: plan.selection.defaultPresetId
        }))
    }
    if (plan.selection?.nextPresetId && !snapshotPresetById.has(plan.selection.nextPresetId)) {
        conflicts.push(conflict('unknown-next-preset', 'Next preset selection references an unknown preset.', {
            presetId: plan.selection.nextPresetId
        }))
    }

    for (const presetPlan of plan.presetPlans) {
        const snapshotPreset = snapshotPresetById.get(presetPlan.presetId)
        if (!snapshotPreset) {
            conflicts.push(conflict('unknown-preset', 'Patch references an unknown preset.', {
                presetId: presetPlan.presetId
            }))
            continue
        }
        if (!comparePresetPrevious(presetPlan.previous, snapshotPreset)) {
            conflicts.push(conflict('preset-stale', 'Patch preset previous state does not match the current sanitized snapshot.', {
                presetId: presetPlan.presetId
            }))
        }

        const seenRefs = new Set()
        for (const ref of presetPlan.next.itemRefs) {
            if (seenRefs.has(ref.itemId)) {
                conflicts.push(conflict('duplicate-item-ref', 'Patch preset contains a duplicate safe item reference.', {
                    presetId: presetPlan.presetId,
                    itemId: ref.itemId
                }))
                continue
            }
            seenRefs.add(ref.itemId)

            const snapshotItem = snapshotItemById.get(ref.itemId)
            const newBrowserItem = newBrowserById.get(ref.itemId)
            const item = snapshotItem || newBrowserItem
            if (newBrowserItem) {
                newBrowserRefCounts.set(ref.itemId, (newBrowserRefCounts.get(ref.itemId) || 0) + 1)
            }
            if (!item) {
                conflicts.push(conflict('unknown-safe-item', 'Patch references an unknown safe item id.', {
                    presetId: presetPlan.presetId,
                    itemId: ref.itemId
                }))
                continue
            }
            if (snapshotItem && (snapshotItem.type !== ref.itemType || snapshotItem.source !== ref.itemSource)) {
                conflicts.push(conflict('safe-item-mismatch', 'Patch safe item type/source does not match the current sanitized snapshot.', {
                    presetId: presetPlan.presetId,
                    itemId: ref.itemId
                }))
            }
            if (newBrowserItem && (!ref.newBrowserItem || ref.itemType !== 'browser-tab' || ref.itemSource !== 'phone-patch')) {
                conflicts.push(conflict('new-browser-item-mismatch', 'Patch new browser item reference is not browser-tab metadata.', {
                    presetId: presetPlan.presetId,
                    itemId: ref.itemId
                }))
            }
            if (!newBrowserItem && ref.newBrowserItem) {
                conflicts.push(conflict('stale-new-browser-reference', 'Patch marks an existing snapshot item as a new browser item.', {
                    presetId: presetPlan.presetId,
                    itemId: ref.itemId
                }))
            }
            if ((ref.itemType === 'desktop-app' || ref.itemType === 'host-folder') && !snapshotItem) {
                conflicts.push(conflict('desktop-authority-not-published', 'Desktop app and host folder refs must point to already-published safe item ids.', {
                    presetId: presetPlan.presetId,
                    itemId: ref.itemId
                }))
            }
            if ((ref.accountIntentionId || ref.profileIntentionId) && ref.itemType !== 'browser-tab') {
                conflicts.push(conflict('intention-on-non-browser-item', 'Account/profile intention mappings are only allowed on browser tabs.', {
                    presetId: presetPlan.presetId,
                    itemId: ref.itemId
                }))
            }
            if (ref.accountIntentionId && !accountIds.has(ref.accountIntentionId)) {
                conflicts.push(conflict('unknown-account-intention', 'Patch item reference points at an unknown account intention.', {
                    presetId: presetPlan.presetId,
                    itemId: ref.itemId,
                    accountIntentionId: ref.accountIntentionId
                }))
            }
            if (ref.profileIntentionId && !profileIds.has(ref.profileIntentionId)) {
                conflicts.push(conflict('unknown-profile-intention', 'Patch item reference points at an unknown profile intention.', {
                    presetId: presetPlan.presetId,
                    itemId: ref.itemId,
                    profileIntentionId: ref.profileIntentionId
                }))
            }
        }
    }
    for (const [itemId, count] of newBrowserRefCounts.entries()) {
        if (count !== 1) {
            conflicts.push(conflict('new-browser-reference-count', 'Patch new browser items must be referenced by exactly one preset item ref.', {
                itemId,
                references: count
            }))
        }
    }
    return conflicts
}

function normalizeExistingMergedBrowserItem(value, index) {
    const item = normalizePlanBrowserItem({
        ...value,
        type: 'browser-tab',
        source: 'phone-patch',
        metadataOnly: true,
        createsCapability: false,
        createsDesktopAppAuthority: false,
        createsHostFolderAuthority: false,
        launchable: false
    }, index)
    return item
}

function existingMergedBrowserItems(workspace) {
    const metadata = workspace?.[WORKSPACE_SAFE_PRESET_METADATA_KEY]
    if (!isPlainObject(metadata) || metadata.version !== SAFE_PRESET_METADATA_VERSION) return []
    return normalizeArray(
        metadata.newBrowserItems,
        `${WORKSPACE_SAFE_PRESET_METADATA_KEY}.newBrowserItems`,
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxBrowserItems
    ).map(normalizeExistingMergedBrowserItem)
}

function metadataRefFromSnapshotRef(ref) {
    return {
        id: ref.id,
        itemId: ref.itemId,
        order: ref.order,
        enabled: ref.enabled,
        ...(ref.accountIntentionId ? { accountIntentionId: ref.accountIntentionId } : {}),
        ...(ref.profileIntentionId ? { profileIntentionId: ref.profileIntentionId } : {}),
        metadataOnly: true
    }
}

function metadataRefFromPlanRef(ref, presetId, existingRefsByItemId, index) {
    const existingRef = existingRefsByItemId.get(ref.itemId)
    return {
        id: existingRef?.id || deterministicRefId({
            presetId,
            itemId: ref.itemId,
            order: ref.order,
            index
        }),
        itemId: ref.itemId,
        order: ref.order,
        enabled: ref.enabled,
        ...(ref.accountIntentionId ? { accountIntentionId: ref.accountIntentionId } : {}),
        ...(ref.profileIntentionId ? { profileIntentionId: ref.profileIntentionId } : {}),
        metadataOnly: true
    }
}

function buildMergedPresetMetadata({ plan, snapshot, workspace, mergedAt }) {
    const planByPresetId = indexById(plan.presetPlans.map(entry => ({ id: entry.presetId, entry })))
    const planNewBrowserIds = new Set(plan.newBrowserItems.map(item => item.id))
    const browserItemById = new Map()
    const accountIds = new Set(snapshot.availableItems.filter(item => item.type === 'account-intention').map(item => item.id))
    const profileIds = new Set(snapshot.availableItems.filter(item => item.type === 'profile-intention').map(item => item.id))
    for (const item of existingMergedBrowserItems(workspace)) browserItemById.set(item.id, item)
    for (const item of plan.newBrowserItems) browserItemById.set(item.id, item)

    const presets = snapshot.presets.map((preset) => {
        const planEntry = planByPresetId.get(preset.id)?.entry
        if (!planEntry) {
            return {
                id: preset.id,
                name: preset.name,
                order: preset.order,
                enabled: preset.enabled,
                itemRefs: preset.itemRefs.map(metadataRefFromSnapshotRef),
                metadataOnly: true
            }
        }
        const existingRefsByItemId = indexById(preset.itemRefs.map(ref => ({ id: ref.itemId, ref })))
        return {
            id: preset.id,
            name: planEntry.next.name,
            order: planEntry.next.order,
            enabled: planEntry.next.enabled,
            itemRefs: planEntry.next.itemRefs.map((ref, index) => metadataRefFromPlanRef(
                ref,
                preset.id,
                new Map([...existingRefsByItemId.entries()].map(([key, value]) => [key, value.ref])),
                index
            )),
            metadataOnly: true
        }
    })

    const referencedPatchItems = new Set()
    for (const preset of presets) {
        for (const ref of preset.itemRefs) {
            if (ref.itemId.startsWith('patch_item_')) referencedPatchItems.add(ref.itemId)
        }
    }
    const newBrowserItems = [...referencedPatchItems]
        .sort()
        .map(itemId => {
            const item = browserItemById.get(itemId)
            if (!item) fail(`Merged preset metadata references missing browser item metadata: ${itemId}`)
            if (item.accountIntentionId && !accountIds.has(item.accountIntentionId)) {
                fail(`Merged browser item references an unknown account intention: ${itemId}`)
            }
            if (item.profileIntentionId && !profileIds.has(item.profileIntentionId)) {
                fail(`Merged browser item references an unknown profile intention: ${itemId}`)
            }
            return {
                id: item.id,
                type: 'browser-tab',
                source: 'phone-patch',
                url: item.url,
                label: item.label,
                notes: item.notes,
                enabled: item.enabled,
                ...(item.accountIntentionId ? { accountIntentionId: item.accountIntentionId } : {}),
                ...(item.profileIntentionId ? { profileIntentionId: item.profileIntentionId } : {}),
                metadataOnly: true
            }
        })

    return {
        version: SAFE_PRESET_METADATA_VERSION,
        metadataOnly: true,
        source: 'safe-preset-patch-merge',
        lastMergedPatchId: plan.patchId,
        lastMergedPatchRevisionId: plan.patchRevisionId,
        baseSnapshotRevisionId: plan.baseSnapshotRevisionId,
        mergedAt,
        selection: plan.selection
            ? {
                defaultPresetId: plan.selection.defaultPresetId,
                nextPresetId: plan.selection.nextPresetId,
                metadataOnly: true,
                selectionKind: 'metadata-only'
            }
            : {
                defaultPresetId: snapshot.selection.defaultPresetId,
                nextPresetId: snapshot.selection.nextPresetId,
                metadataOnly: true,
                selectionKind: 'metadata-only'
            },
        presets: presets.sort((a, b) => a.order - b.order || a.name.localeCompare(b.name)),
        newBrowserItems,
        _planNewBrowserIds: planNewBrowserIds
    }
}

function summarizeAppliedChanges(plan, metadata) {
    const changes = []
    for (const presetPlan of plan.presetPlans) {
        const fields = Object.entries(presetPlan.changes)
            .filter(([, changed]) => changed)
            .map(([field]) => field)
            .sort()
        changes.push({
            type: 'preset',
            presetId: presetPlan.presetId,
            fields,
            itemRefs: presetPlan.next.itemRefs.length,
            metadataOnly: true
        })
    }
    for (const item of plan.newBrowserItems) {
        changes.push({
            type: 'browser-tab',
            itemId: item.id,
            metadataOnly: true
        })
    }
    if (plan.selection) {
        changes.push({
            type: 'selection',
            defaultPresetId: metadata.selection.defaultPresetId,
            nextPresetId: metadata.selection.nextPresetId,
            metadataOnly: true,
            authorizesLaunch: false
        })
    }
    return changes
}

function assertCapabilityVaultPreserved(beforeWorkspace, afterWorkspace) {
    const before = clone(beforeWorkspace?.[WORKSPACE_CAPABILITY_VAULT_KEY] || null)
    const after = clone(afterWorkspace?.[WORKSPACE_CAPABILITY_VAULT_KEY] || null)
    if (JSON.stringify(canonicalize(before)) !== JSON.stringify(canonicalize(after))) {
        fail('Safe preset patch merge attempted to change launch capability vault records.')
    }
}

function persistVaultAndMeta(deps, { vault, meta, operation }) {
    deps.commitVaultMeta({ vault, meta, operation })
}

async function resolveCurrentSnapshot({ sanitizedSnapshot, snapshotBuilder, deps, workspace }) {
    if (sanitizedSnapshot) return normalizeCurrentSnapshot(sanitizedSnapshot)
    if (typeof snapshotBuilder === 'function') {
        return normalizeCurrentSnapshot(await snapshotBuilder({ workspace: clone(workspace) }))
    }
    if (typeof deps.buildCurrentSanitizedSnapshot === 'function') {
        return normalizeCurrentSnapshot(await deps.buildCurrentSanitizedSnapshot({ workspace: clone(workspace) }))
    }
    fail('Current sanitized snapshot is required before safe preset patch merge.')
}

function statusForError(err) {
    return /session is locked|vault is locked|locked vault|unlock required/i.test(err?.message || '') ? 'locked' : 'rejected'
}

function publicErrorResult(err) {
    const status = statusForError(err)
    return baseResult(status, {
        error: err?.message || 'Safe preset patch merge failed.',
        sideEffects: sideEffectsNone()
    })
}

export async function mergeSafePresetPatchPlanAfterUnlock({
    importPlan,
    patch,
    sanitizedSnapshot,
    snapshotBuilder,
    callerContext,
    deps,
    now = Date.now
} = {}) {
    try {
        requireUnlockedCallerContext(callerContext)
        const mergeDeps = requireObject(deps, 'safe preset patch merge deps')
        if (typeof mergeDeps.requireActiveSession !== 'function') fail('Safe preset patch merge requires requireActiveSession.')
        if (typeof mergeDeps.loadActiveVaultWorkspace !== 'function') fail('Safe preset patch merge requires loadActiveVaultWorkspace.')
        if (typeof mergeDeps.loadVaultMeta !== 'function') fail('Safe preset patch merge requires loadVaultMeta.')
        if (typeof mergeDeps.getDriveInfo !== 'function') fail('Safe preset patch merge requires getDriveInfo.')
        if (typeof mergeDeps.getActiveMasterPassword !== 'function') fail('Safe preset patch merge requires getActiveMasterPassword.')
        if (typeof mergeDeps.encryptVault !== 'function') fail('Safe preset patch merge requires encryptVault.')
        if (typeof mergeDeps.commitVaultMeta !== 'function') {
            fail('Safe preset patch merge requires transactional commitVaultMeta.')
        }

        mergeDeps.requireActiveSession()
        const workspace = clone(mergeDeps.loadActiveVaultWorkspace())
        const currentSnapshot = await resolveCurrentSnapshot({
            sanitizedSnapshot,
            snapshotBuilder,
            deps: mergeDeps,
            workspace
        })
        const plan = patch
            ? normalizeImportPlan(planSafePresetPatchImport({ sanitizedSnapshot: currentSnapshot, patch }))
            : normalizeImportPlan(importPlan)
        const conflicts = validatePlanAgainstSnapshot(plan, currentSnapshot)
        if (conflicts.length > 0) {
            return baseResult('conflict', {
                patchId: plan.patchId,
                patchRevisionId: plan.patchRevisionId,
                baseSnapshotRevisionId: plan.baseSnapshotRevisionId,
                currentSnapshotRevisionId: currentSnapshot.revisionId,
                conflicts
            })
        }

        const mergedAtValue = typeof now === 'function' ? now() : now
        const mergedAt = new Date(mergedAtValue).toISOString()
        const metadata = buildMergedPresetMetadata({
            plan,
            snapshot: currentSnapshot,
            workspace,
            mergedAt
        })
        delete metadata._planNewBrowserIds
        const nextWorkspace = {
            ...workspace,
            [WORKSPACE_SAFE_PRESET_METADATA_KEY]: metadata
        }
        assertCapabilityVaultPreserved(workspace, nextWorkspace)

        const driveInfo = await mergeDeps.getDriveInfo()
        const payload = {
            ...nextWorkspace,
            _honeyToken: mergeDeps.honeyToken
        }
        const encryptedVault = mergeDeps.encryptVault(
            payload,
            mergeDeps.getActiveMasterPassword(),
            driveInfo.driveType === 3
        )
        persistVaultAndMeta(mergeDeps, {
            vault: encryptedVault,
            meta: mergeDeps.loadVaultMeta() || { version: '1.0.0' },
            operation: 'safe-preset-patch-merge'
        })

        return baseResult('merged', {
            patchId: plan.patchId,
            patchRevisionId: plan.patchRevisionId,
            baseSnapshotRevisionId: plan.baseSnapshotRevisionId,
            currentSnapshotRevisionId: currentSnapshot.revisionId,
            appliedChanges: summarizeAppliedChanges(plan, metadata),
            sideEffects: sideEffectsNone({ writesVault: true })
        })
    } catch (err) {
        return publicErrorResult(err)
    }
}
