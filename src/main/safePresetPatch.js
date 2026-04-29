import { validateCloudDraft } from './cloudDraftSchema.js'
import {
    SANITIZED_PRESET_SNAPSHOT_KIND,
    SANITIZED_PRESET_SNAPSHOT_LIMITS,
    SANITIZED_PRESET_SNAPSHOT_SCHEMA_VERSION
} from './sanitizedPresetSnapshot.js'

export const SAFE_PRESET_PATCH_SCHEMA_VERSION = 1
export const SAFE_PRESET_PATCH_KIND = 'safe-preset-patch'
export const SAFE_PRESET_PATCH_IMPORT_PLAN_VERSION = 1

export const SAFE_PRESET_PATCH_LIMITS = Object.freeze({
    maxPatchJsonBytes: 256 * 1024,
    maxPresets: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresets,
    maxPresetItemRefs: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetItemRefs,
    maxNewBrowserItems: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxBrowserItems,
    maxPresetNameLength: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetNameLength,
    maxBrowserTabUrlLength: 2048,
    maxBrowserTabLabelLength: 80,
    maxBrowserTabNotesLength: 500,
    maxIdLength: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength
})

const MAX_TIMESTAMP = 8_640_000_000_000_000
const SAFE_ID_PATTERN = /^[A-Za-z][A-Za-z0-9_-]+$/
const CAPABILITY_ID_PATTERN = /\bcap_[a-f0-9]{32,64}\b/i
const RAW_ACCOUNT_SLOT_ID_PATTERN = /\bacct_[a-f0-9]{32,64}\b/i

const TOP_LEVEL_PATCH_KEYS = new Set([
    'product',
    'kind',
    'schemaVersion',
    'patchId',
    'patchRevisionId',
    'baseSnapshotRevisionId',
    'authorDeviceId',
    'createdAt',
    'updatedAt',
    'selection',
    'presets',
    'newBrowserItems'
])
const PATCH_SELECTION_KEYS = new Set(['defaultPresetId', 'nextPresetId', 'metadataOnly', 'selectionKind'])
const PATCH_PRESET_KEYS = new Set(['id', 'name', 'order', 'enabled', 'itemRefs', 'metadataOnly'])
const PATCH_ITEM_REF_KEYS = new Set([
    'itemId',
    'order',
    'enabled',
    'accountIntentionId',
    'profileIntentionId',
    'metadataOnly'
])
const NEW_BROWSER_ITEM_KEYS = new Set([
    'id',
    'url',
    'label',
    'notes',
    'enabled',
    'accountIntentionId',
    'profileIntentionId',
    'metadataOnly'
])

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
const SNAPSHOT_ITEM_REF_KEYS = new Set([
    'id',
    'itemId',
    'order',
    'enabled',
    'accountIntentionId',
    'profileIntentionId',
    'metadataOnly'
])
const SNAPSHOT_AVAILABLE_ITEM_KEYS = new Set([
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
const SNAPSHOT_LIMIT_KEYS = new Set(Object.keys(SANITIZED_PRESET_SNAPSHOT_LIMITS))

const ITEM_TYPES = new Set([
    'browser-tab',
    'desktop-app',
    'host-folder',
    'account-intention',
    'profile-intention'
])
const ITEM_STATUSES = new Set(['available', 'disabled', 'redacted', 'broken'])
const ITEM_SOURCES = new Set(['browser', 'desktop', 'account', 'profile'])
const ACCOUNT_STATES = new Set([
    'unknown',
    'signed-in',
    'needs-recheck',
    'needs-auth',
    'needs-phone-approval',
    'needs-passkey',
    'blocked-or-suspicious',
    'user-action-required'
])
const PROVIDERS = new Set(['google'])

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
    return JSON.parse(JSON.stringify(value))
}

function jsonByteLength(value) {
    return Buffer.byteLength(JSON.stringify(value), 'utf8')
}

function jsonByteLengthForInput(input, fieldName) {
    if (typeof input === 'string') return Buffer.byteLength(input, 'utf8')
    if (Buffer.isBuffer(input)) return input.length
    try {
        const json = JSON.stringify(input)
        if (typeof json !== 'string') fail(`${fieldName} must be JSON data.`)
        return Buffer.byteLength(json, 'utf8')
    } catch (_) {
        fail(`${fieldName} must be JSON-serializable.`)
    }
}

function parseJsonInput(input, fieldName, maxBytes) {
    const bytes = jsonByteLengthForInput(input, fieldName)
    if (bytes > maxBytes) fail(`${fieldName} exceeds the ${maxBytes} byte limit.`)

    if (typeof input === 'string' || Buffer.isBuffer(input)) {
        const text = Buffer.isBuffer(input) ? input.toString('utf8') : input
        try {
            return JSON.parse(text)
        } catch (_) {
            fail(`${fieldName} must be valid JSON.`)
        }
    }

    return input
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
            fail(`${fieldName}.${key} is not accepted because safe preset patches cannot carry secrets, paths, commands, registry, process, vault, browser session, or launch capability material.`)
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
    max,
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
    if (rejectDangerous && hasDangerousStringMaterial(text)) fail(`${fieldName} contains forbidden safe patch material.`)
    return text
}

function normalizeOptionalString(value, fieldName, options = {}) {
    if (value == null || value === '') return ''
    return normalizeString(value, fieldName, options)
}

function normalizeTimestamp(value, fieldName) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > MAX_TIMESTAMP) {
        fail(`${fieldName} must be a non-negative timestamp.`)
    }
    return Math.floor(value)
}

function normalizeOptionalBoolean(value, fieldName) {
    if (typeof value !== 'boolean') fail(`${fieldName} must be a boolean.`)
    return value
}

function normalizeBoolean(value, fieldName, defaultValue = false) {
    if (value == null) return defaultValue
    return normalizeOptionalBoolean(value, fieldName)
}

function normalizeOrder(value, fieldName) {
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

function assertUniqueValues(values, fieldName) {
    const seen = new Set()
    for (const value of values) {
        if (seen.has(value)) fail(`${fieldName} contains a duplicate id.`)
        seen.add(value)
    }
}

function normalizeSafeId(value, fieldName, prefixes, { nullable = false, required = true } = {}) {
    if (value == null || value === '') {
        if (nullable) return null
        if (required) fail(`${fieldName} is required.`)
        return ''
    }
    const id = normalizeString(value, fieldName, {
        required: true,
        max: SAFE_PRESET_PATCH_LIMITS.maxIdLength,
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

function normalizePublicBrowserUrl(value, fieldName) {
    try {
        const draft = validateCloudDraft({
            product: 'wipesnap',
            schemaVersion: 1,
            draftId: 'safe_patch_url_check',
            revisionId: 'safe_patch_url_check_rev',
            baseRevisionId: null,
            authorDeviceId: 'safe_patch_url_check_device',
            name: 'Safe Patch URL Check',
            notes: '',
            isDefault: false,
            accountSlots: [],
            browserProfileSlots: [],
            browserTabs: [{
                id: 'safe_patch_url_check_tab',
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

function assertNoForbiddenMaterial(value, path = 'safe preset patch') {
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoForbiddenMaterial(item, `${path}[${index}]`))
        return
    }
    if (isPlainObject(value)) {
        for (const [key, nested] of Object.entries(value)) {
            if (looksLikeForbiddenField(key)) fail(`${path}.${key} is forbidden in safe preset patches.`)
            assertNoForbiddenMaterial(nested, `${path}.${key}`)
        }
        return
    }
    if (typeof value === 'string' && path.endsWith('.url')) {
        normalizePublicBrowserUrl(value, path)
        return
    }
    if (typeof value === 'string' && hasDangerousStringMaterial(value)) {
        fail(`${path} contains forbidden safe patch material.`)
    }
}

function validateMetadataOnly(value, fieldName) {
    if (value == null) return true
    if (value !== true) fail(`${fieldName} must be true because safe preset patches are metadata only.`)
    return true
}

function validatePatchSelection(value) {
    if (value == null) return null
    const selection = requireObject(value, 'safe preset patch.selection')
    rejectUnknownKeys(selection, PATCH_SELECTION_KEYS, 'safe preset patch.selection')
    validateMetadataOnly(selection.metadataOnly, 'safe preset patch.selection.metadataOnly')
    if (selection.selectionKind != null && selection.selectionKind !== 'metadata-only') {
        fail('safe preset patch.selection.selectionKind must be metadata-only.')
    }
    return {
        defaultPresetId: normalizeSafeId(selection.defaultPresetId, 'safe preset patch.selection.defaultPresetId', ['preset_'], {
            nullable: true,
            required: false
        }),
        nextPresetId: normalizeSafeId(selection.nextPresetId, 'safe preset patch.selection.nextPresetId', ['preset_'], {
            nullable: true,
            required: false
        }),
        metadataOnly: true,
        selectionKind: 'metadata-only'
    }
}

function normalizeOptionalIntentionId(value, fieldName, prefix) {
    if (value == null || value === '') return ''
    return normalizeSafeId(value, fieldName, [prefix], { required: false })
}

function validateNewBrowserItem(value, index) {
    const fieldName = `safe preset patch.newBrowserItems[${index}]`
    const item = requireObject(value, fieldName)
    rejectUnknownKeys(item, NEW_BROWSER_ITEM_KEYS, fieldName)
    validateMetadataOnly(item.metadataOnly, `${fieldName}.metadataOnly`)

    const next = {
        id: normalizeSafeId(item.id, `${fieldName}.id`, ['patch_item_']),
        type: 'browser-tab',
        source: 'phone-patch',
        url: normalizePublicBrowserUrl(item.url, `${fieldName}.url`),
        label: normalizeOptionalString(item.label, `${fieldName}.label`, {
            max: SAFE_PRESET_PATCH_LIMITS.maxBrowserTabLabelLength
        }),
        notes: normalizeOptionalString(item.notes, `${fieldName}.notes`, {
            max: SAFE_PRESET_PATCH_LIMITS.maxBrowserTabNotesLength,
            multiline: true
        }),
        enabled: normalizeBoolean(item.enabled, `${fieldName}.enabled`, true),
        metadataOnly: true,
        createsCapability: false,
        createsDesktopAppAuthority: false,
        createsHostFolderAuthority: false
    }
    if (Object.hasOwn(item, 'accountIntentionId')) {
        next.accountIntentionId = normalizeOptionalIntentionId(item.accountIntentionId, `${fieldName}.accountIntentionId`, 'accti_')
    }
    if (Object.hasOwn(item, 'profileIntentionId')) {
        next.profileIntentionId = normalizeOptionalIntentionId(item.profileIntentionId, `${fieldName}.profileIntentionId`, 'profi_')
    }
    return next
}

function validatePatchItemRef(value, index, presetIndex) {
    const fieldName = `safe preset patch.presets[${presetIndex}].itemRefs[${index}]`
    const ref = requireObject(value, fieldName)
    rejectUnknownKeys(ref, PATCH_ITEM_REF_KEYS, fieldName)
    validateMetadataOnly(ref.metadataOnly, `${fieldName}.metadataOnly`)

    const next = {
        itemId: normalizeSafeId(ref.itemId, `${fieldName}.itemId`, ['item_', 'accti_', 'profi_', 'patch_item_']),
        order: normalizeOrder(ref.order, `${fieldName}.order`),
        enabled: normalizeOptionalBoolean(ref.enabled, `${fieldName}.enabled`),
        metadataOnly: true
    }
    if (Object.hasOwn(ref, 'accountIntentionId')) {
        next.accountIntentionId = normalizeOptionalIntentionId(ref.accountIntentionId, `${fieldName}.accountIntentionId`, 'accti_')
    }
    if (Object.hasOwn(ref, 'profileIntentionId')) {
        next.profileIntentionId = normalizeOptionalIntentionId(ref.profileIntentionId, `${fieldName}.profileIntentionId`, 'profi_')
    }
    return next
}

function validatePatchPreset(value, index) {
    const fieldName = `safe preset patch.presets[${index}]`
    const preset = requireObject(value, fieldName)
    rejectUnknownKeys(preset, PATCH_PRESET_KEYS, fieldName)
    validateMetadataOnly(preset.metadataOnly, `${fieldName}.metadataOnly`)

    const next = {
        id: normalizeSafeId(preset.id, `${fieldName}.id`, ['preset_']),
        metadataOnly: true
    }
    if (Object.hasOwn(preset, 'name')) {
        next.name = normalizeString(preset.name, `${fieldName}.name`, {
            required: true,
            max: SAFE_PRESET_PATCH_LIMITS.maxPresetNameLength
        })
    }
    if (Object.hasOwn(preset, 'order')) next.order = normalizeOrder(preset.order, `${fieldName}.order`)
    if (Object.hasOwn(preset, 'enabled')) next.enabled = normalizeOptionalBoolean(preset.enabled, `${fieldName}.enabled`)
    if (Object.hasOwn(preset, 'itemRefs')) {
        next.itemRefs = normalizeArray(
            preset.itemRefs,
            `${fieldName}.itemRefs`,
            SAFE_PRESET_PATCH_LIMITS.maxPresetItemRefs,
            { required: true }
        ).map((ref, refIndex) => validatePatchItemRef(ref, refIndex, index))
        assertUniqueValues(next.itemRefs.map(ref => ref.itemId), `${fieldName}.itemRefs`)
    }
    return next
}

export function validateSafePresetPatch(input) {
    const rawPatch = parseJsonInput(input, 'safe preset patch JSON', SAFE_PRESET_PATCH_LIMITS.maxPatchJsonBytes)
    const patch = requireObject(rawPatch, 'safe preset patch')
    assertNoForbiddenMaterial(patch)
    rejectUnknownKeys(patch, TOP_LEVEL_PATCH_KEYS, 'safe preset patch')

    const product = normalizeString(patch.product, 'safe preset patch.product', {
        required: true,
        max: 40,
        rejectDangerous: false
    }).toLowerCase()
    if (product !== 'wipesnap') fail('safe preset patch.product is not supported.')
    if (patch.kind !== SAFE_PRESET_PATCH_KIND) fail('safe preset patch.kind is not supported.')
    if (patch.schemaVersion !== SAFE_PRESET_PATCH_SCHEMA_VERSION) fail('safe preset patch.schemaVersion is not supported.')

    const newBrowserItems = normalizeArray(
        patch.newBrowserItems,
        'safe preset patch.newBrowserItems',
        SAFE_PRESET_PATCH_LIMITS.maxNewBrowserItems
    ).map(validateNewBrowserItem)
    assertUniqueValues(newBrowserItems.map(item => item.id), 'safe preset patch.newBrowserItems')

    const presets = normalizeArray(
        patch.presets,
        'safe preset patch.presets',
        SAFE_PRESET_PATCH_LIMITS.maxPresets
    ).map(validatePatchPreset)
    assertUniqueValues(presets.map(preset => preset.id), 'safe preset patch.presets')

    const normalized = {
        product,
        kind: SAFE_PRESET_PATCH_KIND,
        schemaVersion: SAFE_PRESET_PATCH_SCHEMA_VERSION,
        patchId: normalizeSafeId(patch.patchId, 'safe preset patch.patchId', ['patch_']),
        patchRevisionId: normalizeSafeId(patch.patchRevisionId, 'safe preset patch.patchRevisionId', ['patchrev_']),
        baseSnapshotRevisionId: normalizeSafeId(patch.baseSnapshotRevisionId, 'safe preset patch.baseSnapshotRevisionId', ['srev_']),
        authorDeviceId: normalizeSafeId(patch.authorDeviceId, 'safe preset patch.authorDeviceId', ['dev_']),
        createdAt: normalizeTimestamp(patch.createdAt, 'safe preset patch.createdAt'),
        updatedAt: normalizeTimestamp(patch.updatedAt, 'safe preset patch.updatedAt'),
        selection: validatePatchSelection(patch.selection),
        presets,
        newBrowserItems
    }

    if (jsonByteLength(normalized) > SAFE_PRESET_PATCH_LIMITS.maxPatchJsonBytes) {
        fail(`safe preset patch JSON exceeds the ${SAFE_PRESET_PATCH_LIMITS.maxPatchJsonBytes} byte limit.`)
    }
    return normalized
}

function validateSnapshotLimits(value) {
    const limits = requireObject(value, 'sanitized snapshot.limits')
    rejectUnknownKeys(limits, SNAPSHOT_LIMIT_KEYS, 'sanitized snapshot.limits')
    for (const [key, expected] of Object.entries(SANITIZED_PRESET_SNAPSHOT_LIMITS)) {
        if (limits[key] !== expected) fail(`sanitized snapshot.limits.${key} is invalid.`)
    }
    return { ...SANITIZED_PRESET_SNAPSHOT_LIMITS }
}

function validateSnapshotSelection(value) {
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

function expectedSourceForType(type) {
    if (type === 'browser-tab') return 'browser'
    if (type === 'desktop-app' || type === 'host-folder') return 'desktop'
    if (type === 'account-intention') return 'account'
    if (type === 'profile-intention') return 'profile'
    return ''
}

function expectedIdPrefixesForType(type) {
    if (type === 'account-intention') return ['accti_']
    if (type === 'profile-intention') return ['profi_']
    if (type === 'browser-tab') return ['item_', 'patch_item_']
    return ['item_']
}

function validateSnapshotAvailableItem(value, index) {
    const fieldName = `sanitized snapshot.availableItems[${index}]`
    const item = requireObject(value, fieldName)
    rejectUnknownKeys(item, SNAPSHOT_AVAILABLE_ITEM_KEYS, fieldName)
    const type = normalizeString(item.type, `${fieldName}.type`, {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!ITEM_TYPES.has(type)) fail(`${fieldName}.type is invalid.`)
    const source = normalizeString(item.source, `${fieldName}.source`, {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!ITEM_SOURCES.has(source)) fail(`${fieldName}.source is invalid.`)
    if (source !== expectedSourceForType(type)) fail(`${fieldName}.source does not match its type.`)
    const status = normalizeString(item.status, `${fieldName}.status`, {
        required: true,
        max: 40,
        rejectDangerous: false
    })
    if (!ITEM_STATUSES.has(status)) fail(`${fieldName}.status is invalid.`)
    if (item.metadataOnly != null && item.metadataOnly !== true) fail(`${fieldName}.metadataOnly must be true when present.`)
    if ((type === 'account-intention' || type === 'profile-intention') && item.metadataOnly !== true) {
        fail(`${fieldName}.metadataOnly must be true for account/profile intentions.`)
    }

    const next = {
        id: normalizeSafeId(item.id, `${fieldName}.id`, expectedIdPrefixesForType(type)),
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
        if (!PROVIDERS.has(next.provider)) fail(`${fieldName}.provider is not supported.`)
    }
    if (item.identifierHint != null) {
        next.identifierHint = normalizeOptionalString(item.identifierHint, `${fieldName}.identifierHint`, {
            max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxAccountIdentifierHintLength
        })
    }
    if (item.state != null) {
        next.state = normalizeString(item.state, `${fieldName}.state`, {
            required: true,
            max: 80,
            rejectDangerous: false
        })
        if (!ACCOUNT_STATES.has(next.state)) fail(`${fieldName}.state is not supported.`)
    }
    if (item.metadataOnly === true) next.metadataOnly = true
    return next
}

function validateSnapshotItemRef(value, index, presetIndex) {
    const fieldName = `sanitized snapshot.presets[${presetIndex}].itemRefs[${index}]`
    const ref = requireObject(value, fieldName)
    rejectUnknownKeys(ref, SNAPSHOT_ITEM_REF_KEYS, fieldName)
    if (ref.metadataOnly !== true) fail(`${fieldName}.metadataOnly must be true.`)
    const next = {
        id: normalizeSafeId(ref.id, `${fieldName}.id`, ['pref_']),
        itemId: normalizeSafeId(ref.itemId, `${fieldName}.itemId`, ['item_', 'accti_', 'profi_', 'patch_item_']),
        order: normalizeOrder(ref.order, `${fieldName}.order`),
        enabled: normalizeOptionalBoolean(ref.enabled, `${fieldName}.enabled`),
        metadataOnly: true
    }
    if (ref.accountIntentionId != null) {
        next.accountIntentionId = normalizeOptionalIntentionId(ref.accountIntentionId, `${fieldName}.accountIntentionId`, 'accti_')
    }
    if (ref.profileIntentionId != null) {
        next.profileIntentionId = normalizeOptionalIntentionId(ref.profileIntentionId, `${fieldName}.profileIntentionId`, 'profi_')
    }
    return next
}

function validateSnapshotPreset(value, index) {
    const fieldName = `sanitized snapshot.presets[${index}]`
    const preset = requireObject(value, fieldName)
    rejectUnknownKeys(preset, SNAPSHOT_PRESET_KEYS, fieldName)
    const itemRefs = normalizeArray(
        preset.itemRefs,
        `${fieldName}.itemRefs`,
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetItemRefs,
        { required: true }
    ).map((ref, refIndex) => validateSnapshotItemRef(ref, refIndex, index))
    assertUniqueValues(itemRefs.map(ref => ref.id), `${fieldName}.itemRefs`)
    assertUniqueValues(itemRefs.map(ref => ref.itemId), `${fieldName}.itemRefs`)
    return {
        id: normalizeSafeId(preset.id, `${fieldName}.id`, ['preset_']),
        name: normalizeString(preset.name, `${fieldName}.name`, {
            required: true,
            max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetNameLength
        }),
        order: normalizeOrder(preset.order, `${fieldName}.order`),
        enabled: normalizeOptionalBoolean(preset.enabled, `${fieldName}.enabled`),
        itemRefs
    }
}

function validateSanitizedSnapshotForPatchPlanning(input) {
    const rawSnapshot = parseJsonInput(
        input,
        'sanitized snapshot JSON',
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxSnapshotJsonBytes
    )
    const snapshot = requireObject(rawSnapshot, 'sanitized snapshot')
    assertNoForbiddenMaterial(snapshot, 'sanitized snapshot')
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
    ).map(validateSnapshotAvailableItem)
    assertUniqueValues(availableItems.map(item => item.id), 'sanitized snapshot.availableItems')

    const presets = normalizeArray(
        snapshot.presets,
        'sanitized snapshot.presets',
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresets,
        { required: true }
    ).map(validateSnapshotPreset)
    assertUniqueValues(presets.map(preset => preset.id), 'sanitized snapshot.presets')

    const itemIds = new Set(availableItems.map(item => item.id))
    const accountIds = new Set(availableItems.filter(item => item.type === 'account-intention').map(item => item.id))
    const profileIds = new Set(availableItems.filter(item => item.type === 'profile-intention').map(item => item.id))
    for (const preset of presets) {
        for (const ref of preset.itemRefs) {
            if (!itemIds.has(ref.itemId)) fail('sanitized snapshot preset item reference points at an unknown safe item.')
            if (ref.accountIntentionId && !accountIds.has(ref.accountIntentionId)) {
                fail('sanitized snapshot preset item reference points at an unknown account intention.')
            }
            if (ref.profileIntentionId && !profileIds.has(ref.profileIntentionId)) {
                fail('sanitized snapshot preset item reference points at an unknown profile intention.')
            }
        }
    }

    const normalized = {
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
        limits: validateSnapshotLimits(snapshot.limits),
        selection: validateSnapshotSelection(snapshot.selection),
        presets,
        availableItems
    }
    if (jsonByteLength(normalized) > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxSnapshotJsonBytes) {
        fail('sanitized snapshot JSON exceeds the byte limit.')
    }
    return normalized
}

function indexById(items) {
    const map = new Map()
    for (const item of items) map.set(item.id, item)
    return map
}

function assertPatchReferencesSnapshot(patch, snapshot, indexes) {
    if (patch.baseSnapshotRevisionId !== snapshot.revisionId) {
        fail('safe preset patch.baseSnapshotRevisionId does not match the sanitized snapshot revision.')
    }

    if (snapshot.availableItems.length + patch.newBrowserItems.length > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxAvailableItems) {
        fail('safe preset patch would exceed the sanitized snapshot available item limit.')
    }

    for (const item of patch.newBrowserItems) {
        if (indexes.availableItems.has(item.id)) {
            fail('safe preset patch new browser item id already exists in the sanitized snapshot.')
        }
    }

    for (const presetPatch of patch.presets) {
        if (!indexes.presets.has(presetPatch.id)) fail('safe preset patch references an unknown preset id.')
        if (!Object.hasOwn(presetPatch, 'itemRefs')) continue
        for (const ref of presetPatch.itemRefs) {
            if (!indexes.availableItems.has(ref.itemId) && !indexes.newBrowserItems.has(ref.itemId)) {
                fail('safe preset patch references an unknown safe item id.')
            }
        }
    }

    if (patch.selection?.defaultPresetId && !indexes.presets.has(patch.selection.defaultPresetId)) {
        fail('safe preset patch.selection.defaultPresetId references an unknown preset id.')
    }
    if (patch.selection?.nextPresetId && !indexes.presets.has(patch.selection.nextPresetId)) {
        fail('safe preset patch.selection.nextPresetId references an unknown preset id.')
    }
}

function resolveMapping({ ref, existingRef, newBrowserItem, key }) {
    if (Object.hasOwn(ref, key)) {
        const value = ref[key]
        if (newBrowserItem && Object.hasOwn(newBrowserItem, key) && newBrowserItem[key] && value && newBrowserItem[key] !== value) {
            fail(`safe preset patch has conflicting ${key} values for a new browser item.`)
        }
        return value || ''
    }
    if (newBrowserItem && Object.hasOwn(newBrowserItem, key)) return newBrowserItem[key] || ''
    return existingRef?.[key] || ''
}

function assertIntentionMappingAllowed({ item, accountIntentionId, profileIntentionId, indexes }) {
    if (accountIntentionId && !indexes.accountIntentions.has(accountIntentionId)) {
        fail('safe preset patch references an unknown account intention id.')
    }
    if (profileIntentionId && !indexes.profileIntentions.has(profileIntentionId)) {
        fail('safe preset patch references an unknown profile intention id.')
    }
    if ((accountIntentionId || profileIntentionId) && item.type !== 'browser-tab') {
        fail('safe preset patch account/profile mappings are only allowed on browser tabs.')
    }
}

function createPlannedItemRef({ ref, item, existingRef, newBrowserItem, indexes }) {
    const accountIntentionId = resolveMapping({
        ref,
        existingRef,
        newBrowserItem,
        key: 'accountIntentionId'
    })
    const profileIntentionId = resolveMapping({
        ref,
        existingRef,
        newBrowserItem,
        key: 'profileIntentionId'
    })
    assertIntentionMappingAllowed({ item, accountIntentionId, profileIntentionId, indexes })
    return {
        itemId: ref.itemId,
        itemType: item.type,
        itemSource: item.source,
        label: item.label || newBrowserItem?.label || '',
        order: ref.order,
        enabled: ref.enabled,
        accountIntentionId,
        profileIntentionId,
        metadataOnly: true,
        existingSnapshotItem: !newBrowserItem,
        newBrowserItem: !!newBrowserItem,
        createsCapability: false,
        createsDesktopAppAuthority: false,
        createsHostFolderAuthority: false,
        launchable: false
    }
}

function snapshotRefByItemId(preset) {
    const map = new Map()
    for (const ref of preset.itemRefs) map.set(ref.itemId, ref)
    return map
}

function createPresetPlan({ presetPatch, snapshotPreset, indexes, usedNewBrowserItemIds }) {
    const existingRefs = snapshotRefByItemId(snapshotPreset)
    const patchRefs = Object.hasOwn(presetPatch, 'itemRefs')
        ? presetPatch.itemRefs
        : snapshotPreset.itemRefs.map(ref => ({
            itemId: ref.itemId,
            order: ref.order,
            enabled: ref.enabled,
            ...(ref.accountIntentionId ? { accountIntentionId: ref.accountIntentionId } : {}),
            ...(ref.profileIntentionId ? { profileIntentionId: ref.profileIntentionId } : {}),
            metadataOnly: true
        }))

    const itemRefs = patchRefs.map(ref => {
        const newBrowserItem = indexes.newBrowserItems.get(ref.itemId) || null
        if (newBrowserItem) {
            if (usedNewBrowserItemIds.has(ref.itemId)) fail('safe preset patch contains a duplicate new browser item reference.')
            usedNewBrowserItemIds.add(ref.itemId)
        }
        const item = newBrowserItem || indexes.availableItems.get(ref.itemId)
        if (!item) fail('safe preset patch references an unknown safe item id.')
        return createPlannedItemRef({
            ref,
            item,
            existingRef: existingRefs.get(ref.itemId) || null,
            newBrowserItem,
            indexes
        })
    }).map((ref, index) => ({ ref, index }))
        .sort((a, b) => a.ref.order - b.ref.order || a.index - b.index)
        .map(({ ref }) => ref)

    return {
        presetId: presetPatch.id,
        previous: {
            name: snapshotPreset.name,
            order: snapshotPreset.order,
            enabled: snapshotPreset.enabled,
            itemRefs: clone(snapshotPreset.itemRefs)
        },
        next: {
            name: Object.hasOwn(presetPatch, 'name') ? presetPatch.name : snapshotPreset.name,
            order: Object.hasOwn(presetPatch, 'order') ? presetPatch.order : snapshotPreset.order,
            enabled: Object.hasOwn(presetPatch, 'enabled') ? presetPatch.enabled : snapshotPreset.enabled,
            itemRefs
        },
        changes: {
            name: Object.hasOwn(presetPatch, 'name') && presetPatch.name !== snapshotPreset.name,
            order: Object.hasOwn(presetPatch, 'order') && presetPatch.order !== snapshotPreset.order,
            enabled: Object.hasOwn(presetPatch, 'enabled') && presetPatch.enabled !== snapshotPreset.enabled,
            itemRefs: Object.hasOwn(presetPatch, 'itemRefs')
        },
        metadataOnly: true,
        createsCapability: false,
        createsDesktopAppAuthority: false,
        createsHostFolderAuthority: false,
        writesVault: false,
        launches: false
    }
}

function createSelectionPlan(patch) {
    if (!patch.selection) return null
    return {
        defaultPresetId: patch.selection.defaultPresetId,
        nextPresetId: patch.selection.nextPresetId,
        metadataOnly: true,
        selectionKind: 'metadata-only',
        authorizesLaunch: false
    }
}

export function planSafePresetPatchImport(input = {}) {
    const payload = requireObject(input, 'safe preset patch import input')
    const snapshot = validateSanitizedSnapshotForPatchPlanning(payload.sanitizedSnapshot ?? payload.snapshot)
    const patch = validateSafePresetPatch(payload.patch)
    const indexes = {
        availableItems: indexById(snapshot.availableItems),
        presets: indexById(snapshot.presets),
        newBrowserItems: indexById(patch.newBrowserItems),
        accountIntentions: new Set(snapshot.availableItems.filter(item => item.type === 'account-intention').map(item => item.id)),
        profileIntentions: new Set(snapshot.availableItems.filter(item => item.type === 'profile-intention').map(item => item.id))
    }
    assertPatchReferencesSnapshot(patch, snapshot, indexes)

    const usedNewBrowserItemIds = new Set()
    const presetPlans = patch.presets.map(presetPatch => createPresetPlan({
        presetPatch,
        snapshotPreset: indexes.presets.get(presetPatch.id),
        indexes,
        usedNewBrowserItemIds
    }))

    for (const item of patch.newBrowserItems) {
        if (!usedNewBrowserItemIds.has(item.id)) fail('safe preset patch new browser items must be referenced by exactly one preset item ref.')
    }

    return {
        success: true,
        importPlanVersion: SAFE_PRESET_PATCH_IMPORT_PLAN_VERSION,
        source: 'safe-preset-patch',
        schemaVersion: SAFE_PRESET_PATCH_SCHEMA_VERSION,
        patchId: patch.patchId,
        patchRevisionId: patch.patchRevisionId,
        baseSnapshotRevisionId: patch.baseSnapshotRevisionId,
        authorDeviceId: patch.authorDeviceId,
        createdAt: patch.createdAt,
        updatedAt: patch.updatedAt,
        snapshot: {
            snapshotId: snapshot.snapshotId,
            revisionId: snapshot.revisionId,
            sourceDeviceId: snapshot.sourceDeviceId
        },
        selection: createSelectionPlan(patch),
        newBrowserItems: patch.newBrowserItems.map(item => ({
            id: item.id,
            type: 'browser-tab',
            source: 'phone-patch',
            url: item.url,
            label: item.label,
            notes: item.notes,
            enabled: item.enabled,
            accountIntentionId: item.accountIntentionId || '',
            profileIntentionId: item.profileIntentionId || '',
            metadataOnly: true,
            createsCapability: false,
            createsDesktopAppAuthority: false,
            createsHostFolderAuthority: false,
            launchable: false
        })),
        presetPlans,
        sideEffects: {
            writesVault: false,
            writesCapabilityVault: false,
            createsCapability: false,
            createsAccountSlots: false,
            createsBrowserProfiles: false,
            launches: false
        },
        planned: {
            presets: presetPlans.length,
            newBrowserItems: patch.newBrowserItems.length,
            selectionMetadata: patch.selection ? 1 : 0
        },
        warnings: []
    }
}
