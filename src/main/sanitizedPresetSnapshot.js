import { createHmac } from 'crypto'
import { validateCloudDraft } from './cloudDraftSchema.js'
import { normalizeAccountSlots } from './accountSlots.js'
import { createCapabilityStore } from './capabilityStore.js'
import {
    WORKSPACE_CAPABILITY_VAULT_KEY,
    workspaceEntryHasRawLaunchAuthority
} from './workspaceCapabilityMigration.js'
import {
    SAFE_PRESET_METADATA_VERSION,
    WORKSPACE_SAFE_PRESET_METADATA_KEY
} from './safePresetMetadata.js'

export const SANITIZED_PRESET_SNAPSHOT_SCHEMA_VERSION = 1
export const SANITIZED_PRESET_SNAPSHOT_KIND = 'sanitized-preset-snapshot'

export const SANITIZED_PRESET_SNAPSHOT_LIMITS = Object.freeze({
    maxSnapshotJsonBytes: 256 * 1024,
    maxPresets: 25,
    maxPresetItemRefs: 256,
    maxAvailableItems: 256,
    maxBrowserItems: 64,
    maxDesktopItems: 64,
    maxAccountIntentions: 16,
    maxProfileIntentions: 8,
    maxPresetNameLength: 80,
    maxItemLabelLength: 80,
    maxAccountIdentifierHintLength: 160,
    maxIdLength: 64
})

const MIN_SAFE_ID_SECRET_BYTES = 32

const SAFE_ID_DOMAINS = Object.freeze({
    snapshot: { prefix: 'snap_', maxLength: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength },
    revision: { prefix: 'srev_', maxLength: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength },
    'source-device': { prefix: 'dev_', maxLength: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength },
    preset: { prefix: 'preset_', maxLength: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength },
    item: { prefix: 'item_', maxLength: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength },
    'preset-item-ref': { prefix: 'pref_', maxLength: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength },
    'account-intention': { prefix: 'accti_', maxLength: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength },
    'profile-intention': { prefix: 'profi_', maxLength: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength }
})

const TOP_LEVEL_KEYS = new Set([
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
const SELECTION_KEYS = new Set(['defaultPresetId', 'nextPresetId', 'metadataOnly', 'selectionKind'])
const PRESET_KEYS = new Set(['id', 'name', 'order', 'enabled', 'itemRefs'])
const PRESET_ITEM_REF_KEYS = new Set([
    'id',
    'itemId',
    'order',
    'enabled',
    'accountIntentionId',
    'profileIntentionId',
    'metadataOnly'
])
const AVAILABLE_ITEM_KEYS = new Set([
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
const SAFE_PRESET_METADATA_KEYS = new Set([
    'version',
    'metadataOnly',
    'source',
    'lastMergedPatchId',
    'lastMergedPatchRevisionId',
    'baseSnapshotRevisionId',
    'mergedAt',
    'selection',
    'presets',
    'newBrowserItems'
])
const SAFE_PRESET_METADATA_SELECTION_KEYS = new Set(['defaultPresetId', 'nextPresetId', 'metadataOnly', 'selectionKind'])
const SAFE_PRESET_METADATA_PRESET_KEYS = new Set(['id', 'name', 'order', 'enabled', 'itemRefs', 'metadataOnly'])
const SAFE_PRESET_METADATA_REF_KEYS = new Set([
    'id',
    'itemId',
    'order',
    'enabled',
    'accountIntentionId',
    'profileIntentionId',
    'metadataOnly'
])
const SAFE_PRESET_METADATA_BROWSER_ITEM_KEYS = new Set([
    'id',
    'type',
    'source',
    'url',
    'label',
    'notes',
    'enabled',
    'accountIntentionId',
    'profileIntentionId',
    'metadataOnly'
])

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
    'path',
    'command',
    'script',
    'registry',
    'process',
    'pid',
    'shell',
    'session',
    'browserprofiledata',
    'rawbrowser',
    'launch',
    'args',
    'userargs',
    'manifest',
    'storage',
    'shortcut'
]
const RAW_ACCOUNT_SLOT_ID_PATTERN = /\bacct_[a-f0-9]{32,64}\b/i
const CAPABILITY_ID_PATTERN = /\bcap_[a-f0-9]{32,64}\b/i
const MAX_TIMESTAMP = 8_640_000_000_000_000

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

function normalizeSecret(secret) {
    let bytes = null
    if (Buffer.isBuffer(secret)) {
        bytes = Buffer.from(secret)
    } else if (typeof secret === 'string') {
        bytes = Buffer.from(secret, 'utf8')
    } else if (ArrayBuffer.isView(secret)) {
        bytes = Buffer.from(secret.buffer, secret.byteOffset, secret.byteLength)
    }
    if (!bytes || bytes.length < MIN_SAFE_ID_SECRET_BYTES) {
        fail('snapshotSafeIdSecret is required and must contain at least 32 bytes.')
    }
    return bytes
}

function normalizeRequiredString(value, fieldName, max = 256) {
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    if (value.includes('\0') || /[\r\n]/.test(value)) fail(`${fieldName} contains unsupported control characters.`)
    const text = value.trim()
    if (!text) fail(`${fieldName} is required.`)
    if (text.length > max) fail(`${fieldName} is too long.`)
    return text
}

function normalizeTimestamp(value) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > MAX_TIMESTAMP) {
        fail('snapshot.timestamp must be a non-negative timestamp.')
    }
    return Math.floor(value)
}

function normalizeBoolean(value, defaultValue = false) {
    if (value == null) return defaultValue
    if (typeof value !== 'boolean') fail('Snapshot boolean fields must be booleans.')
    return value
}

function normalizeOrder(value, fallback) {
    if (value == null || value === '') return fallback
    if (!Number.isSafeInteger(value) || value < 0) fail('Snapshot order fields must be non-negative integers.')
    return value
}

function canonicalize(value) {
    if (Array.isArray(value)) return value.map(canonicalize)
    if (isPlainObject(value)) {
        const next = {}
        for (const key of Object.keys(value).sort()) next[key] = canonicalize(value[key])
        return next
    }
    if (value === undefined) return null
    return value
}

function deriveSafeId(secret, domain, material) {
    const config = SAFE_ID_DOMAINS[domain]
    if (!config) fail(`Unsupported safe id domain: ${domain}`)
    const digest = createHmac('sha256', secret)
        .update(`wipesnap.phase18.${domain}.v1\0`)
        .update(JSON.stringify(canonicalize(material)))
        .digest('base64url')
        .slice(0, 32)
    const id = `${config.prefix}${digest}`
    if (id.length > config.maxLength || !/^[A-Za-z][A-Za-z0-9_-]+$/.test(id)) {
        fail(`Generated ${domain} id is invalid.`)
    }
    return id
}

function normalizedKey(value) {
    return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '')
}

function looksLikeForbiddenField(key) {
    const normalized = normalizedKey(key)
    return SECRET_FIELD_MARKERS.some(marker => normalized.includes(marker)) ||
        AUTHORITY_FIELD_MARKERS.some(marker => normalized.includes(marker))
}

function looksLikeSecretString(value) {
    return /\b(?:password|passcode|backup\s*code|cookie|oauth|refresh[_\s-]*token|access[_\s-]*token|id[_\s-]*token|token|credential|secret|pin|fastboot|hidden[_\s-]*master)\b\s*[:=]/i.test(value) ||
        /\bbearer\s+[A-Za-z0-9._~+/-]{16,}/i.test(value) ||
        /\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b/i.test(value) ||
        /\bAIza[A-Za-z0-9_-]{20,}\b/.test(value) ||
        /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/.test(value)
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

function hasDangerousStringMaterial(value) {
    return looksLikeSecretString(value) ||
        looksLikeWindowsPathString(value) ||
        looksLikeRegistryString(value) ||
        looksLikeProcessSelector(value) ||
        looksLikeShellCommand(value) ||
        looksLikeExecutableReference(value) ||
        CAPABILITY_ID_PATTERN.test(value) ||
        RAW_ACCOUNT_SLOT_ID_PATTERN.test(value)
}

function safeText(value, fallback, {
    max = SANITIZED_PRESET_SNAPSHOT_LIMITS.maxItemLabelLength,
    required = true
} = {}) {
    if (typeof value !== 'string') return required ? fallback : ''
    if (value.includes('\0')) return required ? fallback : ''
    let text = value.normalize('NFC').replace(/\r\n?/g, '\n')
    if (/[\u0000-\u001F\u007F]/.test(text)) return required ? fallback : ''
    text = text.trim()
    if (!text) return required ? fallback : ''
    if (text.length > max) text = text.slice(0, max).trim()
    if (!text || hasDangerousStringMaterial(text)) return required ? fallback : ''
    return text
}

function normalizePublicBrowserUrl(value) {
    try {
        const draft = validateCloudDraft({
            product: 'wipesnap',
            schemaVersion: 1,
            draftId: 'snapshot_url_check',
            revisionId: 'snapshot_url_check_rev',
            baseRevisionId: null,
            authorDeviceId: 'snapshot_url_check_device',
            name: 'Snapshot URL Check',
            notes: '',
            isDefault: false,
            accountSlots: [],
            browserProfileSlots: [],
            browserTabs: [{
                id: 'snapshot_url_check_tab',
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
        return ''
    }
}

function hostnameLabel(url) {
    try {
        return safeText(new URL(url).hostname, 'Browser Tab')
    } catch (_) {
        return 'Browser Tab'
    }
}

function normalizeProfileSlots(value) {
    if (value == null) return []
    if (!Array.isArray(value)) fail('browserProfileSlots must be an array.')
    if (value.length > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxProfileIntentions) {
        fail('browserProfileSlots exceeds the sanitized snapshot limit.')
    }
    const seen = new Set()
    return value.map((slot, index) => {
        const profile = requireObject(slot, `browserProfileSlots[${index}]`)
        const id = normalizeRequiredString(String(profile.id || ''), `browserProfileSlots[${index}].id`, 160)
        if (seen.has(id)) fail('browserProfileSlots contains a duplicate id.')
        seen.add(id)
        const provider = safeText(profile.provider || 'google', 'google', { max: 40 }).toLowerCase()
        if (!PROVIDERS.has(provider)) fail(`browserProfileSlots[${index}].provider is not supported.`)
        return {
            id,
            provider,
            label: safeText(profile.label, 'Browser Profile', {
                max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxItemLabelLength
            })
        }
    })
}

function sortedEntries(items) {
    return items
        .map((item, index) => ({ item, index }))
        .sort((a, b) => {
            const orderA = Number.isSafeInteger(a.item?.order) ? a.item.order : a.index
            const orderB = Number.isSafeInteger(b.item?.order) ? b.item.order : b.index
            return orderA - orderB || a.index - b.index
        })
}

function assertArrayLimit(value, fieldName, max) {
    if (value == null) return []
    if (!Array.isArray(value)) fail(`${fieldName} must be an array.`)
    if (value.length > max) fail(`${fieldName} exceeds the sanitized snapshot limit.`)
    return value
}

function createCapabilityReader(capabilityVault) {
    try {
        return createCapabilityStore({ vaultValue: capabilityVault || null })
    } catch (_) {
        fail('snapshot capability vault is malformed.')
    }
}

function addUniqueValue(seen, value, fieldName) {
    if (seen.has(value)) fail(`${fieldName} contains a duplicate generated id.`)
    seen.add(value)
}

function addSourceKey(sourceIndex, key, itemId) {
    if (!key) return
    if (sourceIndex.has(key) && sourceIndex.get(key) !== itemId) {
        fail('Snapshot item source references produced conflicting safe ids.')
    }
    sourceIndex.set(key, itemId)
}

function normalizeSafeMetadataId(value, fieldName, prefixes, { nullable = false } = {}) {
    if (value == null || value === '') {
        if (nullable) return null
        fail(`${fieldName} is required.`)
    }
    const id = normalizeRequiredString(value, fieldName, SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength)
    if (!/^[A-Za-z][A-Za-z0-9_-]+$/.test(id)) fail(`${fieldName} must be a safe id.`)
    if (CAPABILITY_ID_PATTERN.test(id) || RAW_ACCOUNT_SLOT_ID_PATTERN.test(id)) {
        fail(`${fieldName} cannot use a raw authority id shape.`)
    }
    if (!prefixes.some(prefix => id.startsWith(prefix))) {
        fail(`${fieldName} must use an allowed safe id prefix.`)
    }
    return id
}

function normalizeSafeMetadataOptionalIntentionId(value, fieldName, prefix) {
    if (value == null || value === '') return ''
    return normalizeSafeMetadataId(value, fieldName, [prefix])
}

function normalizeSafeMetadataOrder(value, fieldName) {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${fieldName} must be a non-negative integer.`)
    return value
}

function normalizeSafeMetadataBoolean(value, fieldName, defaultValue = true) {
    if (value == null) return defaultValue
    if (typeof value !== 'boolean') fail(`${fieldName} must be a boolean.`)
    return value
}

function addMergedSafeBrowserItems(metadata, availableItems) {
    const values = assertArrayLimit(
        metadata.newBrowserItems,
        `${WORKSPACE_SAFE_PRESET_METADATA_KEY}.newBrowserItems`,
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxBrowserItems
    )
    const itemIds = new Set(availableItems.map(item => item.id))
    const accountIds = new Set(availableItems.filter(item => item.type === 'account-intention').map(item => item.id))
    const profileIds = new Set(availableItems.filter(item => item.type === 'profile-intention').map(item => item.id))
    const newItems = []
    for (const [index, input] of values.entries()) {
        const fieldName = `${WORKSPACE_SAFE_PRESET_METADATA_KEY}.newBrowserItems[${index}]`
        const item = requireObject(input, fieldName)
        assertAllowedKeys(item, SAFE_PRESET_METADATA_BROWSER_ITEM_KEYS, fieldName)
        if (item.metadataOnly !== true) fail(`${fieldName}.metadataOnly must be true.`)
        if (item.type != null && item.type !== 'browser-tab') fail(`${fieldName}.type must be browser-tab.`)
        if (item.source != null && item.source !== 'phone-patch') fail(`${fieldName}.source must be phone-patch.`)
        const id = normalizeSafeMetadataId(item.id, `${fieldName}.id`, ['patch_item_'])
        addUniqueValue(itemIds, id, `${WORKSPACE_SAFE_PRESET_METADATA_KEY}.newBrowserItems`)
        const safeUrl = normalizePublicBrowserUrl(item.url)
        if (!safeUrl || safeUrl !== item.url) fail(`${fieldName}.url is not an accepted public browser URL.`)
        const accountIntentionId = normalizeSafeMetadataOptionalIntentionId(item.accountIntentionId, `${fieldName}.accountIntentionId`, 'accti_')
        const profileIntentionId = normalizeSafeMetadataOptionalIntentionId(item.profileIntentionId, `${fieldName}.profileIntentionId`, 'profi_')
        if (accountIntentionId && !accountIds.has(accountIntentionId)) {
            fail(`${fieldName}.accountIntentionId references an unknown account intention.`)
        }
        if (profileIntentionId && !profileIds.has(profileIntentionId)) {
            fail(`${fieldName}.profileIntentionId references an unknown profile intention.`)
        }
        const label = safeText(item.label, hostnameLabel(safeUrl), {
            max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxItemLabelLength
        })
        newItems.push({
            id,
            type: 'browser-tab',
            label,
            status: item.enabled === false ? 'disabled' : 'available',
            source: 'browser',
            url: safeUrl
        })
    }
    if (availableItems.length + newItems.length > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxAvailableItems) {
        fail('availableItems exceeds the sanitized snapshot limit.')
    }
    availableItems.push(...newItems)
}

function normalizeSafePresetMetadataSelection(value, presetIds) {
    const selection = value == null ? {} : requireObject(value, `${WORKSPACE_SAFE_PRESET_METADATA_KEY}.selection`)
    assertAllowedKeys(selection, SAFE_PRESET_METADATA_SELECTION_KEYS, `${WORKSPACE_SAFE_PRESET_METADATA_KEY}.selection`)
    if (selection.metadataOnly != null && selection.metadataOnly !== true) {
        fail(`${WORKSPACE_SAFE_PRESET_METADATA_KEY}.selection.metadataOnly must be true.`)
    }
    if (selection.selectionKind != null && selection.selectionKind !== 'metadata-only') {
        fail(`${WORKSPACE_SAFE_PRESET_METADATA_KEY}.selection.selectionKind must be metadata-only.`)
    }
    const defaultPresetId = normalizeSafeMetadataId(selection.defaultPresetId, `${WORKSPACE_SAFE_PRESET_METADATA_KEY}.selection.defaultPresetId`, ['preset_'], {
        nullable: true
    })
    const nextPresetId = normalizeSafeMetadataId(selection.nextPresetId, `${WORKSPACE_SAFE_PRESET_METADATA_KEY}.selection.nextPresetId`, ['preset_'], {
        nullable: true
    })
    if (defaultPresetId && !presetIds.has(defaultPresetId)) {
        fail(`${WORKSPACE_SAFE_PRESET_METADATA_KEY}.selection.defaultPresetId references an unknown preset.`)
    }
    if (nextPresetId && !presetIds.has(nextPresetId)) {
        fail(`${WORKSPACE_SAFE_PRESET_METADATA_KEY}.selection.nextPresetId references an unknown preset.`)
    }
    return {
        defaultPresetId,
        nextPresetId,
        metadataOnly: true,
        selectionKind: 'metadata-only'
    }
}

function buildMergedSafePresetEntries(metadata, availableItems) {
    const values = assertArrayLimit(
        metadata.presets,
        `${WORKSPACE_SAFE_PRESET_METADATA_KEY}.presets`,
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresets
    )
    const itemIds = new Set(availableItems.map(item => item.id))
    const accountIds = new Set(availableItems.filter(item => item.type === 'account-intention').map(item => item.id))
    const profileIds = new Set(availableItems.filter(item => item.type === 'profile-intention').map(item => item.id))
    const seenPresetIds = new Set()
    return values.map((presetInput, presetIndex) => {
        const fieldName = `${WORKSPACE_SAFE_PRESET_METADATA_KEY}.presets[${presetIndex}]`
        const preset = requireObject(presetInput, fieldName)
        assertAllowedKeys(preset, SAFE_PRESET_METADATA_PRESET_KEYS, fieldName)
        if (preset.metadataOnly !== true) fail(`${fieldName}.metadataOnly must be true.`)
        const id = normalizeSafeMetadataId(preset.id, `${fieldName}.id`, ['preset_'])
        addUniqueValue(seenPresetIds, id, `${WORKSPACE_SAFE_PRESET_METADATA_KEY}.presets`)
        const refs = assertArrayLimit(
            preset.itemRefs,
            `${fieldName}.itemRefs`,
            SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetItemRefs
        )
        const seenRefIds = new Set()
        const seenItemIds = new Set()
        const itemRefs = refs.map((refInput, refIndex) => {
            const refFieldName = `${fieldName}.itemRefs[${refIndex}]`
            const ref = requireObject(refInput, refFieldName)
            assertAllowedKeys(ref, SAFE_PRESET_METADATA_REF_KEYS, refFieldName)
            if (ref.metadataOnly !== true) fail(`${refFieldName}.metadataOnly must be true.`)
            const itemId = normalizeSafeMetadataId(ref.itemId, `${refFieldName}.itemId`, ['item_', 'accti_', 'profi_', 'patch_item_'])
            if (!itemIds.has(itemId)) fail(`${refFieldName}.itemId references an unknown safe item.`)
            addUniqueValue(seenItemIds, itemId, `${fieldName}.itemRefs`)
            const accountIntentionId = normalizeSafeMetadataOptionalIntentionId(ref.accountIntentionId, `${refFieldName}.accountIntentionId`, 'accti_')
            const profileIntentionId = normalizeSafeMetadataOptionalIntentionId(ref.profileIntentionId, `${refFieldName}.profileIntentionId`, 'profi_')
            if (accountIntentionId && !accountIds.has(accountIntentionId)) {
                fail(`${refFieldName}.accountIntentionId references an unknown account intention.`)
            }
            if (profileIntentionId && !profileIds.has(profileIntentionId)) {
                fail(`${refFieldName}.profileIntentionId references an unknown profile intention.`)
            }
            const refId = ref.id
                ? normalizeSafeMetadataId(ref.id, `${refFieldName}.id`, ['pref_'])
                : deriveSafeId(Buffer.from(id), 'preset-item-ref', {
                    presetId: id,
                    itemId,
                    order: ref.order ?? refIndex
                })
            addUniqueValue(seenRefIds, refId, `${fieldName}.itemRefs`)
            return {
                id: refId,
                itemId,
                order: normalizeSafeMetadataOrder(ref.order, `${refFieldName}.order`),
                enabled: normalizeSafeMetadataBoolean(ref.enabled, `${refFieldName}.enabled`, true),
                ...(accountIntentionId ? { accountIntentionId } : {}),
                ...(profileIntentionId ? { profileIntentionId } : {}),
                metadataOnly: true
            }
        })
        return {
            rawKey: id,
            preset: {
                id,
                name: safeText(preset.name, `Preset ${presetIndex + 1}`, {
                    max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetNameLength
                }),
                order: normalizeSafeMetadataOrder(preset.order, `${fieldName}.order`),
                enabled: normalizeSafeMetadataBoolean(preset.enabled, `${fieldName}.enabled`, true),
                itemRefs
            }
        }
    })
}

function normalizeMergedSafePresetMetadata(value, availableItems) {
    if (value == null) return null
    const metadata = requireObject(value, WORKSPACE_SAFE_PRESET_METADATA_KEY)
    assertAllowedKeys(metadata, SAFE_PRESET_METADATA_KEYS, WORKSPACE_SAFE_PRESET_METADATA_KEY)
    if (metadata.version !== SAFE_PRESET_METADATA_VERSION) {
        fail(`${WORKSPACE_SAFE_PRESET_METADATA_KEY}.version is not supported.`)
    }
    if (metadata.metadataOnly !== true) fail(`${WORKSPACE_SAFE_PRESET_METADATA_KEY}.metadataOnly must be true.`)
    addMergedSafeBrowserItems(metadata, availableItems)
    const presetEntries = buildMergedSafePresetEntries(metadata, availableItems)
    const presetIds = new Set(presetEntries.map(entry => entry.preset.id))
    return {
        presetEntries,
        selection: normalizeSafePresetMetadataSelection(metadata.selection, presetIds)
    }
}

function desktopItemTypeForRecord(record) {
    if (record?.type === 'host-folder' || record?.type === 'shell-execute') return 'host-folder'
    return 'desktop-app'
}

function buildAvailableItems({
    workspace,
    accountSlots,
    profileSlots,
    capabilityStore,
    secret
}) {
    const availableItems = []
    const itemIdSeen = new Set()
    const sourceIndex = new Map()
    const browserRows = []
    const desktopRows = []
    const accountIdByRaw = new Map()
    const profileIdByRaw = new Map()

    const webTabs = assertArrayLimit(
        workspace.webTabs,
        'workspace.webTabs',
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxBrowserItems
    )
    const desktopApps = assertArrayLimit(
        workspace.desktopApps,
        'workspace.desktopApps',
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxDesktopItems
    )

    for (const { item: tab, index } of sortedEntries(webTabs)) {
        const value = isPlainObject(tab) ? tab : {}
        const safeUrl = normalizePublicBrowserUrl(value.url)
        const rawKey = value.id != null && value.id !== ''
            ? `browser-id:${String(value.id)}`
            : `browser-index:${index}`
        const itemId = deriveSafeId(secret, 'item', {
            itemType: 'browser-tab',
            rawKey,
            url: safeUrl || null
        })
        addUniqueValue(itemIdSeen, itemId, 'availableItems')
        const status = safeUrl
            ? value.enabled === false ? 'disabled' : 'available'
            : 'redacted'
        const label = safeText(value.label || value.title, safeUrl ? hostnameLabel(safeUrl) : 'Browser Tab')
        const itemRecord = {
            id: itemId,
            type: 'browser-tab',
            label,
            status,
            source: 'browser',
            ...(safeUrl ? { url: safeUrl } : {})
        }
        availableItems.push(itemRecord)
        browserRows.push({ raw: value, rawKey, itemId, index, status })
        addSourceKey(sourceIndex, `browser-index:${index}`, itemId)
        if (value.id != null && value.id !== '') addSourceKey(sourceIndex, `browser-id:${String(value.id)}`, itemId)
    }

    for (const { item: app, index } of sortedEntries(desktopApps)) {
        const value = isPlainObject(app) ? app : {}
        let record = null
        let broken = false
        if (value.capabilityId) {
            try {
                record = capabilityStore.read(value.capabilityId)
                broken = !record
            } catch (_) {
                broken = true
            }
        } else {
            broken = true
        }

        const type = desktopItemTypeForRecord(record)
        const rawKey = value.capabilityId
            ? `capability:${String(value.capabilityId)}`
            : value.id != null && value.id !== ''
                ? `desktop-id:${String(value.id)}`
                : `desktop-index:${index}`
        const itemId = deriveSafeId(secret, 'item', {
            itemType: type,
            rawKey
        })
        addUniqueValue(itemIdSeen, itemId, 'availableItems')
        const hasRawAuthority = workspaceEntryHasRawLaunchAuthority(value)
        const status = broken || value.quarantined === true || (!value.capabilityId && hasRawAuthority)
            ? 'broken'
            : value.enabled === false ? 'disabled' : 'available'
        const fallback = type === 'host-folder' ? 'Folder' : 'Desktop App'
        const label = safeText(value.displayName || value.name || record?.displayName, fallback)
        availableItems.push({
            id: itemId,
            type,
            label,
            status,
            source: 'desktop'
        })
        desktopRows.push({ raw: value, rawKey, itemId, index, status })
        addSourceKey(sourceIndex, `desktop-index:${index}`, itemId)
        if (value.id != null && value.id !== '') addSourceKey(sourceIndex, `desktop-id:${String(value.id)}`, itemId)
        if (value.capabilityId) addSourceKey(sourceIndex, `capability:${String(value.capabilityId)}`, itemId)
    }

    for (const slot of accountSlots) {
        const safeId = deriveSafeId(secret, 'account-intention', {
            accountSlotId: slot.id
        })
        addUniqueValue(itemIdSeen, safeId, 'availableItems')
        accountIdByRaw.set(slot.id, safeId)
        availableItems.push({
            id: safeId,
            type: 'account-intention',
            label: safeText(slot.label, 'Account'),
            status: 'available',
            source: 'account',
            provider: slot.provider,
            identifierHint: safeText(slot.identifierHint, '', {
                max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxAccountIdentifierHintLength,
                required: false
            }),
            state: ACCOUNT_STATES.has(slot.state) ? slot.state : 'unknown',
            metadataOnly: true
        })
        addSourceKey(sourceIndex, `account:${slot.id}`, safeId)
    }

    for (const profile of profileSlots) {
        const safeId = deriveSafeId(secret, 'profile-intention', {
            profileSlotId: profile.id
        })
        addUniqueValue(itemIdSeen, safeId, 'availableItems')
        profileIdByRaw.set(profile.id, safeId)
        availableItems.push({
            id: safeId,
            type: 'profile-intention',
            label: profile.label,
            status: 'available',
            source: 'profile',
            provider: profile.provider,
            metadataOnly: true
        })
        addSourceKey(sourceIndex, `profile:${profile.id}`, safeId)
    }

    if (availableItems.length > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxAvailableItems) {
        fail('availableItems exceeds the sanitized snapshot limit.')
    }

    return {
        availableItems,
        browserRows,
        desktopRows,
        accountIdByRaw,
        profileIdByRaw,
        sourceIndex
    }
}

function createPresetItemRef({
    secret,
    presetRawKey,
    sourceKind,
    rawKey,
    itemId,
    raw,
    order,
    accountIdByRaw,
    profileIdByRaw
}) {
    const refId = deriveSafeId(secret, 'preset-item-ref', {
        presetRawKey,
        sourceKind,
        rawKey,
        order
    })
    const accountRawId = raw?.accountSlotId || raw?.accountIntentionId || ''
    const profileRawId = raw?.profileSlotId || raw?.profileIntentionId || ''
    return {
        id: refId,
        itemId,
        order,
        enabled: normalizeBoolean(raw?.enabled, true),
        ...(accountIdByRaw.has(accountRawId) ? { accountIntentionId: accountIdByRaw.get(accountRawId) } : {}),
        ...(profileIdByRaw.has(profileRawId) ? { profileIntentionId: profileIdByRaw.get(profileRawId) } : {}),
        metadataOnly: true
    }
}

function defaultPresetRawKey(workspace) {
    if (workspace?.presetId != null && workspace.presetId !== '') return `preset-id:${String(workspace.presetId)}`
    if (workspace?.id != null && workspace.id !== '') return `workspace-id:${String(workspace.id)}`
    return 'workspace-current'
}

function buildCurrentWorkspacePreset({
    workspace,
    browserRows,
    desktopRows,
    accountIdByRaw,
    profileIdByRaw,
    secret
}) {
    const rawKey = defaultPresetRawKey(workspace)
    const id = deriveSafeId(secret, 'preset', {
        presetRawKey: rawKey
    })
    const itemRefs = []
    const refIds = new Set()
    let order = 0

    for (const row of browserRows) {
        const ref = createPresetItemRef({
            secret,
            presetRawKey: rawKey,
            sourceKind: 'browser',
            rawKey: row.rawKey,
            itemId: row.itemId,
            raw: row.raw,
            order,
            accountIdByRaw,
            profileIdByRaw
        })
        addUniqueValue(refIds, ref.id, 'preset.itemRefs')
        itemRefs.push(ref)
        order += 1
    }

    for (const row of desktopRows) {
        const ref = createPresetItemRef({
            secret,
            presetRawKey: rawKey,
            sourceKind: 'desktop',
            rawKey: row.rawKey,
            itemId: row.itemId,
            raw: row.raw,
            order,
            accountIdByRaw,
            profileIdByRaw
        })
        addUniqueValue(refIds, ref.id, 'preset.itemRefs')
        itemRefs.push(ref)
        order += 1
    }

    if (itemRefs.length > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetItemRefs) {
        fail('preset.itemRefs exceeds the sanitized snapshot limit.')
    }

    return {
        rawKey,
        preset: {
            id,
            name: safeText(workspace?.name, 'Current Workspace', {
                max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetNameLength
            }),
            order: 0,
            enabled: normalizeBoolean(workspace?.enabled, true),
            itemRefs
        }
    }
}

function resolveSourceItemId(ref, sourceIndex) {
    if (!isPlainObject(ref)) return ''
    if (ref.capabilityId) return sourceIndex.get(`capability:${String(ref.capabilityId)}`) || ''
    if (ref.desktopAppId != null && ref.desktopAppId !== '') return sourceIndex.get(`desktop-id:${String(ref.desktopAppId)}`) || ''
    if (ref.browserTabId != null && ref.browserTabId !== '') return sourceIndex.get(`browser-id:${String(ref.browserTabId)}`) || ''
    if (ref.accountSlotId != null && ref.accountSlotId !== '') return sourceIndex.get(`account:${String(ref.accountSlotId)}`) || ''
    if (ref.profileSlotId != null && ref.profileSlotId !== '') return sourceIndex.get(`profile:${String(ref.profileSlotId)}`) || ''
    if (Number.isSafeInteger(ref.desktopIndex)) return sourceIndex.get(`desktop-index:${ref.desktopIndex}`) || ''
    if (Number.isSafeInteger(ref.browserIndex)) return sourceIndex.get(`browser-index:${ref.browserIndex}`) || ''
    return ''
}

function buildExplicitPresets({
    presets,
    sourceIndex,
    accountIdByRaw,
    profileIdByRaw,
    secret
}) {
    const values = assertArrayLimit(
        presets,
        'presets',
        SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresets
    )
    const seenPresetIds = new Set()
    return values.map((presetInput, presetIndex) => {
        const preset = requireObject(presetInput, `presets[${presetIndex}]`)
        const rawKey = preset.id != null && preset.id !== ''
            ? `preset-id:${String(preset.id)}`
            : `preset-index:${presetIndex}`
        const id = deriveSafeId(secret, 'preset', { presetRawKey: rawKey })
        addUniqueValue(seenPresetIds, id, 'presets')
        const refs = assertArrayLimit(
            preset.itemRefs || preset.items || [],
            `presets[${presetIndex}].itemRefs`,
            SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetItemRefs
        )
        const refIds = new Set()
        const itemRefs = refs.map((refInput, refIndex) => {
            const ref = requireObject(refInput, `presets[${presetIndex}].itemRefs[${refIndex}]`)
            const itemId = resolveSourceItemId(ref, sourceIndex)
            if (!itemId) fail('Preset item reference is missing, stale, or unavailable.')
            const order = normalizeOrder(ref.order, refIndex)
            const refId = deriveSafeId(secret, 'preset-item-ref', {
                presetRawKey: rawKey,
                refIndex,
                itemId,
                order
            })
            addUniqueValue(refIds, refId, 'preset.itemRefs')
            const accountRawId = ref.accountSlotId || ''
            const profileRawId = ref.profileSlotId || ''
            return {
                id: refId,
                itemId,
                order,
                enabled: normalizeBoolean(ref.enabled, true),
                ...(accountIdByRaw.has(accountRawId) ? { accountIntentionId: accountIdByRaw.get(accountRawId) } : {}),
                ...(profileIdByRaw.has(profileRawId) ? { profileIntentionId: profileIdByRaw.get(profileRawId) } : {}),
                metadataOnly: true
            }
        })
        return {
            rawKey,
            preset: {
                id,
                name: safeText(preset.name, `Preset ${presetIndex + 1}`, {
                    max: SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresetNameLength
                }),
                order: normalizeOrder(preset.order, presetIndex),
                enabled: normalizeBoolean(preset.enabled, true),
                itemRefs
            }
        }
    })
}

function resolveSelectionId(value, presetIdByRawKey) {
    if (value == null || value === '') return null
    const direct = String(value)
    for (const rawKey of [
        direct,
        `preset-id:${direct}`,
        `workspace-id:${direct}`
    ]) {
        if (presetIdByRawKey.has(rawKey)) return presetIdByRawKey.get(rawKey)
    }
    return null
}

function assertAllowedKeys(value, allowedKeys, fieldName) {
    for (const key of Object.keys(value || {})) {
        if (!allowedKeys.has(key)) fail(`${fieldName}.${key} is not part of the sanitized snapshot schema.`)
    }
}

function assertSafeId(value, prefix, fieldName) {
    if (typeof value !== 'string' || !value.startsWith(prefix) || value.length > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxIdLength) {
        fail(`${fieldName} must be a safe ${prefix} id.`)
    }
}

function assertSnapshotShape(snapshot) {
    assertAllowedKeys(snapshot, TOP_LEVEL_KEYS, 'snapshot')
    assertSafeId(snapshot.snapshotId, 'snap_', 'snapshot.snapshotId')
    assertSafeId(snapshot.revisionId, 'srev_', 'snapshot.revisionId')
    if (snapshot.baseRevisionId != null) assertSafeId(snapshot.baseRevisionId, 'srev_', 'snapshot.baseRevisionId')
    assertSafeId(snapshot.sourceDeviceId, 'dev_', 'snapshot.sourceDeviceId')
    assertAllowedKeys(snapshot.selection, SELECTION_KEYS, 'snapshot.selection')
    if (snapshot.selection.defaultPresetId != null) assertSafeId(snapshot.selection.defaultPresetId, 'preset_', 'snapshot.selection.defaultPresetId')
    if (snapshot.selection.nextPresetId != null) assertSafeId(snapshot.selection.nextPresetId, 'preset_', 'snapshot.selection.nextPresetId')

    for (const [key, value] of Object.entries(SANITIZED_PRESET_SNAPSHOT_LIMITS)) {
        if (snapshot.limits[key] !== value) fail(`snapshot.limits.${key} is invalid.`)
    }

    const itemIds = new Set()
    const presetIds = new Set()
    for (const item of snapshot.availableItems) {
        assertAllowedKeys(item, AVAILABLE_ITEM_KEYS, 'snapshot.availableItems[]')
        if (!ITEM_TYPES.has(item.type)) fail('snapshot.availableItems[].type is invalid.')
        if (!ITEM_STATUSES.has(item.status)) fail('snapshot.availableItems[].status is invalid.')
        if (!ITEM_SOURCES.has(item.source)) fail('snapshot.availableItems[].source is invalid.')
        if (item.type === 'account-intention' || item.type === 'profile-intention') {
            if (item.metadataOnly !== true) fail('Snapshot intentions must be metadata only.')
        }
        addUniqueValue(itemIds, item.id, 'snapshot.availableItems')
    }

    for (const preset of snapshot.presets) {
        assertAllowedKeys(preset, PRESET_KEYS, 'snapshot.presets[]')
        assertSafeId(preset.id, 'preset_', 'snapshot.presets[].id')
        addUniqueValue(presetIds, preset.id, 'snapshot.presets')
        const refIds = new Set()
        for (const ref of preset.itemRefs) {
            assertAllowedKeys(ref, PRESET_ITEM_REF_KEYS, 'snapshot.presets[].itemRefs[]')
            assertSafeId(ref.id, 'pref_', 'snapshot.presets[].itemRefs[].id')
            if (!itemIds.has(ref.itemId)) fail('snapshot preset item reference points at an unknown safe item.')
            addUniqueValue(refIds, ref.id, 'snapshot.presets[].itemRefs')
            if (ref.metadataOnly !== true) fail('Snapshot preset item references must be metadata only.')
        }
    }
}

function assertNoForbiddenSnapshotMaterial(value, path = 'snapshot') {
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoForbiddenSnapshotMaterial(item, `${path}[${index}]`))
        return
    }
    if (isPlainObject(value)) {
        for (const [key, nested] of Object.entries(value)) {
            if (looksLikeForbiddenField(key)) fail(`${path}.${key} is forbidden in sanitized snapshots.`)
            assertNoForbiddenSnapshotMaterial(nested, `${path}.${key}`)
        }
        return
    }
    if (typeof value === 'string' && path.endsWith('.url')) {
        if (normalizePublicBrowserUrl(value) !== value) fail(`${path} is not an accepted public browser URL.`)
        return
    }
    if (typeof value === 'string' && hasDangerousStringMaterial(value)) {
        fail(`${path} contains forbidden snapshot material.`)
    }
}

function jsonByteLength(value) {
    return Buffer.byteLength(JSON.stringify(value), 'utf8')
}

export function buildSanitizedPresetSnapshot(input = {}) {
    const options = requireObject(input, 'sanitized snapshot input')
    const secret = normalizeSecret(options.snapshotSafeIdSecret)
    const workspace = isPlainObject(options.workspace) ? options.workspace : {}
    const sourceDeviceMaterial = normalizeRequiredString(options.sourceDeviceId, 'sourceDeviceId')
    const snapshotMaterial = normalizeRequiredString(options.snapshotId, 'snapshotId')
    const revisionMaterial = normalizeRequiredString(options.revisionId, 'revisionId')
    const baseRevisionMaterial = options.baseRevisionId == null || options.baseRevisionId === ''
        ? null
        : normalizeRequiredString(options.baseRevisionId, 'baseRevisionId')
    const timestamp = normalizeTimestamp(options.timestamp)
    const capabilityVault = options.capabilityVault || workspace[WORKSPACE_CAPABILITY_VAULT_KEY] || null
    const capabilityStore = createCapabilityReader(capabilityVault)
    const accountSlots = normalizeAccountSlots(options.accountSlots || workspace.accountSlots || [])
    if (accountSlots.length > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxAccountIntentions) {
        fail('accountSlots exceeds the sanitized snapshot limit.')
    }
    const profileSlots = normalizeProfileSlots(options.browserProfileSlots || workspace.browserProfileSlots || [])

    const {
        availableItems,
        browserRows,
        desktopRows,
        accountIdByRaw,
        profileIdByRaw,
        sourceIndex
    } = buildAvailableItems({
        workspace,
        accountSlots,
        profileSlots,
        capabilityStore,
        secret
    })

    const mergedSafePresetMetadata = options.presets
        ? null
        : normalizeMergedSafePresetMetadata(workspace[WORKSPACE_SAFE_PRESET_METADATA_KEY], availableItems)

    const presetEntries = mergedSafePresetMetadata?.presetEntries || (Array.isArray(options.presets || workspace.presets)
        ? buildExplicitPresets({
            presets: options.presets || workspace.presets,
            sourceIndex,
            accountIdByRaw,
            profileIdByRaw,
            secret
        })
        : [buildCurrentWorkspacePreset({
            workspace,
            browserRows,
            desktopRows,
            accountIdByRaw,
            profileIdByRaw,
            secret
        })]
    )

    if (presetEntries.length > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxPresets) {
        fail('presets exceeds the sanitized snapshot limit.')
    }

    const presetIdByRawKey = new Map()
    for (const entry of presetEntries) {
        if (presetIdByRawKey.has(entry.rawKey)) fail('presets contains duplicate source ids.')
        presetIdByRawKey.set(entry.rawKey, entry.preset.id)
    }

    const defaultPresetRaw = options.defaultPresetId ?? workspace.defaultPresetId ?? presetEntries.find(entry => entry.preset.enabled)?.rawKey ?? presetEntries[0]?.rawKey ?? null
    const nextPresetRaw = options.nextPresetId ?? workspace.nextPresetId ?? null
    const selection = mergedSafePresetMetadata?.selection || {
        defaultPresetId: resolveSelectionId(defaultPresetRaw, presetIdByRawKey),
        nextPresetId: resolveSelectionId(nextPresetRaw, presetIdByRawKey),
        metadataOnly: true,
        selectionKind: 'metadata-only'
    }
    const snapshot = {
        product: 'wipesnap',
        kind: SANITIZED_PRESET_SNAPSHOT_KIND,
        schemaVersion: SANITIZED_PRESET_SNAPSHOT_SCHEMA_VERSION,
        snapshotId: deriveSafeId(secret, 'snapshot', { snapshotId: snapshotMaterial }),
        revisionId: deriveSafeId(secret, 'revision', { revisionId: revisionMaterial }),
        ...(baseRevisionMaterial ? { baseRevisionId: deriveSafeId(secret, 'revision', { revisionId: baseRevisionMaterial }) } : {}),
        sourceDeviceId: deriveSafeId(secret, 'source-device', { sourceDeviceId: sourceDeviceMaterial }),
        timestamp,
        limits: { ...SANITIZED_PRESET_SNAPSHOT_LIMITS },
        selection,
        presets: presetEntries
            .map(entry => entry.preset)
            .sort((a, b) => a.order - b.order || a.name.localeCompare(b.name)),
        availableItems
    }

    assertSnapshotShape(snapshot)
    assertNoForbiddenSnapshotMaterial(snapshot)
    if (jsonByteLength(snapshot) > SANITIZED_PRESET_SNAPSHOT_LIMITS.maxSnapshotJsonBytes) {
        fail('sanitized snapshot exceeds the byte limit.')
    }
    return snapshot
}
