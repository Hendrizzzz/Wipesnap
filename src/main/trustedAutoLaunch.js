import { createHash, randomBytes } from 'crypto'
import { existsSync, statSync } from 'fs'
import { join } from 'path'
import { validateCloudDraft } from './cloudDraftSchema.js'
import { validateBrowserUrl } from './ipcValidation.js'
import {
    SAFE_PRESET_METADATA_VERSION,
    WORKSPACE_SAFE_PRESET_METADATA_KEY
} from './safePresetMetadata.js'
import {
    WORKSPACE_CAPABILITY_VAULT_KEY,
    rehydrateWorkspaceLaunchCapabilities,
    workspaceEntryHasRawLaunchAuthority
} from './workspaceCapabilityMigration.js'
import {
    WORKSPACE_HEALTH_STATUSES,
    loadWorkspaceHealthSummary
} from './workspaceHealth.js'

export const TRUSTED_AUTO_LAUNCH_OPERATION = 'trusted-auto-launch'
export const TRUSTED_AUTO_LAUNCH_SETTINGS_KEY = 'trustedAutoLaunch'
export const TRUSTED_AUTO_LAUNCH_STATE_KEY = 'trustedAutoLaunchState'
export const TRUSTED_AUTO_LAUNCH_SETTINGS_VERSION = 1

const DEFAULT_COUNTDOWN_SECONDS = 5
const MIN_COUNTDOWN_SECONDS = 3
const MAX_COUNTDOWN_SECONDS = 30
const MAX_LABEL_LENGTH = 80
const MAX_STATUS_HINTS = 5
const MAX_BLOCKER_CODES = 12
const SAFE_PRESET_ID_PATTERN = /^preset_[A-Za-z0-9_-]{1,56}$/
const SAFE_PATCH_REVISION_ID_PATTERN = /^patchrev_[A-Za-z0-9_-]{1,120}$/
const SAFE_ITEM_ID_PATTERN = /^(?:item_|patch_item_|accti_|profi_)[A-Za-z0-9_-]{1,96}$/
const SAFE_REF_ID_PATTERN = /^pref_[A-Za-z0-9_-]{1,96}$/
const SAFE_TOKEN_PATTERN = /^[a-z][a-z0-9-]{0,80}$/
const HOST_LAUNCH_TYPES = new Set([
    'host-exe',
    'host-folder',
    'registry-uninstall',
    'app-paths',
    'start-menu-shortcut',
    'shell-execute',
    'protocol-uri',
    'packaged-app'
])
const READY_ACCOUNT_STATE = 'signed-in'
const BLOCKING_AUTO_IMPORT_CATEGORIES = new Set([
    'conflict',
    'stale-base',
    'revoked-device',
    'invalid-signature',
    'invalid-key',
    'invalid-patch',
    'forbidden-material',
    'duplicate-patch',
    'schema-invalid',
    'schema-rejected',
    'untrusted-author',
    'unavailable-runtime',
    'not-configured',
    'locked',
    'rejected',
    'transaction-failure',
    'unknown-error',
    'skipped'
])
const NON_TERMINAL_AUTO_IMPORT_CATEGORIES = new Set(['idle', 'scheduled', 'running'])
const CLEAN_AUTO_IMPORT_CATEGORIES = new Set(['no-patches', 'applied'])
const STATUS_CATEGORIES = new Set([
    'idle',
    'disabled',
    'waiting-auto-import',
    'countdown',
    'launching',
    'launched',
    'blocked',
    'canceled',
    'failed'
])
const VOLATILE_LAUNCH_CONFIG_KEYS = new Set([
    'id',
    'resolvedAt',
    'checkedAt',
    'lastCheckedAt',
    'createdAt',
    'updatedAt',
    'timestamp',
    'durationMs',
    'probeCount'
])
const FORBIDDEN_STATUS_TEXT = /https?:\/\/|[?#][A-Za-z0-9_=&%.-]+|deviceSessionToken|bearer\s+|syncRootKey|rootKeyMaterial|privateKey|vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile|AppData[\\/]|cap_[A-Za-z0-9_-]{4,128}|patchrev_[A-Za-z0-9_-]{4,128}|patch_[A-Za-z0-9_-]{4,128}|[A-Za-z]:[\\/]|\\\\|HKEY_|HKLM|HKCU|powershell|taskkill|cmd\s|ciphertext|cloudEnvelope|encryptedEnvelope|importPlan|launchPlan|patchPayload|vaultData|devicePrivateKey|credential|browserSession|launchAuthority|firebase[-_\s]*(api[-_\s]*)?key|firebaseSecret|stack trace|\bat\s+.*:\d+:\d+/i
const URL_LIKE_TEXT = /\b(?:https?:\/\/|www\.|[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:[/?#][^\s]*)?)/gi
const WINDOWS_PATH_TEXT = /(?:^|[\s"'([{])(?:[A-Za-z]:[\\/]|\\\\|\[USB\][\\/])\S*/gi

const RECOVERY_HINTS = Object.freeze({
    disabled: 'Enable trusted auto-launch in advanced personal settings.',
    'auto-import-not-clean': 'Review trusted auto-import before launching automatically.',
    'no-target': 'Choose a local override preset or accept validated selection metadata.',
    'missing-preset': 'Review preset selection before trying again.',
    'disabled-preset': 'Enable the selected preset or choose another target.',
    'stale-preset': 'Refresh the workspace preset metadata before launching.',
    'workspace-health-blocked': 'Open workspace health and resolve the blocking check.',
    'missing-capability': 'Open settings and repair the app capability manually.',
    'missing-browser-profile': 'Save a browser profile before launching tab presets automatically.',
    'account-not-ready': 'Sign in to the required local account slot before launching.',
    'profile-not-ready': 'Select a ready local browser profile before launching.',
    'host-unavailable': 'Install or reconnect the required host app before launching.',
    'active-launch': 'Wait for the current launch to finish.',
    locked: 'Unlock the vault before launching.',
    'author-not-trusted': 'Review trusted devices before launching this synced preset.',
    'token-invalid': 'Start a fresh auto-launch attempt.'
})

function fail(message, code = 'auto-launch-invalid') {
    const error = new Error(message)
    error.code = code
    throw error
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function safeCount(value) {
    return Number.isSafeInteger(value) && value >= 0 ? value : 0
}

function safeToken(value, fallback = 'unknown') {
    if (typeof value !== 'string') return fallback
    const token = value.trim().toLowerCase()
    if (!token || token.length > 80 || FORBIDDEN_STATUS_TEXT.test(token)) return fallback
    return SAFE_TOKEN_PATTERN.test(token) ? token : fallback
}

function safeStatusCategory(value, fallback = 'idle') {
    const token = safeToken(value, fallback)
    return STATUS_CATEGORIES.has(token) ? token : fallback
}

function uniqueTokens(values) {
    return Array.from(new Set((values || []).map(value => safeToken(value, '')).filter(Boolean))).slice(0, MAX_BLOCKER_CODES)
}

function hashValue(value) {
    return createHash('sha256')
        .update(JSON.stringify(canonicalize(value)))
        .digest('base64url')
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

function normalizeBoolean(value, fieldName, defaultValue = false) {
    if (value == null) return defaultValue
    if (typeof value !== 'boolean') fail(`${fieldName} must be a boolean.`, 'invalid-setting')
    return value
}

function normalizeCountdownSeconds(value, fieldName = 'trusted auto-launch countdownSeconds') {
    if (value == null) return DEFAULT_COUNTDOWN_SECONDS
    if (!Number.isSafeInteger(value) || value < MIN_COUNTDOWN_SECONDS || value > MAX_COUNTDOWN_SECONDS) {
        fail(`${fieldName} must be a safe integer from ${MIN_COUNTDOWN_SECONDS} to ${MAX_COUNTDOWN_SECONDS}.`, 'invalid-setting')
    }
    return value
}

function normalizeSafePresetId(value, fieldName, { nullable = false } = {}) {
    if (value == null || value === '') {
        if (nullable) return null
        fail(`${fieldName} is required.`, 'invalid-setting')
    }
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`, 'invalid-setting')
    const id = value.trim()
    if (!SAFE_PRESET_ID_PATTERN.test(id)) fail(`${fieldName} must be a safe preset id.`, 'invalid-setting')
    if (FORBIDDEN_STATUS_TEXT.test(id)) fail(`${fieldName} cannot contain authority material.`, 'invalid-setting')
    return id
}

function normalizedKey(value) {
    return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '')
}

function looksLikeForbiddenSettingField(key) {
    const normalized = normalizedKey(key)
    return [
        'vault',
        'capability',
        'path',
        'appdata',
        'browserprofile',
        'browsersession',
        'process',
        'pid',
        'shell',
        'command',
        'registry',
        'token',
        'credential',
        'password',
        'passcode',
        'pin',
        'cookie',
        'oauth',
        'secret',
        'syncrootkey',
        'rootkeymaterial',
        'privatekey',
        'patchpayload',
        'cloudenvelope',
        'launchplan',
        'importplan'
    ].some(marker => normalized.includes(marker))
}

function assertNoForbiddenSettingMaterial(value, path = 'trusted auto-launch setting') {
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoForbiddenSettingMaterial(item, `${path}[${index}]`))
        return
    }
    if (isPlainObject(value)) {
        for (const [key, nested] of Object.entries(value)) {
            if (looksLikeForbiddenSettingField(key)) {
                fail(`${path}.${key} is not accepted for trusted auto-launch settings.`, 'invalid-setting')
            }
            assertNoForbiddenSettingMaterial(nested, `${path}.${key}`)
        }
        return
    }
    if (typeof value === 'string' && FORBIDDEN_STATUS_TEXT.test(value)) {
        fail(`${path} contains forbidden trusted auto-launch material.`, 'invalid-setting')
    }
}

export function defaultTrustedAutoLaunchSetting() {
    return {
        version: TRUSTED_AUTO_LAUNCH_SETTINGS_VERSION,
        enabled: false,
        advancedPersonalMode: false,
        localDesktopOverridePresetId: null,
        acceptValidatedSelectionMetadata: false,
        countdownSeconds: DEFAULT_COUNTDOWN_SECONDS
    }
}

export function validateTrustedAutoLaunchSetting(value = {}, { allowPartial = false } = {}) {
    if (!isPlainObject(value)) fail('trusted auto-launch setting must be an object.', 'invalid-setting')
    const allowedKeys = new Set([
        'version',
        'enabled',
        'advancedPersonalMode',
        'localDesktopOverridePresetId',
        'acceptValidatedSelectionMetadata',
        'countdownSeconds'
    ])
    for (const key of Object.keys(value)) {
        if (!allowedKeys.has(key)) {
            if (looksLikeForbiddenSettingField(key)) {
                fail(`trusted auto-launch setting.${key} is not accepted.`, 'invalid-setting')
            }
            fail(`trusted auto-launch setting.${key} is not part of the schema.`, 'invalid-setting')
        }
    }
    assertNoForbiddenSettingMaterial(value)
    const base = allowPartial ? {} : defaultTrustedAutoLaunchSetting()
    const version = value.version == null
        ? TRUSTED_AUTO_LAUNCH_SETTINGS_VERSION
        : value.version
    if (version !== TRUSTED_AUTO_LAUNCH_SETTINGS_VERSION) {
        fail('trusted auto-launch setting.version is not supported.', 'invalid-setting')
    }
    const next = {
        ...base,
        version: TRUSTED_AUTO_LAUNCH_SETTINGS_VERSION
    }
    if ('enabled' in value || !allowPartial) {
        next.enabled = normalizeBoolean(value.enabled, 'trusted auto-launch setting.enabled', false)
    }
    if ('advancedPersonalMode' in value || !allowPartial) {
        next.advancedPersonalMode = normalizeBoolean(value.advancedPersonalMode, 'trusted auto-launch setting.advancedPersonalMode', false)
    }
    if ('localDesktopOverridePresetId' in value || !allowPartial) {
        next.localDesktopOverridePresetId = normalizeSafePresetId(
            value.localDesktopOverridePresetId,
            'trusted auto-launch setting.localDesktopOverridePresetId',
            { nullable: true }
        )
    }
    if ('acceptValidatedSelectionMetadata' in value || !allowPartial) {
        next.acceptValidatedSelectionMetadata = normalizeBoolean(
            value.acceptValidatedSelectionMetadata,
            'trusted auto-launch setting.acceptValidatedSelectionMetadata',
            false
        )
    }
    if ('countdownSeconds' in value || !allowPartial) {
        next.countdownSeconds = normalizeCountdownSeconds(
            value.countdownSeconds,
            'trusted auto-launch setting.countdownSeconds'
        )
    }
    if (next.enabled === true && next.advancedPersonalMode !== true) {
        fail('trusted auto-launch requires advancedPersonalMode when enabled.', 'invalid-setting')
    }
    return next
}

function normalizeStoredSetting(meta) {
    try {
        return validateTrustedAutoLaunchSetting(meta?.[TRUSTED_AUTO_LAUNCH_SETTINGS_KEY] || {})
    } catch (_) {
        return defaultTrustedAutoLaunchSetting()
    }
}

function sanitizePresetLabel(value, fallback = 'Selected preset') {
    if (typeof value !== 'string') return fallback
    let text = value
        .replace(/[\u0000-\u001F\u007F]/g, ' ')
        .replace(URL_LIKE_TEXT, '[redacted-url]')
        .replace(WINDOWS_PATH_TEXT, '[redacted-path]')
        .replace(/\s+/g, ' ')
        .trim()
    if (!text || FORBIDDEN_STATUS_TEXT.test(text)) text = fallback
    if (text.length > MAX_LABEL_LENGTH) text = `${text.slice(0, MAX_LABEL_LENGTH - 3).trim()}...`
    return text || fallback
}

function sanitizeItemCounts(counts) {
    const value = isPlainObject(counts) ? counts : {}
    return {
        total: safeCount(value.total),
        browserTabs: safeCount(value.browserTabs),
        desktopApps: safeCount(value.desktopApps),
        hostFolders: safeCount(value.hostFolders),
        accountIntentions: safeCount(value.accountIntentions),
        profileIntentions: safeCount(value.profileIntentions),
        metadataOnly: true
    }
}

function createStatus({
    category = 'idle',
    countdownSeconds = 0,
    presetLabel = '',
    itemCounts = {},
    blockerReasonCodes = [],
    recoveryHints = []
} = {}) {
    const safeCategory = safeStatusCategory(category)
    const codes = uniqueTokens(blockerReasonCodes)
    const hints = (Array.isArray(recoveryHints) ? recoveryHints : [])
        .map(value => sanitizePresetLabel(value, ''))
        .filter(Boolean)
        .slice(0, MAX_STATUS_HINTS)
    return {
        operation: TRUSTED_AUTO_LAUNCH_OPERATION,
        status: safeCategory,
        statusCategory: safeCategory,
        metadataOnly: true,
        countdownSeconds: safeCount(countdownSeconds),
        presetLabel: sanitizePresetLabel(presetLabel, ''),
        itemCounts: sanitizeItemCounts(itemCounts),
        blockerReasonCodes: codes,
        recoveryHints: hints,
        diagnostics: {
            category: safeCategory,
            blockerReasonCodes: codes,
            metadataOnly: true
        }
    }
}

function recoveryHintsForCodes(codes) {
    return uniqueTokens(codes).map(code => RECOVERY_HINTS[code]).filter(Boolean)
}

export function trustedAutoLaunchStatusContainsForbiddenMaterial(value) {
    const forbiddenKeys = new Set([
        'attemptToken',
        'token',
        'unlockSessionId',
        'attemptId',
        'settingFingerprint',
        'targetFingerprint',
        'workspaceFingerprint',
        'workspaceSnapshotFingerprint',
        'autoImportStatusVersion',
        'patchRevisionId',
        'patchId',
        'authorDeviceId',
        'capabilityId',
        'capabilityRecord',
        'capabilityRecords',
        'vaultPath',
        'vaultData',
        'url',
        'urls',
        'tabs',
        'webTabs',
        'launchPlan',
        'importPlan',
        'cloudEnvelope',
        'patchPayload',
        'syncRootKey',
        'rootKeyMaterial',
        'privateKey',
        'credential',
        'credentials',
        'browserSession',
        'launchAuthority'
    ])
    const scan = (candidate) => {
        if (Array.isArray(candidate)) return candidate.some(scan)
        if (isPlainObject(candidate)) {
            return Object.entries(candidate).some(([key, nested]) =>
                forbiddenKeys.has(key) || scan(nested)
            )
        }
        return typeof candidate === 'string' && FORBIDDEN_STATUS_TEXT.test(candidate)
    }
    return scan(value)
}

function autoImportRecordIsClean(record) {
    const status = safeToken(record?.status, '')
    const reason = safeToken(record?.reason || record?.code || '', '')
    const code = safeToken(record?.code || '', '')
    if (status === 'applied' && (reason === '' || reason === 'merged' || code === 'merged')) return true
    if ((status === 'skipped' || status === 'already-decided') && code === 'already-decided' && reason === 'merged') return true
    if (status === 'already-decided' && reason === 'merged') return true
    return false
}

export function trustedAutoImportStatusIsClean(status) {
    if (!isPlainObject(status)) return false
    const category = safeToken(status.statusCategory || status.diagnostics?.category || status.status, '')
    if (NON_TERMINAL_AUTO_IMPORT_CATEGORIES.has(category)) return false
    if (BLOCKING_AUTO_IMPORT_CATEGORIES.has(category) && category !== 'skipped') return false
    const records = Array.isArray(status.records) ? status.records : []
    if (records.length === 0) return CLEAN_AUTO_IMPORT_CATEGORIES.has(category)
    return records.every(autoImportRecordIsClean)
}

function autoImportStatusBlockerCodes(status) {
    if (!isPlainObject(status)) return ['auto-import-not-clean']
    const category = safeToken(status.statusCategory || status.diagnostics?.category || status.status, 'auto-import-not-clean')
    if (NON_TERMINAL_AUTO_IMPORT_CATEGORIES.has(category)) return ['auto-import-not-clean']
    const records = Array.isArray(status.records) ? status.records : []
    if (category === 'skipped' && records.some(record => !autoImportRecordIsClean(record))) {
        return uniqueTokens(records.map(record => record.reason || record.code || 'auto-import-not-clean'))
    }
    return [category || 'auto-import-not-clean']
}

function normalizeSafePatchRevisionId(value) {
    if (value == null || value === '') return ''
    if (typeof value !== 'string') return ''
    const id = value.trim()
    return SAFE_PATCH_REVISION_ID_PATTERN.test(id) ? id : ''
}

function requireSafePatchRevisionId(value, fieldName = 'safe preset metadata lastMergedPatchRevisionId') {
    const id = normalizeSafePatchRevisionId(value)
    if (!id) fail(`${fieldName} is required for metadata-selected auto-launch.`, 'invalid-safe-metadata')
    return id
}

function validateMergedSafePresetMetadata(value) {
    if (value == null) return null
    if (!isPlainObject(value)) fail('safe preset metadata is malformed.', 'invalid-safe-metadata')
    if (value.version !== SAFE_PRESET_METADATA_VERSION || value.metadataOnly !== true) {
        fail('safe preset metadata is not a validated metadata-only merge.', 'invalid-safe-metadata')
    }
    const presets = Array.isArray(value.presets) ? value.presets : []
    const presetIds = new Set()
    const normalizedPresets = presets.map((preset, index) => {
        if (!isPlainObject(preset) || preset.metadataOnly !== true) {
            fail(`safe preset metadata preset ${index + 1} is malformed.`, 'invalid-safe-metadata')
        }
        const id = normalizeSafePresetId(preset.id, `safe preset metadata presets[${index}].id`)
        if (presetIds.has(id)) fail('safe preset metadata contains duplicate preset ids.', 'invalid-safe-metadata')
        presetIds.add(id)
        return {
            id,
            name: sanitizePresetLabel(preset.name, `Preset ${index + 1}`),
            enabled: preset.enabled !== false,
            itemRefs: Array.isArray(preset.itemRefs) ? preset.itemRefs : []
        }
    })
    const selection = isPlainObject(value.selection) ? value.selection : {}
    const defaultPresetId = selection.defaultPresetId
        ? normalizeSafePresetId(selection.defaultPresetId, 'safe preset metadata selection.defaultPresetId')
        : null
    const nextPresetId = selection.nextPresetId
        ? normalizeSafePresetId(selection.nextPresetId, 'safe preset metadata selection.nextPresetId')
        : null
    if (defaultPresetId && !presetIds.has(defaultPresetId)) fail('safe preset metadata default preset is stale.', 'invalid-safe-metadata')
    if (nextPresetId && !presetIds.has(nextPresetId)) fail('safe preset metadata next preset is stale.', 'invalid-safe-metadata')
    return {
        lastMergedPatchRevisionId: normalizeSafePatchRevisionId(value.lastMergedPatchRevisionId),
        selection: {
            defaultPresetId,
            nextPresetId,
            metadataOnly: true,
            selectionKind: 'metadata-only'
        },
        presets: normalizedPresets,
        newBrowserItems: Array.isArray(value.newBrowserItems) ? value.newBrowserItems : []
    }
}

function validateSanitizedSnapshot(snapshot) {
    if (!isPlainObject(snapshot)) fail('current sanitized snapshot is unavailable.', 'snapshot-invalid')
    if (snapshot.product !== 'wipesnap' || snapshot.kind !== 'sanitized-preset-snapshot' || snapshot.schemaVersion !== 1) {
        fail('current sanitized snapshot is invalid.', 'snapshot-invalid')
    }
    if (!Array.isArray(snapshot.presets) || !Array.isArray(snapshot.availableItems)) {
        fail('current sanitized snapshot is incomplete.', 'snapshot-invalid')
    }
    const itemIds = new Set()
    for (const item of snapshot.availableItems) {
        if (!isPlainObject(item) || typeof item.id !== 'string' || !SAFE_ITEM_ID_PATTERN.test(item.id)) {
            fail('current sanitized snapshot contains an invalid item id.', 'snapshot-invalid')
        }
        if (itemIds.has(item.id)) fail('current sanitized snapshot contains duplicate item ids.', 'snapshot-invalid')
        itemIds.add(item.id)
        if (item.type === 'browser-tab' && item.status === 'available') {
            if (!item.url || validateBrowserUrl(item.url, 'sanitized snapshot browser URL') !== item.url) {
                fail('current sanitized snapshot contains an invalid browser URL.', 'snapshot-invalid')
            }
            if (item.id.startsWith('patch_item_') && validatePublicBrowserUrl(item.url, 'merged safe browser URL') !== item.url) {
                fail('current sanitized snapshot contains a non-public merged browser URL.', 'stale-preset')
            }
        }
    }
    const presetIds = new Set()
    for (const preset of snapshot.presets) {
        if (!isPlainObject(preset)) fail('current sanitized snapshot contains a malformed preset.', 'snapshot-invalid')
        const presetId = normalizeSafePresetId(preset.id, 'current sanitized snapshot preset id')
        if (presetIds.has(presetId)) fail('current sanitized snapshot contains duplicate preset ids.', 'snapshot-invalid')
        presetIds.add(presetId)
        if (!Array.isArray(preset.itemRefs)) fail('current sanitized snapshot preset refs are malformed.', 'snapshot-invalid')
        const refIds = new Set()
        for (const ref of preset.itemRefs) {
            if (!isPlainObject(ref) || typeof ref.id !== 'string' || !SAFE_REF_ID_PATTERN.test(ref.id)) {
                fail('current sanitized snapshot contains an invalid preset ref id.', 'snapshot-invalid')
            }
            if (refIds.has(ref.id)) fail('current sanitized snapshot contains duplicate preset refs.', 'snapshot-invalid')
            refIds.add(ref.id)
            if (!itemIds.has(ref.itemId)) fail('current sanitized snapshot preset refs are stale.', 'snapshot-invalid')
        }
    }
    return snapshot
}

function sortedWorkspaceEntries(items) {
    return (Array.isArray(items) ? items : [])
        .map((item, index) => ({ item, index }))
        .sort((a, b) => {
            const orderA = Number.isSafeInteger(a.item?.order) ? a.item.order : a.index
            const orderB = Number.isSafeInteger(b.item?.order) ? b.item.order : b.index
            return orderA - orderB || a.index - b.index
        })
}

function resolveUsbMacros(workspace, vaultDir) {
    return {
        ...workspace,
        desktopApps: (workspace.desktopApps || []).map(appConfig => {
            if (typeof appConfig?.path === 'string' && appConfig.path.startsWith('[USB]')) {
                return { ...appConfig, path: appConfig.path.replace('[USB]', vaultDir) }
            }
            return appConfig
        })
    }
}

function browserProfileReady(deps, vaultDir) {
    if (typeof deps.browserProfileReady === 'function') return deps.browserProfileReady({ vaultDir }) === true
    try {
        const profilePath = join(vaultDir, 'BrowserProfile')
        const fsApi = deps.fsApi || { existsSync, statSync }
        if (!fsApi.existsSync(profilePath)) return false
        return !!fsApi.statSync(profilePath)?.isDirectory?.()
    } catch (_) {
        return false
    }
}

function validatePublicBrowserUrl(value, fieldName) {
    try {
        const draft = validateCloudDraft({
            product: 'wipesnap',
            schemaVersion: 1,
            draftId: 'auto_launch_url_check',
            revisionId: 'auto_launch_url_check_rev',
            baseRevisionId: null,
            authorDeviceId: 'auto_launch_url_check_device',
            name: 'Auto Launch URL Check',
            notes: '',
            isDefault: false,
            accountSlots: [],
            browserProfileSlots: [],
            browserTabs: [{
                id: 'auto_launch_url_check_tab',
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
        fail(`${fieldName} is not an accepted public browser URL.`, 'stale-preset')
    }
}

function workspaceHealthFor(deps, workspace, vaultDir) {
    if (typeof deps.loadWorkspaceHealthSummary === 'function') {
        return deps.loadWorkspaceHealthSummary({ workspace, vaultDir })
    }
    return loadWorkspaceHealthSummary({ workspace, vaultDir })
}

function activeStoredState(meta) {
    const value = isPlainObject(meta?.[TRUSTED_AUTO_LAUNCH_STATE_KEY])
        ? meta[TRUSTED_AUTO_LAUNCH_STATE_KEY]
        : {}
    const consumedNextPreset = isPlainObject(value.consumedNextPreset)
        ? value.consumedNextPreset
        : null
    return {
        version: 1,
        consumedNextPreset: consumedNextPreset && typeof consumedNextPreset.presetId === 'string'
            ? {
                presetId: consumedNextPreset.presetId,
                patchRevisionId: normalizeSafePatchRevisionId(consumedNextPreset.patchRevisionId),
                targetFingerprint: typeof consumedNextPreset.targetFingerprint === 'string'
                    ? consumedNextPreset.targetFingerprint
                    : '',
                consumedAt: Number.isSafeInteger(consumedNextPreset.consumedAt) ? consumedNextPreset.consumedAt : 0
            }
            : null,
        metadataOnly: true
    }
}

function nextPresetConsumed(state, metadata, presetId) {
    const patchRevisionId = metadata?.lastMergedPatchRevisionId || ''
    const consumed = state?.consumedNextPreset
    return !!(consumed &&
        consumed.presetId === presetId &&
        consumed.patchRevisionId === patchRevisionId)
}

function persistConsumedNextPreset(deps, meta, target, token, timestamp = Date.now()) {
    if (target.source !== 'metadata-next') return
    const nextMeta = {
        ...(meta || { version: '1.0.0' }),
        [TRUSTED_AUTO_LAUNCH_STATE_KEY]: {
            version: 1,
            consumedNextPreset: {
                presetId: target.presetId,
                patchRevisionId: target.patchRevisionId || '',
                targetFingerprint: token.targetFingerprint,
                consumedAt: timestamp
            },
            metadataOnly: true
        }
    }
    deps.saveVaultMeta(nextMeta, 'trusted-auto-launch-consume-next-preset')
}

function resolveTargetPolicy({ setting, snapshot, metadata, state }) {
    if (setting.localDesktopOverridePresetId) {
        return {
            source: 'local-override',
            presetId: setting.localDesktopOverridePresetId,
            patchRevisionId: '',
            targetFingerprint: hashValue({
                source: 'local-override',
                presetId: setting.localDesktopOverridePresetId
            })
        }
    }
    if (setting.acceptValidatedSelectionMetadata === true && metadata?.selection?.nextPresetId) {
        const presetId = metadata.selection.nextPresetId
        if (!nextPresetConsumed(state, metadata, presetId)) {
            const patchRevisionId = requireSafePatchRevisionId(metadata.lastMergedPatchRevisionId)
            return {
                source: 'metadata-next',
                presetId,
                patchRevisionId,
                targetFingerprint: hashValue({
                    source: 'metadata-next',
                    presetId,
                    patchRevisionId
                })
            }
        }
    }
    if (setting.acceptValidatedSelectionMetadata === true && metadata?.selection?.defaultPresetId) {
        const presetId = metadata.selection.defaultPresetId
        const patchRevisionId = requireSafePatchRevisionId(metadata.lastMergedPatchRevisionId)
        return {
            source: 'metadata-default',
            presetId,
            patchRevisionId,
            targetFingerprint: hashValue({
                source: 'metadata-default',
                presetId,
                patchRevisionId
            })
        }
    }
    return null
}

function itemCountsFor(items, refs = []) {
    const counts = {
        total: 0,
        browserTabs: 0,
        desktopApps: 0,
        hostFolders: 0,
        accountIntentions: 0,
        profileIntentions: 0
    }
    for (const item of items) {
        counts.total += 1
        if (item.type === 'browser-tab') counts.browserTabs += 1
        else if (item.type === 'host-folder') counts.hostFolders += 1
        else if (item.type === 'account-intention') counts.accountIntentions += 1
        else if (item.type === 'profile-intention') counts.profileIntentions += 1
        else counts.desktopApps += 1
    }
    for (const ref of refs) {
        if (ref.accountIntentionId) counts.accountIntentions += 1
        if (ref.profileIntentionId) counts.profileIntentions += 1
    }
    return counts
}

function buildItemIndexes({ workspace, snapshot, metadata }) {
    const snapshotItems = snapshot.availableItems || []
    const itemById = new Map(snapshotItems.map(item => [item.id, item]))
    const desktopSnapshotItems = snapshotItems.filter(item => item.source === 'desktop')
    const existingBrowserSnapshotItems = snapshotItems.filter(item =>
        item.source === 'browser' &&
        item.type === 'browser-tab' &&
        item.id.startsWith('item_')
    )
    const desktopEntries = sortedWorkspaceEntries(workspace.desktopApps)
    const browserEntries = sortedWorkspaceEntries(workspace.webTabs)
    const desktopEntryByItemId = new Map()
    const browserEntryByItemId = new Map()
    desktopSnapshotItems.forEach((item, index) => {
        if (desktopEntries[index]) desktopEntryByItemId.set(item.id, desktopEntries[index].item)
    })
    existingBrowserSnapshotItems.forEach((item, index) => {
        if (browserEntries[index]) browserEntryByItemId.set(item.id, browserEntries[index].item)
    })
    const patchBrowserByItemId = new Map()
    for (const item of metadata?.newBrowserItems || []) {
        if (item?.id) patchBrowserByItemId.set(item.id, item)
    }
    return {
        itemById,
        desktopEntryByItemId,
        browserEntryByItemId,
        patchBrowserByItemId
    }
}

function capabilityRecordExists(capabilityVault, capabilityId) {
    return isPlainObject(capabilityVault?.records) && isPlainObject(capabilityVault.records[capabilityId])
}

function capabilityRecordFor(capabilityVault, capabilityId) {
    return isPlainObject(capabilityVault?.records) && isPlainObject(capabilityVault.records[capabilityId])
        ? capabilityVault.records[capabilityId]
        : null
}

function validateIntentionsForRef(ref, itemById, selectedItems) {
    const accountIntentionId = ref.accountIntentionId || ''
    if (accountIntentionId) {
        const accountItem = itemById.get(accountIntentionId)
        if (!accountItem || accountItem.type !== 'account-intention' || accountItem.state !== READY_ACCOUNT_STATE) {
            fail('A required account intention is not signed in.', 'account-not-ready')
        }
        selectedItems.push(accountItem)
    }
    const profileIntentionId = ref.profileIntentionId || ''
    if (profileIntentionId) {
        const profileItem = itemById.get(profileIntentionId)
        if (!profileItem || profileItem.type !== 'profile-intention' || profileItem.status !== 'available') {
            fail('A required profile intention is not ready.', 'profile-not-ready')
        }
        selectedItems.push(profileItem)
    }
}

function normalizeLaunchBrowserUrl(url, fieldName, expectedUrl = '') {
    const normalized = validateBrowserUrl(url, fieldName)
    if (expectedUrl && normalized !== expectedUrl) fail(`${fieldName} is stale or was not normalized by the sanitized snapshot.`, 'stale-preset')
    return normalized
}

function resolveSelectedWorkspaceSubset({ workspace, snapshot, metadata, preset }) {
    const indexes = buildItemIndexes({ workspace, snapshot, metadata })
    const selectedTabs = []
    const selectedDesktopEntries = []
    const selectedItems = []
    const refs = [...(preset.itemRefs || [])]
        .filter(ref => ref?.enabled !== false)
        .sort((a, b) => {
            const orderA = Number.isSafeInteger(a.order) ? a.order : 0
            const orderB = Number.isSafeInteger(b.order) ? b.order : 0
            return orderA - orderB || String(a.id || '').localeCompare(String(b.id || ''))
        })

    for (const ref of refs) {
        const item = indexes.itemById.get(ref.itemId)
        if (!item) fail('The selected preset references a stale item.', 'stale-preset')
        if (item.status !== 'available') fail('The selected preset contains a disabled or broken item.', 'stale-preset')
        selectedItems.push(item)
        validateIntentionsForRef(ref, indexes.itemById, selectedItems)

        if (item.type === 'browser-tab') {
            let url = ''
            if (item.id.startsWith('patch_item_')) {
                const mergedItem = indexes.patchBrowserByItemId.get(item.id)
                url = normalizeLaunchBrowserUrl(mergedItem?.url || item.url, 'merged safe browser URL', item.url)
                if (validatePublicBrowserUrl(url, 'merged safe browser URL') !== url) {
                    fail('Merged safe browser URL is not public.', 'stale-preset')
                }
            } else {
                const tab = indexes.browserEntryByItemId.get(item.id)
                url = normalizeLaunchBrowserUrl(tab?.url || item.url, 'desktop browser URL', item.url)
                if (item.url && url !== item.url) fail('The selected preset browser item is stale.', 'stale-preset')
            }
            selectedTabs.push({
                url,
                enabled: true,
                label: sanitizePresetLabel(item.label, 'Browser tab')
            })
            continue
        }

        if (item.type === 'desktop-app' || item.type === 'host-folder') {
            const entry = indexes.desktopEntryByItemId.get(item.id)
            if (!entry || entry.enabled === false || entry.quarantined === true) {
                fail('The selected preset desktop item is missing or disabled.', 'missing-capability')
            }
            if (workspaceEntryHasRawLaunchAuthority(entry) && !entry.capabilityId) {
                fail('The selected preset desktop item requires capability migration.', 'missing-capability')
            }
            if (!capabilityRecordExists(workspace[WORKSPACE_CAPABILITY_VAULT_KEY], entry.capabilityId)) {
                fail('The selected preset desktop item has a missing or stale capability.', 'missing-capability')
            }
            selectedDesktopEntries.push(entry)
            continue
        }

        if (item.type === 'account-intention' && item.state !== READY_ACCOUNT_STATE) {
            fail('A selected account intention is not signed in.', 'account-not-ready')
        }
        if (item.type === 'profile-intention' && item.status !== 'available') {
            fail('A selected profile intention is not ready.', 'profile-not-ready')
        }
    }

    return {
        selectedWorkspace: {
            name: workspace.name,
            webTabs: selectedTabs,
            desktopApps: selectedDesktopEntries,
            [WORKSPACE_CAPABILITY_VAULT_KEY]: workspace[WORKSPACE_CAPABILITY_VAULT_KEY] || null
        },
        selectedItems,
        selectedDesktopEntries,
        refs,
        itemCounts: itemCountsFor(selectedItems, refs)
    }
}

function preparedLaunchConfigIsReady(config) {
    for (const appConfig of config.desktopApps || []) {
        if (appConfig?.enabled === false) continue
        if (appConfig?.hostResolution && appConfig.hostResolution.status !== 'available') return false
        if (appConfig?.availabilityStatus && appConfig.availabilityStatus !== 'available') return false
        if (HOST_LAUNCH_TYPES.has(appConfig?.launchSourceType) &&
            appConfig?.hostResolution?.status &&
            appConfig.hostResolution.status !== 'available') {
            return false
        }
    }
    return true
}

function classifyGateError(error) {
    const code = safeToken(error?.code || '', '')
    if (code && code !== 'auto-launch-invalid') return code
    const text = String(error?.message || '').toLowerCase()
    if (/locked|unlock/.test(text)) return 'locked'
    if (/auto-import/.test(text)) return 'auto-import-not-clean'
    if (/preset/.test(text) && /missing/.test(text)) return 'missing-preset'
    if (/disabled/.test(text)) return 'disabled-preset'
    if (/stale|unknown/.test(text)) return 'stale-preset'
    if (/health/.test(text)) return 'workspace-health-blocked'
    if (/capability|migration|repair/.test(text)) return 'missing-capability'
    if (/browser profile/.test(text)) return 'missing-browser-profile'
    if (/account/.test(text)) return 'account-not-ready'
    if (/profile/.test(text)) return 'profile-not-ready'
    if (/host|availability|available/.test(text)) return 'host-unavailable'
    if (/active launch|concurrent/.test(text)) return 'active-launch'
    if (/author|trusted|revoked|key/.test(text)) return 'author-not-trusted'
    return 'blocked'
}

function selectedRefMaterial(refs) {
    return (refs || []).map(ref => ({
        id: ref.id || '',
        itemId: ref.itemId || '',
        order: Number.isSafeInteger(ref.order) ? ref.order : 0,
        enabled: ref.enabled !== false,
        accountIntentionId: ref.accountIntentionId || '',
        profileIntentionId: ref.profileIntentionId || ''
    }))
}

function selectedItemMaterial(items) {
    return (items || []).map(item => ({
        id: item.id || '',
        type: item.type || '',
        status: item.status || '',
        state: item.state || '',
        source: item.source || '',
        url: item.type === 'browser-tab' ? item.url || '' : '',
        provider: item.provider || ''
    }))
}

function selectedCapabilityRecordMaterial(capabilityVault, desktopEntries) {
    return (desktopEntries || []).map(entry => {
        const record = capabilityRecordFor(capabilityVault, entry.capabilityId)
        return {
            entryId: entry.id || '',
            capabilityId: entry.capabilityId || '',
            enabled: entry.enabled !== false,
            userArgs: Array.isArray(entry.userArgs) ? entry.userArgs : [],
            recordFingerprint: record ? hashValue(record) : ''
        }
    })
}

function stableLaunchConfigMaterial(value, key = '') {
    if (key && (VOLATILE_LAUNCH_CONFIG_KEYS.has(key) || /At$/.test(key))) return undefined
    if (Array.isArray(value)) {
        return value.map(item => stableLaunchConfigMaterial(item))
    }
    if (isPlainObject(value)) {
        const next = {}
        for (const currentKey of Object.keys(value).sort()) {
            const normalized = stableLaunchConfigMaterial(value[currentKey], currentKey)
            if (normalized !== undefined) next[currentKey] = normalized
        }
        return next
    }
    if (value === undefined) return null
    return value
}

function buildLaunchMaterialFingerprint({
    target,
    preset,
    resolved,
    capabilityVault,
    launchWorkspaceConfig
}) {
    return hashValue({
        target: {
            source: target.source,
            presetId: target.presetId,
            patchRevisionId: target.patchRevisionId || ''
        },
        preset: {
            id: preset.id,
            name: preset.name || '',
            enabled: preset.enabled !== false
        },
        refs: selectedRefMaterial(resolved.refs),
        selectedItems: selectedItemMaterial(resolved.selectedItems),
        selectedCapabilityRecords: selectedCapabilityRecordMaterial(
            capabilityVault,
            resolved.selectedDesktopEntries
        ),
        launchWorkspaceConfig: stableLaunchConfigMaterial(launchWorkspaceConfig)
    })
}

function tokenFromGate({
    unlockSessionId,
    attemptId,
    setting,
    target,
    snapshot,
    metadata,
    itemCounts,
    autoImportStatusVersion,
    launchMaterialFingerprint
}) {
    return {
        unlockSessionId,
        attemptId,
        settingFingerprint: hashValue(setting),
        targetFingerprint: target.targetFingerprint,
        workspaceSnapshotFingerprint: hashValue({
            presets: snapshot.presets?.map(preset => ({
                id: preset.id,
                name: preset.name || '',
                enabled: preset.enabled !== false,
                refs: preset.itemRefs?.map(ref => ({
                    id: ref.id || '',
                    itemId: ref.itemId,
                    order: Number.isSafeInteger(ref.order) ? ref.order : 0,
                    enabled: ref.enabled !== false,
                    accountIntentionId: ref.accountIntentionId || '',
                    profileIntentionId: ref.profileIntentionId || ''
                }))
            })),
            items: snapshot.availableItems?.map(item => ({
                id: item.id,
                type: item.type,
                status: item.status,
                state: item.state || ''
            })),
            metadataRevision: metadata?.lastMergedPatchRevisionId || '',
            launchMaterialFingerprint,
            itemCounts
        }),
        autoImportStatusVersion
    }
}

function tokensMatch(left, right) {
    return !!left && !!right &&
        left.unlockSessionId === right.unlockSessionId &&
        left.attemptId === right.attemptId &&
        left.settingFingerprint === right.settingFingerprint &&
        left.targetFingerprint === right.targetFingerprint &&
        left.workspaceSnapshotFingerprint === right.workspaceSnapshotFingerprint &&
        left.autoImportStatusVersion === right.autoImportStatusVersion
}

function createAttemptId() {
    return `attempt_${Date.now()}_${randomBytes(6).toString('hex')}`
}

function buildBlockedStatus(codes, context = {}) {
    return createStatus({
        category: 'blocked',
        presetLabel: context.presetLabel || '',
        itemCounts: context.itemCounts || {},
        blockerReasonCodes: codes,
        recoveryHints: recoveryHintsForCodes(codes)
    })
}

export function createTrustedAutoLaunchOrchestrator({
    deps,
    resolveDeps,
    schedule = (callback, ms = 1000) => setTimeout(callback, ms),
    clearScheduled = (handle) => clearTimeout(handle),
    onStatus = () => {},
    logger = null,
    now = Date.now
} = {}) {
    const getDeps = () => {
        const resolved = typeof resolveDeps === 'function' ? resolveDeps() : deps
        if (!resolved || typeof resolved !== 'object') fail('Trusted auto-launch requires dependencies.')
        return resolved
    }

    let unlockSessionId = 0
    let autoImportStatusVersion = 0
    let lastAutoImportStatus = null
    let lastStatus = createStatus({ category: 'idle' })
    let currentAttempt = null
    let countdownHandle = null
    const automaticAttemptedSessionIds = new Set()

    const emit = (status) => {
        lastStatus = clone(status)
        try {
            onStatus(clone(lastStatus))
        } catch (_) {
            if (logger?.warn) logger.warn('[Wipesnap] trusted auto-launch status emit failed.')
        }
        return clone(lastStatus)
    }

    const clearCountdown = () => {
        if (countdownHandle != null) {
            try { clearScheduled(countdownHandle) } catch (_) { }
            countdownHandle = null
        }
    }

    const invalidateCurrentAttempt = (reason = 'token-invalid', category = 'canceled') => {
        clearCountdown()
        currentAttempt = null
        const status = createStatus({
            category,
            blockerReasonCodes: [reason],
            recoveryHints: recoveryHintsForCodes([reason])
        })
        return emit(status)
    }

    const readMetaAndSetting = (activeDeps) => {
        const meta = activeDeps.loadVaultMeta ? activeDeps.loadVaultMeta() : null
        return {
            meta,
            setting: normalizeStoredSetting(meta),
            state: activeStoredState(meta)
        }
    }

    const evaluateGates = async ({ attemptId = createAttemptId(), token = null } = {}) => {
        const activeDeps = getDeps()
        if (typeof activeDeps.requireActiveSession === 'function') activeDeps.requireActiveSession()
        if (typeof activeDeps.isLaunchActive === 'function' && activeDeps.isLaunchActive()) {
            fail('Another launch is already active.', 'active-launch')
        }
        const { meta, setting, state } = readMetaAndSetting(activeDeps)
        if (setting.enabled !== true) fail('Trusted auto-launch is disabled.', 'disabled')
        if (!trustedAutoImportStatusIsClean(lastAutoImportStatus)) {
            const codes = autoImportStatusBlockerCodes(lastAutoImportStatus)
            fail(`Trusted auto-import is not clean: ${codes.join(', ')}`, 'auto-import-not-clean')
        }

        const workspace = activeDeps.loadActiveVaultWorkspace()
        const snapshotBuilder = activeDeps.buildCurrentSanitizedSnapshot
        if (typeof snapshotBuilder !== 'function') fail('Current sanitized snapshot is unavailable.', 'snapshot-invalid')
        const snapshot = validateSanitizedSnapshot(await snapshotBuilder({ workspace }))
        const metadata = validateMergedSafePresetMetadata(workspace[WORKSPACE_SAFE_PRESET_METADATA_KEY])
        const target = resolveTargetPolicy({ setting, snapshot, metadata, state })
        if (!target) fail('Trusted auto-launch could not resolve a preset target.', 'no-target')

        const preset = snapshot.presets.find(candidate => candidate.id === target.presetId)
        if (!preset) fail('Trusted auto-launch preset is missing.', 'missing-preset')
        if (preset.enabled === false) fail('Trusted auto-launch preset is disabled.', 'disabled-preset')

        const metadataPresetIds = new Set((metadata?.presets || []).map(candidate => candidate.id))
        if (metadataPresetIds.has(preset.id)) {
            const patchRevisionId = requireSafePatchRevisionId(
                metadata?.lastMergedPatchRevisionId,
                'selected safe preset metadata lastMergedPatchRevisionId'
            )
            if (typeof activeDeps.verifyMergedPatchAuthor !== 'function') {
                fail('Merged patch author trust cannot be verified before launch.', 'author-not-trusted')
            }
            const trust = await activeDeps.verifyMergedPatchAuthor({
                patchRevisionId
            })
            if (!trust || trust.trusted !== true) {
                fail('Merged patch author is no longer trusted.', 'author-not-trusted')
            }
        }

        const vaultDir = activeDeps.getVaultDir()
        const health = await workspaceHealthFor(activeDeps, workspace, vaultDir)
        if (health?.status !== WORKSPACE_HEALTH_STATUSES.READY) {
            fail('Workspace health is not ready.', 'workspace-health-blocked')
        }

        const resolved = resolveSelectedWorkspaceSubset({ workspace, snapshot, metadata, preset })
        if (resolved.itemCounts.browserTabs > 0 && !browserProfileReady(activeDeps, vaultDir)) {
            fail('Browser profile is missing or not ready.', 'missing-browser-profile')
        }

        const rehydrated = rehydrateWorkspaceLaunchCapabilities(resolved.selectedWorkspace, {
            capabilityVault: workspace[WORKSPACE_CAPABILITY_VAULT_KEY] || null,
            manifestResolver: activeDeps.manifestResolver
        })
        const safeWorkspace = resolveUsbMacros({
            ...rehydrated,
            webTabs: resolved.selectedWorkspace.webTabs
        }, vaultDir)
        const prepared = typeof activeDeps.prepareLaunchWorkspaceConfig === 'function'
            ? await activeDeps.prepareLaunchWorkspaceConfig(safeWorkspace, { allowLegacyRepair: false })
            : safeWorkspace
        if (!preparedLaunchConfigIsReady(prepared)) {
            fail('A host launch reference is not available on this PC.', 'host-unavailable')
        }

        const itemCounts = sanitizeItemCounts(resolved.itemCounts)
        const launchMaterialFingerprint = buildLaunchMaterialFingerprint({
            target,
            preset,
            resolved,
            capabilityVault: workspace[WORKSPACE_CAPABILITY_VAULT_KEY] || null,
            launchWorkspaceConfig: prepared
        })
        const nextToken = tokenFromGate({
            unlockSessionId,
            attemptId,
            setting,
            target,
            snapshot,
            metadata,
            itemCounts,
            autoImportStatusVersion,
            launchMaterialFingerprint
        })
        if (token && !tokensMatch(token, nextToken)) fail('Trusted auto-launch token is stale.', 'token-invalid')

        return {
            token: nextToken,
            meta,
            setting,
            target,
            snapshot,
            metadata,
            preset,
            presetLabel: sanitizePresetLabel(preset.name, 'Selected preset'),
            itemCounts,
            launchWorkspaceConfig: prepared
        }
    }

    const launchFromGate = async (gate, token) => {
        if (!currentAttempt || !tokensMatch(currentAttempt.token, token)) return { success: false, status: clone(lastStatus) }
        let checkedGate
        try {
            checkedGate = await evaluateGates({ attemptId: token.attemptId, token })
        } catch (error) {
            const code = classifyGateError(error)
            currentAttempt = null
            clearCountdown()
            emit(buildBlockedStatus([code], gate))
            return { success: false, status: clone(lastStatus), error: code }
        }
        currentAttempt = null
        clearCountdown()
        emit(createStatus({
            category: 'launching',
            presetLabel: checkedGate.presetLabel,
            itemCounts: checkedGate.itemCounts
        }))
        try {
            await getDeps().launchWorkspace(checkedGate.launchWorkspaceConfig, {
                operation: TRUSTED_AUTO_LAUNCH_OPERATION,
                presetLabel: checkedGate.presetLabel,
                itemCounts: checkedGate.itemCounts,
                metadataOnly: true
            })
            persistConsumedNextPreset(getDeps(), checkedGate.meta, checkedGate.target, checkedGate.token, now())
            emit(createStatus({
                category: 'launched',
                presetLabel: checkedGate.presetLabel,
                itemCounts: checkedGate.itemCounts
            }))
            return { success: true, status: clone(lastStatus) }
        } catch (error) {
            const code = classifyGateError(error)
            emit(createStatus({
                category: 'failed',
                presetLabel: checkedGate.presetLabel,
                itemCounts: checkedGate.itemCounts,
                blockerReasonCodes: [code],
                recoveryHints: recoveryHintsForCodes([code])
            }))
            return { success: false, status: clone(lastStatus), error: code }
        }
    }

    const scheduleCountdownTick = () => {
        if (!currentAttempt) return
        countdownHandle = schedule(async () => {
            const attempt = currentAttempt
            if (!attempt || !tokensMatch(attempt.token, currentAttempt?.token)) return
            try {
                await evaluateGates({ attemptId: attempt.token.attemptId, token: attempt.token })
            } catch (error) {
                const code = classifyGateError(error)
                currentAttempt = null
                clearCountdown()
                emit(buildBlockedStatus([code], attempt))
                return
            }
            attempt.secondsRemaining -= 1
            if (attempt.secondsRemaining > 0) {
                emit(createStatus({
                    category: 'countdown',
                    countdownSeconds: attempt.secondsRemaining,
                    presetLabel: attempt.presetLabel,
                    itemCounts: attempt.itemCounts
                }))
                scheduleCountdownTick()
                return
            }
            await launchFromGate(attempt, attempt.token)
        }, 1000)
    }

    const startAttempt = async ({ automatic = false, immediate = false } = {}) => {
        if (!unlockSessionId) return emit(buildBlockedStatus(['locked']))
        if (automatic) {
            if (automaticAttemptedSessionIds.has(unlockSessionId)) return clone(lastStatus)
            automaticAttemptedSessionIds.add(unlockSessionId)
        }
        clearCountdown()
        currentAttempt = null
        let gate
        try {
            gate = await evaluateGates({})
        } catch (error) {
            const code = classifyGateError(error)
            return emit(buildBlockedStatus([code]))
        }
        currentAttempt = {
            token: gate.token,
            presetLabel: gate.presetLabel,
            itemCounts: gate.itemCounts,
            launchWorkspaceConfig: gate.launchWorkspaceConfig,
            secondsRemaining: immediate ? 0 : gate.setting.countdownSeconds
        }
        if (immediate) return launchFromGate(currentAttempt, currentAttempt.token)
        emit(createStatus({
            category: 'countdown',
            countdownSeconds: currentAttempt.secondsRemaining,
            presetLabel: currentAttempt.presetLabel,
            itemCounts: currentAttempt.itemCounts
        }))
        scheduleCountdownTick()
        return clone(lastStatus)
    }

    return {
        beginUnlockSession() {
            unlockSessionId += 1
            autoImportStatusVersion += 1
            lastAutoImportStatus = null
            clearCountdown()
            currentAttempt = null
            const activeDeps = getDeps()
            const { setting } = readMetaAndSetting(activeDeps)
            return emit(createStatus({ category: setting.enabled ? 'waiting-auto-import' : 'disabled' }))
        },
        observeAutoImportStatus(status) {
            autoImportStatusVersion += 1
            lastAutoImportStatus = clone(status)
            if (currentAttempt) {
                invalidateCurrentAttempt('auto-import-not-clean', 'canceled')
                return clone(lastStatus)
            }
            const setting = normalizeStoredSetting(getDeps().loadVaultMeta ? getDeps().loadVaultMeta() : null)
            if (setting.enabled !== true) return emit(createStatus({ category: 'disabled' }))
            if (trustedAutoImportStatusIsClean(lastAutoImportStatus)) {
                return startAttempt({ automatic: true })
            }
            const category = safeToken(status?.statusCategory || status?.diagnostics?.category || status?.status, '')
            if (category && !NON_TERMINAL_AUTO_IMPORT_CATEGORIES.has(category)) {
                automaticAttemptedSessionIds.add(unlockSessionId)
                const codes = autoImportStatusBlockerCodes(status)
                return emit(buildBlockedStatus(codes))
            }
            return emit(createStatus({ category: 'waiting-auto-import' }))
        },
        cancelCurrentAttempt() {
            if (!currentAttempt) return clone(lastStatus)
            return invalidateCurrentAttempt('canceled', 'canceled')
        },
        disableAutoLaunch() {
            const activeDeps = getDeps()
            if (typeof activeDeps.requireActiveSession === 'function') activeDeps.requireActiveSession()
            const meta = activeDeps.loadVaultMeta ? activeDeps.loadVaultMeta() : null
            const setting = normalizeStoredSetting(meta)
            const nextMeta = {
                ...(meta || { version: '1.0.0' }),
                [TRUSTED_AUTO_LAUNCH_SETTINGS_KEY]: {
                    ...setting,
                    enabled: false
                }
            }
            activeDeps.saveVaultMeta(nextMeta, 'trusted-auto-launch-disable')
            clearCountdown()
            currentAttempt = null
            return emit(createStatus({ category: 'disabled' }))
        },
        updateSetting(input) {
            const activeDeps = getDeps()
            if (typeof activeDeps.requireActiveSession === 'function') activeDeps.requireActiveSession()
            const meta = activeDeps.loadVaultMeta ? activeDeps.loadVaultMeta() : null
            const existing = normalizeStoredSetting(meta)
            const patch = validateTrustedAutoLaunchSetting(input, { allowPartial: true })
            const setting = validateTrustedAutoLaunchSetting({ ...existing, ...patch })
            const nextMeta = {
                ...(meta || { version: '1.0.0' }),
                [TRUSTED_AUTO_LAUNCH_SETTINGS_KEY]: setting
            }
            activeDeps.saveVaultMeta(nextMeta, 'trusted-auto-launch-update-setting')
            clearCountdown()
            currentAttempt = null
            return emit(createStatus({ category: setting.enabled ? 'waiting-auto-import' : 'disabled' }))
        },
        launchNow() {
            if (currentAttempt) return launchFromGate(currentAttempt, currentAttempt.token)
            return startAttempt({ automatic: false, immediate: true })
        },
        invalidate(reason = 'token-invalid') {
            if (currentAttempt) return invalidateCurrentAttempt(reason, 'canceled')
            return clone(lastStatus)
        },
        markLocked() {
            unlockSessionId += 1
            autoImportStatusVersion += 1
            lastAutoImportStatus = null
            clearCountdown()
            currentAttempt = null
            return emit(createStatus({
                category: 'blocked',
                blockerReasonCodes: ['locked'],
                recoveryHints: recoveryHintsForCodes(['locked'])
            }))
        },
        getStatus() {
            return clone(lastStatus)
        }
    }
}
