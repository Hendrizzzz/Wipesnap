import { createHash } from 'crypto'
import {
    createCapabilityRecord,
    createCapabilityStore,
    normalizeCapabilityArgsPolicy,
    normalizeCapabilityUserArgs,
    validateCapabilityRecord,
    validateCapabilityUserArgs,
    validateCapabilityId
} from './capabilityStore.js'
import { normalizeAccountSlots } from './accountSlots.js'
import {
    describePathKind,
    validateWorkspaceInput
} from './ipcValidation.js'
import { isDangerousExecutablePath } from './appManifest.js'
import { WORKSPACE_SAFE_PRESET_METADATA_KEY } from './safePresetMetadata.js'

export const WORKSPACE_CAPABILITY_VAULT_KEY = 'launchCapabilityVault'
export const WORKSPACE_CAPABILITY_MIGRATION_REPORT_KEY = 'launchCapabilityMigration'

const MAX_NAME_LENGTH = 160
const MAX_STRING_LENGTH = 4096
const MAX_ID_LENGTH = 128
const HOST_WORKSPACE_LAUNCH_TYPES = new Set([
    'host-exe',
    'host-folder',
    'registry-uninstall',
    'app-paths',
    'start-menu-shortcut',
    'shell-execute',
    'protocol-uri',
    'packaged-app'
])
const VAULT_LAUNCH_TYPES = new Set(['vault-archive', 'vault-directory', 'imported-app'])
const RAW_LAUNCH_AUTHORITY_FIELDS = new Set([
    'path',
    'args',
    'launchCapabilityId',
    'launchSourceType',
    'launchMethod',
    'registryKey',
    'registryDisplayName',
    'registryInstallLocation',
    'registryDisplayIcon',
    'appPathsKey',
    'appPathsExecutableName',
    'appPathsPathValue',
    'shortcutPath',
    'shortcutTargetPath',
    'shortcutArguments',
    'shortcutWorkingDirectory',
    'shortcutIconLocation',
    'protocolScheme',
    'protocolCommand',
    'protocolRegistryKey',
    'packagedAppId',
    'manifestId',
    'launchProfile',
    'dataProfile',
    'readinessProfile',
    'supportTier',
    'supportSummary',
    'supportEvidence',
    'limitations',
    'ownershipProofLevel',
    'closePolicy',
    'canQuitFromOmniLaunch',
    'closeManagedAfterSpawn',
    'portableData',
    'launchAdapter',
    'runtimeAdapter'
])
const RENDERER_WORKSPACE_INTERNAL_FIELDS = new Set([
    WORKSPACE_CAPABILITY_VAULT_KEY,
    WORKSPACE_CAPABILITY_MIGRATION_REPORT_KEY,
    WORKSPACE_SAFE_PRESET_METADATA_KEY,
    'accountSlots'
])
const RENDERER_CAPABILITY_ENTRY_KEYS = new Set([
    'id',
    'capabilityId',
    'enabled',
    'displayName',
    'name',
    'userArgs',
    'quarantined',
    'quarantineReason',
    'quarantineCode'
])

function fail(message) {
    throw new Error(message)
}

function cloneValue(value) {
    return JSON.parse(JSON.stringify(value))
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function requireObject(value, fieldName) {
    if (!isPlainObject(value)) fail(`${fieldName} must be an object.`)
    return value
}

function normalizeString(value, fieldName, {
    required = false,
    max = MAX_STRING_LENGTH,
    allowEmpty = false
} = {}) {
    if (value == null) {
        if (required) fail(`${fieldName} is required.`)
        return ''
    }
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    if (value.includes('\0')) fail(`${fieldName} contains an invalid null byte.`)
    if (/[\r\n]/.test(value)) fail(`${fieldName} cannot contain control line breaks.`)
    const trimmed = value.trim()
    if (required && !trimmed) fail(`${fieldName} is required.`)
    if (!allowEmpty && value.length > 0 && !trimmed) fail(`${fieldName} cannot be blank.`)
    if (trimmed.length > max) fail(`${fieldName} is too long.`)
    return trimmed
}

function normalizeOptionalString(value, fieldName, options = {}) {
    if (value == null || value === '') return ''
    return normalizeString(value, fieldName, options)
}

function normalizeDisplayName(value, fallback, fieldName) {
    const displayName = normalizeString(value || fallback || 'Quarantined app', fieldName, {
        required: true,
        max: MAX_NAME_LENGTH
    })
    if (/[\t]/.test(displayName)) fail(`${fieldName} cannot contain control whitespace.`)
    return displayName
}

function normalizeBoolean(value, fieldName, defaultValue = false) {
    if (value == null) return defaultValue
    if (typeof value !== 'boolean') fail(`${fieldName} must be a boolean.`)
    return value
}

function normalizeId(value, fieldName) {
    if (value == null || value === '') return undefined
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value) || value < 0) fail(`${fieldName} must be a safe non-negative integer.`)
        return value
    }
    return normalizeString(value, fieldName, { max: MAX_ID_LENGTH })
}

function includeDefined(target, key, value) {
    if (value !== undefined && value !== null && value !== '') target[key] = value
}

function hasTraversalSegment(value) {
    return String(value || '')
        .split(/[\\/]+/)
        .some(part => part === '..')
}

function normalizePathSeparators(value) {
    return String(value || '').replace(/\//g, '\\')
}

function defaultLaunchSourceForPath(pathValue) {
    const kind = describePathKind(pathValue)
    if (kind === 'usb-macro') return 'vault-archive'
    if (kind === 'packaged-app') return 'packaged-app'
    if (kind === 'protocol') return 'protocol-uri'
    if (kind === 'absolute') return 'host-exe'
    return ''
}

function defaultLaunchMethodForSource(sourceType) {
    if (sourceType === 'protocol-uri' || sourceType === 'protocol') return 'protocol'
    if (sourceType === 'packaged-app') return 'packaged-app'
    if (sourceType === 'shell-execute' || sourceType === 'host-folder') return 'shell-execute'
    return 'spawn'
}

function hasLaunchArgs(value) {
    if (value == null || value === '') return false
    if (Array.isArray(value)) return value.some(item => String(item ?? '').trim())
    return String(value).trim().length > 0
}

function normalizeUserArgs(value, fieldName) {
    return normalizeCapabilityUserArgs(value, fieldName)
}

function normalizeWorkspaceShell(workspace) {
    const value = requireObject(workspace || {}, 'workspace')
    const safeWebOnly = validateWorkspaceInput({
        ...value,
        desktopApps: []
    })
    return {
        webTabs: safeWebOnly.webTabs,
        desktopApps: Array.isArray(value.desktopApps) ? value.desktopApps : [],
        ...(safeWebOnly.name ? { name: safeWebOnly.name } : {})
    }
}

export function rejectRendererSuppliedInternalWorkspaceFields(value) {
    for (const key of Object.keys(value || {})) {
        if (RENDERER_WORKSPACE_INTERNAL_FIELDS.has(key)) {
            fail(`workspace.${key} is main-owned workspace metadata and cannot be supplied by the renderer.`)
        }
    }
}

function normalizeCapabilityWorkspaceEntry(appConfig, index) {
    const value = requireObject(appConfig, `workspace.desktopApps[${index}]`)
    const fieldPrefix = `workspace.desktopApps[${index}]`
    const capabilityId = normalizeOptionalString(value.capabilityId, `${fieldPrefix}.capabilityId`, {
        max: 96
    })
    const displayName = normalizeDisplayName(value.displayName || value.name, capabilityId || `Desktop app ${index + 1}`, `${fieldPrefix}.displayName`)
    const next = {
        displayName,
        name: displayName,
        enabled: normalizeBoolean(value.enabled, `${fieldPrefix}.enabled`, true)
    }
    includeDefined(next, 'id', normalizeId(value.id, `${fieldPrefix}.id`))
    if (capabilityId) next.capabilityId = validateCapabilityId(capabilityId, `${fieldPrefix}.capabilityId`)
    const userArgs = normalizeUserArgs(value.userArgs, `${fieldPrefix}.userArgs`)
    if (userArgs.length > 0) next.userArgs = userArgs
    if (value.quarantined === true) {
        next.enabled = false
        next.quarantined = true
        next.quarantineReason = normalizeOptionalString(value.quarantineReason, `${fieldPrefix}.quarantineReason`, {
            max: 512
        }) || 'This app entry is quarantined.'
        next.quarantineCode = normalizeOptionalString(value.quarantineCode, `${fieldPrefix}.quarantineCode`, {
            max: 80
        }) || 'quarantined'
    }
    return next
}

function normalizeRendererCapabilityWorkspaceEntry(appConfig, index) {
    const value = requireObject(appConfig, `workspace.desktopApps[${index}]`)
    const fieldPrefix = `workspace.desktopApps[${index}]`

    for (const key of Object.keys(value)) {
        if (!RENDERER_CAPABILITY_ENTRY_KEYS.has(key)) {
            fail(`${fieldPrefix}.${key} is not accepted from renderer workspace data.`)
        }
    }

    const entry = normalizeCapabilityWorkspaceEntry(value, index)
    if (!entry.quarantined && !entry.capabilityId) {
        fail(`${fieldPrefix}.capabilityId is required.`)
    }
    return entry
}

function normalizeLegacyWorkspaceEntry(appConfig, index) {
    const value = requireObject(appConfig, `workspace.desktopApps[${index}]`)
    const fieldPrefix = `workspace.desktopApps[${index}]`
    const path = normalizeOptionalString(value.path, `${fieldPrefix}.path`)
    const displayName = normalizeDisplayName(value.displayName || value.name, path || `Desktop app ${index + 1}`, `${fieldPrefix}.name`)
    const launchSourceType = normalizeOptionalString(value.launchSourceType, `${fieldPrefix}.launchSourceType`, {
        max: 80
    }) || defaultLaunchSourceForPath(path)
    const launchMethod = normalizeOptionalString(value.launchMethod, `${fieldPrefix}.launchMethod`, {
        max: 80
    }) || defaultLaunchMethodForSource(launchSourceType)
    const next = {
        displayName,
        name: displayName,
        path,
        enabled: normalizeBoolean(value.enabled, `${fieldPrefix}.enabled`, true),
        launchSourceType,
        launchMethod,
        args: value.args
    }
    includeDefined(next, 'id', normalizeId(value.id, `${fieldPrefix}.id`))
    for (const key of [
        'launchCapabilityId',
        'registryKey',
        'registryDisplayName',
        'registryInstallLocation',
        'registryDisplayIcon',
        'appPathsKey',
        'appPathsExecutableName',
        'appPathsPathValue',
        'shortcutPath',
        'shortcutTargetPath',
        'shortcutArguments',
        'shortcutWorkingDirectory',
        'shortcutIconLocation',
        'protocolScheme',
        'protocolCommand',
        'protocolRegistryKey',
        'packagedAppId',
        'manifestId'
    ]) {
        const normalized = normalizeOptionalString(value[key], `${fieldPrefix}.${key}`)
        if (normalized) next[key] = normalized
    }
    return next
}

function normalizeWorkspaceForMigration(workspace) {
    const shell = normalizeWorkspaceShell(workspace)
    return {
        ...shell,
        desktopApps: shell.desktopApps.map((appConfig, index) => {
            if (isPlainObject(appConfig) && !appConfig.path && appConfig.capabilityId) {
                return normalizeCapabilityWorkspaceEntry(appConfig, index)
            }
            if (isPlainObject(appConfig) && appConfig.quarantined === true && !appConfig.path) {
                return normalizeCapabilityWorkspaceEntry(appConfig, index)
            }
            return normalizeLegacyWorkspaceEntry(appConfig, index)
        })
    }
}

function legacyLaunchReference(appConfig) {
    const reference = {
        launchSourceType: appConfig.launchSourceType,
        launchMethod: appConfig.launchMethod,
        path: appConfig.path
    }
    for (const key of [
        'registryKey',
        'appPathsKey',
        'shortcutPath',
        'protocolScheme',
        'packagedAppId'
    ]) {
        if (appConfig[key]) reference[key] = appConfig[key]
    }
    return reference
}

function legacyCapabilityIdFor(reference) {
    return `cap_${createHash('sha256').update(JSON.stringify(reference)).digest('hex').slice(0, 24)}`
}

function normalizeLegacyCapabilityRecords(records) {
    const normalized = new Map()
    const values = records instanceof Map
        ? [...records.values()]
        : Array.isArray(records)
            ? records
            : isPlainObject(records)
                ? Object.values(records)
                : []
    for (const record of values) {
        if (!isPlainObject(record) || !record.id) continue
        normalized.set(String(record.id), cloneValue(record))
    }
    return normalized
}

function legacyReferencesMatch(appConfig, record) {
    return JSON.stringify(legacyLaunchReference(appConfig)) === JSON.stringify(legacyLaunchReference(record))
}

function resolveLegacyEvidence(appConfig, legacyCapabilities) {
    const reference = legacyLaunchReference(appConfig)
    const ids = [
        appConfig.launchCapabilityId,
        legacyCapabilityIdFor(reference)
    ].filter(Boolean).map(String)

    for (const id of ids) {
        const record = legacyCapabilities.get(id)
        if (record && legacyReferencesMatch(appConfig, record)) return record
    }
    return null
}

function resolveProvenance(value, fallback = 'legacy-migration') {
    const normalized = String(value || fallback).trim().toLowerCase().replace(/[^a-z0-9-]/g, '-')
    return normalized.replace(/-+/g, '-').replace(/^-|-$/g, '').slice(0, 80) || fallback
}

function manifestArgsPolicy(manifest) {
    if (manifest?.launchArgsPolicy == null) return {}
    if (!isPlainObject(manifest.launchArgsPolicy)) {
        fail('Imported app manifest launchArgsPolicy must be an object.')
    }
    const argsPolicy = normalizeCapabilityArgsPolicy(
        manifest.launchArgsPolicy,
        'imported app manifest launchArgsPolicy'
    )
    return argsPolicy.allowedArgs === 'none' ? {} : argsPolicy
}

function policyForType(type, { manifest = null } = {}) {
    const ownedProcessTypes = new Set([
        'host-exe',
        'registry-uninstall',
        'app-paths',
        'start-menu-shortcut',
        'shortcut',
        'vault-archive',
        'vault-directory',
        'imported-app'
    ])
    return {
        allowedArgs: 'none',
        ...(VAULT_LAUNCH_TYPES.has(type) ? manifestArgsPolicy(manifest) : {}),
        canCloseFromWipesnap: ownedProcessTypes.has(type),
        ownership: ownedProcessTypes.has(type) ? 'owned-process' : 'external'
    }
}

function pickFirstString(...values) {
    for (const value of values) {
        if (typeof value === 'string' && value.trim()) return value.trim()
    }
    return ''
}

function buildHostCapabilityInput(appConfig, evidence) {
    if (!HOST_WORKSPACE_LAUNCH_TYPES.has(appConfig.launchSourceType)) {
        fail(`Unsupported legacy launch source: ${appConfig.launchSourceType || 'unknown'}.`)
    }

    const type = appConfig.launchSourceType
    const launch = {
        method: appConfig.launchMethod || defaultLaunchMethodForSource(type)
    }

    if (type === 'protocol-uri') {
        launch.uri = appConfig.path
    } else if (type === 'packaged-app') {
        launch.path = appConfig.path
    } else {
        launch.path = appConfig.path
    }

    const optionalFields = {
        'registry-uninstall': ['registryKey', 'registryDisplayName', 'registryInstallLocation', 'registryDisplayIcon'],
        'app-paths': ['appPathsKey', 'appPathsExecutableName', 'appPathsPathValue'],
        'start-menu-shortcut': ['shortcutPath', 'shortcutTargetPath', 'shortcutArguments', 'shortcutWorkingDirectory', 'shortcutIconLocation'],
        'shell-execute': ['shortcutPath', 'shortcutTargetPath', 'shortcutArguments', 'shortcutWorkingDirectory', 'shortcutIconLocation'],
        'protocol-uri': ['protocolScheme', 'protocolCommand', 'protocolRegistryKey'],
        'packaged-app': ['packagedAppId']
    }
    for (const key of optionalFields[type] || []) {
        const value = pickFirstString(appConfig[key], evidence?.[key])
        if (value) launch[key] = value
    }

    return {
        type,
        provenance: resolveProvenance(evidence?.provenance, 'legacy-host-launch'),
        displayName: appConfig.displayName || appConfig.name,
        launch,
        policy: policyForType(type)
    }
}

function parseUsbAppPath(pathValue) {
    const normalized = normalizePathSeparators(pathValue)
    const match = normalized.match(/^\[USB\]\\Apps\\([^\\]+)\\(.+)$/i)
    if (!match) fail('Imported app path must use [USB]\\Apps\\<storageId>\\<executable>.')

    const storageId = match[1]
    const exeRelativePath = match[2]
    if (!storageId || hasTraversalSegment(storageId) || hasTraversalSegment(exeRelativePath)) {
        fail('Imported app path cannot contain parent-directory traversal.')
    }
    if (isDangerousExecutablePath(exeRelativePath)) {
        fail(`Refusing to migrate unsafe imported executable target: ${exeRelativePath}.`)
    }
    return { storageId, exeRelativePath: normalizePathSeparators(exeRelativePath) }
}

function normalizeManifestSelectedExecutable(manifest) {
    const selected = normalizePathSeparators(manifest?.selectedExecutable?.relativePath || '')
    if (!selected) fail('Imported app manifest is missing a selected executable.')
    if (hasTraversalSegment(selected) || isDangerousExecutablePath(selected)) {
        fail('Imported app manifest selected executable is unsafe.')
    }
    return selected
}

function buildVaultCapabilityInput(appConfig, { manifestResolver } = {}) {
    const parsed = parseUsbAppPath(appConfig.path)
    if (!appConfig.manifestId) fail('Imported app entry is missing manifestId.')
    if (typeof manifestResolver !== 'function') {
        fail('Imported app capability cannot be verified without a manifest resolver.')
    }
    const manifest = manifestResolver(appConfig.manifestId, {
        storageId: parsed.storageId,
        appConfig
    })
    if (!manifest || typeof manifest !== 'object') {
        fail('Imported app manifest is missing or unavailable.')
    }
    if (manifest.manifestId && manifest.manifestId !== appConfig.manifestId) {
        fail('Imported app manifestId does not match the workspace entry.')
    }
    if (manifest.safeName && manifest.safeName !== parsed.storageId) {
        fail('Imported app manifest storage id does not match the workspace entry.')
    }
    const selectedExecutable = normalizeManifestSelectedExecutable(manifest)
    if (selectedExecutable.toLowerCase() !== parsed.exeRelativePath.toLowerCase()) {
        fail('Imported app executable does not match the verified manifest selection.')
    }

    const type = appConfig.launchSourceType === 'vault-directory' ? 'vault-directory' : 'vault-archive'
    return {
        type,
        provenance: 'import-manifest',
        displayName: appConfig.displayName || appConfig.name || manifest.displayName,
        launch: {
            method: 'spawn',
            storageId: parsed.storageId,
            manifestId: appConfig.manifestId
        },
        policy: policyForType(type, { manifest })
    }
}

export function createVaultLocalExecutableCapability({
    vaultRelativePath,
    manifest,
    id,
    randomBytes,
    now = Date.now
} = {}) {
    const relativePath = normalizePathSeparators(normalizeString(vaultRelativePath, 'vaultRelativePath', {
        required: true
    })).replace(/^\\+/, '')
    const parsed = parseUsbAppPath(`[USB]\\${relativePath}`)

    if (!manifest || typeof manifest !== 'object') {
        fail('USB-local executable browse requires a verified imported app manifest.')
    }

    const manifestId = manifest.manifestId || manifest.safeName || parsed.storageId
    const appConfig = {
        displayName: manifest.displayName || manifest.safeName || parsed.storageId,
        name: manifest.displayName || manifest.safeName || parsed.storageId,
        path: `[USB]\\${relativePath}`,
        launchSourceType: 'vault-archive',
        launchMethod: 'spawn',
        manifestId,
        enabled: true
    }
    includeDefined(appConfig, 'id', id)

    const input = buildVaultCapabilityInput(appConfig, {
        manifestResolver: () => manifest
    })
    const record = createCapabilityRecord(input, { randomBytes, now })
    const displayName = normalizeDisplayName(input.displayName, record.displayName, 'vaultLocalBrowse.displayName')

    return {
        record,
        appConfig: {
            capabilityId: record.capabilityId,
            displayName,
            name: displayName,
            path: appConfig.path,
            launchSourceType: 'vault-archive',
            launchMethod: 'spawn',
            enabled: true,
            ...(id !== undefined && id !== null && id !== '' ? { id } : {})
        }
    }
}

function createQuarantinedEntry(appConfig, reason, code = 'unverified-launch-reference') {
    const displayName = normalizeDisplayName(appConfig?.displayName || appConfig?.name, appConfig?.path || 'Quarantined app', 'quarantined.displayName')
    const next = {
        displayName,
        enabled: false,
        quarantined: true,
        quarantineCode: code,
        quarantineReason: reason
    }
    includeDefined(next, 'id', appConfig?.id)
    return next
}

function createLimitedCapabilityEntry(appConfig, record) {
    const displayName = normalizeDisplayName(appConfig.displayName || appConfig.name || record.displayName, record.displayName, 'workspace capability displayName')
    const next = {
        capabilityId: record.capabilityId,
        displayName,
        enabled: appConfig.enabled !== false
    }
    includeDefined(next, 'id', appConfig.id)
    if (Array.isArray(appConfig.userArgs) && appConfig.userArgs.length > 0) {
        next.userArgs = [...appConfig.userArgs]
    }
    return next
}

function hasRawLaunchAuthority(entry) {
    if (!isPlainObject(entry)) return false
    return Object.keys(entry).some(key => RAW_LAUNCH_AUTHORITY_FIELDS.has(key))
}

function createMigrationReport({ migratedAt, entries }) {
    const verified = entries.filter(entry => entry.status === 'verified').length
    const quarantined = entries.filter(entry => entry.status === 'quarantined').length
    const alreadyMigrated = entries.filter(entry => entry.status === 'already-migrated').length
    return {
        version: 1,
        migratedAt,
        verified,
        quarantined,
        alreadyMigrated,
        entries
    }
}

export function migrationReportToMetadataSummary(report) {
    if (!report) return null
    return {
        version: 1,
        migratedAt: report.migratedAt,
        verified: Number(report.verified || 0),
        quarantined: Number(report.quarantined || 0),
        alreadyMigrated: Number(report.alreadyMigrated || 0)
    }
}

export function workspaceEntryHasRawLaunchAuthority(entry) {
    return hasRawLaunchAuthority(entry)
}

export function migrateWorkspaceLaunchCapabilities(workspace, {
    existingCapabilityVault = null,
    legacyCapabilities = null,
    manifestResolver = null,
    failClosedOnUnverifiedEnabled = false,
    randomBytes,
    now = Date.now
} = {}) {
    const normalizedWorkspace = normalizeWorkspaceForMigration(workspace || {})
    const accountSlots = normalizeAccountSlots(workspace?.accountSlots || [])
    const store = createCapabilityStore({ vaultValue: existingCapabilityVault || null })
    const legacyCapabilityMap = normalizeLegacyCapabilityRecords(legacyCapabilities)
    const migratedAt = typeof now === 'function' ? new Date(now()).toISOString() : new Date(now).toISOString()
    const reportEntries = []
    let changed = false

    const desktopApps = normalizedWorkspace.desktopApps.map((appConfig, index) => {
        const displayName = appConfig.displayName || appConfig.name || `Desktop app ${index + 1}`

        if (appConfig.capabilityId && !hasRawLaunchAuthority(appConfig)) {
            const record = store.read(appConfig.capabilityId)
            if (!record) {
                if (failClosedOnUnverifiedEnabled && appConfig.enabled !== false && appConfig.quarantined !== true) {
                    fail('Capability is missing, stale, or unavailable.')
                }
                changed = true
                const reason = 'Capability is missing, stale, or unavailable.'
                reportEntries.push({ index, displayName, status: 'quarantined', reason })
                return createQuarantinedEntry(appConfig, reason, 'missing-capability')
            }
            reportEntries.push({
                index,
                displayName,
                status: 'already-migrated',
                capabilityId: record.capabilityId
            })
            return createLimitedCapabilityEntry(appConfig, record)
        }

        try {
            if (!appConfig.path) fail('Legacy app entry is missing a launch path.')
            if (hasLaunchArgs(appConfig.args)) {
                fail('Renderer-supplied launch arguments require an explicit capability args policy.')
            }

            let input
            if (VAULT_LAUNCH_TYPES.has(appConfig.launchSourceType) || describePathKind(appConfig.path) === 'usb-macro') {
                input = buildVaultCapabilityInput(appConfig, { manifestResolver })
            } else {
                const evidence = resolveLegacyEvidence(appConfig, legacyCapabilityMap)
                if (!evidence) {
                    fail('No main-issued legacy capability evidence matched this launch reference.')
                }
                input = buildHostCapabilityInput(appConfig, evidence)
            }

            const record = store.create(input, { randomBytes, now })
            changed = true
            reportEntries.push({
                index,
                displayName,
                status: 'verified',
                capabilityId: record.capabilityId
            })
            return createLimitedCapabilityEntry(appConfig, record)
        } catch (err) {
            if (failClosedOnUnverifiedEnabled && appConfig.enabled !== false && appConfig.quarantined !== true) {
                throw err
            }
            changed = true
            const reason = err?.message || 'Launch reference could not be verified.'
            reportEntries.push({ index, displayName, status: 'quarantined', reason })
            return createQuarantinedEntry(appConfig, reason)
        }
    })

    const report = createMigrationReport({ migratedAt, entries: reportEntries })
    const migratedWorkspace = {
        ...('name' in normalizedWorkspace ? { name: normalizedWorkspace.name } : {}),
        webTabs: normalizedWorkspace.webTabs,
        desktopApps,
        accountSlots,
        [WORKSPACE_CAPABILITY_VAULT_KEY]: store.toVaultValue(),
        [WORKSPACE_CAPABILITY_MIGRATION_REPORT_KEY]: report
    }

    return {
        workspace: migratedWorkspace,
        capabilityVault: migratedWorkspace[WORKSPACE_CAPABILITY_VAULT_KEY],
        migrationReport: report,
        changed
    }
}

function addPendingCapabilityRecords(store, pendingCapabilityRecords) {
    const values = pendingCapabilityRecords instanceof Map
        ? [...pendingCapabilityRecords.values()]
        : Array.isArray(pendingCapabilityRecords)
            ? pendingCapabilityRecords
            : isPlainObject(pendingCapabilityRecords)
                ? Object.values(pendingCapabilityRecords)
                : []

    for (const record of values) {
        store.put(validateCapabilityRecord(record))
    }
}

export function prepareRendererWorkspaceSave(workspace, {
    existingCapabilityVault = null,
    pendingCapabilityRecords = null
} = {}) {
    const workspaceInput = requireObject(workspace || {}, 'workspace')
    rejectRendererSuppliedInternalWorkspaceFields(workspaceInput)

    const shell = normalizeWorkspaceShell(workspaceInput)
    const sourceStore = createCapabilityStore({ vaultValue: existingCapabilityVault || null })
    addPendingCapabilityRecords(sourceStore, pendingCapabilityRecords)

    const persistedStore = createCapabilityStore()
    const desktopApps = shell.desktopApps.map((appConfig, index) => {
        const entry = normalizeRendererCapabilityWorkspaceEntry(appConfig, index)
        if (entry.quarantined) {
            return createQuarantinedEntry(entry, entry.quarantineReason || 'This app entry is quarantined.', entry.quarantineCode || 'quarantined')
        }

        const record = sourceStore.require(entry.capabilityId)
        requireAllowedUserArgs(entry, record)
        persistedStore.put(record)
        return createLimitedCapabilityEntry(entry, record)
    })

    return {
        workspace: {
            ...('name' in shell ? { name: shell.name } : {}),
            webTabs: shell.webTabs,
            desktopApps,
            [WORKSPACE_CAPABILITY_VAULT_KEY]: persistedStore.toVaultValue()
        },
        capabilityVault: persistedStore.toVaultValue(),
        migrationReport: null,
        changed: true,
        capabilities: {}
    }
}

function requireAllowedUserArgs(entry, record) {
    return validateCapabilityUserArgs(entry.userArgs || [], record, {
        fieldName: 'workspace entry userArgs'
    })
}

function manifestPathForCapability(record, manifestResolver) {
    if (typeof manifestResolver !== 'function') {
        fail(`Capability ${record.capabilityId} requires a manifest resolver.`)
    }
    const manifest = manifestResolver(record.launch.manifestId || record.launch.storageId, {
        storageId: record.launch.storageId,
        capability: record
    })
    if (!manifest || typeof manifest !== 'object') {
        fail(`Capability ${record.capabilityId} manifest is missing or unavailable.`)
    }
    if (manifest.safeName && manifest.safeName !== record.launch.storageId) {
        fail(`Capability ${record.capabilityId} manifest storage id mismatch.`)
    }
    const selectedExecutable = normalizeManifestSelectedExecutable(manifest)
    return `[USB]\\Apps\\${record.launch.storageId}\\${selectedExecutable}`
}

function rehydrateCapabilityRecord(entry, record, { manifestResolver } = {}) {
    const displayName = normalizeDisplayName(entry.displayName || entry.name || record.displayName, record.displayName, 'workspace capability displayName')
    const appConfig = {
        id: entry.id,
        name: displayName,
        enabled: true,
        args: requireAllowedUserArgs(entry, record),
        launchSourceType: record.type,
        launchMethod: record.launch.method,
        capabilityId: record.capabilityId
    }

    if (record.type === 'protocol-uri' || record.type === 'protocol') {
        appConfig.path = record.launch.uri
        appConfig.launchSourceType = 'protocol-uri'
        for (const key of ['protocolScheme', 'protocolCommand', 'protocolRegistryKey']) {
            if (record.launch[key]) appConfig[key] = record.launch[key]
        }
    } else if (record.type === 'packaged-app') {
        appConfig.path = record.launch.path || `shell:AppsFolder\\${record.launch.appId}`
        if (record.launch.appId) appConfig.packagedAppId = record.launch.appId
    } else if (VAULT_LAUNCH_TYPES.has(record.type)) {
        appConfig.path = manifestPathForCapability(record, manifestResolver)
        appConfig.launchSourceType = record.type === 'vault-directory' ? 'vault-directory' : 'vault-archive'
        if (record.launch.manifestId) appConfig.manifestId = record.launch.manifestId
    } else {
        appConfig.path = record.launch.path
        for (const key of [
            'registryKey',
            'registryDisplayName',
            'registryInstallLocation',
            'registryDisplayIcon',
            'appPathsKey',
            'appPathsExecutableName',
            'appPathsPathValue',
            'shortcutPath',
            'shortcutTargetPath',
            'shortcutArguments',
            'shortcutWorkingDirectory',
            'shortcutIconLocation'
        ]) {
            if (record.launch[key]) appConfig[key] = record.launch[key]
        }
    }

    return appConfig
}

export function rehydrateWorkspaceLaunchCapabilities(workspace, {
    capabilityVault = null,
    manifestResolver = null,
    includeDisabled = false
} = {}) {
    const normalizedWorkspace = normalizeWorkspaceForMigration(workspace || {})
    const store = createCapabilityStore({ vaultValue: capabilityVault || null })
    const desktopApps = []

    for (const appConfig of normalizedWorkspace.desktopApps) {
        if (appConfig.quarantined) {
            if (includeDisabled) desktopApps.push(createQuarantinedEntry(appConfig, appConfig.quarantineReason || 'This app entry is quarantined.', appConfig.quarantineCode || 'quarantined'))
            continue
        }
        if (appConfig.enabled === false) {
            if (includeDisabled && appConfig.capabilityId) {
                const record = store.read(appConfig.capabilityId)
                if (record) {
                    desktopApps.push({
                        ...rehydrateCapabilityRecord({ ...appConfig, enabled: true }, record, { manifestResolver }),
                        enabled: false
                    })
                }
            }
            continue
        }
        if (!appConfig.capabilityId) {
            fail('Workspace entry is missing a capabilityId and cannot be launched.')
        }
        const record = store.require(appConfig.capabilityId)
        desktopApps.push(rehydrateCapabilityRecord(appConfig, record, { manifestResolver }))
    }

    return {
        ...('name' in normalizedWorkspace ? { name: normalizedWorkspace.name } : {}),
        webTabs: normalizedWorkspace.webTabs,
        desktopApps
    }
}

export function sanitizeWorkspaceForRenderer(workspace) {
    const shell = normalizeWorkspaceShell(workspace || {})
    return {
        ...('name' in shell ? { name: shell.name } : {}),
        webTabs: shell.webTabs,
        desktopApps: shell.desktopApps.map((appConfig, index) => {
            if (isPlainObject(appConfig) && appConfig.quarantined === true) {
                const entry = normalizeCapabilityWorkspaceEntry(appConfig, index)
                return createQuarantinedEntry(entry, entry.quarantineReason || 'This app entry is quarantined.', entry.quarantineCode || 'quarantined')
            }
            if (isPlainObject(appConfig) && appConfig.capabilityId && !hasRawLaunchAuthority(appConfig)) {
                return normalizeCapabilityWorkspaceEntry(appConfig, index)
            }
            return createQuarantinedEntry(
                isPlainObject(appConfig) ? appConfig : {},
                'Stored app entry still contains raw launch authority and was not exposed to the renderer.',
                'raw-launch-authority'
            )
        })
    }
}
