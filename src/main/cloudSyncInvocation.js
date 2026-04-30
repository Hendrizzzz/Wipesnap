import { validateCloudSyncInvocationInput } from './ipcValidation.js'
import {
    applyTrustedCloudSafePresetPatchesAfterUnlock,
    downloadDesktopEncryptedPatchSummaries,
    downloadDesktopPatchPlans,
    uploadDesktopSanitizedSnapshot
} from './cloudSyncClientTransport.js'

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function sideEffectsNone(extra = {}) {
    return {
        writesVault: false,
        writesCapabilityVault: false,
        createsCapability: false,
        createsAccountSlots: false,
        createsBrowserProfiles: false,
        launches: false,
        writesCloudSnapshot: false,
        writesCloudPatchStatus: false,
        mergesPatch: false,
        ...extra
    }
}

function isLockedError(error) {
    return /session is locked|vault is locked|locked vault|unlock required|after vault unlock|active vault session|unlock/i
        .test(error?.message || '')
}

function isRuntimeUnavailableError(error) {
    return /cloud sync (invocation|transport).*requires|requires (unlocked desktop cloud sync storage|desktop cloud sync storage|a Functions client|a Firestore client|a current sanitized snapshot builder)|cannot (call|read|list) cloud sync|runtime is not configured/i
        .test(error?.message || '')
}

function safeErrorMessage(error, status) {
    if (status === 'locked') return 'Cloud sync requires an active unlocked vault session.'
    if (status === 'unavailable') return 'Cloud sync is not configured on this desktop.'
    const message = String(error?.message || '')
    if (/vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile|AppData[\\/]|[A-Za-z]:[\\/]|\\\\|cap_[a-f0-9]{32,64}|bearer\s+/i.test(message)) {
        return 'Cloud sync invocation failed.'
    }
    return message || 'Cloud sync invocation failed.'
}

function errorSummary(operation, error) {
    const status = isLockedError(error) ? 'locked' : isRuntimeUnavailableError(error) ? 'unavailable' : 'rejected'
    return {
        success: false,
        operation,
        status,
        error: safeErrorMessage(error, status),
        metadataOnly: true,
        records: [],
        summary: {
            uploaded: 0,
            downloaded: 0,
            planned: 0,
            applied: 0,
            conflicts: 0,
            skipped: 0
        },
        sideEffects: sideEffectsNone()
    }
}

function requireActiveVaultSession(deps) {
    if (!deps || typeof deps.requireActiveSession !== 'function') {
        fail('Cloud sync invocation requires requireActiveSession.')
    }
    deps.requireActiveSession()
}

function requireDependency(deps, key, message) {
    if (!deps?.[key]) fail(message)
    return deps[key]
}

function resolveDeps(deps) {
    return typeof deps === 'function' ? deps() : deps
}

function normalizeNow(now) {
    if (typeof now === 'function') return now()
    return now == null ? Date.now() : now
}

function createCurrentSnapshotBuilder(deps) {
    if (typeof deps?.buildCurrentSanitizedSnapshot !== 'function') {
        fail('Cloud sync invocation requires a current sanitized snapshot builder.')
    }
    return async ({ ownerUid, device, now, workspace } = {}) => {
        requireActiveVaultSession(deps)
        const activeWorkspace = workspace || (typeof deps.loadActiveVaultWorkspace === 'function'
            ? deps.loadActiveVaultWorkspace()
            : null)
        if (!activeWorkspace) fail('Cloud sync invocation requires loadActiveVaultWorkspace.')
        return deps.buildCurrentSanitizedSnapshot({
            ownerUid,
            device: clone(device),
            now,
            workspace: clone(activeWorkspace)
        })
    }
}

function summarizeCloudStatus(result) {
    if (!isPlainObject(result)) return null
    return {
        status: String(result.status || ''),
        reason: result.reason ? String(result.reason) : '',
        metadataOnly: true
    }
}

function summarizeSnapshotUpload(result) {
    return {
        success: true,
        operation: 'upload-sanitized-snapshot',
        status: result.status,
        revisionId: result.revisionId,
        metadataOnly: true,
        summary: {
            uploaded: result.status === 'accepted' ? 1 : 0,
            downloaded: 0,
            planned: 0,
            applied: 0,
            conflicts: 0,
            skipped: result.status === 'accepted' ? 0 : 1
        },
        cloudStatus: summarizeCloudStatus(result.result),
        sideEffects: sideEffectsNone({ writesCloudSnapshot: result.status === 'accepted' })
    }
}

function summarizePatchPlan(plan) {
    const importPlan = plan.importPlan || {}
    return {
        status: 'planned',
        reason: 'validate-only',
        patchRevisionId: plan.patchRevisionId || importPlan.patchRevisionId || '',
        patchId: importPlan.patchId || null,
        authorDeviceId: plan.authorDeviceId || importPlan.authorDeviceId || null,
        baseSnapshotRevisionId: importPlan.baseSnapshotRevisionId || null,
        currentSnapshotRevisionId: importPlan.snapshot?.revisionId || null,
        metadataOnly: true,
        planned: {
            presets: importPlan.planned?.presets || 0,
            newBrowserItems: importPlan.planned?.newBrowserItems || 0,
            selectionMetadata: importPlan.planned?.selectionMetadata || 0
        },
        sideEffects: sideEffectsNone({
            writesVault: importPlan.sideEffects?.writesVault === true,
            launches: importPlan.sideEffects?.launches === true
        })
    }
}

function summarizePatchPlanning(result) {
    const records = (result.plans || []).map(summarizePatchPlan)
    return {
        success: true,
        operation: 'plan-safe-preset-patches',
        status: result.status,
        metadataOnly: true,
        records,
        summary: {
            uploaded: 0,
            downloaded: records.length,
            planned: records.length,
            applied: 0,
            conflicts: 0,
            skipped: 0
        },
        sideEffects: sideEffectsNone({
            writesVault: result.sideEffects?.writesVault === true,
            launches: result.sideEffects?.launches === true,
            mergesPatch: result.sideEffects?.mergesPatch === true
        })
    }
}

function summarizeEncryptedDownload(result) {
    const records = (result.records || []).map(record => ({
        status: record.status,
        reason: record.reason,
        patchRevisionId: record.patchRevisionId,
        patchId: record.patchId || null,
        authorDeviceId: record.authorDeviceId || null,
        baseSnapshotRevisionId: record.baseSnapshotRevisionId || null,
        metadataOnly: true,
        encrypted: true,
        cloudStatus: record.cloudStatus || null,
        authorTrust: record.authorTrust || null,
        sideEffects: sideEffectsNone()
    }))
    return {
        success: true,
        operation: 'download-encrypted-patch-summaries',
        status: result.status,
        metadataOnly: true,
        records,
        summary: {
            uploaded: 0,
            downloaded: result.summary?.downloaded || 0,
            planned: 0,
            applied: 0,
            conflicts: result.summary?.conflicts || 0,
            skipped: result.summary?.skipped || 0
        },
        sideEffects: sideEffectsNone({
            writesCloudPatchStatus: result.sideEffects?.writesCloudPatchStatus === true,
            mergesPatch: result.sideEffects?.mergesPatch === true
        })
    }
}

function summarizeTrustedApply(result) {
    const records = (result.records || []).map(record => ({
        status: record.status,
        code: record.code || '',
        reason: record.reason,
        patchRevisionId: record.patchRevisionId,
        patchId: record.patchId || null,
        authorDeviceId: record.authorDeviceId || null,
        baseSnapshotRevisionId: record.baseSnapshotRevisionId || null,
        currentSnapshotRevisionId: record.currentSnapshotRevisionId || null,
        mergeStatus: record.mergeStatus || '',
        metadataOnly: true,
        cloudStatus: summarizeCloudStatus(record.cloudStatus),
        sideEffects: sideEffectsNone({
            writesVault: record.sideEffects?.writesVault === true
        })
    }))
    return {
        success: result.status === 'completed',
        operation: 'apply-trusted-patches',
        status: result.status,
        metadataOnly: true,
        records,
        summary: {
            uploaded: 0,
            downloaded: records.length,
            planned: 0,
            applied: result.summary?.applied || 0,
            conflicts: result.summary?.conflicts || 0,
            skipped: result.summary?.skipped || 0
        },
        sideEffects: sideEffectsNone({
            writesVault: result.sideEffects?.writesVault === true,
            writesCloudPatchStatus: result.sideEffects?.writesCloudPatchStatus === true
        }),
        ...(result.error ? { error: safeErrorMessage({ message: result.error }, result.status) } : {})
    }
}

export async function uploadSanitizedSnapshotInvocationHandlerCore({ input = {}, deps } = {}) {
    const operation = 'upload-sanitized-snapshot'
    try {
        validateCloudSyncInvocationInput(input)
        const resolved = resolveDeps(deps)
        requireActiveVaultSession(resolved)
        const result = await uploadDesktopSanitizedSnapshot({
            storage: requireDependency(resolved, 'storage', 'Cloud sync invocation requires desktop cloud sync storage.'),
            functionsClient: requireDependency(resolved, 'functionsClient', 'Cloud sync invocation requires a Functions client.'),
            snapshotBuilder: createCurrentSnapshotBuilder(resolved),
            now: normalizeNow(resolved.now)
        })
        return summarizeSnapshotUpload(result)
    } catch (error) {
        return errorSummary(operation, error)
    }
}

export async function downloadEncryptedPatchSummariesInvocationHandlerCore({ input = {}, deps } = {}) {
    const operation = 'download-encrypted-patch-summaries'
    try {
        const request = validateCloudSyncInvocationInput(input)
        const resolved = resolveDeps(deps)
        requireActiveVaultSession(resolved)
        const result = await downloadDesktopEncryptedPatchSummaries({
            storage: requireDependency(resolved, 'storage', 'Cloud sync invocation requires desktop cloud sync storage.'),
            firestoreClient: requireDependency(resolved, 'firestoreClient', 'Cloud sync invocation requires a Firestore client.'),
            patchRevisionIds: request.patchRevisionIds
        })
        return summarizeEncryptedDownload(result)
    } catch (error) {
        return errorSummary(operation, error)
    }
}

export async function planSafePresetPatchesInvocationHandlerCore({ input = {}, deps } = {}) {
    const operation = 'plan-safe-preset-patches'
    try {
        const request = validateCloudSyncInvocationInput(input)
        const resolved = resolveDeps(deps)
        requireActiveVaultSession(resolved)
        const snapshotBuilder = createCurrentSnapshotBuilder(resolved)
        const sanitizedSnapshot = await snapshotBuilder({ now: normalizeNow(resolved.now) })
        const result = await downloadDesktopPatchPlans({
            storage: requireDependency(resolved, 'storage', 'Cloud sync invocation requires desktop cloud sync storage.'),
            firestoreClient: requireDependency(resolved, 'firestoreClient', 'Cloud sync invocation requires a Firestore client.'),
            sanitizedSnapshot,
            patchRevisionIds: request.patchRevisionIds
        })
        return summarizePatchPlanning(result)
    } catch (error) {
        return errorSummary(operation, error)
    }
}

export async function applyTrustedPatchesInvocationHandlerCore({ input = {}, deps } = {}) {
    const operation = 'apply-trusted-patches'
    try {
        const request = validateCloudSyncInvocationInput(input)
        const resolved = resolveDeps(deps)
        requireActiveVaultSession(resolved)
        const result = await applyTrustedCloudSafePresetPatchesAfterUnlock({
            storage: requireDependency(resolved, 'storage', 'Cloud sync invocation requires desktop cloud sync storage.'),
            firestoreClient: requireDependency(resolved, 'firestoreClient', 'Cloud sync invocation requires a Firestore client.'),
            functionsClient: requireDependency(resolved, 'functionsClient', 'Cloud sync invocation requires a Functions client.'),
            deps: resolved,
            snapshotBuilder: createCurrentSnapshotBuilder(resolved),
            patchRevisionIds: request.patchRevisionIds,
            callerContext: {
                unlocked: true,
                vaultBacked: true,
                authority: 'desktop-main'
            },
            now: normalizeNow(resolved.now)
        })
        return summarizeTrustedApply(result)
    } catch (error) {
        return errorSummary(operation, error)
    }
}

export function registerCloudSyncInvocationIpcHandlers({ trustedHandle, deps } = {}) {
    if (typeof trustedHandle !== 'function') fail('Cloud sync IPC registration requires trustedHandle.')
    trustedHandle('cloud-sync:upload-sanitized-snapshot', async (_event, input = {}) =>
        uploadSanitizedSnapshotInvocationHandlerCore({ input, deps }))
    trustedHandle('cloud-sync:download-encrypted-patch-summaries', async (_event, input = {}) =>
        downloadEncryptedPatchSummariesInvocationHandlerCore({ input, deps }))
    trustedHandle('cloud-sync:plan-safe-preset-patches', async (_event, input = {}) =>
        planSafePresetPatchesInvocationHandlerCore({ input, deps }))
    trustedHandle('cloud-sync:apply-trusted-patches', async (_event, input = {}) =>
        applyTrustedPatchesInvocationHandlerCore({ input, deps }))
}
