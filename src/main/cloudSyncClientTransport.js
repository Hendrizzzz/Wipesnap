import { createPublicKey } from 'crypto'
import {
    CLOUD_SYNC_SIGNING_ALGORITHM,
    CLOUD_SYNC_PATCH_DOC_TYPE,
    CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
    assertNoForbiddenCloudSyncBackendPlaintext,
    createEncryptedCloudSyncEnvelope,
    decryptCloudSyncEnvelope,
    signCloudSyncCanonicalMetadata,
    validateCloudSyncConflictMetadata,
    validateCloudSyncDeviceRecord,
    validateCloudSyncEnvelope
} from './cloudSyncEnvelope.js'
import {
    CLOUD_SYNC_INGESTION_OPERATIONS,
    CLOUD_SYNC_INGESTION_SCHEMA_VERSION,
    CLOUD_SYNC_PATCH_APPLY_DECISION_RECORD_TYPE,
    createCloudSyncIngestionSignatureMetadata,
    validateCloudSyncPatchApplyDecisionRecord
} from './cloudSyncIngestion.js'
import { planSafePresetPatchImport, validateSafePresetPatch } from './safePresetPatch.js'
import { mergeSafePresetPatchPlanAfterUnlock } from './safePresetPatchMerge.js'
import { redactCloudSyncClientLogValue } from './cloudSyncClientStorage.js'

function fail(message) {
    throw new Error(message)
}

function failCode(code, message) {
    const err = new Error(message)
    err.code = code
    throw err
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function normalizeDeviceState(state, role, fieldName) {
    const device = isPlainObject(state?.device) ? state.device : fail(`${fieldName}.device is required.`)
    if (role === 'desktop' && device.role !== 'desktop') fail(`${fieldName} requires a desktop device.`)
    if (role === 'phone' && !['phone', 'web-planner'].includes(device.role)) {
        fail(`${fieldName} requires a phone or web planner device.`)
    }
    if (typeof state.ownerUid !== 'string' || state.ownerUid !== device.ownerUid) {
        fail(`${fieldName}.ownerUid must match the device owner.`)
    }
    if (!state.syncRootKey) fail(`${fieldName}.syncRootKey is required in memory for local app encryption.`)
    return { ...state, device }
}

function nextDeviceSequence(device) {
    if (!Number.isSafeInteger(device.deviceSequence) || device.deviceSequence < 0) {
        fail('Device sequence is invalid.')
    }
    return device.deviceSequence + 1
}

async function callCloudFunction(functionsClient, name, data) {
    if (!functionsClient) fail('Cloud sync transport requires a Functions client adapter.')
    if (typeof functionsClient.callCloudSyncFunction === 'function') {
        return functionsClient.callCloudSyncFunction(name, data)
    }
    if (typeof functionsClient.call === 'function') return functionsClient.call(name, data)
    if (typeof functionsClient[name] === 'function') return functionsClient[name](data)
    fail(`Functions client cannot call ${name}.`)
}

async function getCloudDocument(firestoreClient, path) {
    if (!firestoreClient) fail('Cloud sync transport requires a Firestore client adapter.')
    if (typeof firestoreClient.getCloudSyncDocument === 'function') {
        return firestoreClient.getCloudSyncDocument(path)
    }
    if (typeof firestoreClient.getDocument === 'function') return firestoreClient.getDocument(path)
    if (typeof firestoreClient.get === 'function') return firestoreClient.get(path)
    fail('Firestore client cannot read cloud sync documents.')
}

async function listCloudDocuments(firestoreClient, collectionPath) {
    if (!firestoreClient) fail('Cloud sync transport requires a Firestore client adapter.')
    if (typeof firestoreClient.listCloudSyncDocuments === 'function') {
        return firestoreClient.listCloudSyncDocuments(collectionPath)
    }
    if (typeof firestoreClient.listDocuments === 'function') return firestoreClient.listDocuments(collectionPath)
    if (typeof firestoreClient.list === 'function') return firestoreClient.list(collectionPath)
    fail('Firestore client cannot list cloud sync documents.')
}

async function getTrustedDeviceRecord(firestoreClient, ownerUid, deviceId) {
    if (typeof firestoreClient?.getTrustedDeviceRecord === 'function') {
        return firestoreClient.getTrustedDeviceRecord({ ownerUid, deviceId })
    }
    if (typeof firestoreClient?.getDeviceRecord === 'function') {
        return firestoreClient.getDeviceRecord(ownerUid, deviceId)
    }
    return getCloudDocument(firestoreClient, `users/${ownerUid}/devices/${deviceId}`)
}

function publicKeyFromDeviceRecord(device) {
    if (!device?.signingPublicKey?.spki) fail('Device signing public key is required.')
    return createPublicKey({
        key: Buffer.from(device.signingPublicKey.spki, 'base64url'),
        format: 'der',
        type: 'spki'
    })
}

function envelopeWithoutBackendIngestionMetadata(rawEnvelope) {
    const envelope = clone(rawEnvelope)
    if (isPlainObject(envelope)) {
        if (envelope.ingestion != null) assertNoForbiddenCloudSyncBackendPlaintext(envelope.ingestion, 'cloud sync envelope.ingestion')
        if (envelope.apply != null) validateCloudSyncPatchApplyDecisionRecord(envelope.apply)
        delete envelope.ingestion
        delete envelope.apply
    }
    return envelope
}

async function updateLocalSequence(storage, deviceSequence) {
    if (typeof storage.updateDeviceSequence === 'function') {
        await storage.updateDeviceSequence(deviceSequence)
    }
}

function nowMs(now) {
    const value = typeof now === 'function' ? now() : now
    if (!Number.isSafeInteger(value) || value < 0) fail('A safe patch apply timestamp is required.')
    return value
}

function sortPatchDocuments(documents) {
    return [...documents].sort((a, b) => {
        const aCreated = Number.isSafeInteger(a?.createdAt) ? a.createdAt : Number.MAX_SAFE_INTEGER
        const bCreated = Number.isSafeInteger(b?.createdAt) ? b.createdAt : Number.MAX_SAFE_INTEGER
        if (aCreated !== bCreated) return aCreated - bCreated
        return String(a?.revisionId || '').localeCompare(String(b?.revisionId || ''))
    })
}

function backendIngestionConflict(rawEnvelope) {
    if (!isPlainObject(rawEnvelope?.ingestion) || rawEnvelope.ingestion.conflict == null) return null
    return validateCloudSyncConflictMetadata(rawEnvelope.ingestion.conflict)
}

function backendApplyDecision(rawEnvelope) {
    if (rawEnvelope?.apply == null) return null
    return validateCloudSyncPatchApplyDecisionRecord(rawEnvelope.apply)
}

function requireTrustedPatchAuthorDevice(authorDevice, state, envelope) {
    let device
    try {
        device = validateCloudSyncDeviceRecord(authorDevice)
    } catch (error) {
        failCode('invalid-author-device', error.message || 'Patch author device is invalid.')
    }
    if (device.ownerUid !== state.ownerUid || device.deviceId !== envelope.deviceId) {
        failCode('invalid-author-device', 'Patch author device does not match the encrypted envelope.')
    }
    if (!['phone', 'web-planner'].includes(device.role)) {
        failCode('invalid-author-device', 'Patch author must be a phone or web planner device.')
    }
    if (!Array.isArray(device.syncScopes) || !device.syncScopes.includes('patch-upload')) {
        failCode('invalid-author-device', 'Patch author device is not trusted for patch uploads.')
    }
    if (device.keyVersion !== envelope.keyVersion) {
        failCode('invalid-key', 'Patch author key version does not match the envelope.')
    }
    if (device.status !== 'active' || device.revokedAt != null) {
        failCode('revoked-device', 'Patch author device has been revoked.')
    }
    return device
}

function reasonForMergeConflict(conflictCode) {
    if (conflictCode === 'stale-base' || conflictCode === 'snapshot-mismatch' || conflictCode === 'preset-stale') return 'stale-base'
    if (conflictCode === 'unknown-safe-item' ||
        conflictCode === 'unknown-account-intention' ||
        conflictCode === 'unknown-profile-intention') return 'unknown-safe-id'
    if (conflictCode === 'unknown-preset' ||
        conflictCode === 'unknown-default-preset' ||
        conflictCode === 'unknown-next-preset') return 'unknown-safe-preset'
    if (String(conflictCode || '').includes('duplicate')) return 'duplicate-patch'
    return 'schema-rejected'
}

function reasonForMergeRejection(mergeResult) {
    const text = `${mergeResult?.status || ''} ${mergeResult?.error || ''}`.toLowerCase()
    if (/transaction|commitvaultmeta|commit vault/.test(text)) return 'transaction-failure'
    return 'merge-rejected'
}

function classifyPatchApplyError(error) {
    const code = String(error?.code || '')
    const message = String(error?.message || '')
    const text = `${code} ${message}`.toLowerCase()
    if (code === 'revoked-device' || /revoked|not active/.test(text)) {
        return { status: 'skipped', reason: 'revoked-device', code: 'revoked-device' }
    }
    if (code === 'invalid-key' || /stale key version|key version|could not be decrypted|authenticated|syncrootkey/.test(text)) {
        return { status: 'skipped', reason: 'invalid-key', code: 'invalid-key' }
    }
    if (/signature|not valid/.test(text)) {
        return { status: 'skipped', reason: 'invalid-signature', code: 'invalid-signature' }
    }
    if (/forbidden|not accepted because|secret|path|command|registry|process|vault|browser session|launch capability|material/.test(text)) {
        return { status: 'skipped', reason: 'forbidden-material', code: 'forbidden-material' }
    }
    if (/base.*does not match|stale-base|snapshot revision/.test(text)) {
        return { status: 'conflict', reason: 'stale-base', code: 'stale-base' }
    }
    if (/unknown safe item|unknown account intention|unknown profile intention/.test(text)) {
        return { status: 'conflict', reason: 'unknown-safe-id', code: 'unknown-safe-id' }
    }
    if (/unknown preset|defaultpresetid references an unknown|nextpresetid references an unknown/.test(text)) {
        return { status: 'conflict', reason: 'unknown-safe-preset', code: 'unknown-safe-preset' }
    }
    if (/duplicate|already exists|replayed/.test(text)) {
        return { status: 'skipped', reason: 'duplicate-patch', code: 'duplicate-patch' }
    }
    if (/transaction|commitvaultmeta|commit vault/.test(text)) {
        return { status: 'skipped', reason: 'transaction-failure', code: 'transaction-failure' }
    }
    if (/cloud sync envelope/.test(text)) {
        return { status: 'skipped', reason: 'invalid-envelope', code: 'invalid-envelope' }
    }
    return { status: 'skipped', reason: 'schema-rejected', code: 'schema-rejected' }
}

function sideEffectsNone(extra = {}) {
    return {
        writesVault: false,
        writesCapabilityVault: false,
        createsCapability: false,
        createsAccountSlots: false,
        createsBrowserProfiles: false,
        launches: false,
        ...extra
    }
}

function patchRecord({
    status,
    code,
    reason,
    envelope = null,
    patch = null,
    currentSnapshot = null,
    mergeResult = null,
    cloudStatus = null,
    message = ''
}) {
    return {
        status,
        code,
        reason,
        patchRevisionId: patch?.patchRevisionId || envelope?.revisionId || '',
        patchId: patch?.patchId || envelope?.patchId || null,
        authorDeviceId: patch?.authorDeviceId || envelope?.deviceId || null,
        baseSnapshotRevisionId: patch?.baseSnapshotRevisionId || envelope?.baseRevisionId || null,
        currentSnapshotRevisionId: currentSnapshot?.revisionId || mergeResult?.currentSnapshotRevisionId || null,
        mergeStatus: mergeResult?.status || '',
        metadataOnly: true,
        cloudStatus,
        sideEffects: sideEffectsNone({
            writesVault: mergeResult?.sideEffects?.writesVault === true
        }),
        ...(message ? { message } : {})
    }
}

function encryptedPatchSummaryRecord({
    status,
    reason,
    envelope = null,
    requestedRevisionId = '',
    cloudStatus = null,
    authorTrust = null,
    message = ''
}) {
    return {
        status,
        reason,
        patchRevisionId: envelope?.revisionId || requestedRevisionId || '',
        patchId: envelope?.patchId || null,
        authorDeviceId: envelope?.deviceId || null,
        baseSnapshotRevisionId: envelope?.baseRevisionId || null,
        metadataOnly: true,
        encrypted: true,
        cloudStatus,
        authorTrust,
        sideEffects: sideEffectsNone(),
        ...(message ? { message } : {})
    }
}

async function trustedPatchAuthorSummary(firestoreClient, state, envelope) {
    try {
        const device = validateCloudSyncDeviceRecord(
            await getTrustedDeviceRecord(firestoreClient, state.ownerUid, envelope.deviceId)
        )
        if (device.ownerUid !== state.ownerUid || device.deviceId !== envelope.deviceId) {
            return { status: 'invalid', metadataOnly: true }
        }
        if (!['phone', 'web-planner'].includes(device.role)) {
            return { status: 'invalid-role', role: device.role, metadataOnly: true }
        }
        if (device.status !== 'active' || device.revokedAt != null) {
            return { status: 'revoked', role: device.role, metadataOnly: true }
        }
        if (!Array.isArray(device.syncScopes) || !device.syncScopes.includes('patch-upload')) {
            return { status: 'untrusted', role: device.role, metadataOnly: true }
        }
        if (device.keyVersion !== envelope.keyVersion) {
            return { status: 'invalid-key', role: device.role, metadataOnly: true }
        }
        return { status: 'trusted', role: device.role, metadataOnly: true }
    } catch (_) {
        return { status: 'invalid', metadataOnly: true }
    }
}

export async function verifyTrustedPatchAuthorForAutoLaunch({
    storage,
    firestoreClient,
    patchRevisionId
} = {}) {
    try {
        if (!storage || typeof storage.loadAfterUnlock !== 'function') {
            fail('Trusted auto-launch requires unlocked desktop cloud sync storage.')
        }
        if (typeof patchRevisionId !== 'string' || !/^patchrev_[A-Za-z0-9_-]{1,120}$/.test(patchRevisionId.trim())) {
            return { trusted: false, reason: 'invalid-patch', metadataOnly: true }
        }
        const state = normalizeDeviceState(await storage.loadAfterUnlock(), 'desktop', 'desktop cloud sync state')
        const rawEnvelope = await getCloudDocument(firestoreClient, `users/${state.ownerUid}/patches/${patchRevisionId.trim()}`)
        if (!rawEnvelope) return { trusted: false, reason: 'not-found', metadataOnly: true }
        const envelope = validateCloudSyncEnvelope(envelopeWithoutBackendIngestionMetadata(rawEnvelope), {
            expectedDocType: CLOUD_SYNC_PATCH_DOC_TYPE,
            activeKeyVersion: state.device.keyVersion
        })
        if (envelope.revisionId !== patchRevisionId.trim()) {
            return { trusted: false, reason: 'invalid-patch', metadataOnly: true }
        }
        requireTrustedPatchAuthorDevice(
            await getTrustedDeviceRecord(firestoreClient, state.ownerUid, envelope.deviceId),
            state,
            envelope
        )
        return { trusted: true, metadataOnly: true }
    } catch (error) {
        const code = error?.code
        if (code === 'revoked-device') return { trusted: false, reason: 'revoked-device', metadataOnly: true }
        if (code === 'invalid-key') return { trusted: false, reason: 'invalid-key', metadataOnly: true }
        if (code === 'invalid-author-device') return { trusted: false, reason: 'untrusted-author', metadataOnly: true }
        const classified = classifyPatchApplyError(error)
        return {
            trusted: false,
            reason: classified.reason || 'invalid-patch',
            metadataOnly: true
        }
    }
}

function requireActiveVaultSessionForTrustedPatchApply(deps) {
    if (!deps || typeof deps.requireActiveSession !== 'function') {
        fail('Trusted cloud patch apply requires requireActiveSession.')
    }
    deps.requireActiveSession()
}

async function buildCurrentSanitizedSnapshotForPatchApply({ deps, snapshotBuilder }) {
    requireActiveVaultSessionForTrustedPatchApply(deps)
    if (typeof deps.loadActiveVaultWorkspace !== 'function') {
        fail('Trusted cloud patch apply requires loadActiveVaultWorkspace.')
    }
    const workspace = clone(deps.loadActiveVaultWorkspace())
    if (typeof snapshotBuilder === 'function') {
        return snapshotBuilder({ workspace: clone(workspace) })
    }
    if (typeof deps.buildCurrentSanitizedSnapshot === 'function') {
        return deps.buildCurrentSanitizedSnapshot({ workspace: clone(workspace) })
    }
    fail('Trusted cloud patch apply requires a current sanitized snapshot builder.')
}

function createPatchApplyDecision({ state, envelope, patch = null, status, reason, currentSnapshotRevisionId = null, mergeStatus = '', decidedAt }) {
    return validateCloudSyncPatchApplyDecisionRecord({
        product: 'wipesnap',
        recordType: CLOUD_SYNC_PATCH_APPLY_DECISION_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_INGESTION_SCHEMA_VERSION,
        ownerUid: state.ownerUid,
        patchId: patch?.patchId || envelope.patchId,
        patchRevisionId: patch?.patchRevisionId || envelope.revisionId,
        baseSnapshotRevisionId: patch?.baseSnapshotRevisionId || envelope.baseRevisionId || null,
        currentSnapshotRevisionId,
        sourcePatchDeviceId: patch?.authorDeviceId || envelope.deviceId,
        desktopDeviceId: state.device.deviceId,
        status,
        reason,
        decidedAt,
        mergeStatus,
        metadataOnly: true
    })
}

async function recordPatchApplyDecision({
    storage,
    functionsClient,
    state,
    envelope,
    patch = null,
    status,
    reason,
    currentSnapshotRevisionId = null,
    mergeStatus = '',
    now
}) {
    const decidedAt = nowMs(now)
    const deviceSequence = nextDeviceSequence(state.device)
    const decision = createPatchApplyDecision({
        state,
        envelope,
        patch,
        status,
        reason,
        currentSnapshotRevisionId,
        mergeStatus,
        decidedAt
    })
    const signature = {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        keyId: state.device.deviceId,
        value: signCloudSyncCanonicalMetadata({
            canonicalMetadata: createCloudSyncIngestionSignatureMetadata({
                operation: CLOUD_SYNC_INGESTION_OPERATIONS.patchApplyDecision,
                ownerUid: state.ownerUid,
                deviceId: state.device.deviceId,
                deviceSequence,
                enrollmentEpoch: state.device.enrollmentEpoch,
                keyVersion: state.device.keyVersion,
                documentId: decision.patchRevisionId,
                document: decision,
                requestedAt: decidedAt
            }),
            privateKey: state.signingPrivateKey
        })
    }
    const result = await callCloudFunction(functionsClient, 'recordCloudSyncPatchApplyDecision', {
        documentId: decision.patchRevisionId,
        document: decision,
        signature,
        deviceSequence,
        requestedAt: decidedAt
    })
    const effectiveDeviceSequence = Number.isSafeInteger(result?.deviceSequence) && result.deviceSequence >= deviceSequence
        ? result.deviceSequence
        : deviceSequence
    state.device = { ...state.device, deviceSequence: effectiveDeviceSequence }
    await updateLocalSequence(storage, effectiveDeviceSequence)
    return {
        status: result.status,
        reason: result.reason,
        deviceSequence: effectiveDeviceSequence
    }
}

async function tryRecordPatchApplyDecision(input) {
    try {
        requireActiveVaultSessionForTrustedPatchApply(input?.deps)
        return await recordPatchApplyDecision(input)
    } catch (error) {
        return {
            status: 'failed',
            reason: classifyPatchApplyError(error).reason
        }
    }
}

export async function exchangeDeviceSessionTokenMemoryOnly({
    deviceSessionToken,
    authClient,
    logger
} = {}) {
    if (typeof deviceSessionToken !== 'string' || !deviceSessionToken) {
        fail('A raw device session token is required for immediate Firebase sign-in.')
    }
    if (!authClient || typeof authClient.signInWithCustomToken !== 'function') {
        fail('A Firebase Auth client adapter is required for device session token exchange.')
    }
    let rawToken = deviceSessionToken
    try {
        const credential = await authClient.signInWithCustomToken(rawToken)
        if (logger?.info) {
            logger.info(redactCloudSyncClientLogValue({
                event: 'cloud-sync-device-session-exchanged',
                deviceSessionToken: rawToken
            }))
        }
        return {
            status: 'signed-in',
            user: credential?.user || null,
            rawTokenRetained: false
        }
    } finally {
        rawToken = null
    }
}

export async function uploadDesktopSanitizedSnapshot({
    storage,
    functionsClient,
    snapshot,
    snapshotBuilder,
    now = Date.now()
} = {}) {
    if (!storage || typeof storage.loadAfterUnlock !== 'function') {
        fail('Desktop snapshot upload requires unlocked desktop cloud sync storage.')
    }
    const state = normalizeDeviceState(await storage.loadAfterUnlock(), 'desktop', 'desktop cloud sync state')
    const payload = snapshot || await snapshotBuilder?.({
        ownerUid: state.ownerUid,
        device: clone(state.device),
        now
    })
    if (!payload) fail('Desktop snapshot upload requires a sanitized snapshot payload builder.')
    const deviceSequence = nextDeviceSequence(state.device)
    const envelope = createEncryptedCloudSyncEnvelope({
        docType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        payload,
        ownerUid: state.ownerUid,
        deviceId: state.device.deviceId,
        deviceSequence,
        keyVersion: state.device.keyVersion,
        syncRootKey: state.syncRootKey,
        signingPrivateKey: state.signingPrivateKey,
        signingKeyId: state.device.deviceId,
        now
    })
    const result = await callCloudFunction(functionsClient, 'ingestCloudSyncDocument', {
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
        documentId: envelope.revisionId,
        document: envelope
    })
    await updateLocalSequence(storage, deviceSequence)
    return {
        status: result.status,
        result,
        envelope,
        revisionId: envelope.revisionId,
        deviceSequence
    }
}

export async function downloadPhoneLatestSnapshot({
    storage,
    firestoreClient,
    revisionId
} = {}) {
    if (!storage || typeof storage.loadSessionState !== 'function') {
        fail('Phone snapshot download requires phone cloud sync storage.')
    }
    const state = normalizeDeviceState(await storage.loadSessionState(), 'phone', 'phone cloud sync state')
    const syncState = revisionId
        ? null
        : await getCloudDocument(firestoreClient, `users/${state.ownerUid}/state/sync`)
    const targetRevisionId = revisionId || syncState?.latestSnapshotRevisionId
    if (!targetRevisionId) fail('No latest cloud sync snapshot is available.')
    const envelope = validateCloudSyncEnvelope(envelopeWithoutBackendIngestionMetadata(await getCloudDocument(
        firestoreClient,
        `users/${state.ownerUid}/snapshots/${targetRevisionId}`
    )), { expectedDocType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE, activeKeyVersion: state.device.keyVersion })
    const authorDevice = await getTrustedDeviceRecord(firestoreClient, state.ownerUid, envelope.deviceId)
    const decrypted = decryptCloudSyncEnvelope({
        envelope,
        syncRootKey: state.syncRootKey,
        verifyPublicKey: publicKeyFromDeviceRecord(authorDevice),
        expectedOwnerUid: state.ownerUid,
        expectedDocType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        activeKeyVersion: state.device.keyVersion
    })
    if (typeof storage.cacheEncryptedSnapshotEnvelope === 'function') {
        await storage.cacheEncryptedSnapshotEnvelope(envelope)
    }
    return {
        envelope,
        snapshot: decrypted.payload,
        revisionId: envelope.revisionId
    }
}

export async function uploadPhoneSafePresetPatch({
    storage,
    functionsClient,
    patch,
    patchBuilder,
    baseSnapshot,
    now = Date.now()
} = {}) {
    if (!storage || typeof storage.loadSessionState !== 'function') {
        fail('Phone patch upload requires phone cloud sync storage.')
    }
    const state = normalizeDeviceState(await storage.loadSessionState(), 'phone', 'phone cloud sync state')
    const payload = validateSafePresetPatch(patch || await patchBuilder?.({
        ownerUid: state.ownerUid,
        device: clone(state.device),
        baseSnapshot,
        now
    }))
    const deviceSequence = nextDeviceSequence(state.device)
    const envelope = createEncryptedCloudSyncEnvelope({
        docType: CLOUD_SYNC_PATCH_DOC_TYPE,
        payload,
        ownerUid: state.ownerUid,
        deviceId: state.device.deviceId,
        deviceSequence,
        keyVersion: state.device.keyVersion,
        syncRootKey: state.syncRootKey,
        signingPrivateKey: state.signingPrivateKey,
        signingKeyId: state.device.deviceId,
        now
    })
    const result = await callCloudFunction(functionsClient, 'ingestCloudSyncDocument', {
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.patchEnvelope,
        documentId: envelope.revisionId,
        document: envelope
    })
    if (typeof storage.cacheEncryptedPatchEnvelope === 'function') {
        await storage.cacheEncryptedPatchEnvelope(envelope)
    }
    await updateLocalSequence(storage, deviceSequence)
    return {
        status: result.status,
        result,
        envelope,
        patchRevisionId: envelope.revisionId,
        deviceSequence
    }
}

export async function downloadDesktopPatchPlans({
    storage,
    firestoreClient,
    sanitizedSnapshot,
    patchRevisionIds
} = {}) {
    if (!storage || typeof storage.loadAfterUnlock !== 'function') {
        fail('Desktop patch download requires unlocked desktop cloud sync storage.')
    }
    const state = normalizeDeviceState(await storage.loadAfterUnlock(), 'desktop', 'desktop cloud sync state')
    const patchDocs = Array.isArray(patchRevisionIds)
        ? await Promise.all(patchRevisionIds.map(id => getCloudDocument(firestoreClient, `users/${state.ownerUid}/patches/${id}`)))
        : await listCloudDocuments(firestoreClient, `users/${state.ownerUid}/patches`)
    const plans = []
    for (const rawEnvelope of patchDocs.filter(Boolean)) {
        const envelope = validateCloudSyncEnvelope(envelopeWithoutBackendIngestionMetadata(rawEnvelope), {
            expectedDocType: CLOUD_SYNC_PATCH_DOC_TYPE,
            activeKeyVersion: state.device.keyVersion
        })
        const authorDevice = await getTrustedDeviceRecord(firestoreClient, state.ownerUid, envelope.deviceId)
        const decrypted = decryptCloudSyncEnvelope({
            envelope,
            syncRootKey: state.syncRootKey,
            verifyPublicKey: publicKeyFromDeviceRecord(authorDevice),
            expectedOwnerUid: state.ownerUid,
            expectedDocType: CLOUD_SYNC_PATCH_DOC_TYPE,
            activeKeyVersion: state.device.keyVersion
        })
        const importPlan = planSafePresetPatchImport({
            sanitizedSnapshot,
            patch: decrypted.payload
        })
        plans.push({
            patchRevisionId: decrypted.payload.patchRevisionId,
            authorDeviceId: decrypted.payload.authorDeviceId,
            importPlan,
            envelope
        })
    }
    return {
        status: 'planned',
        plans,
        sideEffects: {
            writesVault: false,
            writesCapabilityVault: false,
            launches: false,
            mergesPatch: false
        }
    }
}

export async function downloadDesktopEncryptedPatchSummaries({
    storage,
    firestoreClient,
    patchRevisionIds
} = {}) {
    if (!storage || typeof storage.loadAfterUnlock !== 'function') {
        fail('Desktop encrypted patch download requires unlocked desktop cloud sync storage.')
    }
    const state = normalizeDeviceState(await storage.loadAfterUnlock(), 'desktop', 'desktop cloud sync state')
    const requestedPatchDocs = Array.isArray(patchRevisionIds)
        ? await Promise.all(patchRevisionIds.map(async revisionId => ({
            requestedRevisionId: revisionId,
            rawEnvelope: await getCloudDocument(firestoreClient, `users/${state.ownerUid}/patches/${revisionId}`)
        })))
        : sortPatchDocuments(await listCloudDocuments(firestoreClient, `users/${state.ownerUid}/patches`))
            .map(rawEnvelope => ({ requestedRevisionId: '', rawEnvelope }))

    const records = []
    for (const { requestedRevisionId, rawEnvelope } of requestedPatchDocs) {
        let envelope = null
        try {
            if (!rawEnvelope) {
                records.push(encryptedPatchSummaryRecord({
                    status: 'skipped',
                    reason: 'not-found',
                    requestedRevisionId,
                    message: 'Patch revision was not found.'
                }))
                continue
            }
            envelope = validateCloudSyncEnvelope(envelopeWithoutBackendIngestionMetadata(rawEnvelope), {
                expectedDocType: CLOUD_SYNC_PATCH_DOC_TYPE,
                activeKeyVersion: state.device.keyVersion
            })
            const existingDecision = backendApplyDecision(rawEnvelope)
            if (existingDecision) {
                records.push(encryptedPatchSummaryRecord({
                    status: 'already-decided',
                    reason: existingDecision.reason,
                    envelope,
                    cloudStatus: {
                        status: existingDecision.status,
                        reason: existingDecision.reason,
                        metadataOnly: true
                    },
                    authorTrust: await trustedPatchAuthorSummary(firestoreClient, state, envelope)
                }))
                continue
            }
            const ingestionConflict = backendIngestionConflict(rawEnvelope)
            if (ingestionConflict) {
                records.push(encryptedPatchSummaryRecord({
                    status: 'conflict',
                    reason: ingestionConflict.reason || 'cloud-conflict',
                    envelope,
                    cloudStatus: {
                        status: 'conflict',
                        reason: ingestionConflict.reason || 'cloud-conflict',
                        metadataOnly: true
                    },
                    authorTrust: await trustedPatchAuthorSummary(firestoreClient, state, envelope)
                }))
                continue
            }
            records.push(encryptedPatchSummaryRecord({
                status: 'downloaded',
                reason: 'encrypted',
                envelope,
                authorTrust: await trustedPatchAuthorSummary(firestoreClient, state, envelope)
            }))
        } catch (error) {
            const classified = classifyPatchApplyError(error)
            records.push(encryptedPatchSummaryRecord({
                status: 'skipped',
                reason: classified.reason,
                envelope,
                requestedRevisionId,
                message: 'Patch envelope failed encrypted download validation.'
            }))
        }
    }

    return {
        status: 'downloaded',
        records,
        summary: {
            downloaded: records.filter(record => ['downloaded', 'already-decided', 'conflict'].includes(record.status)).length,
            conflicts: records.filter(record => record.status === 'conflict').length,
            skipped: records.filter(record => record.status === 'skipped').length
        },
        sideEffects: {
            ...sideEffectsNone(),
            writesCloudPatchStatus: false,
            mergesPatch: false
        }
    }
}

export async function applyTrustedCloudSafePresetPatchesAfterUnlock({
    storage,
    firestoreClient,
    functionsClient,
    deps,
    snapshotBuilder,
    patchRevisionIds,
    callerContext,
    now = Date.now
} = {}) {
    let state
    try {
        if (!storage || typeof storage.loadAfterUnlock !== 'function') {
            fail('Trusted cloud patch apply requires unlocked desktop cloud sync storage.')
        }
        state = normalizeDeviceState(await storage.loadAfterUnlock(), 'desktop', 'desktop cloud sync state')
    } catch (error) {
        const locked = /unlock|locked/i.test(error?.message || '')
        return {
            status: locked ? 'locked' : 'rejected',
            error: error?.message || 'Trusted cloud patch apply failed before unlock.',
            records: [],
            summary: { applied: 0, conflicts: 0, skipped: 0 },
            sideEffects: {
                ...sideEffectsNone(),
                writesCloudPatchStatus: false
            }
        }
    }
    try {
        requireActiveVaultSessionForTrustedPatchApply(deps)
    } catch (error) {
        const locked = /unlock|locked/i.test(error?.message || '')
        return {
            status: locked ? 'locked' : 'rejected',
            error: error?.message || 'Trusted cloud patch apply requires an active vault session.',
            records: [],
            summary: { applied: 0, conflicts: 0, skipped: 0 },
            sideEffects: {
                ...sideEffectsNone(),
                writesCloudPatchStatus: false
            }
        }
    }
    if (!functionsClient) {
        return {
            status: 'rejected',
            error: 'Trusted cloud patch apply requires a Functions client adapter for patch status decisions.',
            records: [],
            summary: { applied: 0, conflicts: 0, skipped: 0 },
            sideEffects: {
                ...sideEffectsNone(),
                writesCloudPatchStatus: false
            }
        }
    }

    const patchDocs = Array.isArray(patchRevisionIds)
        ? await Promise.all(patchRevisionIds.map(id => getCloudDocument(firestoreClient, `users/${state.ownerUid}/patches/${id}`)))
        : await listCloudDocuments(firestoreClient, `users/${state.ownerUid}/patches`)
    const records = []
    const seenRevisionIds = new Set()
    const seenPatchIds = new Set()
    const applyCallerContext = callerContext || {
        unlocked: true,
        vaultBacked: true,
        authority: 'desktop-main'
    }

    for (const rawEnvelope of sortPatchDocuments(patchDocs.filter(Boolean))) {
        let envelope = null
        let patch = null
        let currentSnapshot = null
        try {
            envelope = validateCloudSyncEnvelope(envelopeWithoutBackendIngestionMetadata(rawEnvelope), {
                expectedDocType: CLOUD_SYNC_PATCH_DOC_TYPE,
                activeKeyVersion: state.device.keyVersion
            })
            if (seenRevisionIds.has(envelope.revisionId)) {
                records.push(patchRecord({
                    status: 'skipped',
                    code: 'duplicate-patch',
                    reason: 'duplicate-patch',
                    envelope,
                    message: 'Duplicate patch revision was skipped.'
                }))
                continue
            }
            seenRevisionIds.add(envelope.revisionId)

            const existingDecision = backendApplyDecision(rawEnvelope)
            if (existingDecision) {
                records.push(patchRecord({
                    status: 'skipped',
                    code: 'already-decided',
                    reason: existingDecision.reason,
                    envelope,
                    currentSnapshot: existingDecision.currentSnapshotRevisionId
                        ? { revisionId: existingDecision.currentSnapshotRevisionId }
                        : null,
                    cloudStatus: { status: 'already-decided', reason: existingDecision.reason },
                    message: 'Patch already has a backend apply decision.'
                }))
                continue
            }

            const ingestionConflict = backendIngestionConflict(rawEnvelope)
            if (ingestionConflict) {
                const reason = ingestionConflict.reason === 'stale-base'
                    ? 'stale-base'
                    : 'cloud-conflict'
                const cloudStatus = await tryRecordPatchApplyDecision({
                    storage,
                    functionsClient,
                    deps,
                    state,
                    envelope,
                    status: 'conflict',
                    reason,
                    currentSnapshotRevisionId: ingestionConflict.currentRevisionId,
                    mergeStatus: 'cloud-conflict',
                    now
                })
                records.push(patchRecord({
                    status: 'conflict',
                    code: reason,
                    reason,
                    envelope,
                    currentSnapshot: { revisionId: ingestionConflict.currentRevisionId },
                    cloudStatus,
                    message: 'Patch already carried backend conflict metadata.'
                }))
                continue
            }

            const authorDevice = requireTrustedPatchAuthorDevice(
                await getTrustedDeviceRecord(firestoreClient, state.ownerUid, envelope.deviceId),
                state,
                envelope
            )

            try {
                const decrypted = decryptCloudSyncEnvelope({
                    envelope,
                    syncRootKey: state.syncRootKey,
                    verifyPublicKey: publicKeyFromDeviceRecord(authorDevice),
                    expectedOwnerUid: state.ownerUid,
                    expectedDocType: CLOUD_SYNC_PATCH_DOC_TYPE,
                    activeKeyVersion: state.device.keyVersion
                })
                patch = decrypted.payload
            } catch (error) {
                const classified = classifyPatchApplyError(error)
                const cloudStatus = await tryRecordPatchApplyDecision({
                    storage,
                    functionsClient,
                    deps,
                    state,
                    envelope,
                    status: classified.status,
                    reason: classified.reason,
                    mergeStatus: classified.code,
                    now
                })
                records.push(patchRecord({
                    ...classified,
                    envelope,
                    cloudStatus,
                    message: 'Patch envelope failed decrypt or signature validation.'
                }))
                continue
            }

            if (seenPatchIds.has(patch.patchId)) {
                const cloudStatus = await tryRecordPatchApplyDecision({
                    storage,
                    functionsClient,
                    deps,
                    state,
                    envelope,
                    patch,
                    status: 'skipped',
                    reason: 'duplicate-patch',
                    mergeStatus: 'duplicate-patch',
                    now
                })
                records.push(patchRecord({
                    status: 'skipped',
                    code: 'duplicate-patch',
                    reason: 'duplicate-patch',
                    envelope,
                    patch,
                    cloudStatus,
                    message: 'Duplicate patch id was skipped.'
                }))
                continue
            }
            seenPatchIds.add(patch.patchId)

            currentSnapshot = await buildCurrentSanitizedSnapshotForPatchApply({ deps, snapshotBuilder })
            let importPlan
            try {
                importPlan = planSafePresetPatchImport({
                    sanitizedSnapshot: currentSnapshot,
                    patch
                })
            } catch (error) {
                const classified = classifyPatchApplyError(error)
                const cloudStatus = await tryRecordPatchApplyDecision({
                    storage,
                    functionsClient,
                    deps,
                    state,
                    envelope,
                    patch,
                    status: classified.status,
                    reason: classified.reason,
                    currentSnapshotRevisionId: currentSnapshot.revisionId,
                    mergeStatus: classified.code,
                    now
                })
                records.push(patchRecord({
                    ...classified,
                    envelope,
                    patch,
                    currentSnapshot,
                    cloudStatus,
                    message: 'Patch failed planning against the current sanitized snapshot.'
                }))
                continue
            }

            const mergeResult = await mergeSafePresetPatchPlanAfterUnlock({
                importPlan,
                sanitizedSnapshot: currentSnapshot,
                callerContext: applyCallerContext,
                deps,
                now
            })
            if (mergeResult.status === 'merged') {
                const cloudStatus = await tryRecordPatchApplyDecision({
                    storage,
                    functionsClient,
                    deps,
                    state,
                    envelope,
                    patch,
                    status: 'applied',
                    reason: 'merged',
                    currentSnapshotRevisionId: mergeResult.currentSnapshotRevisionId || currentSnapshot.revisionId,
                    mergeStatus: 'merged',
                    now
                })
                records.push(patchRecord({
                    status: 'applied',
                    code: 'merged',
                    reason: 'merged',
                    envelope,
                    patch,
                    currentSnapshot,
                    mergeResult,
                    cloudStatus
                }))
                continue
            }
            if (mergeResult.status === 'conflict') {
                const reason = reasonForMergeConflict(mergeResult.conflicts?.[0]?.code)
                const cloudStatus = await tryRecordPatchApplyDecision({
                    storage,
                    functionsClient,
                    deps,
                    state,
                    envelope,
                    patch,
                    status: 'conflict',
                    reason,
                    currentSnapshotRevisionId: mergeResult.currentSnapshotRevisionId || currentSnapshot.revisionId,
                    mergeStatus: mergeResult.status,
                    now
                })
                records.push(patchRecord({
                    status: 'conflict',
                    code: reason,
                    reason,
                    envelope,
                    patch,
                    currentSnapshot,
                    mergeResult,
                    cloudStatus,
                    message: 'Patch conflicted during safe preset metadata merge.'
                }))
                continue
            }

            const rejectedReason = reasonForMergeRejection(mergeResult)
            records.push(patchRecord({
                status: 'skipped',
                code: rejectedReason,
                reason: rejectedReason,
                envelope,
                patch,
                currentSnapshot,
                mergeResult,
                cloudStatus: { status: 'not-recorded', reason: rejectedReason },
                message: 'Patch merge was rejected; no applied acknowledgement was recorded.'
            }))
        } catch (error) {
            const classified = classifyPatchApplyError(error)
            const canRecord = envelope && envelope.patchId && classified.reason !== 'invalid-envelope'
            const cloudStatus = canRecord
                ? await tryRecordPatchApplyDecision({
                    storage,
                    functionsClient,
                    deps,
                    state,
                    envelope,
                    patch,
                    status: classified.status,
                    reason: classified.reason,
                    currentSnapshotRevisionId: currentSnapshot?.revisionId || null,
                    mergeStatus: classified.code,
                    now
                })
                : null
            records.push(patchRecord({
                ...classified,
                envelope,
                patch,
                currentSnapshot,
                cloudStatus,
                message: 'Patch was skipped by trusted apply orchestration.'
            }))
        }
    }

    const applied = records.filter(record => record.status === 'applied').length
    const conflicts = records.filter(record => record.status === 'conflict').length
    const skipped = records.filter(record => record.status === 'skipped').length
    return {
        status: 'completed',
        records,
        summary: { applied, conflicts, skipped },
        sideEffects: {
            ...sideEffectsNone({
                writesVault: records.some(record => record.sideEffects.writesVault === true)
            }),
            writesCloudPatchStatus: records.some(record =>
                record.cloudStatus &&
                record.cloudStatus.status !== 'failed' &&
                record.cloudStatus.status !== 'not-recorded'
            )
        }
    }
}
