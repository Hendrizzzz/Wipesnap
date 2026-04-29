import { createPublicKey } from 'crypto'
import {
    CLOUD_SYNC_PATCH_DOC_TYPE,
    CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
    createEncryptedCloudSyncEnvelope,
    decryptCloudSyncEnvelope,
    validateCloudSyncEnvelope
} from './cloudSyncEnvelope.js'
import { CLOUD_SYNC_INGESTION_OPERATIONS } from './cloudSyncIngestion.js'
import { planSafePresetPatchImport, validateSafePresetPatch } from './safePresetPatch.js'
import { redactCloudSyncClientLogValue } from './cloudSyncClientStorage.js'

function fail(message) {
    throw new Error(message)
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
    if (isPlainObject(envelope)) delete envelope.ingestion
    return envelope
}

async function updateLocalSequence(storage, deviceSequence) {
    if (typeof storage.updateDeviceSequence === 'function') {
        await storage.updateDeviceSequence(deviceSequence)
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
