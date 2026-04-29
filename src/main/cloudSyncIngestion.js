import { createHash, createPublicKey } from 'crypto'
import {
    CLOUD_SYNC_PATCH_DOC_TYPE,
    CLOUD_SYNC_SIGNING_ALGORITHM,
    CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
    assertNoForbiddenCloudSyncBackendPlaintext,
    serializeCanonicalCloudSyncMetadata,
    validateCloudSyncDeviceRecord,
    validateCloudSyncEnvelope,
    validateCloudSyncKeyGrant,
    verifyCloudSyncCanonicalMetadata,
    verifyCloudSyncEnvelopeSignature
} from './cloudSyncEnvelope.js'

export const CLOUD_SYNC_INGESTION_SCHEMA_VERSION = 1
export const CLOUD_SYNC_INGESTION_RATE_LIMIT = Object.freeze({
    windowMs: 60_000,
    maxWritesPerWindow: 20
})
export const CLOUD_SYNC_INGESTION_OPERATIONS = Object.freeze({
    deviceRecord: 'device-record',
    keyGrant: 'key-grant',
    snapshotEnvelope: 'snapshot-envelope',
    patchEnvelope: 'patch-envelope'
})
export const CLOUD_SYNC_ADMIN_OPERATIONS = Object.freeze({
    bootstrapDesktopDevice: 'bootstrap-desktop-device',
    requestDeviceEnrollment: 'request-device-enrollment',
    approveDeviceEnrollment: 'approve-device-enrollment',
    claimDeviceSession: 'claim-device-session',
    revokeDevice: 'revoke-device'
})

const DEVICE_ROLES = new Set(['desktop', 'phone', 'web-planner'])
const DEVICE_ID_PATTERN = /^dev_[A-Za-z0-9_-]{1,92}$/
const OWNER_UID_PATTERN = /^[A-Za-z0-9:_-]{1,128}$/
const GRANT_ID_PATTERN = /^grant_[A-Za-z0-9_-]{1,90}$/
const PAIRING_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/
const HASH_PATTERN = /^[A-Za-z0-9_-]{32,128}$/
const MAX_TIMESTAMP = 8_640_000_000_000_000

export class CloudSyncIngestionError extends Error {
    constructor(code, message) {
        super(message)
        this.name = 'CloudSyncIngestionError'
        this.code = code
    }
}

function fail(code, message) {
    throw new CloudSyncIngestionError(code, message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function normalizeString(value, fieldName, { required = true, max = 256 } = {}) {
    if (value == null || value === '') {
        if (required) fail('invalid-argument', `${fieldName} is required.`)
        return ''
    }
    if (typeof value !== 'string') fail('invalid-argument', `${fieldName} must be a string.`)
    if (value.includes('\0') || /[\u0000-\u001F\u007F]/.test(value)) {
        fail('invalid-argument', `${fieldName} contains unsupported control characters.`)
    }
    const text = value.trim()
    if (required && !text) fail('invalid-argument', `${fieldName} is required.`)
    if (text.length > max) fail('invalid-argument', `${fieldName} is too long.`)
    return text
}

function normalizeOwnerUid(value, fieldName = 'ownerUid') {
    const text = normalizeString(value, fieldName, { max: 128 })
    if (!OWNER_UID_PATTERN.test(text)) fail('invalid-argument', `${fieldName} must be a safe Firebase uid.`)
    return text
}

function normalizeDeviceId(value, fieldName = 'deviceId') {
    const text = normalizeString(value, fieldName, { max: 96 })
    if (!DEVICE_ID_PATTERN.test(text)) fail('invalid-argument', `${fieldName} must be a safe device id.`)
    return text
}

function normalizeGrantId(value, fieldName = 'grantId') {
    const text = normalizeString(value, fieldName, { max: 96 })
    if (!GRANT_ID_PATTERN.test(text)) fail('invalid-argument', `${fieldName} must be a safe key grant id.`)
    return text
}

function normalizePairingChallenge(value, fieldName = 'pairingChallenge') {
    const text = normalizeString(value, fieldName, { max: 128 })
    if (!PAIRING_CHALLENGE_PATTERN.test(text)) {
        fail('invalid-argument', `${fieldName} must be a safe one-time pairing challenge.`)
    }
    return text
}

function normalizeHash(value, fieldName) {
    const text = normalizeString(value, fieldName, { max: 128 })
    if (!HASH_PATTERN.test(text)) fail('invalid-argument', `${fieldName} must be a safe hash.`)
    return text
}

function normalizePositiveInteger(value, fieldName) {
    if (!Number.isSafeInteger(value) || value <= 0) {
        fail('invalid-argument', `${fieldName} must be a positive safe integer.`)
    }
    return value
}

function normalizeNonNegativeInteger(value, fieldName) {
    if (!Number.isSafeInteger(value) || value < 0) {
        fail('invalid-argument', `${fieldName} must be a non-negative safe integer.`)
    }
    return value
}

function normalizeTimestamp(value, fieldName, fallback) {
    const candidate = value == null ? fallback : value
    if (!Number.isSafeInteger(candidate) || candidate < 0 || candidate > MAX_TIMESTAMP) {
        fail('invalid-argument', `${fieldName} must be a non-negative timestamp.`)
    }
    return candidate
}

function normalizeAuth(auth) {
    if (!isPlainObject(auth) || !auth.uid) fail('unauthenticated', 'Cloud sync ingestion requires authentication.')
    const uid = normalizeOwnerUid(auth.uid, 'auth.uid')
    const token = isPlainObject(auth.token) ? auth.token : isPlainObject(auth.claims) ? auth.claims : {}
    const deviceId = normalizeDeviceId(token.wipesnapDeviceId, 'auth.token.wipesnapDeviceId')
    const role = normalizeString(token.wipesnapDeviceRole, 'auth.token.wipesnapDeviceRole', { max: 40 })
    if (!DEVICE_ROLES.has(role)) fail('permission-denied', 'Cloud sync ingestion requires a supported device role claim.')
    return {
        uid,
        deviceId,
        role,
        enrollmentEpoch: normalizePositiveInteger(token.wipesnapEnrollmentEpoch, 'auth.token.wipesnapEnrollmentEpoch'),
        keyVersion: normalizePositiveInteger(token.wipesnapKeyVersion, 'auth.token.wipesnapKeyVersion')
    }
}

function sha256Base64Url(value) {
    return createHash('sha256').update(value).digest('base64url')
}

function hashPairingChallenge(pairingChallenge) {
    return sha256Base64Url(Buffer.from(pairingChallenge, 'utf8'))
}

function documentHash(document) {
    return sha256Base64Url(Buffer.from(serializeCanonicalCloudSyncMetadata(document), 'utf8'))
}

function emptyToNull(value) {
    return value == null || value === '' ? null : value
}

export function createCloudSyncIngestionSignatureMetadata({
    operation,
    ownerUid,
    deviceId,
    deviceSequence,
    enrollmentEpoch,
    keyVersion,
    documentId,
    document,
    requestedAt
}) {
    return serializeCanonicalCloudSyncMetadata({
        product: 'wipesnap',
        schemaVersion: CLOUD_SYNC_INGESTION_SCHEMA_VERSION,
        operation,
        ownerUid,
        deviceId,
        deviceSequence,
        enrollmentEpoch,
        keyVersion,
        documentId,
        documentHash: documentHash(document),
        requestedAt
    })
}

export function createCloudSyncAdminSignatureMetadata({
    operation,
    ownerUid,
    actorDeviceId,
    targetDeviceId,
    deviceSequence,
    enrollmentEpoch,
    keyVersion,
    documentId,
    document,
    requestedAt
}) {
    return serializeCanonicalCloudSyncMetadata({
        product: 'wipesnap',
        schemaVersion: CLOUD_SYNC_INGESTION_SCHEMA_VERSION,
        operation,
        ownerUid,
        actorDeviceId: emptyToNull(actorDeviceId),
        targetDeviceId,
        deviceSequence,
        enrollmentEpoch,
        keyVersion,
        documentId,
        documentHash: documentHash(document),
        requestedAt
    })
}

export function createCloudSyncDeviceSessionClaimDocument({
    requestId,
    deviceId,
    keyGrantId,
    pairingChallengeHash
}) {
    return {
        product: 'wipesnap',
        schemaVersion: CLOUD_SYNC_INGESTION_SCHEMA_VERSION,
        purpose: 'device-session-claim',
        requestId: normalizeDeviceId(requestId, 'requestId'),
        deviceId: normalizeDeviceId(deviceId, 'deviceId'),
        keyGrantId: normalizeGrantId(keyGrantId, 'keyGrantId'),
        pairingChallengeHash: normalizeHash(pairingChallengeHash, 'pairingChallengeHash')
    }
}

function publicKeyFromDeviceRecord(device) {
    try {
        return createPublicKey({
            key: Buffer.from(device.signingPublicKey.spki, 'base64url'),
            format: 'der',
            type: 'spki'
        })
    } catch (_) {
        fail('failed-precondition', 'Enrolled device signing public key is not usable.')
    }
}

function invalidArgumentFrom(error) {
    if (error instanceof CloudSyncIngestionError) throw error
    fail('invalid-argument', error.message || 'Cloud sync ingestion input is invalid.')
}

function permissionDeniedFrom(error) {
    if (error instanceof CloudSyncIngestionError) throw error
    fail('permission-denied', error.message || 'Cloud sync ingestion signature is not valid.')
}

function verifyDetachedIngestionSignature({
    authContext,
    device,
    operation,
    documentId,
    document,
    deviceSequence,
    requestedAt,
    signature
}) {
    if (!isPlainObject(signature)) fail('permission-denied', 'Cloud sync ingestion request signature is required.')
    if (signature.alg !== CLOUD_SYNC_SIGNING_ALGORITHM) {
        fail('permission-denied', 'Cloud sync ingestion request signature algorithm is not supported.')
    }
    if (signature.keyId !== authContext.deviceId) {
        fail('permission-denied', 'Cloud sync ingestion request signature key does not match the caller device.')
    }
    const canonicalMetadata = createCloudSyncIngestionSignatureMetadata({
        operation,
        ownerUid: authContext.uid,
        deviceId: authContext.deviceId,
        deviceSequence,
        enrollmentEpoch: authContext.enrollmentEpoch,
        keyVersion: authContext.keyVersion,
        documentId,
        document,
        requestedAt
    })
    let valid = false
    try {
        valid = verifyCloudSyncCanonicalMetadata({
            canonicalMetadata,
            signature: signature.value,
            publicKey: publicKeyFromDeviceRecord(device)
        })
    } catch (error) {
        permissionDeniedFrom(error)
    }
    if (!valid) fail('permission-denied', 'Cloud sync ingestion request signature is not valid.')
}

function verifyDetachedAdminSignature({
    operation,
    ownerUid,
    actorDevice,
    targetDeviceId,
    documentId,
    document,
    deviceSequence,
    enrollmentEpoch,
    keyVersion,
    requestedAt,
    signature
}) {
    if (!isPlainObject(signature)) fail('permission-denied', 'Cloud sync admin request signature is required.')
    if (signature.alg !== CLOUD_SYNC_SIGNING_ALGORITHM) {
        fail('permission-denied', 'Cloud sync admin request signature algorithm is not supported.')
    }
    if (signature.keyId !== actorDevice.deviceId) {
        fail('permission-denied', 'Cloud sync admin request signature key does not match the actor device.')
    }
    const canonicalMetadata = createCloudSyncAdminSignatureMetadata({
        operation,
        ownerUid,
        actorDeviceId: actorDevice.deviceId,
        targetDeviceId,
        deviceSequence,
        enrollmentEpoch,
        keyVersion,
        documentId,
        document,
        requestedAt
    })
    let valid = false
    try {
        valid = verifyCloudSyncCanonicalMetadata({
            canonicalMetadata,
            signature: signature.value,
            publicKey: publicKeyFromDeviceRecord(actorDevice)
        })
    } catch (error) {
        permissionDeniedFrom(error)
    }
    if (!valid) fail('permission-denied', 'Cloud sync admin request signature is not valid.')
}

function requireScope(device, scope) {
    if (!Array.isArray(device.syncScopes) || !device.syncScopes.includes(scope)) {
        fail('permission-denied', `Cloud sync ingestion requires ${scope} scope.`)
    }
}

function requireRole(authContext, allowedRoles, message) {
    if (!allowedRoles.includes(authContext.role)) fail('permission-denied', message)
}

function assertClaimsMatchDevice(authContext, device) {
    if (device.ownerUid !== authContext.uid) fail('permission-denied', 'Device owner does not match caller.')
    if (device.deviceId !== authContext.deviceId) fail('permission-denied', 'Device id does not match caller.')
    if (device.role !== authContext.role) fail('permission-denied', 'Device role does not match caller.')
    if (device.enrollmentEpoch !== authContext.enrollmentEpoch) {
        fail('permission-denied', 'Device enrollment epoch does not match caller.')
    }
    if (device.keyVersion !== authContext.keyVersion) fail('permission-denied', 'Device key version does not match caller.')
}

function assertActiveDevice(authContext, device) {
    assertClaimsMatchDevice(authContext, device)
    if (device.status !== 'active' || device.revokedAt != null) {
        fail('permission-denied', 'Device is not active or has been revoked.')
    }
}

function assertMonotonicDeviceSequence(device, nextSequence) {
    if (nextSequence <= device.deviceSequence) {
        fail('already-exists', 'Cloud sync ingestion rejected a replayed or stale device sequence.')
    }
}

function userPath(uid, collection, id) {
    return `users/${uid}/${collection}/${id}`
}

function replayEventId(deviceId, sequence) {
    return `${deviceId}_${sequence}`
}

function rateBucketId(deviceId, now, windowMs) {
    return `${deviceId}_${Math.floor(now / windowMs) * windowMs}`
}

async function requireExistingActiveDevice(tx, authContext) {
    const path = userPath(authContext.uid, 'devices', authContext.deviceId)
    const raw = await tx.get(path)
    if (!raw) fail('permission-denied', 'Cloud sync device is not enrolled.')
    let device
    try {
        device = validateCloudSyncDeviceRecord(raw)
    } catch (error) {
        fail('failed-precondition', error.message || 'Cloud sync device record is invalid.')
    }
    assertActiveDevice(authContext, device)
    return { path, device }
}

async function requireExistingActiveDesktop(tx, authContext) {
    requireRole(authContext, ['desktop'], 'Only desktop devices may approve cloud sync authority changes.')
    const active = await requireExistingActiveDevice(tx, authContext)
    requireScope(active.device, 'read')
    return active
}

async function assertCreateOnly(tx, path) {
    if (await tx.get(path)) fail('already-exists', 'Cloud sync ingestion target document already exists.')
}

async function enforceReplayAndRateLimit(tx, {
    authContext,
    deviceSequence,
    operation,
    documentId,
    now,
    rateLimit
}) {
    const eventPath = userPath(authContext.uid, 'ingestionEvents', replayEventId(authContext.deviceId, deviceSequence))
    if (await tx.get(eventPath)) fail('already-exists', 'Cloud sync ingestion rejected a replayed device sequence.')

    const bucketId = rateBucketId(authContext.deviceId, now, rateLimit.windowMs)
    const bucketPath = userPath(authContext.uid, 'rateLimits', bucketId)
    const bucket = await tx.get(bucketPath)
    const count = Number.isSafeInteger(bucket?.count) ? bucket.count : 0
    if (count >= rateLimit.maxWritesPerWindow) fail('resource-exhausted', 'Cloud sync ingestion rate limit exceeded.')
    await tx.set(bucketPath, {
        ownerUid: authContext.uid,
        deviceId: authContext.deviceId,
        bucketStart: Math.floor(now / rateLimit.windowMs) * rateLimit.windowMs,
        windowMs: rateLimit.windowMs,
        count: count + 1,
        updatedAt: now
    })
    await tx.create(eventPath, {
        ownerUid: authContext.uid,
        deviceId: authContext.deviceId,
        deviceSequence,
        operation,
        targetRef: documentId,
        createdAt: now
    })
}

async function updateDeviceSequence(tx, path, device, deviceSequence, now) {
    await tx.set(path, {
        ...device,
        deviceSequence,
        updatedAt: Math.max(device.updatedAt, now)
    })
}

function validateEnvelopeForIngestion({ envelopeInput, expectedDocType, authContext, documentId }) {
    let envelope
    try {
        envelope = validateCloudSyncEnvelope(envelopeInput, {
            expectedDocType,
            activeKeyVersion: authContext.keyVersion
        })
    } catch (error) {
        invalidArgumentFrom(error)
    }
    if (envelope.ownerUid !== authContext.uid) fail('permission-denied', 'Cloud sync envelope owner does not match caller.')
    if (envelope.deviceId !== authContext.deviceId) fail('permission-denied', 'Cloud sync envelope device does not match caller.')
    if (envelope.revisionId !== documentId) fail('invalid-argument', 'Cloud sync envelope revision id must match the target document id.')
    return envelope
}

function verifyEnvelopeSignatureForDevice(envelope, device) {
    try {
        verifyCloudSyncEnvelopeSignature({ envelope, publicKey: publicKeyFromDeviceRecord(device) })
    } catch (error) {
        permissionDeniedFrom(error)
    }
}

function acceptedEnvelopeDocument(envelope, authContext, now, extra = {}) {
    const stored = {
        ...envelope,
        ingestion: {
            status: 'accepted',
            ingestedAt: now,
            ingestedByDeviceId: authContext.deviceId,
            deviceRole: authContext.role,
            ...extra
        }
    }
    assertNoForbiddenCloudSyncBackendPlaintext(stored)
    return stored
}

async function ingestSnapshotEnvelope({
    tx,
    authContext,
    documentId,
    document,
    now,
    rateLimit
}) {
    requireRole(authContext, ['desktop'], 'Only desktop devices may ingest sanitized snapshot envelopes.')
    const { path: devicePath, device } = await requireExistingActiveDevice(tx, authContext)
    requireScope(device, 'snapshot-upload')
    const envelope = validateEnvelopeForIngestion({
        envelopeInput: document,
        expectedDocType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        authContext,
        documentId
    })
    assertMonotonicDeviceSequence(device, envelope.deviceSequence)
    verifyEnvelopeSignatureForDevice(envelope, device)

    const snapshotPath = userPath(authContext.uid, 'snapshots', envelope.revisionId)
    await assertCreateOnly(tx, snapshotPath)
    await enforceReplayAndRateLimit(tx, {
        authContext,
        deviceSequence: envelope.deviceSequence,
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
        documentId: envelope.revisionId,
        now,
        rateLimit
    })
    await tx.create(snapshotPath, acceptedEnvelopeDocument(envelope, authContext, now))
    await tx.set(userPath(authContext.uid, 'state', 'sync'), {
        ownerUid: authContext.uid,
        keyVersion: authContext.keyVersion,
        latestSnapshotRevisionId: envelope.revisionId,
        latestSnapshotDeviceId: authContext.deviceId,
        latestSnapshotDeviceSequence: envelope.deviceSequence,
        updatedAt: now
    })
    await updateDeviceSequence(tx, devicePath, device, envelope.deviceSequence, now)
    return { status: 'accepted', path: snapshotPath, revisionId: envelope.revisionId }
}

function conflictForPatch(envelope, latestSnapshotRevisionId, now) {
    if (!latestSnapshotRevisionId || envelope.baseRevisionId === latestSnapshotRevisionId) return null
    return {
        status: 'conflict',
        reason: 'stale-base',
        detectedAt: now,
        detectedByDeviceId: envelope.deviceId,
        baseRevisionId: envelope.baseRevisionId,
        currentRevisionId: latestSnapshotRevisionId,
        conflictingRevisionId: envelope.revisionId
    }
}

async function ingestPatchEnvelope({
    tx,
    authContext,
    documentId,
    document,
    now,
    rateLimit
}) {
    requireRole(authContext, ['phone', 'web-planner'], 'Only phone or web planner devices may ingest safe patch envelopes.')
    const { path: devicePath, device } = await requireExistingActiveDevice(tx, authContext)
    requireScope(device, 'patch-upload')
    const envelope = validateEnvelopeForIngestion({
        envelopeInput: document,
        expectedDocType: CLOUD_SYNC_PATCH_DOC_TYPE,
        authContext,
        documentId
    })
    assertMonotonicDeviceSequence(device, envelope.deviceSequence)
    verifyEnvelopeSignatureForDevice(envelope, device)

    const patchPath = userPath(authContext.uid, 'patches', envelope.revisionId)
    await assertCreateOnly(tx, patchPath)
    const state = await tx.get(userPath(authContext.uid, 'state', 'sync'))
    const conflict = conflictForPatch(envelope, state?.latestSnapshotRevisionId || null, now)
    await enforceReplayAndRateLimit(tx, {
        authContext,
        deviceSequence: envelope.deviceSequence,
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.patchEnvelope,
        documentId: envelope.revisionId,
        now,
        rateLimit
    })
    await tx.create(patchPath, acceptedEnvelopeDocument(envelope, authContext, now, {
        pending: true,
        ...(conflict ? { conflict } : {})
    }))
    await updateDeviceSequence(tx, devicePath, device, envelope.deviceSequence, now)
    return {
        status: conflict ? 'conflict' : 'accepted',
        path: patchPath,
        revisionId: envelope.revisionId,
        conflict
    }
}

async function ingestKeyGrant({
    tx,
    authContext,
    documentId,
    document,
    signature,
    requestedAt,
    deviceSequence,
    now,
    rateLimit
}) {
    requireRole(authContext, ['desktop'], 'Only desktop devices may ingest key grants.')
    const { path: devicePath, device } = await requireExistingActiveDevice(tx, authContext)
    requireScope(device, 'read')
    assertMonotonicDeviceSequence(device, deviceSequence)
    let keyGrant
    try {
        keyGrant = validateCloudSyncKeyGrant(document)
    } catch (error) {
        invalidArgumentFrom(error)
    }
    if (keyGrant.ownerUid !== authContext.uid) fail('permission-denied', 'Key grant owner does not match caller.')
    if (keyGrant.grantId !== documentId) fail('invalid-argument', 'Key grant id must match the target document id.')
    if (keyGrant.createdByDeviceId !== authContext.deviceId) {
        fail('permission-denied', 'Key grant creator must match the caller device.')
    }
    if (keyGrant.keyVersion !== authContext.keyVersion) fail('permission-denied', 'Key grant key version does not match caller.')
    const recipient = await tx.get(userPath(authContext.uid, 'devices', keyGrant.recipientDeviceId))
    if (!recipient) fail('failed-precondition', 'Key grant recipient device is not enrolled.')
    let recipientDevice
    try {
        recipientDevice = validateCloudSyncDeviceRecord(recipient)
    } catch (error) {
        fail('failed-precondition', error.message || 'Key grant recipient device record is invalid.')
    }
    if (recipientDevice.ownerUid !== authContext.uid || recipientDevice.status !== 'active' || recipientDevice.revokedAt != null) {
        fail('permission-denied', 'Key grant recipient device is not active.')
    }
    if (recipientDevice.keyVersion !== authContext.keyVersion) fail('permission-denied', 'Key grant recipient key version is stale.')
    verifyDetachedIngestionSignature({
        authContext,
        device,
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
        documentId,
        document: keyGrant,
        deviceSequence,
        requestedAt,
        signature
    })

    const grantPath = userPath(authContext.uid, 'keyGrants', keyGrant.grantId)
    await assertCreateOnly(tx, grantPath)
    await enforceReplayAndRateLimit(tx, {
        authContext,
        deviceSequence,
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
        documentId: keyGrant.grantId,
        now,
        rateLimit
    })
    assertNoForbiddenCloudSyncBackendPlaintext(keyGrant)
    await tx.create(grantPath, keyGrant)
    await updateDeviceSequence(tx, devicePath, device, deviceSequence, now)
    return { status: 'accepted', path: grantPath, grantId: keyGrant.grantId }
}

async function ingestDeviceRecord({
    tx,
    authContext,
    documentId,
    document,
    signature,
    requestedAt,
    now,
    rateLimit
}) {
    let deviceRecord
    try {
        deviceRecord = validateCloudSyncDeviceRecord(document)
    } catch (error) {
        invalidArgumentFrom(error)
    }
    if (deviceRecord.ownerUid !== authContext.uid) fail('permission-denied', 'Device record owner does not match caller.')
    if (deviceRecord.deviceId !== documentId) fail('invalid-argument', 'Device record id must match the target document id.')
    if (deviceRecord.status !== 'active' || deviceRecord.revokedAt != null) {
        fail('permission-denied', 'Only active non-revoked device records may be ingested in this slice.')
    }
    assertClaimsMatchDevice(authContext, deviceRecord)
    verifyDetachedIngestionSignature({
        authContext,
        device: deviceRecord,
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.deviceRecord,
        documentId,
        document: deviceRecord,
        deviceSequence: deviceRecord.deviceSequence,
        requestedAt,
        signature
    })

    const devicePath = userPath(authContext.uid, 'devices', deviceRecord.deviceId)
    await assertCreateOnly(tx, devicePath)
    await enforceReplayAndRateLimit(tx, {
        authContext,
        deviceSequence: deviceRecord.deviceSequence,
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.deviceRecord,
        documentId: deviceRecord.deviceId,
        now,
        rateLimit
    })
    assertNoForbiddenCloudSyncBackendPlaintext(deviceRecord)
    await tx.create(devicePath, deviceRecord)
    return { status: 'accepted', path: devicePath, deviceId: deviceRecord.deviceId }
}

function normalizeOperation(value) {
    const operation = normalizeString(value, 'operation', { max: 40 })
    if (!Object.values(CLOUD_SYNC_INGESTION_OPERATIONS).includes(operation)) {
        fail('invalid-argument', 'Cloud sync ingestion operation is not supported.')
    }
    return operation
}

export async function ingestCloudSyncDocument(input = {}) {
    if (!isPlainObject(input)) fail('invalid-argument', 'Cloud sync ingestion input must be an object.')
    if (!input.store || typeof input.store.runTransaction !== 'function') {
        fail('failed-precondition', 'Cloud sync ingestion requires a Firestore Admin store.')
    }
    const authContext = normalizeAuth(input.auth)
    const operation = normalizeOperation(input.operation)
    const documentId = normalizeString(input.documentId, 'documentId', { max: 128 })
    const document = clone(input.document)
    const now = normalizeTimestamp(input.now, 'now', Date.now())
    const requestedAt = normalizeTimestamp(input.requestedAt, 'requestedAt', now)
    const rateLimit = {
        windowMs: normalizePositiveInteger(
            input.rateLimit?.windowMs ?? CLOUD_SYNC_INGESTION_RATE_LIMIT.windowMs,
            'rateLimit.windowMs'
        ),
        maxWritesPerWindow: normalizePositiveInteger(
            input.rateLimit?.maxWritesPerWindow ?? CLOUD_SYNC_INGESTION_RATE_LIMIT.maxWritesPerWindow,
            'rateLimit.maxWritesPerWindow'
        )
    }
    const deviceSequence = input.deviceSequence == null
        ? null
        : normalizeNonNegativeInteger(input.deviceSequence, 'deviceSequence')

    try {
        return await input.store.runTransaction(async tx => {
            if (operation === CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope) {
                return ingestSnapshotEnvelope({ tx, authContext, documentId, document, now, rateLimit })
            }
            if (operation === CLOUD_SYNC_INGESTION_OPERATIONS.patchEnvelope) {
                return ingestPatchEnvelope({ tx, authContext, documentId, document, now, rateLimit })
            }
            if (operation === CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant) {
                if (deviceSequence == null) fail('invalid-argument', 'deviceSequence is required for key grant ingestion.')
                return ingestKeyGrant({
                    tx,
                    authContext,
                    documentId,
                    document,
                    signature: input.signature,
                    requestedAt,
                    deviceSequence,
                    now,
                    rateLimit
                })
            }
            if (operation === CLOUD_SYNC_INGESTION_OPERATIONS.deviceRecord) {
                return ingestDeviceRecord({
                    tx,
                    authContext,
                    documentId,
                    document,
                    signature: input.signature,
                    requestedAt,
                    now,
                    rateLimit
                })
            }
            fail('invalid-argument', 'Cloud sync ingestion operation is not supported.')
        })
    } catch (error) {
        if (error instanceof CloudSyncIngestionError) throw error
        fail('invalid-argument', error.message || 'Cloud sync ingestion failed closed.')
    }
}

function normalizeSignedInOwnerAuth(auth) {
    if (!isPlainObject(auth) || !auth.uid) fail('unauthenticated', 'Cloud sync admin operation requires authentication.')
    return { uid: normalizeOwnerUid(auth.uid, 'auth.uid') }
}

function deviceAuthClaims(device) {
    return {
        wipesnapDeviceId: device.deviceId,
        wipesnapDeviceRole: device.role,
        wipesnapEnrollmentEpoch: device.enrollmentEpoch,
        wipesnapKeyVersion: device.keyVersion
    }
}

async function issueDeviceSessionToken({ authIssuer, ownerUid, device }) {
    if (!authIssuer || typeof authIssuer.createCustomToken !== 'function') {
        fail('failed-precondition', 'Cloud sync device session issuance requires an Auth admin issuer.')
    }
    const claims = deviceAuthClaims(device)
    const deviceSessionToken = await authIssuer.createCustomToken(ownerUid, claims)
    return {
        customClaims: claims,
        deviceSessionToken,
        deviceSessionSignInRequired: true
    }
}

function normalizeEnrollmentRequestId(input, fallbackDeviceId) {
    const id = input == null || input === '' ? fallbackDeviceId : input
    return normalizeDeviceId(id, 'requestId')
}

function enrollmentRequestPath(uid, requestId) {
    return userPath(uid, 'deviceEnrollmentRequests', requestId)
}

function validateDeviceRecordForAdmin({
    document,
    ownerUid,
    documentId,
    expectedStatus,
    expectedRole
}) {
    let device
    try {
        device = validateCloudSyncDeviceRecord(document)
    } catch (error) {
        invalidArgumentFrom(error)
    }
    if (device.ownerUid !== ownerUid) fail('permission-denied', 'Device owner does not match caller.')
    if (device.deviceId !== documentId) fail('invalid-argument', 'Device id must match the target document id.')
    if (expectedStatus && device.status !== expectedStatus) {
        fail('invalid-argument', `Device record status must be ${expectedStatus}.`)
    }
    if (expectedRole && device.role !== expectedRole) {
        fail('permission-denied', `Device record role must be ${expectedRole}.`)
    }
    if (device.revokedAt != null) fail('permission-denied', 'Revoked devices cannot be enrolled.')
    assertNoForbiddenCloudSyncBackendPlaintext(device)
    return device
}

export async function bootstrapCloudSyncDesktopDevice(input = {}) {
    if (!isPlainObject(input)) fail('invalid-argument', 'Cloud sync bootstrap input must be an object.')
    if (!input.store || typeof input.store.runTransaction !== 'function') {
        fail('failed-precondition', 'Cloud sync bootstrap requires a Firestore Admin store.')
    }
    const ownerAuth = normalizeSignedInOwnerAuth(input.auth)
    const now = normalizeTimestamp(input.now, 'now', Date.now())
    const requestedAt = normalizeTimestamp(input.requestedAt, 'requestedAt', now)
    const document = clone(input.document)
    const documentId = normalizeDeviceId(input.documentId, 'documentId')

    const result = await input.store.runTransaction(async tx => {
        const device = validateDeviceRecordForAdmin({
            document,
            ownerUid: ownerAuth.uid,
            documentId,
            expectedStatus: 'active',
            expectedRole: 'desktop'
        })
        requireScope(device, 'read')
        requireScope(device, 'snapshot-upload')
        verifyDetachedAdminSignature({
            operation: CLOUD_SYNC_ADMIN_OPERATIONS.bootstrapDesktopDevice,
            ownerUid: ownerAuth.uid,
            actorDevice: device,
            targetDeviceId: device.deviceId,
            documentId: device.deviceId,
            document: device,
            deviceSequence: device.deviceSequence,
            enrollmentEpoch: device.enrollmentEpoch,
            keyVersion: device.keyVersion,
            requestedAt,
            signature: input.signature
        })

        const statePath = userPath(ownerAuth.uid, 'state', 'enrollment')
        if (await tx.get(statePath)) fail('already-exists', 'Cloud sync desktop authority is already bootstrapped.')
        const devicePath = userPath(ownerAuth.uid, 'devices', device.deviceId)
        await assertCreateOnly(tx, devicePath)
        await tx.create(devicePath, { ...device, updatedAt: Math.max(device.updatedAt, now) })
        await tx.set(statePath, {
            ownerUid: ownerAuth.uid,
            keyVersion: device.keyVersion,
            desktopAuthorityDeviceId: device.deviceId,
            enrollmentEpoch: device.enrollmentEpoch,
            bootstrappedAt: now,
            updatedAt: now
        })
        return { status: 'accepted', deviceId: device.deviceId, device }
    })
    const issued = await issueDeviceSessionToken({
        authIssuer: input.authIssuer,
        ownerUid: ownerAuth.uid,
        device: result.device
    })
    return { status: result.status, deviceId: result.deviceId, device: result.device, ...issued }
}

export async function requestCloudSyncDeviceEnrollment(input = {}) {
    if (!isPlainObject(input)) fail('invalid-argument', 'Cloud sync enrollment request input must be an object.')
    if (!input.store || typeof input.store.runTransaction !== 'function') {
        fail('failed-precondition', 'Cloud sync enrollment request requires a Firestore Admin store.')
    }
    const ownerAuth = normalizeSignedInOwnerAuth(input.auth)
    const now = normalizeTimestamp(input.now, 'now', Date.now())
    const requestedAt = normalizeTimestamp(input.requestedAt, 'requestedAt', now)
    const document = clone(input.document)
    const documentId = normalizeDeviceId(input.documentId, 'documentId')
    const pairingChallenge = normalizePairingChallenge(input.pairingChallenge, 'pairingChallenge')
    const pairingChallengeHash = hashPairingChallenge(pairingChallenge)

    return input.store.runTransaction(async tx => {
        const device = validateDeviceRecordForAdmin({
            document,
            ownerUid: ownerAuth.uid,
            documentId,
            expectedStatus: 'pending'
        })
        if (device.role === 'desktop') fail('permission-denied', 'Additional desktop enrollment is not supported in this slice.')
        verifyDetachedAdminSignature({
            operation: CLOUD_SYNC_ADMIN_OPERATIONS.requestDeviceEnrollment,
            ownerUid: ownerAuth.uid,
            actorDevice: device,
            targetDeviceId: device.deviceId,
            documentId: device.deviceId,
            document: device,
            deviceSequence: device.deviceSequence,
            enrollmentEpoch: device.enrollmentEpoch,
            keyVersion: device.keyVersion,
            requestedAt,
            signature: input.signature
        })

        const requestId = normalizeEnrollmentRequestId(input.requestId, device.deviceId)
        const requestPath = enrollmentRequestPath(ownerAuth.uid, requestId)
        await assertCreateOnly(tx, requestPath)
        await tx.create(requestPath, {
            ownerUid: ownerAuth.uid,
            requestId,
            status: 'pending',
            pairingChallengeAlg: 'SHA-256-BASE64URL',
            pairingChallengeHash,
            device,
            requestedAt: now,
            updatedAt: now
        })
        return { status: 'pending', requestId, deviceId: device.deviceId }
    })
}

export async function approveCloudSyncDeviceEnrollment(input = {}) {
    if (!isPlainObject(input)) fail('invalid-argument', 'Cloud sync enrollment approval input must be an object.')
    if (!input.store || typeof input.store.runTransaction !== 'function') {
        fail('failed-precondition', 'Cloud sync enrollment approval requires a Firestore Admin store.')
    }
    const authContext = normalizeAuth(input.auth)
    const requestId = normalizeEnrollmentRequestId(input.requestId, input.documentId)
    const now = normalizeTimestamp(input.now, 'now', Date.now())
    const requestedAt = normalizeTimestamp(input.requestedAt, 'requestedAt', now)

    return input.store.runTransaction(async tx => {
        const { device: approver } = await requireExistingActiveDesktop(tx, authContext)
        const requestPath = enrollmentRequestPath(authContext.uid, requestId)
        const request = await tx.get(requestPath)
        if (!isPlainObject(request) || request.status !== 'pending') {
            fail('failed-precondition', 'Cloud sync enrollment request is not pending.')
        }
        const pending = validateDeviceRecordForAdmin({
            document: request.device,
            ownerUid: authContext.uid,
            documentId: requestId,
            expectedStatus: 'pending'
        })
        if (pending.role === 'desktop') fail('permission-denied', 'Additional desktop enrollment is not supported in this slice.')
        verifyDetachedAdminSignature({
            operation: CLOUD_SYNC_ADMIN_OPERATIONS.approveDeviceEnrollment,
            ownerUid: authContext.uid,
            actorDevice: approver,
            targetDeviceId: pending.deviceId,
            documentId: requestId,
            document: pending,
            deviceSequence: input.deviceSequence == null
                ? approver.deviceSequence + 1
                : normalizeNonNegativeInteger(input.deviceSequence, 'deviceSequence'),
            enrollmentEpoch: authContext.enrollmentEpoch,
            keyVersion: authContext.keyVersion,
            requestedAt,
            signature: input.signature
        })

        const approved = {
            ...pending,
            status: 'active',
            updatedAt: now,
            revokedAt: null,
            revokedByDeviceId: null
        }
        const devicePath = userPath(authContext.uid, 'devices', approved.deviceId)
        await assertCreateOnly(tx, devicePath)
        await tx.create(devicePath, approved)
        await tx.set(requestPath, {
            ...request,
            status: 'approved',
            approvedAt: now,
            approvedByDeviceId: approver.deviceId,
            device: approved,
            updatedAt: now
        })
        return {
            status: 'approved',
            requestId,
            deviceId: approved.deviceId,
            device: approved,
            deviceSessionClaimRequired: true
        }
    })
}

export async function claimApprovedCloudSyncDeviceSession(input = {}) {
    if (!isPlainObject(input)) fail('invalid-argument', 'Cloud sync device session claim input must be an object.')
    if (!input.store || typeof input.store.runTransaction !== 'function') {
        fail('failed-precondition', 'Cloud sync device session claim requires a Firestore Admin store.')
    }
    const ownerAuth = normalizeSignedInOwnerAuth(input.auth)
    const deviceId = normalizeDeviceId(input.deviceId, 'deviceId')
    const requestId = normalizeEnrollmentRequestId(input.requestId, deviceId)
    const keyGrantId = normalizeGrantId(input.keyGrantId, 'keyGrantId')
    const pairingChallenge = normalizePairingChallenge(input.pairingChallenge, 'pairingChallenge')
    const pairingChallengeHash = hashPairingChallenge(pairingChallenge)
    const now = normalizeTimestamp(input.now, 'now', Date.now())
    const requestedAt = normalizeTimestamp(input.requestedAt, 'requestedAt', now)
    const deviceSequence = normalizeNonNegativeInteger(input.deviceSequence, 'deviceSequence')
    const rateLimit = {
        windowMs: normalizePositiveInteger(
            input.rateLimit?.windowMs ?? CLOUD_SYNC_INGESTION_RATE_LIMIT.windowMs,
            'rateLimit.windowMs'
        ),
        maxWritesPerWindow: normalizePositiveInteger(
            input.rateLimit?.maxWritesPerWindow ?? CLOUD_SYNC_INGESTION_RATE_LIMIT.maxWritesPerWindow,
            'rateLimit.maxWritesPerWindow'
        )
    }

    const result = await input.store.runTransaction(async tx => {
        const requestPath = enrollmentRequestPath(ownerAuth.uid, requestId)
        const request = await tx.get(requestPath)
        if (!isPlainObject(request)) {
            fail('failed-precondition', 'Cloud sync enrollment request is not approved.')
        }
        if (request.status === 'claimed') {
            fail('failed-precondition', 'Cloud sync enrollment request has already been claimed.')
        }
        if (request.status !== 'approved') fail('failed-precondition', 'Cloud sync enrollment request is not approved.')
        if (request.ownerUid !== ownerAuth.uid) fail('permission-denied', 'Enrollment request owner does not match caller.')
        if (request.requestId !== requestId) fail('failed-precondition', 'Enrollment request id does not match caller.')
        if (request.pairingChallengeAlg !== 'SHA-256-BASE64URL' || request.pairingChallengeHash !== pairingChallengeHash) {
            fail('permission-denied', 'Cloud sync pairing challenge is not valid.')
        }

        const devicePath = userPath(ownerAuth.uid, 'devices', deviceId)
        const rawDevice = await tx.get(devicePath)
        if (!rawDevice) fail('permission-denied', 'Cloud sync device is not enrolled.')
        let device
        try {
            device = validateCloudSyncDeviceRecord(rawDevice)
        } catch (error) {
            fail('failed-precondition', error.message || 'Cloud sync device record is invalid.')
        }
        if (device.ownerUid !== ownerAuth.uid) fail('permission-denied', 'Device owner does not match caller.')
        if (device.deviceId !== deviceId) fail('permission-denied', 'Device id does not match caller.')
        if (!['phone', 'web-planner'].includes(device.role)) {
            fail('permission-denied', 'Only phone or web planner devices may claim a phone planning device session.')
        }
        if (device.status !== 'active' || device.revokedAt != null) {
            fail('permission-denied', 'Device is not active or has been revoked.')
        }
        requireScope(device, 'read')
        requireScope(device, 'patch-upload')
        assertMonotonicDeviceSequence(device, deviceSequence)

        const requestDevice = validateDeviceRecordForAdmin({
            document: request.device,
            ownerUid: ownerAuth.uid,
            documentId: deviceId,
            expectedStatus: 'active'
        })
        if (
            requestDevice.role !== device.role ||
            requestDevice.enrollmentEpoch !== device.enrollmentEpoch ||
            requestDevice.keyVersion !== device.keyVersion
        ) {
            fail('failed-precondition', 'Approved enrollment request does not match the active device.')
        }

        const keyGrantPath = userPath(ownerAuth.uid, 'keyGrants', keyGrantId)
        const rawKeyGrant = await tx.get(keyGrantPath)
        if (!rawKeyGrant) fail('failed-precondition', 'Approved device session requires a wrapped sync key grant.')
        let keyGrant
        try {
            keyGrant = validateCloudSyncKeyGrant(rawKeyGrant)
        } catch (error) {
            fail('failed-precondition', error.message || 'Cloud sync key grant is invalid.')
        }
        if (keyGrant.ownerUid !== ownerAuth.uid) fail('permission-denied', 'Key grant owner does not match caller.')
        if (keyGrant.recipientDeviceId !== device.deviceId) fail('permission-denied', 'Key grant recipient does not match caller.')
        if (keyGrant.keyVersion !== device.keyVersion) fail('permission-denied', 'Key grant key version does not match caller.')
        if (keyGrant.revokedAt != null) fail('permission-denied', 'Key grant has been revoked.')

        const creator = await tx.get(userPath(ownerAuth.uid, 'devices', keyGrant.createdByDeviceId))
        if (!creator) fail('failed-precondition', 'Key grant creator device is not enrolled.')
        let creatorDevice
        try {
            creatorDevice = validateCloudSyncDeviceRecord(creator)
        } catch (error) {
            fail('failed-precondition', error.message || 'Key grant creator device record is invalid.')
        }
        if (creatorDevice.ownerUid !== ownerAuth.uid || creatorDevice.role !== 'desktop') {
            fail('permission-denied', 'Key grant must be created by an enrolled desktop device.')
        }
        if (creatorDevice.status !== 'active' || creatorDevice.revokedAt != null) {
            fail('permission-denied', 'Key grant creator device is not active.')
        }

        const claimDocument = createCloudSyncDeviceSessionClaimDocument({
            requestId,
            deviceId,
            keyGrantId,
            pairingChallengeHash
        })
        verifyDetachedAdminSignature({
            operation: CLOUD_SYNC_ADMIN_OPERATIONS.claimDeviceSession,
            ownerUid: ownerAuth.uid,
            actorDevice: device,
            targetDeviceId: device.deviceId,
            documentId: requestId,
            document: claimDocument,
            deviceSequence,
            enrollmentEpoch: device.enrollmentEpoch,
            keyVersion: device.keyVersion,
            requestedAt,
            signature: input.signature
        })

        await enforceReplayAndRateLimit(tx, {
            authContext: {
                uid: ownerAuth.uid,
                deviceId: device.deviceId,
                role: device.role,
                enrollmentEpoch: device.enrollmentEpoch,
                keyVersion: device.keyVersion
            },
            deviceSequence,
            operation: CLOUD_SYNC_ADMIN_OPERATIONS.claimDeviceSession,
            documentId: requestId,
            now,
            rateLimit
        })
        await updateDeviceSequence(tx, devicePath, device, deviceSequence, now)
        await tx.set(requestPath, {
            ...request,
            status: 'claimed',
            claimedAt: now,
            claimedByDeviceId: device.deviceId,
            claimedKeyGrantId: keyGrant.grantId,
            lastClaimedAt: now,
            lastClaimedByDeviceId: device.deviceId,
            lastClaimKeyGrantId: keyGrant.grantId,
            updatedAt: now
        })
        return { status: 'accepted', deviceId: device.deviceId, device: { ...device, deviceSequence, updatedAt: Math.max(device.updatedAt, now) } }
    })

    const issued = await issueDeviceSessionToken({
        authIssuer: input.authIssuer,
        ownerUid: ownerAuth.uid,
        device: result.device
    })
    return {
        status: result.status,
        deviceId: result.deviceId,
        customClaims: issued.customClaims,
        deviceSessionToken: issued.deviceSessionToken,
        deviceSessionSignInRequired: issued.deviceSessionSignInRequired
    }
}

export async function revokeCloudSyncDevice(input = {}) {
    if (!isPlainObject(input)) fail('invalid-argument', 'Cloud sync revocation input must be an object.')
    if (!input.store || typeof input.store.runTransaction !== 'function') {
        fail('failed-precondition', 'Cloud sync revocation requires a Firestore Admin store.')
    }
    const authContext = normalizeAuth(input.auth)
    const targetDeviceId = normalizeDeviceId(input.targetDeviceId, 'targetDeviceId')
    const now = normalizeTimestamp(input.now, 'now', Date.now())
    const requestedAt = normalizeTimestamp(input.requestedAt, 'requestedAt', now)
    const deviceSequence = normalizeNonNegativeInteger(input.deviceSequence, 'deviceSequence')

    return input.store.runTransaction(async tx => {
        const { path: approverPath, device: approver } = await requireExistingActiveDesktop(tx, authContext)
        assertMonotonicDeviceSequence(approver, deviceSequence)
        if (targetDeviceId === approver.deviceId) fail('permission-denied', 'Desktop devices cannot revoke themselves in this slice.')
        const targetPath = userPath(authContext.uid, 'devices', targetDeviceId)
        const targetRaw = await tx.get(targetPath)
        if (!targetRaw) fail('failed-precondition', 'Target device is not enrolled.')
        let target
        try {
            target = validateCloudSyncDeviceRecord(targetRaw)
        } catch (error) {
            fail('failed-precondition', error.message || 'Target device record is invalid.')
        }
        if (target.ownerUid !== authContext.uid) fail('permission-denied', 'Target device owner does not match caller.')
        if (target.status !== 'active' || target.revokedAt != null) fail('failed-precondition', 'Target device is not active.')
        verifyDetachedAdminSignature({
            operation: CLOUD_SYNC_ADMIN_OPERATIONS.revokeDevice,
            ownerUid: authContext.uid,
            actorDevice: approver,
            targetDeviceId,
            documentId: targetDeviceId,
            document: target,
            deviceSequence,
            enrollmentEpoch: authContext.enrollmentEpoch,
            keyVersion: authContext.keyVersion,
            requestedAt,
            signature: input.signature
        })

        await tx.set(targetPath, {
            ...target,
            status: 'revoked',
            revokedAt: now,
            revokedByDeviceId: approver.deviceId,
            updatedAt: now
        })
        await updateDeviceSequence(tx, approverPath, approver, deviceSequence, now)
        return {
            status: 'revoked',
            deviceId: targetDeviceId,
            cachedClientDataMayRemain: true
        }
    })
}

export async function approveCloudSyncKeyGrant(input = {}) {
    return ingestCloudSyncDocument({
        ...input,
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant
    })
}

export function createFirestoreAdminStore(db) {
    if (!db || typeof db.runTransaction !== 'function' || typeof db.doc !== 'function') {
        fail('failed-precondition', 'A Firestore Admin SDK database handle is required.')
    }
    return {
        runTransaction(callback) {
            return db.runTransaction(async transaction => callback({
                async get(path) {
                    const snapshot = await transaction.get(db.doc(path))
                    return snapshot.exists ? snapshot.data() : null
                },
                async create(path, data) {
                    transaction.create(db.doc(path), data)
                },
                async set(path, data) {
                    transaction.set(db.doc(path), data)
                },
                async update(path, data) {
                    transaction.update(db.doc(path), data)
                }
            }))
        }
    }
}
