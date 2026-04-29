import assert from 'assert/strict'
import { createHash, generateKeyPairSync } from 'crypto'
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs'
import { createRequire } from 'module'
import { test } from 'node:test'
import { tmpdir } from 'os'
import { dirname, join } from 'path'
import {
    CLOUD_SYNC_DEVICE_RECORD_TYPE,
    CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
    CLOUD_SYNC_PATCH_DOC_TYPE,
    CLOUD_SYNC_SCHEMA_VERSION,
    CLOUD_SYNC_SIGNING_ALGORITHM,
    CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
    assertNoForbiddenCloudSyncBackendPlaintext,
    createEncryptedCloudSyncEnvelope,
    signCloudSyncCanonicalMetadata
} from '../src/main/cloudSyncEnvelope.js'
import {
    CLOUD_SYNC_INGESTION_OPERATIONS,
    CLOUD_SYNC_ADMIN_OPERATIONS,
    approveCloudSyncDeviceEnrollment,
    approveCloudSyncKeyGrant,
    bootstrapCloudSyncDesktopDevice,
    createCloudSyncAdminSignatureMetadata,
    createCloudSyncIngestionSignatureMetadata,
    ingestCloudSyncDocument,
    requestCloudSyncDeviceEnrollment,
    revokeCloudSyncDevice
} from '../src/main/cloudSyncIngestion.js'
import { evaluateCloudSyncFirestoreAccess } from '../src/main/cloudSyncRulesPolicy.js'
import { SANITIZED_PRESET_SNAPSHOT_LIMITS } from '../src/main/sanitizedPresetSnapshot.js'

const UID = 'firebase_uid_phase21_2'
const OTHER_UID = 'firebase_uid_other_phase21_2'
const NOW = 1770000000000
const SYNC_ROOT_KEY = Buffer.alloc(32, 0x21)

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function sha256Base64Url(bytes) {
    return createHash('sha256').update(bytes).digest('base64url')
}

function tamperBase64Url(value) {
    const bytes = Buffer.from(value, 'base64url')
    const tampered = Buffer.from(bytes)
    tampered[0] ^= 0xff
    return tampered.toString('base64url')
}

function signingKeyPair() {
    return generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
}

function publicSigningKeyRecord(publicKey) {
    const spki = publicKey.export({ type: 'spki', format: 'der' })
    return {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        spki: spki.toString('base64url'),
        fingerprint: sha256Base64Url(spki)
    }
}

function wrapPublicKeyRecord(fill = 0x45) {
    const spki = Buffer.alloc(96, fill)
    return {
        alg: 'RSA-OAEP-256',
        spki: spki.toString('base64url'),
        fingerprint: sha256Base64Url(spki)
    }
}

function authFor(device) {
    return {
        uid: device.ownerUid,
        token: {
            wipesnapDeviceId: device.deviceId,
            wipesnapDeviceRole: device.role,
            wipesnapEnrollmentEpoch: device.enrollmentEpoch,
            wipesnapKeyVersion: device.keyVersion
        }
    }
}

function deviceRecord({
    ownerUid = UID,
    deviceId,
    role,
    syncScopes,
    keys,
    sequence = 1,
    status = 'active',
    enrollmentEpoch = 1,
    keyVersion = 1,
    revokedAt = null
}) {
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_DEVICE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid,
        deviceId,
        role,
        status,
        platform: role === 'desktop' ? 'windows-electron' : 'web-pwa',
        syncScopes,
        signingPublicKey: publicSigningKeyRecord(keys.publicKey),
        wrapPublicKey: wrapPublicKeyRecord(role === 'desktop' ? 0x52 : 0x53),
        enrollmentEpoch,
        keyVersion,
        deviceSequence: sequence,
        createdAt: NOW,
        updatedAt: NOW,
        revokedAt,
        revokedByDeviceId: null
    }
}

function snapshotFixture({ revisionId = 'srev_phase21_2_snapshot_1', sourceDeviceId = 'dev_desktop_phase21_2' } = {}) {
    return {
        product: 'wipesnap',
        kind: 'sanitized-preset-snapshot',
        schemaVersion: 1,
        snapshotId: 'snap_phase21_2',
        revisionId,
        baseRevisionId: null,
        sourceDeviceId,
        timestamp: NOW,
        limits: { ...SANITIZED_PRESET_SNAPSHOT_LIMITS },
        selection: {
            defaultPresetId: 'preset_coding',
            nextPresetId: 'preset_coding',
            metadataOnly: true,
            selectionKind: 'metadata-only'
        },
        presets: [{
            id: 'preset_coding',
            name: 'Coding',
            order: 0,
            enabled: true,
            itemRefs: [{
                id: 'pref_ai_studio',
                itemId: 'item_ai_studio',
                order: 0,
                enabled: true,
                metadataOnly: true
            }]
        }],
        availableItems: [{
            id: 'item_ai_studio',
            type: 'browser-tab',
            label: 'AI Studio',
            status: 'available',
            source: 'browser',
            url: 'https://aistudio.google.com/'
        }]
    }
}

function patchFixture({
    patchRevisionId = 'patchrev_phase21_2_patch_1',
    baseSnapshotRevisionId = 'srev_phase21_2_snapshot_1',
    authorDeviceId = 'dev_phone_phase21_2'
} = {}) {
    return {
        product: 'wipesnap',
        kind: 'safe-preset-patch',
        schemaVersion: 1,
        patchId: 'patch_phase21_2',
        patchRevisionId,
        baseSnapshotRevisionId,
        authorDeviceId,
        createdAt: NOW,
        updatedAt: NOW + 1,
        selection: {
            defaultPresetId: 'preset_coding',
            nextPresetId: 'preset_coding',
            metadataOnly: true,
            selectionKind: 'metadata-only'
        },
        presets: [{
            id: 'preset_coding',
            name: 'Coding Phone',
            order: 0,
            enabled: true,
            itemRefs: [{
                itemId: 'item_ai_studio',
                order: 0,
                enabled: false,
                metadataOnly: true
            }],
            metadataOnly: true
        }],
        newBrowserItems: []
    }
}

function envelopeFor({
    docType,
    payload,
    ownerUid = UID,
    device,
    keys,
    sequence,
    saltFill = sequence,
    ivFill = sequence + 10
}) {
    return createEncryptedCloudSyncEnvelope({
        docType,
        payload,
        ownerUid,
        deviceId: device.deviceId,
        deviceSequence: sequence,
        keyVersion: device.keyVersion,
        syncRootKey: SYNC_ROOT_KEY,
        signingPrivateKey: keys.privateKey,
        signingKeyId: device.deviceId,
        salt: Buffer.alloc(32, saltFill),
        iv: Buffer.alloc(12, ivFill),
        now: NOW + sequence
    })
}

function keyGrantRecord({ desktop, phone, sequence = 3 }) {
    const wrapped = Buffer.alloc(96, sequence)
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid: desktop.ownerUid,
        grantId: `grant_phase21_2_${sequence}`,
        recipientDeviceId: phone.deviceId,
        createdByDeviceId: desktop.deviceId,
        keyVersion: desktop.keyVersion,
        wrapAlg: 'RSA-OAEP-256',
        wrappedKeyCiphertext: wrapped.toString('base64url'),
        wrappedKeyHash: sha256Base64Url(wrapped),
        createdAt: NOW + sequence,
        revokedAt: null,
        revokedByDeviceId: null
    }
}

function ingestionSignature({ operation, device, keys, documentId, document, sequence, requestedAt = NOW }) {
    return {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        keyId: device.deviceId,
        value: signCloudSyncCanonicalMetadata({
            canonicalMetadata: createCloudSyncIngestionSignatureMetadata({
                operation,
                ownerUid: device.ownerUid,
                deviceId: device.deviceId,
                deviceSequence: sequence,
                enrollmentEpoch: device.enrollmentEpoch,
                keyVersion: device.keyVersion,
                documentId,
                document,
                requestedAt
            }),
            privateKey: keys.privateKey
        })
    }
}

function adminSignature({
    operation,
    ownerUid = UID,
    actorDevice,
    targetDeviceId,
    keys,
    documentId,
    document,
    sequence,
    enrollmentEpoch = actorDevice.enrollmentEpoch,
    keyVersion = actorDevice.keyVersion,
    requestedAt = NOW
}) {
    return {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        keyId: actorDevice.deviceId,
        value: signCloudSyncCanonicalMetadata({
            canonicalMetadata: createCloudSyncAdminSignatureMetadata({
                operation,
                ownerUid,
                actorDeviceId: actorDevice.deviceId,
                targetDeviceId,
                deviceSequence: sequence,
                enrollmentEpoch,
                keyVersion,
                documentId,
                document,
                requestedAt
            }),
            privateKey: keys.privateKey
        })
    }
}

function authIssuerRecorder() {
    const issued = []
    return {
        issued,
        createCustomToken(uid, claims) {
            issued.push({ uid, claims: clone(claims) })
            return Promise.resolve(`device-session-token:${uid}:${claims.wipesnapDeviceId}`)
        }
    }
}

class InMemoryFirestoreEmulator {
    constructor({ enforceReadBeforeWrite = false } = {}) {
        this.docs = new Map()
        this.enforceReadBeforeWrite = enforceReadBeforeWrite
    }

    normalize(path) {
        return String(path || '').replace(/^\/+|\/+$/g, '')
    }

    seed(path, data) {
        this.docs.set(this.normalize(path), clone(data))
    }

    get(path) {
        return clone(this.docs.get(this.normalize(path)) || null)
    }

    runTransaction(callback) {
        const writes = []
        const pending = new Map()
        let hasWritten = false
        const normalize = path => this.normalize(path)
        const read = path => {
            if (this.enforceReadBeforeWrite && hasWritten) {
                throw new Error(`Firestore transaction read after write: ${normalize(path)}`)
            }
            const key = normalize(path)
            if (pending.has(key)) return clone(pending.get(key))
            return clone(this.docs.get(key) || null)
        }
        const write = (type, path, data) => {
            const key = normalize(path)
            if (type === 'create' && (this.docs.has(key) || pending.has(key))) {
                throw new Error(`Document already exists: ${key}`)
            }
            const value = clone(data)
            hasWritten = true
            pending.set(key, value)
            writes.push({ type, key, value })
        }
        return Promise.resolve(callback({
            get: path => Promise.resolve(read(path)),
            create: (path, data) => {
                write('create', path, data)
                return Promise.resolve()
            },
            set: (path, data) => {
                write('set', path, data)
                return Promise.resolve()
            },
            update: (path, data) => {
                if (!read(path)) throw new Error(`Document does not exist: ${normalize(path)}`)
                write('update', path, { ...read(path), ...data })
                return Promise.resolve()
            }
        })).then(result => {
            for (const { key, value } of writes) this.docs.set(key, clone(value))
            return result
        })
    }

    evaluateClient({ path, operation, auth }) {
        const authUid = auth?.uid || ''
        const authClaims = auth?.token || {}
        const deviceId = authClaims.wipesnapDeviceId
        return evaluateCloudSyncFirestoreAccess({
            path,
            operation,
            authUid,
            authClaims,
            deviceRecord: deviceId ? this.get(`users/${authUid}/devices/${deviceId}`) : null,
            resourceData: this.get(path)
        })
    }
}

function testContext({
    store = new InMemoryFirestoreEmulator(),
    desktopSequence = 1,
    phoneSequence = 1,
    desktopOverrides = {},
    phoneOverrides = {}
} = {}) {
    const desktopKeys = signingKeyPair()
    const phoneKeys = signingKeyPair()
    const desktop = deviceRecord({
        deviceId: 'dev_desktop_phase21_2',
        role: 'desktop',
        syncScopes: ['read', 'snapshot-upload'],
        keys: desktopKeys,
        sequence: desktopSequence,
        ...desktopOverrides
    })
    const phone = deviceRecord({
        deviceId: 'dev_phone_phase21_2',
        role: 'phone',
        syncScopes: ['read', 'patch-upload'],
        keys: phoneKeys,
        sequence: phoneSequence,
        ...phoneOverrides
    })
    store.seed(`users/${UID}/devices/${desktop.deviceId}`, desktop)
    store.seed(`users/${UID}/devices/${phone.deviceId}`, phone)
    return { store, desktop, phone, desktopKeys, phoneKeys }
}

async function ingest(input) {
    return ingestCloudSyncDocument({
        now: NOW + 100,
        requestedAt: NOW,
        ...input
    })
}

async function assertRejectsCode(promiseFactory, code, pattern) {
    await assert.rejects(async () => promiseFactory(), error => {
        assert.equal(error.code, code)
        if (pattern) assert.match(error.message, pattern)
        return true
    })
}

function writeStubModule(path, source) {
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, source, 'utf8')
}

test('Firestore emulator keeps default deny, device-bound reads, and direct client write denial', () => {
    const { store, phone } = testContext()
    store.seed(`users/${UID}/snapshots/srev_phase21_2_snapshot_1`, {
        ownerUid: UID,
        keyVersion: 1,
        ciphertext: Buffer.alloc(32, 0x11).toString('base64url')
    })
    const allowed = store.evaluateClient({
        path: `/users/${UID}/snapshots/srev_phase21_2_snapshot_1`,
        operation: 'get',
        auth: authFor(phone)
    })
    assert.equal(allowed.allowed, true)
    assert.equal(allowed.reason, 'device-bound-read')

    const directWrite = store.evaluateClient({
        path: `/users/${UID}/snapshots/srev_phase21_2_snapshot_1`,
        operation: 'create',
        auth: authFor(phone)
    })
    assert.equal(directWrite.allowed, false)
    assert.equal(directWrite.reason, 'direct-client-writes-denied')

    const unknown = store.evaluateClient({
        path: `/users/${UID}/vault/vault_json`,
        operation: 'get',
        auth: authFor(phone)
    })
    assert.equal(unknown.allowed, false)
    assert.equal(unknown.reason, 'default-deny')
})

test('Functions ingestion emulator accepts encrypted snapshots, patches, key grants, and safe metadata only', async () => {
    const { store, desktop, phone, desktopKeys, phoneKeys } = testContext()
    const snapshot = snapshotFixture({ sourceDeviceId: desktop.deviceId })
    const snapshotEnvelope = envelopeFor({
        docType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        payload: snapshot,
        device: desktop,
        keys: desktopKeys,
        sequence: 2
    })
    const snapshotResult = await ingest({
        store,
        auth: authFor(desktop),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
        documentId: snapshotEnvelope.revisionId,
        document: snapshotEnvelope
    })
    assert.equal(snapshotResult.status, 'accepted')
    assert.equal(store.get(`users/${UID}/state/sync`).latestSnapshotRevisionId, snapshotEnvelope.revisionId)

    const patch = patchFixture({ authorDeviceId: phone.deviceId, baseSnapshotRevisionId: snapshotEnvelope.revisionId })
    const patchEnvelope = envelopeFor({
        docType: CLOUD_SYNC_PATCH_DOC_TYPE,
        payload: patch,
        device: phone,
        keys: phoneKeys,
        sequence: 2
    })
    const patchResult = await ingest({
        store,
        auth: authFor(phone),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.patchEnvelope,
        documentId: patchEnvelope.revisionId,
        document: patchEnvelope
    })
    assert.equal(patchResult.status, 'accepted')

    const grant = keyGrantRecord({ desktop: store.get(`users/${UID}/devices/${desktop.deviceId}`), phone, sequence: 3 })
    const grantResult = await ingest({
        store,
        auth: authFor(store.get(`users/${UID}/devices/${desktop.deviceId}`)),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
        documentId: grant.grantId,
        document: grant,
        deviceSequence: 3,
        signature: ingestionSignature({
            operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
            device: store.get(`users/${UID}/devices/${desktop.deviceId}`),
            keys: desktopKeys,
            documentId: grant.grantId,
            document: grant,
            sequence: 3
        })
    })
    assert.equal(grantResult.status, 'accepted')

    const docs = [
        store.get(`users/${UID}/snapshots/${snapshotEnvelope.revisionId}`),
        store.get(`users/${UID}/patches/${patchEnvelope.revisionId}`),
        store.get(`users/${UID}/keyGrants/${grant.grantId}`),
        store.get(`users/${UID}/state/sync`)
    ]
    for (const doc of docs) assertNoForbiddenCloudSyncBackendPlaintext(doc)
    const serialized = JSON.stringify(docs)
    for (const forbidden of [
        'Coding',
        'Coding Phone',
        'AI Studio',
        'https://aistudio.google.com/',
        'p***@gmail.com',
        'vault.json',
        'capability',
        'password',
        'OAuth'
    ]) {
        assert.equal(serialized.includes(forbidden), false, `backend doc leaked ${forbidden}`)
    }
})

test('Patch ingestion stores stale-base conflict metadata without decrypting patch blobs', async () => {
    const { store, phone, phoneKeys } = testContext()
    store.seed(`users/${UID}/state/sync`, {
        ownerUid: UID,
        keyVersion: 1,
        latestSnapshotRevisionId: 'srev_phase21_2_snapshot_current',
        latestSnapshotDeviceId: 'dev_desktop_phase21_2',
        latestSnapshotDeviceSequence: 2,
        updatedAt: NOW
    })
    const patch = patchFixture({
        patchRevisionId: 'patchrev_phase21_2_stale',
        baseSnapshotRevisionId: 'srev_phase21_2_snapshot_old',
        authorDeviceId: phone.deviceId
    })
    const envelope = envelopeFor({
        docType: CLOUD_SYNC_PATCH_DOC_TYPE,
        payload: patch,
        device: phone,
        keys: phoneKeys,
        sequence: 2
    })
    const result = await ingest({
        store,
        auth: authFor(phone),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.patchEnvelope,
        documentId: envelope.revisionId,
        document: envelope
    })
    assert.equal(result.status, 'conflict')
    const stored = store.get(`users/${UID}/patches/${envelope.revisionId}`)
    assert.equal(stored.ingestion.pending, true)
    assert.equal(stored.ingestion.conflict.reason, 'stale-base')
    assert.equal(stored.ingestion.conflict.currentRevisionId, 'srev_phase21_2_snapshot_current')
    assertNoForbiddenCloudSyncBackendPlaintext(stored)
})

test('Patch ingestion keeps all Firestore transaction reads before writes', async () => {
    const strictStore = new InMemoryFirestoreEmulator({ enforceReadBeforeWrite: true })
    const { store, phone, phoneKeys } = testContext({ store: strictStore })
    store.seed(`users/${UID}/state/sync`, {
        ownerUid: UID,
        keyVersion: 1,
        latestSnapshotRevisionId: 'srev_phase21_2_snapshot_current',
        latestSnapshotDeviceId: 'dev_desktop_phase21_2',
        latestSnapshotDeviceSequence: 2,
        updatedAt: NOW
    })
    const patch = patchFixture({
        patchRevisionId: 'patchrev_phase21_2_read_before_write',
        baseSnapshotRevisionId: 'srev_phase21_2_snapshot_current',
        authorDeviceId: phone.deviceId
    })
    const envelope = envelopeFor({
        docType: CLOUD_SYNC_PATCH_DOC_TYPE,
        payload: patch,
        device: phone,
        keys: phoneKeys,
        sequence: 2
    })
    const result = await ingest({
        store,
        auth: authFor(phone),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.patchEnvelope,
        documentId: envelope.revisionId,
        document: envelope
    })
    assert.equal(result.status, 'accepted')
    assert.equal(store.get(`users/${UID}/patches/${envelope.revisionId}`).ingestion.pending, true)
})

test('Device record ingestion validates claims, doc id, and detached device signature', async () => {
    const store = new InMemoryFirestoreEmulator()
    const keys = signingKeyPair()
    const device = deviceRecord({
        deviceId: 'dev_new_phone_phase21_2',
        role: 'phone',
        syncScopes: ['read', 'patch-upload'],
        keys,
        sequence: 1
    })
    const result = await ingest({
        store,
        auth: authFor(device),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.deviceRecord,
        documentId: device.deviceId,
        document: device,
        signature: ingestionSignature({
            operation: CLOUD_SYNC_INGESTION_OPERATIONS.deviceRecord,
            device,
            keys,
            documentId: device.deviceId,
            document: device,
            sequence: device.deviceSequence
        })
    })
    assert.equal(result.status, 'accepted')
    assert.deepEqual(store.get(`users/${UID}/devices/${device.deviceId}`), device)

    await assertRejectsCode(() => ingest({
        store,
        auth: authFor(device),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.deviceRecord,
        documentId: device.deviceId,
        document: device,
        signature: ingestionSignature({
            operation: CLOUD_SYNC_INGESTION_OPERATIONS.deviceRecord,
            device,
            keys,
            documentId: device.deviceId,
            document: device,
            sequence: device.deviceSequence
        })
    }), 'already-exists', /already exists|replayed/)
})

test('Device enrollment, claim issuance, approval, and revocation stay desktop-authorized', async () => {
    const store = new InMemoryFirestoreEmulator()
    const issuer = authIssuerRecorder()
    const desktopKeys = signingKeyPair()
    const phoneKeys = signingKeyPair()
    const desktop = deviceRecord({
        deviceId: 'dev_desktop_phase21_3',
        role: 'desktop',
        syncScopes: ['read', 'snapshot-upload'],
        keys: desktopKeys,
        sequence: 1
    })
    const bootstrap = await bootstrapCloudSyncDesktopDevice({
        store,
        authIssuer: issuer,
        auth: { uid: UID, token: {} },
        documentId: desktop.deviceId,
        document: desktop,
        signature: adminSignature({
            operation: CLOUD_SYNC_ADMIN_OPERATIONS.bootstrapDesktopDevice,
            actorDevice: desktop,
            targetDeviceId: desktop.deviceId,
            keys: desktopKeys,
            documentId: desktop.deviceId,
            document: desktop,
            sequence: desktop.deviceSequence
        }),
        requestedAt: NOW,
        now: NOW + 10
    })
    assert.equal(bootstrap.status, 'accepted')
    assert.deepEqual(issuer.issued.at(-1), {
        uid: UID,
        claims: authFor(desktop).token
    })
    assert.equal(bootstrap.deviceSessionToken, `device-session-token:${UID}:${desktop.deviceId}`)
    assert.equal(bootstrap.deviceSessionSignInRequired, true)

    const pendingPhone = deviceRecord({
        deviceId: 'dev_phone_phase21_3',
        role: 'phone',
        syncScopes: ['read', 'patch-upload'],
        keys: phoneKeys,
        sequence: 1,
        status: 'pending'
    })
    const request = await requestCloudSyncDeviceEnrollment({
        store,
        auth: { uid: UID, token: {} },
        requestId: pendingPhone.deviceId,
        documentId: pendingPhone.deviceId,
        document: pendingPhone,
        signature: adminSignature({
            operation: CLOUD_SYNC_ADMIN_OPERATIONS.requestDeviceEnrollment,
            actorDevice: pendingPhone,
            targetDeviceId: pendingPhone.deviceId,
            keys: phoneKeys,
            documentId: pendingPhone.deviceId,
            document: pendingPhone,
            sequence: pendingPhone.deviceSequence
        }),
        requestedAt: NOW,
        now: NOW + 20
    })
    assert.equal(request.status, 'pending')

    await assertRejectsCode(() => approveCloudSyncDeviceEnrollment({
        store,
        authIssuer: issuer,
        auth: authFor({ ...pendingPhone, status: 'active' }),
        requestId: pendingPhone.deviceId,
        signature: adminSignature({
            operation: CLOUD_SYNC_ADMIN_OPERATIONS.approveDeviceEnrollment,
            actorDevice: pendingPhone,
            targetDeviceId: pendingPhone.deviceId,
            keys: phoneKeys,
            documentId: pendingPhone.deviceId,
            document: pendingPhone,
            sequence: 2
        }),
        deviceSequence: 2,
        requestedAt: NOW,
        now: NOW + 25
    }), 'permission-denied', /desktop|enrolled/)

    const approval = await approveCloudSyncDeviceEnrollment({
        store,
        authIssuer: issuer,
        auth: authFor(desktop),
        requestId: pendingPhone.deviceId,
        signature: adminSignature({
            operation: CLOUD_SYNC_ADMIN_OPERATIONS.approveDeviceEnrollment,
            actorDevice: desktop,
            targetDeviceId: pendingPhone.deviceId,
            keys: desktopKeys,
            documentId: pendingPhone.deviceId,
            document: pendingPhone,
            sequence: 2
        }),
        deviceSequence: 2,
        requestedAt: NOW,
        now: NOW + 30
    })
    assert.equal(approval.status, 'approved')
    const activePhone = store.get(`users/${UID}/devices/${pendingPhone.deviceId}`)
    assert.equal(activePhone.status, 'active')
    assert.deepEqual(issuer.issued.at(-1), {
        uid: UID,
        claims: authFor(activePhone).token
    })
    assert.equal(approval.deviceSessionToken, `device-session-token:${UID}:${activePhone.deviceId}`)
    assert.equal(approval.deviceSessionSignInRequired, true)

    const revokedRead = store.evaluateClient({
        path: `/users/${UID}/devices/${activePhone.deviceId}`,
        operation: 'get',
        auth: authFor(activePhone)
    })
    assert.equal(revokedRead.allowed, true)

    const currentDesktop = store.get(`users/${UID}/devices/${desktop.deviceId}`)
    const revoke = await revokeCloudSyncDevice({
        store,
        auth: authFor(currentDesktop),
        targetDeviceId: activePhone.deviceId,
        signature: adminSignature({
            operation: CLOUD_SYNC_ADMIN_OPERATIONS.revokeDevice,
            actorDevice: currentDesktop,
            targetDeviceId: activePhone.deviceId,
            keys: desktopKeys,
            documentId: activePhone.deviceId,
            document: activePhone,
            sequence: 3
        }),
        deviceSequence: 3,
        requestedAt: NOW,
        now: NOW + 40
    })
    assert.equal(revoke.status, 'revoked')
    assert.equal(revoke.cachedClientDataMayRemain, true)
    const revokedPhone = store.get(`users/${UID}/devices/${activePhone.deviceId}`)
    assert.equal(revokedPhone.status, 'revoked')
    assert.equal(revokedPhone.revokedByDeviceId, desktop.deviceId)

    const deniedRead = store.evaluateClient({
        path: `/users/${UID}/devices/${activePhone.deviceId}`,
        operation: 'get',
        auth: authFor(activePhone)
    })
    assert.equal(deniedRead.allowed, false)
    assert.equal(deniedRead.reason, 'revoked-device-denied')

    const patch = patchFixture({
        patchRevisionId: 'patchrev_phase21_3_revoked',
        authorDeviceId: activePhone.deviceId
    })
    const patchEnvelope = envelopeFor({
        docType: CLOUD_SYNC_PATCH_DOC_TYPE,
        payload: patch,
        device: activePhone,
        keys: phoneKeys,
        sequence: 2
    })
    await assertRejectsCode(() => ingest({
        store,
        auth: authFor(activePhone),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.patchEnvelope,
        documentId: patchEnvelope.revisionId,
        document: patchEnvelope
    }), 'permission-denied', /revoked|active/)

    const desktopAfterRevoke = store.get(`users/${UID}/devices/${desktop.deviceId}`)
    const grant = keyGrantRecord({ desktop: desktopAfterRevoke, phone: revokedPhone, sequence: 4 })
    await assertRejectsCode(() => approveCloudSyncKeyGrant({
        store,
        auth: authFor(desktopAfterRevoke),
        documentId: grant.grantId,
        document: grant,
        deviceSequence: 4,
        signature: ingestionSignature({
            operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
            device: desktopAfterRevoke,
            keys: desktopKeys,
            documentId: grant.grantId,
            document: grant,
            sequence: 4
        }),
        requestedAt: NOW,
        now: NOW + 50
    }), 'permission-denied', /recipient/)
})

test('Functions ingestion denies anonymous, cross-user, missing-claim, stale, revoked, replayed, and tampered writes', async () => {
    const { store, desktop, desktopKeys } = testContext()
    const snapshot = snapshotFixture({ sourceDeviceId: desktop.deviceId })
    const envelope = envelopeFor({
        docType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        payload: snapshot,
        device: desktop,
        keys: desktopKeys,
        sequence: 2
    })
    const baseInput = {
        store,
        auth: authFor(desktop),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
        documentId: envelope.revisionId,
        document: envelope
    }

    await assertRejectsCode(() => ingest({ ...baseInput, auth: null }), 'unauthenticated')
    await assertRejectsCode(() => ingest({
        ...baseInput,
        auth: { uid: UID, token: {} }
    }), 'invalid-argument')
    await assertRejectsCode(() => ingest({
        ...baseInput,
        auth: { ...authFor(desktop), uid: OTHER_UID }
    }), 'permission-denied')

    const otherKeys = signingKeyPair()
    const otherDevice = deviceRecord({
        deviceId: 'dev_other_phase21_2',
        role: 'desktop',
        syncScopes: ['read', 'snapshot-upload'],
        keys: otherKeys,
        sequence: 1
    })
    store.seed(`users/${UID}/devices/${otherDevice.deviceId}`, otherDevice)
    await assertRejectsCode(() => ingest({
        ...baseInput,
        auth: authFor(otherDevice)
    }), 'permission-denied', /device/)

    await assertRejectsCode(() => ingest({
        ...baseInput,
        auth: {
            uid: UID,
            token: {
                ...authFor(desktop).token,
                wipesnapEnrollmentEpoch: desktop.enrollmentEpoch + 1
            }
        }
    }), 'permission-denied', /epoch/)

    await assertRejectsCode(() => ingest({
        ...baseInput,
        auth: {
            uid: UID,
            token: {
                ...authFor(desktop).token,
                wipesnapKeyVersion: desktop.keyVersion + 1
            }
        }
    }), 'permission-denied', /key version/)

    const revokedStore = new InMemoryFirestoreEmulator()
    const revokedDesktop = { ...desktop, status: 'revoked' }
    revokedStore.seed(`users/${UID}/devices/${desktop.deviceId}`, revokedDesktop)
    await assertRejectsCode(() => ingest({
        ...baseInput,
        store: revokedStore,
        auth: authFor(revokedDesktop)
    }), 'permission-denied', /revoked|active/)

    const tampered = clone(envelope)
    tampered.signature.value = tamperBase64Url(tampered.signature.value)
    await assertRejectsCode(() => ingest({
        ...baseInput,
        document: tampered
    }), 'permission-denied', /signature|base64url|not valid/)

    await ingest(baseInput)

    const replayPayload = snapshotFixture({
        revisionId: 'srev_phase21_2_snapshot_replay',
        sourceDeviceId: desktop.deviceId
    })
    const replayEnvelope = envelopeFor({
        docType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        payload: replayPayload,
        device: desktop,
        keys: desktopKeys,
        sequence: 2,
        saltFill: 4,
        ivFill: 14
    })
    await assertRejectsCode(() => ingest({
        ...baseInput,
        documentId: replayEnvelope.revisionId,
        document: replayEnvelope
    }), 'already-exists', /replayed|stale/)
})

test('Functions ingestion denies duplicate doc id, wrong owner, wrong doc type, wrong role, and rate limit writes', async () => {
    const { store, desktop, phone, desktopKeys, phoneKeys } = testContext()
    const snapshot = snapshotFixture({ sourceDeviceId: desktop.deviceId })
    const firstEnvelope = envelopeFor({
        docType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        payload: snapshot,
        device: desktop,
        keys: desktopKeys,
        sequence: 2
    })
    await ingest({
        store,
        auth: authFor(desktop),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
        documentId: firstEnvelope.revisionId,
        document: firstEnvelope
    })

    const duplicateEnvelope = envelopeFor({
        docType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        payload: snapshot,
        device: { ...desktop, deviceSequence: 2 },
        keys: desktopKeys,
        sequence: 3,
        saltFill: 5,
        ivFill: 15
    })
    await assertRejectsCode(() => ingest({
        store,
        auth: authFor(store.get(`users/${UID}/devices/${desktop.deviceId}`)),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
        documentId: duplicateEnvelope.revisionId,
        document: duplicateEnvelope
    }), 'already-exists', /already exists/)

    const wrongOwnerEnvelope = envelopeFor({
        docType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        payload: snapshot,
        ownerUid: OTHER_UID,
        device: { ...desktop, deviceSequence: 2 },
        keys: desktopKeys,
        sequence: 4,
        saltFill: 6,
        ivFill: 16
    })
    await assertRejectsCode(() => ingest({
        store,
        auth: authFor(store.get(`users/${UID}/devices/${desktop.deviceId}`)),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
        documentId: wrongOwnerEnvelope.revisionId,
        document: wrongOwnerEnvelope
    }), 'permission-denied', /owner/)

    const patch = patchFixture({ authorDeviceId: phone.deviceId, baseSnapshotRevisionId: firstEnvelope.revisionId })
    const patchEnvelope = envelopeFor({
        docType: CLOUD_SYNC_PATCH_DOC_TYPE,
        payload: patch,
        device: phone,
        keys: phoneKeys,
        sequence: 2
    })
    await assertRejectsCode(() => ingest({
        store,
        auth: authFor(store.get(`users/${UID}/devices/${desktop.deviceId}`)),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
        documentId: patchEnvelope.revisionId,
        document: patchEnvelope
    }), 'invalid-argument', /doc type/)

    await assertRejectsCode(() => ingest({
        store,
        auth: authFor(store.get(`users/${UID}/devices/${desktop.deviceId}`)),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.patchEnvelope,
        documentId: patchEnvelope.revisionId,
        document: patchEnvelope
    }), 'permission-denied', /phone|planner/)

    await assertRejectsCode(() => ingest({
        store,
        auth: authFor(phone),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
        documentId: firstEnvelope.revisionId,
        document: firstEnvelope
    }), 'permission-denied', /desktop/)

    const limited = testContext()
    const limitedSnapshot = snapshotFixture({
        revisionId: 'srev_phase21_2_limited',
        sourceDeviceId: limited.desktop.deviceId
    })
    const limitedEnvelope = envelopeFor({
        docType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
        payload: limitedSnapshot,
        device: limited.desktop,
        keys: limited.desktopKeys,
        sequence: 2
    })
    await assertRejectsCode(() => ingest({
        store: limited.store,
        auth: authFor(limited.desktop),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
        documentId: limitedEnvelope.revisionId,
        document: limitedEnvelope,
        rateLimit: { windowMs: 60_000, maxWritesPerWindow: 0 }
    }), 'invalid-argument', /positive/)
    await assertRejectsCode(async () => {
        await ingest({
            store: limited.store,
            auth: authFor(limited.desktop),
            operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
            documentId: limitedEnvelope.revisionId,
            document: limitedEnvelope,
            rateLimit: { windowMs: 60_000, maxWritesPerWindow: 1 }
        })
        const secondSnapshot = snapshotFixture({
            revisionId: 'srev_phase21_2_limited_second',
            sourceDeviceId: limited.desktop.deviceId
        })
        const secondEnvelope = envelopeFor({
            docType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
            payload: secondSnapshot,
            device: { ...limited.desktop, deviceSequence: 2 },
            keys: limited.desktopKeys,
            sequence: 3,
            saltFill: 7,
            ivFill: 17
        })
        await ingest({
            store: limited.store,
            auth: authFor(limited.store.get(`users/${UID}/devices/${limited.desktop.deviceId}`)),
            operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
            documentId: secondEnvelope.revisionId,
            document: secondEnvelope,
            rateLimit: { windowMs: 60_000, maxWritesPerWindow: 1 }
        })
    }, 'resource-exhausted', /rate limit/)
})

test('Key grant ingestion denies wrong-role, stale recipient, bad request signature, and duplicate ids', async () => {
    const { store, desktop, phone, desktopKeys } = testContext()
    const grant = keyGrantRecord({ desktop, phone, sequence: 2 })
    await assertRejectsCode(() => ingest({
        store,
        auth: authFor(phone),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
        documentId: grant.grantId,
        document: grant,
        deviceSequence: 2,
        signature: ingestionSignature({
            operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
            device: phone,
            keys: signingKeyPair(),
            documentId: grant.grantId,
            document: grant,
            sequence: 2
        })
    }), 'permission-denied', /desktop/)

    const badSignature = ingestionSignature({
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
        device: desktop,
        keys: desktopKeys,
        documentId: grant.grantId,
        document: grant,
        sequence: 2
    })
    badSignature.value = tamperBase64Url(badSignature.value)
    await assertRejectsCode(() => ingest({
        store,
        auth: authFor(desktop),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
        documentId: grant.grantId,
        document: grant,
        deviceSequence: 2,
        signature: badSignature
    }), 'permission-denied', /signature/)

    const firstSignature = ingestionSignature({
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
        device: desktop,
        keys: desktopKeys,
        documentId: grant.grantId,
        document: grant,
        sequence: 2
    })
    await ingest({
        store,
        auth: authFor(desktop),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
        documentId: grant.grantId,
        document: grant,
        deviceSequence: 2,
        signature: firstSignature
    })

    const duplicateGrant = keyGrantRecord({
        desktop: store.get(`users/${UID}/devices/${desktop.deviceId}`),
        phone,
        sequence: 3
    })
    duplicateGrant.grantId = grant.grantId
    await assertRejectsCode(() => ingest({
        store,
        auth: authFor(store.get(`users/${UID}/devices/${desktop.deviceId}`)),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
        documentId: duplicateGrant.grantId,
        document: duplicateGrant,
        deviceSequence: 3,
        signature: ingestionSignature({
            operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
            device: store.get(`users/${UID}/devices/${desktop.deviceId}`),
            keys: desktopKeys,
            documentId: duplicateGrant.grantId,
            document: duplicateGrant,
            sequence: 3
        })
    }), 'already-exists', /already exists/)

    const staleRecipientContext = testContext({
        phoneOverrides: { status: 'revoked' }
    })
    const staleGrant = keyGrantRecord({
        desktop: staleRecipientContext.desktop,
        phone: staleRecipientContext.phone,
        sequence: 2
    })
    await assertRejectsCode(() => ingest({
        store: staleRecipientContext.store,
        auth: authFor(staleRecipientContext.desktop),
        operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
        documentId: staleGrant.grantId,
        document: staleGrant,
        deviceSequence: 2,
        signature: ingestionSignature({
            operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
            device: staleRecipientContext.desktop,
            keys: staleRecipientContext.desktopKeys,
            documentId: staleGrant.grantId,
            document: staleGrant,
            sequence: 2
        })
    }), 'permission-denied', /recipient/)
})

test('Functions package smoke loads callable from isolated deploy source', async () => {
    const tempRoot = mkdtempSync(join(tmpdir(), 'wipesnap-functions-package-'))
    const tempFunctions = join(tempRoot, 'functions')
    try {
        mkdirSync(tempFunctions, { recursive: true })
        cpSync(join(process.cwd(), 'functions', 'index.cjs'), join(tempFunctions, 'index.cjs'))
        cpSync(join(process.cwd(), 'functions', 'package.json'), join(tempFunctions, 'package.json'))
        cpSync(join(process.cwd(), 'functions', 'shared'), join(tempFunctions, 'shared'), { recursive: true })

        writeStubModule(join(tempFunctions, 'node_modules', 'firebase-admin', 'index.js'), `
const apps = []
module.exports = {
    apps,
    initializeApp() {
        apps.push({})
        return apps[apps.length - 1]
    },
    firestore() {
        return {
            runTransaction() {
                throw new Error('Firestore should not be reached by unauthenticated smoke call.')
            },
            doc(path) {
                return { path }
            }
        }
    }
}
`)
        writeStubModule(join(tempFunctions, 'node_modules', 'firebase-functions', 'v2', 'https.js'), `
class HttpsError extends Error {
    constructor(code, message) {
        super(message)
        this.code = code
    }
}
function onCall(_options, handler) {
    return handler
}
module.exports = { onCall, HttpsError }
`)

        const requireFromTemp = createRequire(join(tempFunctions, 'index.cjs'))
        const callable = requireFromTemp(join(tempFunctions, 'index.cjs')).ingestCloudSyncDocument
        assert.equal(typeof callable, 'function')
        await assert.rejects(
            () => callable({ auth: null, data: {} }),
            error => {
                assert.equal(error.code, 'unauthenticated')
                return true
            }
        )
    } finally {
        rmSync(tempRoot, { recursive: true, force: true })
    }
})
