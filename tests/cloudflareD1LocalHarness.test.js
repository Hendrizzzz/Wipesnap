import assert from 'assert/strict'
import { webcrypto } from 'crypto'
import { test } from 'node:test'
import { createCloudflareD1Store } from '../src/cloudflare-sync/cloudflareD1Store.js'
import {
    CLOUDFLARE_SYNC_LIMITS,
    CLOUDFLARE_SYNC_OPERATIONS,
    CLOUDFLARE_SYNC_SIGNING_HEADERS
} from '../src/cloudflare-sync/cloudflareSyncConstants.js'
import {
    createCloudflareCanonicalRequestMetadata,
    sha256Base64Url
} from '../src/cloudflare-sync/cloudflareCanonicalRequest.js'
import { createCloudflareSyncWorkerCore } from '../src/cloudflare-sync/cloudflareSyncWorkerCore.js'
import {
    CLOUD_SYNC_CONTENT_ENCRYPTION,
    CLOUD_SYNC_DEVICE_RECORD_TYPE,
    CLOUD_SYNC_ENVELOPE_RECORD_TYPE,
    CLOUD_SYNC_ENVELOPE_VERSION,
    CLOUD_SYNC_KEY_DERIVATION,
    CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
    CLOUD_SYNC_PATCH_DOC_TYPE,
    CLOUD_SYNC_SCHEMA_VERSION,
    CLOUD_SYNC_SIGNING_ALGORITHM,
    CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
    createPendingWebPlannerDeviceRecord,
    generatePhonePlannerCloudKeyPair,
    publicKeyRecord,
    signCloudSyncCanonicalMetadataBrowser
} from '../src/phone-planner/phonePlannerCloudCrypto.js'
import { createMigratedLocalD1Database } from './helpers/cloudflareLocalD1Harness.js'

const OWNER = 'cf_owner_phase31_3'
const HOST = 'https://sync.example.test'
const NOW = 1770001000000

function b64(bytes) {
    return Buffer.from(bytes).toString('base64url')
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

async function desktopDevice({ ownerUid = OWNER, deviceId = 'dev_desktop_phase31_3', sequence = 1 } = {}) {
    const keyPair = await generatePhonePlannerCloudKeyPair(webcrypto)
    return {
        keyPair,
        device: {
            product: 'wipesnap',
            recordType: CLOUD_SYNC_DEVICE_RECORD_TYPE,
            schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
            ownerUid,
            deviceId,
            role: 'desktop',
            status: 'active',
            platform: 'windows-electron',
            syncScopes: ['read', 'snapshot-upload', 'patch-upload'],
            signingPublicKey: await publicKeyRecord(keyPair.signing.publicKey, CLOUD_SYNC_SIGNING_ALGORITHM, webcrypto),
            wrapPublicKey: await publicKeyRecord(keyPair.wrapping.publicKey, 'RSA-OAEP-256', webcrypto),
            enrollmentEpoch: 1,
            keyVersion: 1,
            deviceSequence: sequence,
            createdAt: NOW,
            updatedAt: NOW,
            revokedAt: null,
            revokedByDeviceId: null
        }
    }
}

async function phoneDevice({ ownerUid = OWNER, deviceId = 'dev_web_phase31_3', status = 'pending', sequence = 1 } = {}) {
    const keyPair = await generatePhonePlannerCloudKeyPair(webcrypto)
    const pending = await createPendingWebPlannerDeviceRecord({
        ownerUid,
        deviceId,
        keyPair,
        now: NOW + 1,
        cryptoApi: webcrypto
    })
    return {
        keyPair,
        device: { ...pending.device, status, deviceSequence: sequence, revokedAt: status === 'revoked' ? NOW + 2 : null }
    }
}

async function keyGrant({ recipientDeviceId, createdByDeviceId }) {
    const wrapped = new Uint8Array(256).fill(0x31)
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid: OWNER,
        grantId: `grant_${recipientDeviceId.slice(4)}_v1`,
        recipientDeviceId,
        createdByDeviceId,
        keyVersion: 1,
        wrapAlg: 'RSA-OAEP-256',
        wrappedKeyCiphertext: b64(wrapped),
        wrappedKeyHash: await sha256Base64Url(wrapped, webcrypto),
        createdAt: NOW + 3,
        revokedAt: null,
        revokedByDeviceId: null
    }
}

async function envelope({ docType = CLOUD_SYNC_SNAPSHOT_DOC_TYPE, deviceId, deviceSequence, revisionId } = {}) {
    const ciphertext = new Uint8Array(24).fill(docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE ? 0x41 : 0x42)
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_ENVELOPE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        envelopeVersion: CLOUD_SYNC_ENVELOPE_VERSION,
        docType,
        ownerUid: OWNER,
        snapshotId: docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE ? 'snap_phase31_3' : null,
        patchId: docType === CLOUD_SYNC_PATCH_DOC_TYPE ? 'patch_phase31_3' : null,
        revisionId,
        baseRevisionId: docType === CLOUD_SYNC_PATCH_DOC_TYPE ? 'srev_phase31_3_0' : null,
        deviceId,
        deviceSequence,
        keyVersion: 1,
        createdAt: NOW + deviceSequence,
        updatedAt: NOW + deviceSequence,
        encryption: {
            alg: CLOUD_SYNC_CONTENT_ENCRYPTION,
            kdf: CLOUD_SYNC_KEY_DERIVATION,
            salt: b64(new Uint8Array(32).fill(0x51)),
            iv: b64(new Uint8Array(12).fill(0x52)),
            tag: b64(new Uint8Array(16).fill(0x53))
        },
        ciphertext: b64(ciphertext),
        ciphertextHash: await sha256Base64Url(ciphertext, webcrypto),
        signature: {
            alg: CLOUD_SYNC_SIGNING_ALGORITHM,
            keyId: deviceId,
            value: b64(new Uint8Array(64).fill(0x54))
        },
        tombstone: null,
        conflict: null
    }
}

async function signedRequest({
    method = 'GET',
    path,
    operation,
    body,
    device,
    privateKey,
    sequence,
    ip = '203.0.113.31',
    headerMutator = null
}) {
    const bodyText = method === 'GET' ? '' : JSON.stringify(body ?? {})
    const auth = {
        ownerUid: device.ownerUid,
        deviceId: device.deviceId,
        deviceRole: device.role,
        enrollmentEpoch: device.enrollmentEpoch,
        keyVersion: device.keyVersion,
        deviceSequence: sequence,
        requestedAt: NOW + 100,
        bodyHash: await sha256Base64Url(bodyText, webcrypto),
        signatureAlg: 'ECDSA-P256-SHA256-P1363',
        signatureKeyId: device.deviceId,
        signature: ''
    }
    auth.signature = await signCloudSyncCanonicalMetadataBrowser({
        canonicalMetadata: createCloudflareCanonicalRequestMetadata({
            ...auth,
            method,
            path,
            operation
        }),
        privateKey,
        cryptoApi: webcrypto
    })
    const headers = new Headers({
        'content-type': 'application/json; charset=utf-8',
        'cf-connecting-ip': ip,
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.ownerUid]: auth.ownerUid,
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.deviceId]: auth.deviceId,
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.deviceRole]: auth.deviceRole,
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.enrollmentEpoch]: String(auth.enrollmentEpoch),
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.keyVersion]: String(auth.keyVersion),
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.deviceSequence]: String(auth.deviceSequence),
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.requestedAt]: String(auth.requestedAt),
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.bodyHash]: auth.bodyHash,
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.signatureAlg]: auth.signatureAlg,
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.signatureKeyId]: auth.signatureKeyId,
        [CLOUDFLARE_SYNC_SIGNING_HEADERS.signature]: auth.signature
    })
    if (headerMutator) headerMutator(headers)
    return new Request(`${HOST}${path}`, {
        method,
        headers,
        body: method === 'GET' ? undefined : bodyText
    })
}

async function responseJson(response) {
    return { status: response.status, json: await response.json() }
}

function createLocalWorker() {
    const db = createMigratedLocalD1Database()
    const store = createCloudflareD1Store({ db })
    return {
        db,
        store,
        worker: createCloudflareSyncWorkerCore({ store, cryptoApi: webcrypto, now: () => NOW + 100 })
    }
}

async function bootstrap(worker, desktop) {
    const response = await worker.handle(await signedRequest({
        method: 'POST',
        path: '/v1/bootstrap/desktop',
        operation: CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop,
        body: { document: desktop.device },
        device: desktop.device,
        privateKey: desktop.keyPair.signing.privateKey,
        sequence: 1
    }))
    assert.equal(response.status, 200, JSON.stringify(await response.clone().json()))
}

test('local D1 harness runs the Worker enrollment, grant, snapshot, and patch flow', async () => {
    const { db, worker } = createLocalWorker()
    try {
        const desktop = await desktopDevice()
        await bootstrap(worker, desktop)
        const phone = await phoneDevice()
        const pairingChallengeHash = await sha256Base64Url('phase31.3 pairing', webcrypto)

        let response = await worker.handle(await signedRequest({
            method: 'POST',
            path: '/v1/enrollments/request',
            operation: CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment,
            body: { document: phone.device, pairingChallengeHash },
            device: phone.device,
            privateKey: phone.keyPair.signing.privateKey,
            sequence: 1
        }))
        assert.equal(response.status, 200, JSON.stringify(await response.clone().json()))

        const grant = await keyGrant({ recipientDeviceId: phone.device.deviceId, createdByDeviceId: desktop.device.deviceId })
        response = await worker.handle(await signedRequest({
            method: 'POST',
            path: '/v1/enrollments/approve',
            operation: CLOUDFLARE_SYNC_OPERATIONS.approveEnrollment,
            body: { requestId: phone.device.deviceId, keyGrant: grant },
            device: { ...desktop.device, deviceSequence: 1 },
            privateKey: desktop.keyPair.signing.privateKey,
            sequence: 2
        }))
        assert.equal(response.status, 200, JSON.stringify(await response.clone().json()))

        response = await worker.handle(await signedRequest({
            method: 'POST',
            path: '/v1/enrollments/claim',
            operation: CLOUDFLARE_SYNC_OPERATIONS.claimEnrollment,
            body: { requestId: phone.device.deviceId, keyGrantId: grant.grantId, pairingChallengeHash },
            device: { ...phone.device, status: 'active' },
            privateKey: phone.keyPair.signing.privateKey,
            sequence: 2
        }))
        const claim = await responseJson(response)
        assert.equal(claim.status, 200, JSON.stringify(claim))
        assert.equal(claim.json.keyGrant.wrappedKeyCiphertext, grant.wrappedKeyCiphertext)

        const snapshot = await envelope({
            deviceId: desktop.device.deviceId,
            deviceSequence: 3,
            revisionId: 'srev_phase31_3_d1_flow'
        })
        response = await worker.handle(await signedRequest({
            method: 'POST',
            path: '/v1/snapshots',
            operation: CLOUDFLARE_SYNC_OPERATIONS.uploadSnapshot,
            body: { document: snapshot },
            device: { ...desktop.device, deviceSequence: 2 },
            privateKey: desktop.keyPair.signing.privateKey,
            sequence: 3
        }))
        assert.equal(response.status, 200, JSON.stringify(await response.clone().json()))

        const patch = await envelope({
            docType: CLOUD_SYNC_PATCH_DOC_TYPE,
            deviceId: phone.device.deviceId,
            deviceSequence: 3,
            revisionId: 'patchrev_phase31_3_d1_flow'
        })
        response = await worker.handle(await signedRequest({
            method: 'POST',
            path: '/v1/patches',
            operation: CLOUDFLARE_SYNC_OPERATIONS.uploadPatch,
            body: { document: patch },
            device: { ...phone.device, status: 'active', deviceSequence: 2 },
            privateKey: phone.keyPair.signing.privateKey,
            sequence: 3
        }))
        assert.equal(response.status, 200, JSON.stringify(await response.clone().json()))

        const storedPatch = db.prepare('SELECT envelope_json FROM cloudflare_sync_patches WHERE owner_uid = ? AND revision_id = ?')
            .bind(OWNER, patch.revisionId)
            .first()
        assert.match(storedPatch.envelope_json, /ciphertext/)
        assert.doesNotMatch(storedPatch.envelope_json, /C:\\|AppData|BrowserProfile|syncRootKey|privateKey|launchAuthority/i)
    } finally {
        db.close()
    }
})

test('bootstrap and enrollment are create-only and cannot overwrite active or revoked devices', async () => {
    const { db, worker } = createLocalWorker()
    try {
        const desktop = await desktopDevice()
        await bootstrap(worker, desktop)
        const attackerDesktop = await desktopDevice({ deviceId: desktop.device.deviceId })
        let response = await worker.handle(await signedRequest({
            method: 'POST',
            path: '/v1/bootstrap/desktop',
            operation: CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop,
            body: { document: attackerDesktop.device },
            device: attackerDesktop.device,
            privateKey: attackerDesktop.keyPair.signing.privateKey,
            sequence: 1,
            ip: '203.0.113.32'
        }))
        let rejected = await responseJson(response)
        assert.equal(rejected.status, 409, JSON.stringify(rejected))
        assert.equal(rejected.json.error, 'owner-exists')

        const phone = await phoneDevice({ deviceId: 'dev_web_phase31_3_overwrite' })
        const pairingChallengeHash = await sha256Base64Url('phase31.3 overwrite pairing', webcrypto)
        response = await worker.handle(await signedRequest({
            method: 'POST',
            path: '/v1/enrollments/request',
            operation: CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment,
            body: { document: phone.device, pairingChallengeHash },
            device: phone.device,
            privateKey: phone.keyPair.signing.privateKey,
            sequence: 1
        }))
        assert.equal(response.status, 200, JSON.stringify(await response.clone().json()))
        const grant = await keyGrant({ recipientDeviceId: phone.device.deviceId, createdByDeviceId: desktop.device.deviceId })
        response = await worker.handle(await signedRequest({
            method: 'POST',
            path: '/v1/enrollments/approve',
            operation: CLOUDFLARE_SYNC_OPERATIONS.approveEnrollment,
            body: { requestId: phone.device.deviceId, keyGrant: grant },
            device: { ...desktop.device, deviceSequence: 1 },
            privateKey: desktop.keyPair.signing.privateKey,
            sequence: 2
        }))
        assert.equal(response.status, 200, JSON.stringify(await response.clone().json()))

        const originalPhone = db.prepare('SELECT signing_public_key_json, status FROM cloudflare_sync_devices WHERE owner_uid = ? AND device_id = ?')
            .bind(OWNER, phone.device.deviceId)
            .first()
        const attackerPhone = await phoneDevice({ deviceId: phone.device.deviceId })
        response = await worker.handle(await signedRequest({
            method: 'POST',
            path: '/v1/enrollments/request',
            operation: CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment,
            body: { document: attackerPhone.device, pairingChallengeHash },
            device: attackerPhone.device,
            privateKey: attackerPhone.keyPair.signing.privateKey,
            sequence: 1,
            ip: '203.0.113.33'
        }))
        rejected = await responseJson(response)
        assert.equal(rejected.status, 409, JSON.stringify(rejected))
        assert.equal(rejected.json.error, 'device-exists')
        assert.deepEqual(
            db.prepare('SELECT signing_public_key_json, status FROM cloudflare_sync_devices WHERE owner_uid = ? AND device_id = ?')
                .bind(OWNER, phone.device.deviceId)
                .first(),
            originalPhone
        )

        response = await worker.handle(await signedRequest({
            method: 'POST',
            path: `/v1/devices/${phone.device.deviceId}/revoke`,
            operation: CLOUDFLARE_SYNC_OPERATIONS.revokeDevice,
            body: {},
            device: { ...desktop.device, deviceSequence: 2 },
            privateKey: desktop.keyPair.signing.privateKey,
            sequence: 3
        }))
        assert.equal(response.status, 200, JSON.stringify(await response.clone().json()))
        const revoked = await phoneDevice({ deviceId: phone.device.deviceId })
        response = await worker.handle(await signedRequest({
            method: 'POST',
            path: '/v1/enrollments/request',
            operation: CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment,
            body: { document: revoked.device, pairingChallengeHash },
            device: revoked.device,
            privateKey: revoked.keyPair.signing.privateKey,
            sequence: 1,
            ip: '203.0.113.34'
        }))
        rejected = await responseJson(response)
        assert.equal(rejected.status, 409, JSON.stringify(rejected))
        assert.equal(rejected.json.error, 'device-exists')
        assert.equal(
            db.prepare('SELECT status FROM cloudflare_sync_devices WHERE owner_uid = ? AND device_id = ?')
                .bind(OWNER, phone.device.deviceId)
                .first()
                .status,
            'revoked'
        )
    } finally {
        db.close()
    }
})

test('D1 approval keeps device activation, key grant, and request approval atomic', async () => {
    async function setup(suffix) {
        const db = createMigratedLocalD1Database()
        const store = createCloudflareD1Store({ db })
        const desktop = await desktopDevice({ deviceId: `dev_desktop_phase31_3_atomic_${suffix}` })
        const phone = await phoneDevice({ deviceId: `dev_web_phase31_3_atomic_${suffix}` })
        await store.bootstrapDesktop({ ownerUid: OWNER, device: desktop.device, now: NOW })
        await store.requestEnrollment({
            ownerUid: OWNER,
            requestId: phone.device.deviceId,
            device: phone.device,
            pairingChallengeHash: await sha256Base64Url(`phase31.3 atomic ${phone.device.deviceId}`, webcrypto),
            now: NOW + 1
        })
        return {
            db,
            store,
            desktop,
            phone,
            grant: await keyGrant({
                recipientDeviceId: phone.device.deviceId,
                createdByDeviceId: desktop.device.deviceId
            })
        }
    }

    function failBatchOnSql(db, pattern) {
        const originalBatch = db.batch.bind(db)
        db.batch = statements => originalBatch(statements.map(statement => (
            pattern.test(statement.sql)
                ? { run: () => { throw new Error('injected approval write failure') } }
                : statement
        )))
        return () => { db.batch = originalBatch }
    }

    for (const failure of [
        { name: 'key grant insert', suffix: 'grant_insert', pattern: /INSERT INTO cloudflare_sync_key_grants/i },
        { name: 'request approval update', suffix: 'request_update', pattern: /UPDATE cloudflare_sync_enrollment_requests\s+SET status = 'approved'/i }
    ]) {
        const { db, store, desktop, phone, grant } = await setup(failure.suffix)
        const restore = failBatchOnSql(db, failure.pattern)
        try {
            await assert.rejects(() => store.approveEnrollment({
                ownerUid: OWNER,
                requestId: phone.device.deviceId,
                desktopDeviceId: desktop.device.deviceId,
                keyGrant: grant,
                now: NOW + 2
            }), error => error.code === 'approval-conflict')
            const deviceRow = db.prepare('SELECT status FROM cloudflare_sync_devices WHERE owner_uid = ? AND device_id = ?')
                .bind(OWNER, phone.device.deviceId)
                .first()
            assert.equal(deviceRow.status, 'pending', failure.name)
            const requestRow = db.prepare('SELECT status, approved_at, approved_by_device_id, key_grant_id FROM cloudflare_sync_enrollment_requests WHERE owner_uid = ? AND request_id = ?')
                .bind(OWNER, phone.device.deviceId)
                .first()
            assert.equal(requestRow.status, 'pending', failure.name)
            assert.equal(requestRow.approved_at, null, failure.name)
            assert.equal(requestRow.approved_by_device_id, null, failure.name)
            assert.equal(requestRow.key_grant_id, null, failure.name)
            const grants = db.prepare('SELECT COUNT(*) AS count FROM cloudflare_sync_key_grants WHERE owner_uid = ? AND grant_id = ?')
                .bind(OWNER, grant.grantId)
                .first()
                .count
            assert.equal(grants, 0, failure.name)
        } finally {
            restore()
            db.close()
        }
    }
})

test('D1 sequence advancement uses compare-and-swap and rejects stale out-of-order requests', async () => {
    const db = createMigratedLocalD1Database()
    try {
        const store = createCloudflareD1Store({ db })
        const desktop = await desktopDevice()
        await store.bootstrapDesktop({ ownerUid: OWNER, device: desktop.device, now: NOW })

        const originalPrepare = db.prepare.bind(db)
        db.prepare = sql => {
            if (/SELECT\s+device_sequence,\s*status\s+FROM\s+cloudflare_sync_devices/i.test(sql)) {
                throw new Error('pre-read sequence check is not allowed')
            }
            return originalPrepare(sql)
        }
        await store.advanceDeviceSequence({
            ownerUid: OWNER,
            deviceId: desktop.device.deviceId,
            deviceSequence: 2,
            operation: 'test-operation',
            documentId: 'doc_2',
            now: NOW + 1
        })
        db.prepare = originalPrepare
        await assert.rejects(() => store.advanceDeviceSequence({
            ownerUid: OWNER,
            deviceId: desktop.device.deviceId,
            deviceSequence: 2,
            operation: 'test-operation',
            documentId: 'doc_2_replay',
            now: NOW + 2
        }), /sequence/)
        await store.advanceDeviceSequence({
            ownerUid: OWNER,
            deviceId: desktop.device.deviceId,
            deviceSequence: 5,
            operation: 'test-operation',
            documentId: 'doc_5',
            now: NOW + 3
        })
        await assert.rejects(() => store.advanceDeviceSequence({
            ownerUid: OWNER,
            deviceId: desktop.device.deviceId,
            deviceSequence: 4,
            operation: 'test-operation',
            documentId: 'doc_4_stale',
            now: NOW + 4
        }), /sequence/)
        assert.equal(
            db.prepare('SELECT device_sequence FROM cloudflare_sync_devices WHERE owner_uid = ? AND device_id = ?')
                .bind(OWNER, desktop.device.deviceId)
                .first()
                .device_sequence,
            5
        )
    } finally {
        db.close()
    }
})

test('D1 abuse limits block failed signatures, bootstrap, enrollment, pending records, patches, and retain snapshots', async () => {
    const { db, store, worker } = createLocalWorker()
    try {
        const desktop = await desktopDevice()
        await bootstrap(worker, desktop)

        let last
        for (let index = 0; index <= CLOUDFLARE_SYNC_LIMITS.maxFailedSignaturesPerWindow; index += 1) {
            last = await worker.handle(await signedRequest({
                path: '/v1/snapshots/latest',
                operation: CLOUDFLARE_SYNC_OPERATIONS.getLatestSnapshot,
                device: { ...desktop.device, deviceSequence: 1 },
                privateKey: desktop.keyPair.signing.privateKey,
                sequence: 2,
                headerMutator: headers => headers.set(CLOUDFLARE_SYNC_SIGNING_HEADERS.signature, 'abc')
            }))
        }
        let limited = await responseJson(last)
        assert.equal(limited.status, 429, JSON.stringify(limited))
        assert.equal(limited.json.error, 'failed-signature-rate-limited')

        for (let index = 0; index <= CLOUDFLARE_SYNC_LIMITS.maxBootstrapRequestsPerWindow; index += 1) {
            const duplicateDesktop = await desktopDevice({ deviceId: desktop.device.deviceId })
            last = await worker.handle(await signedRequest({
                method: 'POST',
                path: '/v1/bootstrap/desktop',
                operation: CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop,
                body: { document: duplicateDesktop.device },
                device: duplicateDesktop.device,
                privateKey: duplicateDesktop.keyPair.signing.privateKey,
                sequence: 1,
                ip: '203.0.113.44'
            }))
        }
        limited = await responseJson(last)
        assert.equal(limited.status, 429, JSON.stringify(limited))
        assert.equal(limited.json.error, 'rate-limited')

        for (let index = 0; index <= CLOUDFLARE_SYNC_LIMITS.maxEnrollmentRequestsPerWindow; index += 1) {
            const duplicateAsPhone = await phoneDevice({ deviceId: desktop.device.deviceId })
            last = await worker.handle(await signedRequest({
                method: 'POST',
                path: '/v1/enrollments/request',
                operation: CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment,
                body: {
                    document: duplicateAsPhone.device,
                    pairingChallengeHash: await sha256Base64Url(`phase31.3 rate ${index}`, webcrypto)
                },
                device: duplicateAsPhone.device,
                privateKey: duplicateAsPhone.keyPair.signing.privateKey,
                sequence: 1,
                ip: '203.0.113.45'
            }))
        }
        limited = await responseJson(last)
        assert.equal(limited.status, 429, JSON.stringify(limited))
        assert.equal(limited.json.error, 'rate-limited')

        for (let index = 0; index < CLOUDFLARE_SYNC_LIMITS.maxPendingEnrollmentsPerOwner; index += 1) {
            const pending = await phoneDevice({ deviceId: `dev_pending_phase31_3_${index}` })
            await store.requestEnrollment({
                ownerUid: OWNER,
                requestId: pending.device.deviceId,
                device: pending.device,
                pairingChallengeHash: await sha256Base64Url(`pending ${index}`, webcrypto),
                now: NOW + index
            })
        }
        const overflowPending = await phoneDevice({ deviceId: 'dev_pending_phase31_3_overflow' })
        await assert.rejects(() => store.requestEnrollment({
            ownerUid: OWNER,
            requestId: overflowPending.device.deviceId,
            device: overflowPending.device,
            pairingChallengeHash: 'safe_hash_safe_hash_safe_hash_safe_hash',
            now: NOW + 99
        }), /pending/)

        const phone = await phoneDevice({ deviceId: 'dev_patch_phase31_3', status: 'active' })
        await db.prepare(
            `INSERT INTO cloudflare_sync_devices (
                owner_uid, device_id, role, status, platform, sync_scopes_json,
                signing_public_key_json, wrap_public_key_json, enrollment_epoch, key_version,
                device_sequence, created_at, updated_at, revoked_at, revoked_by_device_id, last_seen_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(
            OWNER,
            phone.device.deviceId,
            phone.device.role,
            'active',
            phone.device.platform,
            JSON.stringify(phone.device.syncScopes),
            JSON.stringify(phone.device.signingPublicKey),
            JSON.stringify(phone.device.wrapPublicKey),
            phone.device.enrollmentEpoch,
            phone.device.keyVersion,
            phone.device.deviceSequence,
            phone.device.createdAt,
            phone.device.updatedAt,
            null,
            null,
            NOW
        ).run()
        for (let index = 0; index < CLOUDFLARE_SYNC_LIMITS.maxPendingPatchesPerOwner; index += 1) {
            await store.insertPatch({
                ownerUid: OWNER,
                envelope: await envelope({
                    docType: CLOUD_SYNC_PATCH_DOC_TYPE,
                    deviceId: phone.device.deviceId,
                    deviceSequence: index + 2,
                    revisionId: `patchrev_phase31_3_pending_${index}`
                }),
                now: NOW + index
            })
        }
        await assert.rejects(async () => store.insertPatch({
            ownerUid: OWNER,
            envelope: await envelope({
                docType: CLOUD_SYNC_PATCH_DOC_TYPE,
                deviceId: phone.device.deviceId,
                deviceSequence: 200,
                revisionId: 'patchrev_phase31_3_pending_overflow'
            }),
            now: NOW + 200
        }), /pending/)

        for (let index = 0; index < CLOUDFLARE_SYNC_LIMITS.maxSnapshotsRetainedPerOwner + 3; index += 1) {
            await store.insertSnapshot({
                ownerUid: OWNER,
                envelope: await envelope({
                    deviceId: desktop.device.deviceId,
                    deviceSequence: 100 + index,
                    revisionId: `srev_phase31_3_retained_${index}`
                }),
                now: NOW + 500 + index
            })
        }
        const snapshotCount = db.prepare('SELECT COUNT(*) AS count FROM cloudflare_sync_snapshots WHERE owner_uid = ?')
            .bind(OWNER)
            .first()
            .count
        assert.equal(snapshotCount, CLOUDFLARE_SYNC_LIMITS.maxSnapshotsRetainedPerOwner)
        assert.equal(
            db.prepare('SELECT latest_snapshot_revision_id FROM cloudflare_sync_state WHERE owner_uid = ?')
                .bind(OWNER)
                .first()
                .latest_snapshot_revision_id,
            `srev_phase31_3_retained_${CLOUDFLARE_SYNC_LIMITS.maxSnapshotsRetainedPerOwner + 2}`
        )
    } finally {
        db.close()
    }
})
