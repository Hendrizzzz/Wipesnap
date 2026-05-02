import assert from 'assert/strict'
import { webcrypto } from 'crypto'
import { test } from 'node:test'
import workerModule from '../cloudflare/src/wipesnapCloudSyncWorker.js'
import { createCloudflareSyncFetchClient } from '../src/cloudflare-sync/cloudflareSyncFetchClient.js'
import { CLOUDFLARE_SYNC_LIMITS } from '../src/cloudflare-sync/cloudflareSyncConstants.js'
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

const OWNER = 'cf_owner_phase31_4_worker'
const BASE_URL = 'http://127.0.0.1:8787'

function b64(bytes) {
    return Buffer.from(bytes).toString('base64url')
}

function forbiddenPattern() {
    return /C:\\|AppData[\\/]|BrowserProfile|vault\.json|cap_[A-Za-z0-9_-]{4,128}|syncRootKey|rootKeyMaterial|privateKey|launchAuthority|Bearer |refreshToken|accessToken|cookie|password/i
}

async function desktopFixture({ deviceId = 'dev_desktop_phase31_4_worker', sequence = 1 } = {}) {
    const keyPair = await generatePhonePlannerCloudKeyPair(webcrypto)
    return {
        keyPair,
        device: {
            product: 'wipesnap',
            recordType: CLOUD_SYNC_DEVICE_RECORD_TYPE,
            schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
            ownerUid: OWNER,
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
            createdAt: Date.now(),
            updatedAt: Date.now(),
            revokedAt: null,
            revokedByDeviceId: null
        }
    }
}

async function phoneFixture({ deviceId = 'dev_web_phase31_4_worker' } = {}) {
    const keyPair = await generatePhonePlannerCloudKeyPair(webcrypto)
    const pending = await createPendingWebPlannerDeviceRecord({
        ownerUid: OWNER,
        deviceId,
        keyPair,
        now: Date.now(),
        cryptoApi: webcrypto
    })
    return { keyPair, device: pending.device }
}

async function keyGrant({ recipientDeviceId, createdByDeviceId }) {
    const wrapped = new Uint8Array(256).fill(0x44)
    const wrappedKeyHash = await cryptoHash(wrapped)
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
        wrappedKeyHash,
        createdAt: Date.now(),
        revokedAt: null,
        revokedByDeviceId: null
    }
}

async function cryptoHash(bytes) {
    const digest = await webcrypto.subtle.digest('SHA-256', bytes)
    return b64(new Uint8Array(digest))
}

async function envelope({ docType, deviceId, deviceSequence, revisionId }) {
    const ciphertext = new Uint8Array(32).fill(docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE ? 0x51 : 0x52)
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_ENVELOPE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        envelopeVersion: CLOUD_SYNC_ENVELOPE_VERSION,
        docType,
        ownerUid: OWNER,
        snapshotId: docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE ? 'snap_phase31_4_worker' : null,
        patchId: docType === CLOUD_SYNC_PATCH_DOC_TYPE ? 'patch_phase31_4_worker' : null,
        revisionId,
        baseRevisionId: docType === CLOUD_SYNC_PATCH_DOC_TYPE ? 'srev_phase31_4_worker_1' : null,
        deviceId,
        deviceSequence,
        keyVersion: 1,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        encryption: {
            alg: CLOUD_SYNC_CONTENT_ENCRYPTION,
            kdf: CLOUD_SYNC_KEY_DERIVATION,
            salt: b64(new Uint8Array(32).fill(0x61)),
            iv: b64(new Uint8Array(12).fill(0x62)),
            tag: b64(new Uint8Array(16).fill(0x63))
        },
        ciphertext: b64(ciphertext),
        ciphertextHash: await cryptoHash(ciphertext),
        signature: {
            alg: CLOUD_SYNC_SIGNING_ALGORITHM,
            keyId: deviceId,
            value: b64(new Uint8Array(64).fill(0x64))
        },
        tombstone: null,
        conflict: null
    }
}

function workerFetch(db) {
    return async (url, options) => workerModule.fetch(new Request(url, options), { WIPESNAP_D1: db })
}

function client(db) {
    return createCloudflareSyncFetchClient({
        apiBaseUrl: BASE_URL,
        useLocalDev: true,
        fetchImpl: workerFetch(db),
        cryptoApi: webcrypto,
        signCanonicalMetadata: ({ canonicalMetadata, privateKey }) =>
            signCloudSyncCanonicalMetadataBrowser({ canonicalMetadata, privateKey, cryptoApi: webcrypto })
    })
}

function deviceState(device, keyPair) {
    return {
        ownerUid: device.ownerUid,
        device,
        signingPrivateKey: keyPair.signing.privateKey
    }
}

test('actual Worker entry runs local D1 bootstrap, enrollment, snapshot, patch, revocation, replay, and rate checks', async () => {
    const db = createMigratedLocalD1Database()
    try {
        const api = client(db)
        const desktop = await desktopFixture()
        let desktopDevice = desktop.device
        let result = await api.bootstrapDesktop({
            document: desktopDevice,
            deviceState: deviceState(desktopDevice, desktop.keyPair),
            deviceSequence: 1
        })
        assert.equal(result.status, 'accepted')

        const phone = await phoneFixture()
        let phoneDevice = phone.device
        const pairingChallengeHash = await cryptoHash(Buffer.from('phase31.4 worker pairing'))
        result = await api.requestEnrollment({
            document: phoneDevice,
            pairingChallengeHash,
            deviceState: deviceState(phoneDevice, phone.keyPair),
            deviceSequence: 1
        })
        assert.equal(result.status, 'pending')

        result = await api.listPendingEnrollments({
            deviceState: deviceState(desktopDevice, desktop.keyPair),
            deviceSequence: 2
        })
        assert.equal(result.records.length, 1)
        desktopDevice = { ...desktopDevice, deviceSequence: result.deviceSequence }

        const grant = await keyGrant({
            recipientDeviceId: phoneDevice.deviceId,
            createdByDeviceId: desktopDevice.deviceId
        })
        result = await api.approveEnrollment({
            requestId: phoneDevice.deviceId,
            keyGrant: grant,
            deviceState: deviceState(desktopDevice, desktop.keyPair),
            deviceSequence: 3
        })
        assert.equal(result.status, 'approved')
        desktopDevice = { ...desktopDevice, deviceSequence: result.deviceSequence }

        result = await api.claimEnrollment({
            requestId: phoneDevice.deviceId,
            keyGrantId: grant.grantId,
            pairingChallengeHash,
            deviceState: deviceState({ ...phoneDevice, status: 'active' }, phone.keyPair),
            deviceSequence: 2
        })
        assert.equal(result.status, 'accepted')
        assert.equal(result.keyGrant.wrappedKeyCiphertext, grant.wrappedKeyCiphertext)
        phoneDevice = { ...result.device }

        const snapshot = await envelope({
            docType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
            deviceId: desktopDevice.deviceId,
            deviceSequence: 4,
            revisionId: 'srev_phase31_4_worker_1'
        })
        result = await api.uploadSnapshot({
            document: snapshot,
            deviceState: deviceState(desktopDevice, desktop.keyPair),
            deviceSequence: 4
        })
        assert.equal(result.status, 'accepted')
        desktopDevice = { ...desktopDevice, deviceSequence: result.deviceSequence }

        result = await api.getLatestSnapshot({
            deviceState: deviceState(phoneDevice, phone.keyPair),
            deviceSequence: 3
        })
        assert.equal(result.envelope.revisionId, snapshot.revisionId)
        phoneDevice = { ...phoneDevice, deviceSequence: result.deviceSequence }

        const patch = await envelope({
            docType: CLOUD_SYNC_PATCH_DOC_TYPE,
            deviceId: phoneDevice.deviceId,
            deviceSequence: 4,
            revisionId: 'patchrev_phase31_4_worker_1'
        })
        result = await api.uploadPatch({
            document: patch,
            deviceState: deviceState(phoneDevice, phone.keyPair),
            deviceSequence: 4
        })
        assert.equal(result.status, 'accepted')
        phoneDevice = { ...phoneDevice, deviceSequence: result.deviceSequence }

        result = await api.listPendingPatches({
            deviceState: deviceState(desktopDevice, desktop.keyPair),
            deviceSequence: 5
        })
        assert.equal(result.records[0].patchRevisionId, patch.revisionId)
        desktopDevice = { ...desktopDevice, deviceSequence: result.deviceSequence }

        for (const status of ['applied', 'skipped', 'conflict', 'rejected']) {
            db.prepare('UPDATE cloudflare_sync_patches SET status = ? WHERE owner_uid = ? AND revision_id = ?')
                .bind(status, OWNER, patch.revisionId)
                .run()
            result = await api.getPatch({
                revisionId: patch.revisionId,
                deviceState: deviceState(desktopDevice, desktop.keyPair),
                deviceSequence: desktopDevice.deviceSequence + 1
            })
            assert.equal(result.status, 'not-found')
            assert.equal(result.envelope, null)
            assert.equal(result.patchStatus, 'not-found')
            desktopDevice = { ...desktopDevice, deviceSequence: result.deviceSequence }
        }

        await assert.rejects(() => api.getLatestSnapshot({
            deviceState: deviceState(phoneDevice, phone.keyPair),
            deviceSequence: 4
        }), error => error.code === 'duplicate-sequence')
        await assert.rejects(() => api.getLatestSnapshot({
            deviceState: deviceState(phoneDevice, phone.keyPair),
            deviceSequence: 3
        }), error => error.code === 'duplicate-sequence')

        result = await api.revokeDevice({
            deviceId: phoneDevice.deviceId,
            deviceState: deviceState(desktopDevice, desktop.keyPair),
            deviceSequence: desktopDevice.deviceSequence + 1
        })
        assert.equal(result.status, 'revoked')
        desktopDevice = { ...desktopDevice, deviceSequence: result.deviceSequence }
        await assert.rejects(() => api.uploadPatch({
            document: { ...patch, revisionId: 'patchrev_phase31_4_worker_revoked', deviceSequence: 5 },
            deviceState: deviceState(phoneDevice, phone.keyPair),
            deviceSequence: 5
        }), error => error.code === 'revoked-device')

        let lastError = null
        for (let index = 0; index <= CLOUDFLARE_SYNC_LIMITS.maxSignedRequestsPerWindow; index += 1) {
            try {
                await api.getDevice({
                    deviceId: desktopDevice.deviceId,
                    deviceState: deviceState(desktopDevice, desktop.keyPair),
                    deviceSequence: desktopDevice.deviceSequence + 1
                })
                desktopDevice = { ...desktopDevice, deviceSequence: desktopDevice.deviceSequence + 1 }
            } catch (error) {
                lastError = error
                break
            }
        }
        assert.equal(lastError?.code, 'rate-limited')

        const storedSnapshot = db.prepare('SELECT envelope_json FROM cloudflare_sync_snapshots WHERE owner_uid = ? AND revision_id = ?')
            .bind(OWNER, snapshot.revisionId)
            .first()
        const storedPatch = db.prepare('SELECT envelope_json FROM cloudflare_sync_patches WHERE owner_uid = ? AND revision_id = ?')
            .bind(OWNER, patch.revisionId)
            .first()
        assert.match(storedSnapshot.envelope_json, /ciphertext/)
        assert.match(storedPatch.envelope_json, /ciphertext/)
        assert.doesNotMatch(JSON.stringify({ storedSnapshot, storedPatch }), forbiddenPattern())
    } finally {
        db.close()
    }
})
