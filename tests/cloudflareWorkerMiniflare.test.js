import assert from 'assert/strict'
import { readFileSync } from 'fs'
import { resolve } from 'path'
import { webcrypto } from 'crypto'
import { test } from 'node:test'
import { Miniflare } from 'miniflare'
import { createCloudflareSyncFetchClient } from '../src/cloudflare-sync/cloudflareSyncFetchClient.js'
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

const OWNER = 'cf_owner_phase31_4_miniflare'
const BASE_URL = 'http://127.0.0.1:8787'
const NOW = 1770000000000

function b64(bytes) {
    return Buffer.from(bytes).toString('base64url')
}

async function cryptoHash(bytes) {
    const digest = await webcrypto.subtle.digest('SHA-256', bytes)
    return b64(new Uint8Array(digest))
}

async function desktopFixture() {
    const keyPair = await generatePhonePlannerCloudKeyPair(webcrypto)
    return {
        keyPair,
        device: {
            product: 'wipesnap',
            recordType: CLOUD_SYNC_DEVICE_RECORD_TYPE,
            schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
            ownerUid: OWNER,
            deviceId: 'dev_desktop_phase31_4_miniflare',
            role: 'desktop',
            status: 'active',
            platform: 'windows-electron',
            syncScopes: ['read', 'snapshot-upload', 'patch-upload'],
            signingPublicKey: await publicKeyRecord(keyPair.signing.publicKey, CLOUD_SYNC_SIGNING_ALGORITHM, webcrypto),
            wrapPublicKey: await publicKeyRecord(keyPair.wrapping.publicKey, 'RSA-OAEP-256', webcrypto),
            enrollmentEpoch: 1,
            keyVersion: 1,
            deviceSequence: 1,
            createdAt: NOW,
            updatedAt: NOW,
            revokedAt: null,
            revokedByDeviceId: null
        }
    }
}

async function phoneFixture() {
    const keyPair = await generatePhonePlannerCloudKeyPair(webcrypto)
    const pending = await createPendingWebPlannerDeviceRecord({
        ownerUid: OWNER,
        deviceId: 'dev_web_phase31_4_miniflare',
        keyPair,
        now: NOW,
        cryptoApi: webcrypto
    })
    return { keyPair, device: pending.device }
}

function deviceState(device, keyPair) {
    return {
        ownerUid: device.ownerUid,
        device,
        signingPrivateKey: keyPair.signing.privateKey
    }
}

async function envelope({ docType, deviceId, deviceSequence, revisionId }) {
    const ciphertext = new Uint8Array(32).fill(docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE ? 0x71 : 0x72)
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_ENVELOPE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        envelopeVersion: CLOUD_SYNC_ENVELOPE_VERSION,
        docType,
        ownerUid: OWNER,
        snapshotId: docType === CLOUD_SYNC_SNAPSHOT_DOC_TYPE ? 'snap_phase31_4_miniflare' : null,
        patchId: docType === CLOUD_SYNC_PATCH_DOC_TYPE ? 'patch_phase31_4_miniflare' : null,
        revisionId,
        baseRevisionId: docType === CLOUD_SYNC_PATCH_DOC_TYPE ? 'srev_phase31_4_miniflare_1' : null,
        deviceId,
        deviceSequence,
        keyVersion: 1,
        createdAt: NOW,
        updatedAt: NOW,
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

async function keyGrant({ recipientDeviceId, createdByDeviceId }) {
    const wrapped = new Uint8Array(256).fill(0x55)
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
        wrappedKeyHash: await cryptoHash(wrapped),
        createdAt: NOW,
        revokedAt: null,
        revokedByDeviceId: null
    }
}

function forbiddenPattern() {
    return /C:\\|AppData[\\/]|BrowserProfile|vault\.json|cap_[A-Za-z0-9_-]{4,128}|syncRootKey|rootKeyMaterial|privateKey|launchAuthority|Bearer |refreshToken|accessToken|cookie|password/i
}

async function applyRealMigration(db) {
    const sql = readFileSync(resolve('cloudflare/migrations/0001_wipesnap_phone_sync.sql'), 'utf8')
    const statements = sql
        .split(/;\s*(?:\r?\n|$)/)
        .map(statement => statement.trim())
        .filter(Boolean)
    for (const statement of statements) {
        await db.prepare(statement).run()
    }
}

test('Miniflare Worker applies real D1 migration and runs signed sync flow', async () => {
    const mf = new Miniflare({
        modules: true,
        scriptPath: resolve('cloudflare/src/wipesnapCloudSyncWorker.js'),
        modulesRoot: resolve('.'),
        modulesRules: [{
            type: 'ESModule',
            include: ['**/*.js']
        }],
        compatibilityDate: '2026-04-01',
        d1Databases: { WIPESNAP_D1: 'wipesnap-phone-sync-miniflare-test' },
        d1Persist: false
    })
    try {
        const db = await mf.getD1Database('WIPESNAP_D1')
        await applyRealMigration(db)
        const api = createCloudflareSyncFetchClient({
            apiBaseUrl: BASE_URL,
            useLocalDev: true,
            fetchImpl: (url, options) => mf.dispatchFetch(url, options),
            cryptoApi: webcrypto,
            now: Date.now,
            signCanonicalMetadata: ({ canonicalMetadata, privateKey }) =>
                signCloudSyncCanonicalMetadataBrowser({ canonicalMetadata, privateKey, cryptoApi: webcrypto })
        })

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
        const pairingChallengeHash = await cryptoHash(Buffer.from('phase31.4 miniflare pairing'))
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
        phoneDevice = { ...result.device }

        const snapshot = await envelope({
            docType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
            deviceId: desktopDevice.deviceId,
            deviceSequence: 4,
            revisionId: 'srev_phase31_4_miniflare_1'
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
            revisionId: 'patchrev_phase31_4_miniflare_1'
        })
        result = await api.uploadPatch({
            document: patch,
            deviceState: deviceState(phoneDevice, phone.keyPair),
            deviceSequence: 4
        })
        assert.equal(result.status, 'accepted')

        result = await api.listPendingPatches({
            deviceState: deviceState(desktopDevice, desktop.keyPair),
            deviceSequence: 5
        })
        assert.equal(result.records[0].patchRevisionId, patch.revisionId)
        assert.doesNotMatch(JSON.stringify(result), forbiddenPattern())
    } finally {
        await mf.dispose()
    }
})
