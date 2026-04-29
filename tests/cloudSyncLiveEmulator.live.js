import assert from 'assert/strict'
import { createHash, generateKeyPairSync } from 'crypto'
import { readFileSync } from 'fs'
import { test } from 'node:test'
import { initializeApp, deleteApp } from 'firebase/app'
import { getAuth, connectAuthEmulator, signInAnonymously, signInWithCustomToken } from 'firebase/auth'
import {
    doc,
    getDoc,
    setDoc,
    connectFirestoreEmulator,
    getFirestore
} from 'firebase/firestore'
import { getFunctions, connectFunctionsEmulator } from 'firebase/functions'
import {
    assertFails,
    assertSucceeds,
    initializeTestEnvironment
} from '@firebase/rules-unit-testing'
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
    CLOUD_SYNC_ADMIN_OPERATIONS,
    CLOUD_SYNC_INGESTION_OPERATIONS,
    createCloudSyncAdminSignatureMetadata,
    createCloudSyncIngestionSignatureMetadata
} from '../src/main/cloudSyncIngestion.js'
import { SANITIZED_PRESET_SNAPSHOT_LIMITS } from '../src/main/sanitizedPresetSnapshot.js'

const PROJECT_ID = process.env.GCLOUD_PROJECT || process.env.FIREBASE_PROJECT || 'wipesnap-phase21-live'
const NOW = 1770000000000
const SYNC_ROOT_KEY = Buffer.alloc(32, 0x33)
const UID = 'firebase_uid_phase21_live'
const OTHER_UID = 'firebase_uid_phase21_live_other'

function emulatorHost(envName, fallbackPort) {
    const value = process.env[envName] || `127.0.0.1:${fallbackPort}`
    const [host, port] = value.replace(/^https?:\/\//, '').split(':')
    return { host: host || '127.0.0.1', port: Number(port || fallbackPort) }
}

const FIRESTORE = emulatorHost('FIRESTORE_EMULATOR_HOST', 8080)
const AUTH = emulatorHost('FIREBASE_AUTH_EMULATOR_HOST', 9099)
const FUNCTIONS = emulatorHost('FIREBASE_FUNCTIONS_EMULATOR_HOST', 5001)

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function sha256Base64Url(bytes) {
    return createHash('sha256').update(bytes).digest('base64url')
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

function wrapPublicKeyRecord(fill = 0x55) {
    const spki = Buffer.alloc(96, fill)
    return {
        alg: 'RSA-OAEP-256',
        spki: spki.toString('base64url'),
        fingerprint: sha256Base64Url(spki)
    }
}

function deviceRecord({
    ownerUid,
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
        wrapPublicKey: wrapPublicKeyRecord(role === 'desktop' ? 0x56 : 0x57),
        enrollmentEpoch,
        keyVersion,
        deviceSequence: sequence,
        createdAt: NOW,
        updatedAt: NOW,
        revokedAt,
        revokedByDeviceId: null
    }
}

function claimsFor(device) {
    return {
        wipesnapDeviceId: device.deviceId,
        wipesnapDeviceRole: device.role,
        wipesnapEnrollmentEpoch: device.enrollmentEpoch,
        wipesnapKeyVersion: device.keyVersion
    }
}

function snapshotFixture({ ownerDeviceId, revisionId = 'srev_phase21_live_snapshot_1' }) {
    return {
        product: 'wipesnap',
        kind: 'sanitized-preset-snapshot',
        schemaVersion: 1,
        snapshotId: 'snap_phase21_live',
        revisionId,
        baseRevisionId: null,
        sourceDeviceId: ownerDeviceId,
        timestamp: NOW,
        limits: { ...SANITIZED_PRESET_SNAPSHOT_LIMITS },
        selection: {
            defaultPresetId: 'preset_live',
            nextPresetId: 'preset_live',
            metadataOnly: true,
            selectionKind: 'metadata-only'
        },
        presets: [{
            id: 'preset_live',
            name: 'Live Coding',
            order: 0,
            enabled: true,
            itemRefs: [{
                id: 'pref_live_ai',
                itemId: 'item_live_ai',
                order: 0,
                enabled: true,
                metadataOnly: true
            }]
        }],
        availableItems: [{
            id: 'item_live_ai',
            type: 'browser-tab',
            label: 'AI Studio Live',
            status: 'available',
            source: 'browser',
            url: 'https://aistudio.google.com/'
        }]
    }
}

function patchFixture({
    authorDeviceId,
    baseSnapshotRevisionId,
    patchRevisionId = 'patchrev_phase21_live_patch_1'
}) {
    return {
        product: 'wipesnap',
        kind: 'safe-preset-patch',
        schemaVersion: 1,
        patchId: 'patch_phase21_live',
        patchRevisionId,
        baseSnapshotRevisionId,
        authorDeviceId,
        createdAt: NOW,
        updatedAt: NOW + 1,
        selection: {
            defaultPresetId: 'preset_live',
            nextPresetId: 'preset_live',
            metadataOnly: true,
            selectionKind: 'metadata-only'
        },
        presets: [],
        newBrowserItems: []
    }
}

function envelopeFor({ docType, payload, ownerUid, device, keys, sequence }) {
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
        salt: Buffer.alloc(32, sequence),
        iv: Buffer.alloc(12, sequence + 20),
        now: NOW + sequence
    })
}

function adminSignature({
    operation,
    ownerUid,
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

function ingestionSignature({ operation, ownerUid, device, keys, documentId, document, sequence, requestedAt = NOW }) {
    return {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        keyId: device.deviceId,
        value: signCloudSyncCanonicalMetadata({
            canonicalMetadata: createCloudSyncIngestionSignatureMetadata({
                operation,
                ownerUid,
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

function keyGrantRecord({ ownerUid, desktop, phone, sequence }) {
    const wrapped = Buffer.alloc(96, sequence)
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid,
        grantId: `grant_phase21_live_${sequence}`,
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

async function callCallable(name, data, idToken) {
    const response = await fetch(`http://${FUNCTIONS.host}:${FUNCTIONS.port}/${PROJECT_ID}/us-central1/${name}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            ...(idToken ? { Authorization: `Bearer ${idToken}` } : {})
        },
        body: JSON.stringify({ data })
    })
    const body = await response.json().catch(() => ({}))
    if (!response.ok || body.error) {
        const error = new Error(body.error?.message || `Callable ${name} failed.`)
        error.code = body.error?.status || response.status
        throw error
    }
    return body.result
}

async function assertCallableFails(name, data, idToken, pattern) {
    await assert.rejects(
        () => callCallable(name, data, idToken),
        error => {
            if (pattern) assert.match(error.message, pattern)
            return true
        }
    )
}

async function assertPermissionDenied(promise) {
    await assert.rejects(
        () => promise,
        error => {
            assert.equal(error.code, 'permission-denied')
            return true
        }
    )
}

function initializeLiveClient(name) {
    const app = initializeApp({ projectId: PROJECT_ID, apiKey: 'phase21-live-emulator' }, name)
    const auth = getAuth(app)
    const db = getFirestore(app)
    const functions = getFunctions(app, 'us-central1')
    connectAuthEmulator(auth, `http://${AUTH.host}:${AUTH.port}`, { disableWarnings: true })
    connectFirestoreEmulator(db, FIRESTORE.host, FIRESTORE.port)
    connectFunctionsEmulator(functions, FUNCTIONS.host, FUNCTIONS.port)
    return { app, auth, db }
}

function assertDeviceTokenClaims(tokenResult, device) {
    assert.equal(tokenResult.claims.wipesnapDeviceId, device.deviceId)
    assert.equal(tokenResult.claims.wipesnapDeviceRole, device.role)
    assert.equal(tokenResult.claims.wipesnapEnrollmentEpoch, device.enrollmentEpoch)
    assert.equal(tokenResult.claims.wipesnapKeyVersion, device.keyVersion)
}

async function signInDeviceSession(client, deviceSessionToken, device) {
    const credential = await signInWithCustomToken(client.auth, deviceSessionToken)
    assert.equal(credential.user.uid, device.ownerUid)
    const tokenResult = await credential.user.getIdTokenResult(true)
    assertDeviceTokenClaims(tokenResult, device)
    return tokenResult.token
}

async function refreshDeviceSessionToken(client, device) {
    assert.ok(client.auth.currentUser, 'device client must already be signed in')
    assert.equal(client.auth.currentUser.uid, device.ownerUid)
    const tokenResult = await client.auth.currentUser.getIdTokenResult(true)
    assertDeviceTokenClaims(tokenResult, device)
    return tokenResult.token
}

test('Live Firestore rules deny non-device, stale, revoked, cross-user, and direct writes', async () => {
    const rules = readFileSync('firestore.rules', 'utf8')
    const testEnv = await initializeTestEnvironment({
        projectId: `${PROJECT_ID}-rules-${Date.now()}`,
        firestore: {
            host: FIRESTORE.host,
            port: FIRESTORE.port,
            rules
        }
    })
    const keys = signingKeyPair()
    const desktop = deviceRecord({
        ownerUid: UID,
        deviceId: 'dev_live_rules_desktop',
        role: 'desktop',
        syncScopes: ['read', 'snapshot-upload'],
        keys,
        sequence: 1
    })
    const revoked = { ...desktop, deviceId: 'dev_live_rules_revoked', status: 'revoked', revokedAt: NOW }
    await testEnv.withSecurityRulesDisabled(async context => {
        const db = context.firestore()
        await setDoc(doc(db, `users/${UID}/devices/${desktop.deviceId}`), desktop)
        await setDoc(doc(db, `users/${UID}/devices/${revoked.deviceId}`), revoked)
        await setDoc(doc(db, `users/${UID}/snapshots/srev_live_rules`), {
            ownerUid: UID,
            keyVersion: desktop.keyVersion,
            ciphertext: Buffer.alloc(32, 0x11).toString('base64url')
        })
    })

    try {
        const activeDb = testEnv.authenticatedContext(UID, claimsFor(desktop)).firestore()
        await assertSucceeds(getDoc(doc(activeDb, `users/${UID}/snapshots/srev_live_rules`)))

        await assertFails(getDoc(doc(testEnv.unauthenticatedContext().firestore(), `users/${UID}/snapshots/srev_live_rules`)))
        await assertFails(getDoc(doc(testEnv.authenticatedContext(OTHER_UID, claimsFor(desktop)).firestore(), `users/${UID}/snapshots/srev_live_rules`)))
        await assertFails(getDoc(doc(testEnv.authenticatedContext(UID).firestore(), `users/${UID}/snapshots/srev_live_rules`)))
        await assertFails(getDoc(doc(testEnv.authenticatedContext(UID, {
            ...claimsFor(desktop),
            wipesnapDeviceId: 'dev_live_rules_missing'
        }).firestore(), `users/${UID}/snapshots/srev_live_rules`)))
        await assertFails(getDoc(doc(testEnv.authenticatedContext(UID, {
            ...claimsFor(desktop),
            wipesnapEnrollmentEpoch: desktop.enrollmentEpoch + 1
        }).firestore(), `users/${UID}/snapshots/srev_live_rules`)))
        await assertFails(getDoc(doc(testEnv.authenticatedContext(UID, {
            ...claimsFor(desktop),
            wipesnapKeyVersion: desktop.keyVersion + 1
        }).firestore(), `users/${UID}/snapshots/srev_live_rules`)))
        await assertFails(getDoc(doc(testEnv.authenticatedContext(UID, {
            ...claimsFor(desktop),
            wipesnapDeviceRole: 'phone'
        }).firestore(), `users/${UID}/snapshots/srev_live_rules`)))
        await assertFails(getDoc(doc(testEnv.authenticatedContext(UID, claimsFor(revoked)).firestore(), `users/${UID}/snapshots/srev_live_rules`)))

        for (const path of [
            `users/${UID}/devices/dev_client_write`,
            `users/${UID}/keyGrants/grant_client_write`,
            `users/${UID}/state/sync`,
            `users/${UID}/snapshots/srev_client_write`,
            `users/${UID}/patches/patchrev_client_write`
        ]) {
            await assertFails(setDoc(doc(activeDb, path), { ownerUid: UID, keyVersion: 1 }))
        }
    } finally {
        await testEnv.cleanup()
    }
})

test('Live Functions emulator enforces independent device sessions, ingestion, key grants, and revocation', async () => {
    const suffix = Date.now()
    const ownerClient = initializeLiveClient(`phase21-live-owner-${suffix}`)
    const desktopClient = initializeLiveClient(`phase21-live-desktop-${suffix}`)
    const phoneClient = initializeLiveClient(`phase21-live-phone-${suffix}`)

    try {
        await signInAnonymously(ownerClient.auth)
        const ownerUid = ownerClient.auth.currentUser.uid
        const ownerToken = await ownerClient.auth.currentUser.getIdToken()
        const desktopKeys = signingKeyPair()
        const phoneKeys = signingKeyPair()
        const desktop = deviceRecord({
            ownerUid,
            deviceId: 'dev_live_desktop',
            role: 'desktop',
            syncScopes: ['read', 'snapshot-upload'],
            keys: desktopKeys,
            sequence: 1
        })
        await assertPermissionDenied(getDoc(doc(ownerClient.db, `users/${ownerUid}/devices/${desktop.deviceId}`)))

        const bootstrap = await callCallable('bootstrapCloudSyncDesktopDevice', {
            documentId: desktop.deviceId,
            document: desktop,
            signature: adminSignature({
                operation: CLOUD_SYNC_ADMIN_OPERATIONS.bootstrapDesktopDevice,
                ownerUid,
                actorDevice: desktop,
                targetDeviceId: desktop.deviceId,
                keys: desktopKeys,
                documentId: desktop.deviceId,
                document: desktop,
                sequence: desktop.deviceSequence
            }),
            requestedAt: NOW
        }, ownerToken)
        assert.equal(bootstrap.status, 'accepted')
        assert.deepEqual(bootstrap.customClaims, claimsFor(desktop))
        assert.equal(typeof bootstrap.deviceSessionToken, 'string')

        let desktopToken = await signInDeviceSession(desktopClient, bootstrap.deviceSessionToken, desktop)
        assert.equal(desktopClient.auth.currentUser.uid, ownerUid)
        await assertPermissionDenied(
            setDoc(doc(desktopClient.db, `users/${ownerUid}/snapshots/srev_live_direct_write`), { ownerUid, keyVersion: 1 })
        )

        const snapshot = snapshotFixture({ ownerDeviceId: desktop.deviceId })
        const snapshotEnvelope = envelopeFor({
            docType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
            payload: snapshot,
            ownerUid,
            device: desktop,
            keys: desktopKeys,
            sequence: 2
        })
        const snapshotResult = await callCallable('ingestCloudSyncDocument', {
            operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
            documentId: snapshotEnvelope.revisionId,
            document: snapshotEnvelope
        }, desktopToken)
        assert.equal(snapshotResult.status, 'accepted')
        const snapshotDoc = (await getDoc(doc(desktopClient.db, `users/${ownerUid}/snapshots/${snapshotEnvelope.revisionId}`))).data()
        assertNoForbiddenCloudSyncBackendPlaintext(snapshotDoc)
        const serializedSnapshot = JSON.stringify(snapshotDoc)
        for (const forbidden of ['Live Coding', 'AI Studio Live', 'https://aistudio.google.com/', 'vault.json', 'capability', 'password']) {
            assert.equal(serializedSnapshot.includes(forbidden), false, `backend doc leaked ${forbidden}`)
        }

        const pendingPhone = deviceRecord({
            ownerUid,
            deviceId: 'dev_live_phone',
            role: 'phone',
            syncScopes: ['read', 'patch-upload'],
            keys: phoneKeys,
            sequence: 1,
            status: 'pending'
        })
        await callCallable('requestCloudSyncDeviceEnrollment', {
            requestId: pendingPhone.deviceId,
            documentId: pendingPhone.deviceId,
            document: pendingPhone,
            signature: adminSignature({
                operation: CLOUD_SYNC_ADMIN_OPERATIONS.requestDeviceEnrollment,
                ownerUid,
                actorDevice: pendingPhone,
                targetDeviceId: pendingPhone.deviceId,
                keys: phoneKeys,
                documentId: pendingPhone.deviceId,
                document: pendingPhone,
                sequence: pendingPhone.deviceSequence
            }),
            requestedAt: NOW
        }, ownerToken)

        const badApproval = clone(pendingPhone)
        badApproval.deviceId = 'dev_live_phone_bad'
        await assertCallableFails('approveCloudSyncDeviceEnrollment', {
            requestId: pendingPhone.deviceId,
            documentId: pendingPhone.deviceId,
            signature: adminSignature({
                operation: CLOUD_SYNC_ADMIN_OPERATIONS.approveDeviceEnrollment,
                ownerUid,
                actorDevice: desktop,
                targetDeviceId: pendingPhone.deviceId,
                keys: desktopKeys,
                documentId: pendingPhone.deviceId,
                document: badApproval,
                sequence: 3
            }),
            deviceSequence: 3,
            requestedAt: NOW
        }, desktopToken, /signature|not valid|document/)

        const approval = await callCallable('approveCloudSyncDeviceEnrollment', {
            requestId: pendingPhone.deviceId,
            documentId: pendingPhone.deviceId,
            signature: adminSignature({
                operation: CLOUD_SYNC_ADMIN_OPERATIONS.approveDeviceEnrollment,
                ownerUid,
                actorDevice: { ...desktop, deviceSequence: 2 },
                targetDeviceId: pendingPhone.deviceId,
                keys: desktopKeys,
                documentId: pendingPhone.deviceId,
                document: pendingPhone,
                sequence: 3
            }),
            deviceSequence: 3,
            requestedAt: NOW
        }, desktopToken)
        assert.equal(approval.status, 'approved')
        assert.deepEqual(approval.customClaims, claimsFor(approval.device))
        assert.equal(typeof approval.deviceSessionToken, 'string')

        const ownerTokenAfterApproval = await ownerClient.auth.currentUser.getIdTokenResult(true)
        assert.equal(ownerTokenAfterApproval.claims.wipesnapDeviceId, undefined)

        const activePhone = approval.device
        const phoneToken = await signInDeviceSession(phoneClient, approval.deviceSessionToken, activePhone)
        assert.equal(phoneClient.auth.currentUser.uid, ownerUid)
        desktopToken = await refreshDeviceSessionToken(desktopClient, desktop)
        await assert.ok((await getDoc(doc(desktopClient.db, `users/${ownerUid}/snapshots/${snapshotEnvelope.revisionId}`))).exists())
        await assert.ok((await getDoc(doc(phoneClient.db, `users/${ownerUid}/snapshots/${snapshotEnvelope.revisionId}`))).exists())

        const revoke = await callCallable('revokeCloudSyncDevice', {
            targetDeviceId: activePhone.deviceId,
            signature: adminSignature({
                operation: CLOUD_SYNC_ADMIN_OPERATIONS.revokeDevice,
                ownerUid,
                actorDevice: { ...desktop, deviceSequence: 3 },
                targetDeviceId: activePhone.deviceId,
                keys: desktopKeys,
                documentId: activePhone.deviceId,
                document: activePhone,
                sequence: 4
            }),
            deviceSequence: 4,
            requestedAt: NOW
        }, desktopToken)
        assert.equal(revoke.status, 'revoked')
        assert.equal(revoke.cachedClientDataMayRemain, true)

        await assertPermissionDenied(getDoc(doc(phoneClient.db, `users/${ownerUid}/snapshots/${snapshotEnvelope.revisionId}`)))
        const revokedPatch = patchFixture({
            authorDeviceId: activePhone.deviceId,
            baseSnapshotRevisionId: snapshotEnvelope.revisionId,
            patchRevisionId: 'patchrev_phase21_live_revoked_phone'
        })
        const revokedPatchEnvelope = envelopeFor({
            docType: CLOUD_SYNC_PATCH_DOC_TYPE,
            payload: revokedPatch,
            ownerUid,
            device: activePhone,
            keys: phoneKeys,
            sequence: 2
        })
        await assertCallableFails('ingestCloudSyncDocument', {
            operation: CLOUD_SYNC_INGESTION_OPERATIONS.patchEnvelope,
            documentId: revokedPatchEnvelope.revisionId,
            document: revokedPatchEnvelope
        }, phoneToken, /revoked|active/)

        desktopToken = await refreshDeviceSessionToken(desktopClient, desktop)
        await assert.ok((await getDoc(doc(desktopClient.db, `users/${ownerUid}/snapshots/${snapshotEnvelope.revisionId}`))).exists())
        const secondSnapshot = snapshotFixture({
            ownerDeviceId: desktop.deviceId,
            revisionId: 'srev_phase21_live_snapshot_after_revoke'
        })
        const secondSnapshotEnvelope = envelopeFor({
            docType: CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
            payload: secondSnapshot,
            ownerUid,
            device: desktop,
            keys: desktopKeys,
            sequence: 5
        })
        const secondSnapshotResult = await callCallable('ingestCloudSyncDocument', {
            operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
            documentId: secondSnapshotEnvelope.revisionId,
            document: secondSnapshotEnvelope
        }, desktopToken)
        assert.equal(secondSnapshotResult.status, 'accepted')

        const grant = keyGrantRecord({
            ownerUid,
            desktop: { ...desktop, deviceSequence: 5 },
            phone: activePhone,
            sequence: 6
        })
        await assertCallableFails('approveCloudSyncKeyGrant', {
            documentId: grant.grantId,
            document: grant,
            deviceSequence: 6,
            signature: ingestionSignature({
                operation: CLOUD_SYNC_INGESTION_OPERATIONS.keyGrant,
                ownerUid,
                device: { ...desktop, deviceSequence: 5 },
                keys: desktopKeys,
                documentId: grant.grantId,
                document: grant,
                sequence: 6
            }),
            requestedAt: NOW
        }, desktopToken, /recipient|active|revoked/)
    } finally {
        await Promise.allSettled([
            deleteApp(ownerClient.app),
            deleteApp(desktopClient.app),
            deleteApp(phoneClient.app)
        ])
    }
})
