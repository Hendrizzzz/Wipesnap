import assert from 'assert/strict'
import { createHash, generateKeyPairSync } from 'crypto'
import { test } from 'node:test'
import {
    CLOUD_SYNC_DEVICE_RECORD_TYPE,
    CLOUD_SYNC_PATCH_DOC_TYPE,
    CLOUD_SYNC_SCHEMA_VERSION,
    CLOUD_SYNC_SIGNING_ALGORITHM,
    CLOUD_SYNC_SNAPSHOT_DOC_TYPE,
    assertNoForbiddenCloudSyncBackendPlaintext
} from '../src/main/cloudSyncEnvelope.js'
import {
    CLOUD_SYNC_INGESTION_OPERATIONS,
    ingestCloudSyncDocument
} from '../src/main/cloudSyncIngestion.js'
import {
    assertNoForbiddenCloudSyncClientPlaintext,
    createDesktopCloudSyncStorage,
    createPhoneCloudSyncStorage,
    redactCloudSyncClientLogValue
} from '../src/main/cloudSyncClientStorage.js'
import {
    downloadDesktopPatchPlans,
    downloadPhoneLatestSnapshot,
    exchangeDeviceSessionTokenMemoryOnly,
    uploadDesktopSanitizedSnapshot,
    uploadPhoneSafePresetPatch
} from '../src/main/cloudSyncClientTransport.js'
import { SANITIZED_PRESET_SNAPSHOT_LIMITS } from '../src/main/sanitizedPresetSnapshot.js'

const UID = 'firebase_uid_phase21_7'
const NOW = 1770000000000
const SYNC_ROOT_KEY = Buffer.alloc(32, 0x71)

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

function wrapPublicKeyRecord(fill = 0x77) {
    const spki = Buffer.alloc(96, fill)
    return {
        alg: 'RSA-OAEP-256',
        spki: spki.toString('base64url'),
        fingerprint: sha256Base64Url(spki)
    }
}

function deviceRecord({ deviceId, role, syncScopes, keys, sequence = 1 }) {
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_DEVICE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid: UID,
        deviceId,
        role,
        status: 'active',
        platform: role === 'desktop' ? 'windows-electron' : 'web-pwa',
        syncScopes,
        signingPublicKey: publicSigningKeyRecord(keys.publicKey),
        wrapPublicKey: wrapPublicKeyRecord(role === 'desktop' ? 0x72 : 0x73),
        enrollmentEpoch: 1,
        keyVersion: 1,
        deviceSequence: sequence,
        createdAt: NOW,
        updatedAt: NOW,
        revokedAt: null,
        revokedByDeviceId: null
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

function snapshotFixture({ sourceDeviceId = 'dev_desktop_phase21_7', revisionId = 'srev_phase21_7_snapshot_1' } = {}) {
    return {
        product: 'wipesnap',
        kind: 'sanitized-preset-snapshot',
        schemaVersion: 1,
        snapshotId: 'snap_phase21_7',
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

function patchFixture({ authorDeviceId, baseSnapshotRevisionId }) {
    return {
        product: 'wipesnap',
        kind: 'safe-preset-patch',
        schemaVersion: 1,
        patchId: 'patch_phase21_7',
        patchRevisionId: 'patchrev_phase21_7_phone_1',
        baseSnapshotRevisionId,
        authorDeviceId,
        createdAt: NOW + 1,
        updatedAt: NOW + 2,
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

class InMemoryFirestore {
    constructor() {
        this.docs = new Map()
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

    list(collectionPath) {
        const prefix = `${this.normalize(collectionPath)}/`
        return Array.from(this.docs.entries())
            .filter(([key]) => key.startsWith(prefix) && !key.slice(prefix.length).includes('/'))
            .map(([, value]) => clone(value))
    }

    runTransaction(callback) {
        const writes = []
        const pending = new Map()
        const read = path => {
            const key = this.normalize(path)
            if (pending.has(key)) return clone(pending.get(key))
            return clone(this.docs.get(key) || null)
        }
        const write = (type, path, data) => {
            const key = this.normalize(path)
            if (type === 'create' && (this.docs.has(key) || pending.has(key))) {
                throw new Error(`Document already exists: ${key}`)
            }
            const value = clone(data)
            pending.set(key, value)
            writes.push({ key, value })
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
                const current = read(path)
                if (!current) throw new Error(`Document does not exist: ${this.normalize(path)}`)
                write('update', path, { ...current, ...data })
                return Promise.resolve()
            }
        })).then(result => {
            for (const { key, value } of writes) this.docs.set(key, clone(value))
            return result
        })
    }
}

class InMemoryIndexedDb {
    constructor() {
        this.values = new Map()
    }

    key(storeName, key) {
        return `${storeName}:${key}`
    }

    put(storeName, key, value) {
        this.values.set(this.key(storeName, key), value)
        return Promise.resolve()
    }

    get(storeName, key) {
        return Promise.resolve(this.values.get(this.key(storeName, key)) || null)
    }

    serialized() {
        return JSON.stringify(Array.from(this.values.entries()))
    }
}

function nonExtractableCryptoProvider() {
    return {
        supportsNonExtractableIndexedDbKeys: true,
        generateSigningKeyPair() {
            return Promise.resolve({
                privateKey: { type: 'private', extractable: false, opaque: 'signing-handle' },
                publicKey: { type: 'public', extractable: true, opaque: 'signing-public' }
            })
        },
        generateWrappingKeyPair() {
            return Promise.resolve({
                privateKey: { type: 'private', extractable: false, opaque: 'wrapping-handle' },
                publicKey: { type: 'public', extractable: true, opaque: 'wrapping-public' }
            })
        }
    }
}

test('desktop and phone client storage fail closed for locked vaults, weak keys, and raw token persistence', async () => {
    let unlocked = false
    let loadCalled = false
    const desktopKeys = signingKeyPair()
    const desktop = deviceRecord({
        deviceId: 'dev_desktop_phase21_7',
        role: 'desktop',
        syncScopes: ['read', 'snapshot-upload'],
        keys: desktopKeys
    })
    const desktopStorage = createDesktopCloudSyncStorage({
        vaultAdapter: {
            isUnlocked: () => unlocked,
            loadCloudSyncState: () => {
                loadCalled = true
                return {
                    ownerUid: UID,
                    device: desktop,
                    syncRootKey: SYNC_ROOT_KEY,
                    signingPrivateKey: desktopKeys.privateKey
                }
            },
            saveCloudSyncState: () => {}
        }
    })
    await assert.rejects(() => desktopStorage.loadAfterUnlock(), /unlock/)
    assert.equal(loadCalled, false)
    unlocked = true
    const loadedDesktop = await desktopStorage.loadAfterUnlock()
    assert.equal(loadedDesktop.device.deviceId, desktop.deviceId)
    assert.deepEqual(desktopStorage.debugSnapshot(loadedDesktop).device.deviceId, desktop.deviceId)
    await assert.rejects(
        () => desktopStorage.saveAfterUnlock({ ...loadedDesktop, deviceSessionToken: 'raw-token' }),
        /tokens cannot be stored/
    )

    const indexedDb = new InMemoryIndexedDb()
    const phoneStorage = createPhoneCloudSyncStorage({
        indexedDbAdapter: indexedDb,
        cryptoProvider: nonExtractableCryptoProvider()
    })
    const enrollment = await phoneStorage.enrollDeviceKeys({ deviceId: 'dev_phone_phase21_7', now: NOW })
    assert.equal(enrollment.keyPersistence, 'indexeddb-non-extractable')
    assert.ok(indexedDb.values.has('cloudSyncCryptoKeys:signing:dev_phone_phase21_7'))
    assert.equal(indexedDb.serialized().includes('raw-device-session-token'), false)

    const weakStorage = createPhoneCloudSyncStorage({
        indexedDbAdapter: new InMemoryIndexedDb(),
        cryptoProvider: {
            supportsNonExtractableIndexedDbKeys: false,
            generateSigningKeyPair: () => Promise.resolve({ privateKey: { extractable: true }, publicKey: {} }),
            generateWrappingKeyPair: () => Promise.resolve({ privateKey: { extractable: true }, publicKey: {} })
        }
    })
    await assert.rejects(() => weakStorage.enrollDeviceKeys({ deviceId: 'dev_phone_weak' }), /non-extractable/)

    assert.throws(
        () => assertNoForbiddenCloudSyncClientPlaintext({ deviceSessionToken: 'raw-device-session-token' }),
        /cannot be persisted|forbidden/
    )
    assert.throws(
        () => assertNoForbiddenCloudSyncClientPlaintext({ memo: 'C:\\Users\\Alice\\vault.json' }),
        /forbidden/
    )
})

test('raw custom token exchange is memory-only and log-redacted', async () => {
    const rawToken = 'device-session-token-with-sensitive-bearer-material'
    const logs = []
    const authClient = {
        received: '',
        signInWithCustomToken(value) {
            this.received = value
            return Promise.resolve({ user: { uid: UID } })
        }
    }
    const result = await exchangeDeviceSessionTokenMemoryOnly({
        deviceSessionToken: rawToken,
        authClient,
        logger: { info: value => logs.push(value) }
    })
    assert.equal(result.status, 'signed-in')
    assert.equal(result.rawTokenRetained, false)
    assert.equal(authClient.received, rawToken)
    assert.equal(JSON.stringify(logs).includes(rawToken), false)
    assert.equal(JSON.stringify(redactCloudSyncClientLogValue({ deviceSessionToken: rawToken })).includes(rawToken), false)
})

test('client transport uploads encrypted snapshots, phone patches offline, and desktop downloads validate-only plans', async () => {
    const store = new InMemoryFirestore()
    const desktopKeys = signingKeyPair()
    const phoneKeys = signingKeyPair()
    const desktop = deviceRecord({
        deviceId: 'dev_desktop_phase21_7',
        role: 'desktop',
        syncScopes: ['read', 'snapshot-upload'],
        keys: desktopKeys
    })
    const phone = deviceRecord({
        deviceId: 'dev_phone_phase21_7',
        role: 'phone',
        syncScopes: ['read', 'patch-upload'],
        keys: phoneKeys
    })
    store.seed(`users/${UID}/devices/${desktop.deviceId}`, desktop)
    store.seed(`users/${UID}/devices/${phone.deviceId}`, phone)

    let desktopState = {
        ownerUid: UID,
        device: desktop,
        syncRootKey: SYNC_ROOT_KEY,
        signingPrivateKey: desktopKeys.privateKey
    }
    const desktopStorage = createDesktopCloudSyncStorage({
        vaultAdapter: {
            isUnlocked: () => true,
            loadCloudSyncState: () => desktopState,
            saveCloudSyncState: state => {
                desktopState = state
            },
            updateCloudSyncDeviceSequence: sequence => {
                desktopState = {
                    ...desktopState,
                    device: { ...desktopState.device, deviceSequence: sequence }
                }
            }
        }
    })
    let phoneState = {
        ownerUid: UID,
        device: phone,
        syncRootKey: SYNC_ROOT_KEY,
        signingPrivateKey: phoneKeys.privateKey
    }
    const cached = { snapshots: [], patches: [] }
    const phoneStorage = {
        loadSessionState: () => Promise.resolve(phoneState),
        cacheEncryptedSnapshotEnvelope: envelope => {
            cached.snapshots.push(envelope)
            return Promise.resolve()
        },
        cacheEncryptedPatchEnvelope: envelope => {
            cached.patches.push(envelope)
            return Promise.resolve()
        },
        updateDeviceSequence: sequence => {
            phoneState = { ...phoneState, device: { ...phoneState.device, deviceSequence: sequence } }
            return Promise.resolve()
        }
    }
    const firestoreClient = {
        getDocument: path => Promise.resolve(store.get(path)),
        listDocuments: path => Promise.resolve(store.list(path))
    }
    const functionsClient = {
        callCloudSyncFunction(name, data) {
            assert.equal(name, 'ingestCloudSyncDocument')
            const authDevice = data.operation === CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope
                ? desktopState.device
                : phoneState.device
            return ingestCloudSyncDocument({
                store,
                auth: authFor(authDevice),
                operation: data.operation,
                documentId: data.documentId,
                document: data.document,
                requestedAt: NOW,
                now: NOW + 100
            })
        }
    }

    let snapshotBuilderCalledAfterUnlock = false
    const uploadedSnapshot = await uploadDesktopSanitizedSnapshot({
        storage: desktopStorage,
        functionsClient,
        snapshotBuilder: () => {
            snapshotBuilderCalledAfterUnlock = true
            return snapshotFixture({ sourceDeviceId: desktop.deviceId })
        },
        now: NOW
    })
    assert.equal(snapshotBuilderCalledAfterUnlock, true)
    assert.equal(uploadedSnapshot.status, 'accepted')
    const backendSnapshot = store.get(`users/${UID}/snapshots/${uploadedSnapshot.revisionId}`)
    assertNoForbiddenCloudSyncBackendPlaintext(backendSnapshot)
    assert.equal(JSON.stringify(backendSnapshot).includes('Coding'), false)
    assert.equal(JSON.stringify(backendSnapshot).includes('AI Studio'), false)

    const downloaded = await downloadPhoneLatestSnapshot({ storage: phoneStorage, firestoreClient })
    assert.equal(downloaded.snapshot.revisionId, uploadedSnapshot.revisionId)
    assert.equal(downloaded.snapshot.presets[0].name, 'Coding')
    assert.equal(cached.snapshots.length, 1)

    const uploadedPatch = await uploadPhoneSafePresetPatch({
        storage: phoneStorage,
        functionsClient,
        baseSnapshot: downloaded.snapshot,
        patchBuilder: ({ baseSnapshot, device }) => patchFixture({
            authorDeviceId: device.deviceId,
            baseSnapshotRevisionId: baseSnapshot.revisionId
        }),
        now: NOW + 1
    })
    assert.equal(uploadedPatch.status, 'accepted')
    assert.equal(cached.patches.length, 1)
    const backendPatch = store.get(`users/${UID}/patches/${uploadedPatch.patchRevisionId}`)
    assertNoForbiddenCloudSyncBackendPlaintext(backendPatch)
    assert.equal(JSON.stringify(backendPatch).includes('Coding Phone'), false)

    const plans = await downloadDesktopPatchPlans({
        storage: desktopStorage,
        firestoreClient,
        sanitizedSnapshot: downloaded.snapshot
    })
    assert.equal(plans.status, 'planned')
    assert.equal(plans.plans.length, 1)
    assert.equal(plans.plans[0].importPlan.sideEffects.writesVault, false)
    assert.equal(plans.plans[0].importPlan.sideEffects.launches, false)
    assert.equal(plans.sideEffects.mergesPatch, false)
    assert.equal(plans.plans[0].importPlan.presetPlans[0].next.name, 'Coding Phone')
})
