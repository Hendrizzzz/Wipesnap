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
    applyTrustedCloudSafePresetPatchesAfterUnlock,
    downloadDesktopPatchPlans,
    downloadPhoneLatestSnapshot,
    exchangeDeviceSessionTokenMemoryOnly,
    uploadDesktopSanitizedSnapshot,
    uploadPhoneSafePresetPatch
} from '../src/main/cloudSyncClientTransport.js'
import { SANITIZED_PRESET_SNAPSHOT_LIMITS } from '../src/main/sanitizedPresetSnapshot.js'
import { WORKSPACE_CAPABILITY_VAULT_KEY } from '../src/main/workspaceCapabilityMigration.js'

const UID = 'firebase_uid_phase21_7'
const NOW = 1770000000000
const SYNC_ROOT_KEY = Buffer.alloc(32, 0x71)

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function sha256Base64Url(bytes) {
    return createHash('sha256').update(bytes).digest('base64url')
}

function tamperBase64Url(value) {
    return `${value[0] === 'A' ? 'B' : 'A'}${value.slice(1)}`
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

function workspaceFixture() {
    return {
        name: 'Coding',
        webTabs: [{
            id: 'raw_ai_studio',
            url: 'https://aistudio.google.com/',
            label: 'AI Studio',
            enabled: true
        }],
        desktopApps: [],
        [WORKSPACE_CAPABILITY_VAULT_KEY]: {
            version: 1,
            records: {
                cap_phase23_sentinel: {
                    capabilityId: 'cap_phase23_sentinel',
                    displayName: 'Sentinel'
                }
            }
        }
    }
}

function createMergeDeps(workspace, {
    unlocked = true,
    failCommit = false,
    onCommit = () => {}
} = {}) {
    let storedWorkspace = clone(workspace)
    let meta = { version: '1.0.0' }
    const calls = {
        commits: 0,
        launchAttempts: 0
    }
    const deps = {
        requireActiveSession: () => {
            if (!unlocked) throw new Error('Session is locked')
        },
        loadActiveVaultWorkspace: () => clone(storedWorkspace),
        loadVaultMeta: () => clone(meta),
        getDriveInfo: async () => ({ driveType: 2, serialNumber: 'USB1234', isRemovable: true }),
        getActiveMasterPassword: () => 'active-password',
        encryptVault: (payload, password, isHardwareBound) => ({
            payload: clone(payload),
            password,
            isHardwareBound
        }),
        commitVaultMeta: ({ vault, meta: nextMeta, operation }) => {
            calls.commits += 1
            onCommit({ vault: clone(vault), meta: clone(nextMeta), operation })
            if (failCommit) throw new Error('transaction failed')
            storedWorkspace = clone(vault.payload)
            meta = clone(nextMeta)
        },
        honeyToken: { marker: true }
    }
    return {
        calls,
        deps,
        storedWorkspace: () => clone(storedWorkspace)
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

test('trusted cloud patch apply validates after unlock, merges through vault transaction, and records backend-safe decisions', async () => {
    const store = new InMemoryFirestore()
    const desktopKeys = signingKeyPair()
    const phoneKeys = signingKeyPair()
    const desktop = deviceRecord({
        deviceId: 'dev_desktop_phase23_7',
        role: 'desktop',
        syncScopes: ['read', 'snapshot-upload'],
        keys: desktopKeys
    })
    const phone = deviceRecord({
        deviceId: 'dev_phone_phase23_7',
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
    const phoneStorage = {
        loadSessionState: () => Promise.resolve(phoneState),
        cacheEncryptedPatchEnvelope: () => Promise.resolve(),
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
            if (name === 'ingestCloudSyncDocument') {
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
            if (name === 'recordCloudSyncPatchApplyDecision') {
                return ingestCloudSyncDocument({
                    store,
                    auth: authFor(desktopState.device),
                    operation: CLOUD_SYNC_INGESTION_OPERATIONS.patchApplyDecision,
                    documentId: data.documentId,
                    document: data.document,
                    signature: data.signature,
                    deviceSequence: data.deviceSequence,
                    requestedAt: data.requestedAt,
                    now: NOW + 200
                })
            }
            throw new Error(`Unexpected function ${name}`)
        }
    }

    const snapshot = snapshotFixture({
        sourceDeviceId: desktop.deviceId,
        revisionId: 'srev_phase23_7_snapshot_1'
    })
    await uploadDesktopSanitizedSnapshot({
        storage: desktopStorage,
        functionsClient,
        snapshot,
        now: NOW
    })
    const validPatchUpload = await uploadPhoneSafePresetPatch({
        storage: phoneStorage,
        functionsClient,
        baseSnapshot: snapshot,
        patch: patchFixture({
            authorDeviceId: phone.deviceId,
            baseSnapshotRevisionId: snapshot.revisionId
        }),
        now: NOW + 1
    })
    const workspace = workspaceFixture()
    const originalCapabilityVault = clone(workspace[WORKSPACE_CAPABILITY_VAULT_KEY])
    const mergeHarness = createMergeDeps(workspace)
    let snapshotBuilds = 0

    const applied = await applyTrustedCloudSafePresetPatchesAfterUnlock({
        storage: desktopStorage,
        firestoreClient,
        functionsClient,
        deps: mergeHarness.deps,
        snapshotBuilder: () => {
            snapshotBuilds += 1
            return snapshot
        },
        patchRevisionIds: [validPatchUpload.patchRevisionId],
        now: NOW + 2
    })

    assert.equal(applied.status, 'completed')
    assert.equal(applied.summary.applied, 1)
    assert.equal(applied.records[0].status, 'applied')
    assert.equal(applied.records[0].cloudStatus.status, 'applied')
    assert.equal(applied.sideEffects.writesVault, true)
    assert.equal(applied.sideEffects.launches, false)
    assert.equal(snapshotBuilds, 1)
    assert.equal(mergeHarness.calls.commits, 1)
    assert.deepEqual(mergeHarness.storedWorkspace()[WORKSPACE_CAPABILITY_VAULT_KEY], originalCapabilityVault)
    const appliedBackendPatch = store.get(`users/${UID}/patches/${validPatchUpload.patchRevisionId}`)
    assert.equal(appliedBackendPatch.apply.status, 'applied')
    assert.equal(appliedBackendPatch.apply.reason, 'merged')
    assert.equal(appliedBackendPatch.ingestion.pending, false)
    assertNoForbiddenCloudSyncBackendPlaintext(appliedBackendPatch)
    assert.equal(JSON.stringify(appliedBackendPatch).includes('Coding Phone'), false)

    let listedWhileLocked = false
    const locked = await applyTrustedCloudSafePresetPatchesAfterUnlock({
        storage: {
            loadAfterUnlock: () => {
                throw new Error('Desktop cloud sync storage is available only after vault unlock.')
            }
        },
        firestoreClient: {
            listDocuments: () => {
                listedWhileLocked = true
                return []
            }
        },
        functionsClient,
        deps: mergeHarness.deps
    })
    assert.equal(locked.status, 'locked')
    assert.equal(listedWhileLocked, false)

    const stalePatch = patchFixture({
        authorDeviceId: phoneState.device.deviceId,
        baseSnapshotRevisionId: snapshot.revisionId
    })
    stalePatch.patchRevisionId = 'patchrev_phase23_7_stale'
    const staleUpload = await uploadPhoneSafePresetPatch({
        storage: phoneStorage,
        functionsClient,
        patch: stalePatch,
        now: NOW + 3
    })
    const staleHarness = createMergeDeps(workspace)
    const currentSnapshot = snapshotFixture({
        sourceDeviceId: desktop.deviceId,
        revisionId: 'srev_phase23_7_snapshot_2'
    })
    const stale = await applyTrustedCloudSafePresetPatchesAfterUnlock({
        storage: desktopStorage,
        firestoreClient,
        functionsClient,
        deps: staleHarness.deps,
        snapshotBuilder: () => currentSnapshot,
        patchRevisionIds: [staleUpload.patchRevisionId],
        now: NOW + 4
    })
    assert.equal(stale.summary.conflicts, 1)
    assert.equal(stale.records[0].reason, 'stale-base')
    assert.equal(staleHarness.calls.commits, 0)
    assert.equal(store.get(`users/${UID}/patches/${staleUpload.patchRevisionId}`).apply.reason, 'stale-base')

    const unknownSafeItemPatch = patchFixture({
        authorDeviceId: phoneState.device.deviceId,
        baseSnapshotRevisionId: snapshot.revisionId
    })
    unknownSafeItemPatch.patchRevisionId = 'patchrev_phase23_7_unknown_safe_item'
    unknownSafeItemPatch.presets[0].itemRefs[0].itemId = 'item_phase23_missing'
    const unknownSafeItemUpload = await uploadPhoneSafePresetPatch({
        storage: phoneStorage,
        functionsClient,
        patch: unknownSafeItemPatch,
        now: NOW + 5
    })
    const unknownSafeItemHarness = createMergeDeps(workspace)
    const unknownSafeItem = await applyTrustedCloudSafePresetPatchesAfterUnlock({
        storage: desktopStorage,
        firestoreClient,
        functionsClient,
        deps: unknownSafeItemHarness.deps,
        snapshotBuilder: () => snapshot,
        patchRevisionIds: [unknownSafeItemUpload.patchRevisionId],
        now: NOW + 6
    })
    assert.equal(unknownSafeItem.summary.conflicts, 1)
    assert.equal(unknownSafeItem.records[0].reason, 'unknown-safe-id')
    assert.equal(unknownSafeItemHarness.calls.commits, 0)
    assert.equal(store.get(`users/${UID}/patches/${unknownSafeItemUpload.patchRevisionId}`).apply.reason, 'unknown-safe-id')

    const failingPatch = patchFixture({
        authorDeviceId: phoneState.device.deviceId,
        baseSnapshotRevisionId: snapshot.revisionId
    })
    failingPatch.patchRevisionId = 'patchrev_phase23_7_failing_commit'
    const failingUpload = await uploadPhoneSafePresetPatch({
        storage: phoneStorage,
        functionsClient,
        patch: failingPatch,
        now: NOW + 7
    })
    const failingHarness = createMergeDeps(workspace, { failCommit: true })
    const failed = await applyTrustedCloudSafePresetPatchesAfterUnlock({
        storage: desktopStorage,
        firestoreClient,
        functionsClient,
        deps: failingHarness.deps,
        snapshotBuilder: () => snapshot,
        patchRevisionIds: [failingUpload.patchRevisionId],
        now: NOW + 8
    })
    assert.equal(failed.records[0].status, 'skipped')
    assert.equal(failed.records[0].cloudStatus.status, 'not-recorded')
    assert.equal(store.get(`users/${UID}/patches/${failingUpload.patchRevisionId}`).apply, undefined)
    assert.deepEqual(failingHarness.storedWorkspace(), workspace)

    const lockedSessionPatch = patchFixture({
        authorDeviceId: phoneState.device.deviceId,
        baseSnapshotRevisionId: snapshot.revisionId
    })
    lockedSessionPatch.patchRevisionId = 'patchrev_phase23_7_locked_session'
    const lockedSessionUpload = await uploadPhoneSafePresetPatch({
        storage: phoneStorage,
        functionsClient,
        patch: lockedSessionPatch,
        now: NOW + 9
    })
    const lockedSessionEnvelope = store.get(`users/${UID}/patches/${lockedSessionUpload.patchRevisionId}`)
    lockedSessionEnvelope.signature.value = tamperBase64Url(lockedSessionEnvelope.signature.value)
    store.seed(`users/${UID}/patches/${lockedSessionUpload.patchRevisionId}`, lockedSessionEnvelope)
    const lockedSessionHarness = createMergeDeps(workspace, { unlocked: false })
    let lockedSessionCloudReads = 0
    let lockedSessionDecisionWrites = 0
    const lockedSessionResult = await applyTrustedCloudSafePresetPatchesAfterUnlock({
        storage: desktopStorage,
        firestoreClient: {
            getDocument: path => {
                lockedSessionCloudReads += 1
                return firestoreClient.getDocument(path)
            },
            listDocuments: path => {
                lockedSessionCloudReads += 1
                return firestoreClient.listDocuments(path)
            }
        },
        functionsClient: {
            callCloudSyncFunction(name, data) {
                if (name === 'recordCloudSyncPatchApplyDecision') lockedSessionDecisionWrites += 1
                return functionsClient.callCloudSyncFunction(name, data)
            }
        },
        deps: lockedSessionHarness.deps,
        snapshotBuilder: () => {
            throw new Error('Locked session must not build a snapshot.')
        },
        patchRevisionIds: [lockedSessionUpload.patchRevisionId],
        now: NOW + 10
    })
    assert.equal(lockedSessionResult.status, 'locked')
    assert.equal(lockedSessionResult.records.length, 0)
    assert.deepEqual(lockedSessionResult.summary, { applied: 0, conflicts: 0, skipped: 0 })
    assert.equal(lockedSessionCloudReads, 0)
    assert.equal(lockedSessionDecisionWrites, 0)
    assert.equal(lockedSessionHarness.calls.commits, 0)
    assert.equal(store.get(`users/${UID}/patches/${lockedSessionUpload.patchRevisionId}`).apply, undefined)
    assert.deepEqual(lockedSessionHarness.storedWorkspace(), workspace)
})

test('trusted cloud patch apply skips invalid signature, invalid key, and revoked-device patches without vault writes', async () => {
    const store = new InMemoryFirestore()
    const desktopKeys = signingKeyPair()
    const phoneKeys = signingKeyPair()
    const desktop = deviceRecord({
        deviceId: 'dev_desktop_phase23_invalid',
        role: 'desktop',
        syncScopes: ['read', 'snapshot-upload'],
        keys: desktopKeys
    })
    const phone = deviceRecord({
        deviceId: 'dev_phone_phase23_invalid',
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
    const phoneStorage = {
        loadSessionState: () => Promise.resolve(phoneState),
        cacheEncryptedPatchEnvelope: () => Promise.resolve(),
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
            if (name === 'ingestCloudSyncDocument') {
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
            if (name === 'recordCloudSyncPatchApplyDecision') {
                return ingestCloudSyncDocument({
                    store,
                    auth: authFor(desktopState.device),
                    operation: CLOUD_SYNC_INGESTION_OPERATIONS.patchApplyDecision,
                    documentId: data.documentId,
                    document: data.document,
                    signature: data.signature,
                    deviceSequence: data.deviceSequence,
                    requestedAt: data.requestedAt,
                    now: NOW + 200
                })
            }
            throw new Error(`Unexpected function ${name}`)
        }
    }
    const snapshot = snapshotFixture({
        sourceDeviceId: desktop.deviceId,
        revisionId: 'srev_phase23_invalid_snapshot_1'
    })
    await uploadDesktopSanitizedSnapshot({
        storage: desktopStorage,
        functionsClient,
        snapshot,
        now: NOW
    })

    const invalidSignaturePatch = patchFixture({
        authorDeviceId: phone.deviceId,
        baseSnapshotRevisionId: snapshot.revisionId
    })
    invalidSignaturePatch.patchRevisionId = 'patchrev_phase23_invalid_signature'
    const invalidSignatureUpload = await uploadPhoneSafePresetPatch({
        storage: phoneStorage,
        functionsClient,
        patch: invalidSignaturePatch,
        now: NOW + 1
    })
    const tampered = store.get(`users/${UID}/patches/${invalidSignatureUpload.patchRevisionId}`)
    tampered.signature.value = tamperBase64Url(tampered.signature.value)
    store.seed(`users/${UID}/patches/${invalidSignatureUpload.patchRevisionId}`, tampered)

    const invalidKeyPatch = patchFixture({
        authorDeviceId: phone.deviceId,
        baseSnapshotRevisionId: snapshot.revisionId
    })
    invalidKeyPatch.patchRevisionId = 'patchrev_phase23_invalid_key'
    const invalidKeyUpload = await uploadPhoneSafePresetPatch({
        storage: phoneStorage,
        functionsClient,
        patch: invalidKeyPatch,
        now: NOW + 2
    })

    const revokedPatch = patchFixture({
        authorDeviceId: phone.deviceId,
        baseSnapshotRevisionId: snapshot.revisionId
    })
    revokedPatch.patchRevisionId = 'patchrev_phase23_revoked_device'
    const revokedUpload = await uploadPhoneSafePresetPatch({
        storage: phoneStorage,
        functionsClient,
        patch: revokedPatch,
        now: NOW + 3
    })

    const harness = createMergeDeps(workspaceFixture())
    let snapshotBuilds = 0
    desktopState = {
        ...desktopState,
        syncRootKey: Buffer.alloc(32, 0x44)
    }
    const invalidResult = await applyTrustedCloudSafePresetPatchesAfterUnlock({
        storage: desktopStorage,
        firestoreClient,
        functionsClient,
        deps: harness.deps,
        snapshotBuilder: () => {
            snapshotBuilds += 1
            return snapshot
        },
        patchRevisionIds: [
            invalidSignatureUpload.patchRevisionId,
            invalidKeyUpload.patchRevisionId
        ],
        now: NOW + 5
    })
    store.seed(`users/${UID}/devices/${phone.deviceId}`, {
        ...store.get(`users/${UID}/devices/${phone.deviceId}`),
        status: 'revoked',
        revokedAt: NOW + 6,
        revokedByDeviceId: desktop.deviceId
    })
    const revokedResult = await applyTrustedCloudSafePresetPatchesAfterUnlock({
        storage: desktopStorage,
        firestoreClient,
        functionsClient,
        deps: harness.deps,
        snapshotBuilder: () => {
            snapshotBuilds += 1
            return snapshot
        },
        patchRevisionIds: [revokedUpload.patchRevisionId],
        now: NOW + 7
    })
    const records = [...invalidResult.records, ...revokedResult.records]

    assert.equal(records.filter(record => record.status === 'skipped').length, 3)
    assert.equal(harness.calls.commits, 0)
    assert.equal(snapshotBuilds, 0)
    assert.deepEqual(
        records.map(record => record.reason).sort(),
        ['invalid-key', 'invalid-signature', 'revoked-device']
    )
    for (const upload of [invalidSignatureUpload, invalidKeyUpload, revokedUpload]) {
        const stored = store.get(`users/${UID}/patches/${upload.patchRevisionId}`)
        assert.equal(stored.apply.status, 'skipped')
        assertNoForbiddenCloudSyncBackendPlaintext(stored)
    }
})
