import assert from 'assert/strict'
import { createCipheriv, createHash, generateKeyPairSync, hkdfSync } from 'crypto'
import { test } from 'node:test'
import {
    CLOUD_SYNC_DEVICE_RECORD_TYPE,
    CLOUD_SYNC_SCHEMA_VERSION,
    CLOUD_SYNC_SIGNING_ALGORITHM,
    canonicalCloudSyncAad,
    canonicalCloudSyncSignatureMetadata,
    serializeCanonicalCloudSyncMetadata,
    signCloudSyncCanonicalMetadata
} from '../src/main/cloudSyncEnvelope.js'
import {
    CLOUD_SYNC_INGESTION_OPERATIONS,
    ingestCloudSyncDocument
} from '../src/main/cloudSyncIngestion.js'
import { createDesktopCloudSyncStorage } from '../src/main/cloudSyncClientStorage.js'
import {
    uploadDesktopSanitizedSnapshot,
    uploadPhoneSafePresetPatch
} from '../src/main/cloudSyncClientTransport.js'
import {
    cloudSyncAutoImportStatusContainsForbiddenMaterial,
    createTrustedAutoImportOrchestrator,
    sanitizeTrustedAutoImportResult
} from '../src/main/cloudSyncAutoImport.js'
import {
    cloudSyncStatusViewContainsForbiddenMaterial,
    createCloudSyncStatusView
} from '../src/renderer/src/cloudSyncStatusUi.js'
import { SANITIZED_PRESET_SNAPSHOT_LIMITS } from '../src/main/sanitizedPresetSnapshot.js'
import { WORKSPACE_CAPABILITY_VAULT_KEY } from '../src/main/workspaceCapabilityMigration.js'
import { WORKSPACE_SAFE_PRESET_METADATA_KEY } from '../src/main/safePresetMetadata.js'

const UID = 'firebase_uid_phase27'
const NOW = 1770000000000
const SYNC_ROOT_KEY = Buffer.alloc(32, 0x27)

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

function wrapPublicKeyRecord(fill = 0x27) {
    const spki = Buffer.alloc(96, fill)
    return {
        alg: 'RSA-OAEP-256',
        spki: spki.toString('base64url'),
        fingerprint: sha256Base64Url(spki)
    }
}

function deviceRecord({ deviceId, role, syncScopes, keys, sequence = 1, status = 'active', revokedAt = null }) {
    return {
        product: 'wipesnap',
        recordType: CLOUD_SYNC_DEVICE_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid: UID,
        deviceId,
        role,
        status,
        platform: role === 'desktop' ? 'windows-electron' : 'web-pwa',
        syncScopes,
        signingPublicKey: publicSigningKeyRecord(keys.publicKey),
        wrapPublicKey: wrapPublicKeyRecord(role === 'desktop' ? 0x28 : 0x29),
        enrollmentEpoch: 1,
        keyVersion: 1,
        deviceSequence: sequence,
        createdAt: NOW,
        updatedAt: NOW,
        revokedAt,
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

function snapshotFixture({
    sourceDeviceId = 'dev_desktop_phase27',
    revisionId = 'srev_phase27_snapshot_1',
    baseRevisionId = null
} = {}) {
    return {
        product: 'wipesnap',
        kind: 'sanitized-preset-snapshot',
        schemaVersion: 1,
        snapshotId: 'snap_phase27',
        revisionId,
        baseRevisionId,
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
    authorDeviceId,
    baseSnapshotRevisionId,
    patchRevisionId = 'patchrev_phase27_patch_1',
    patchId = `patch_${patchRevisionId}`
}) {
    return {
        product: 'wipesnap',
        kind: 'safe-preset-patch',
        schemaVersion: 1,
        patchId,
        patchRevisionId,
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
                cap_phase27_sentinel: {
                    capabilityId: 'cap_phase27_sentinel',
                    displayName: 'Sentinel'
                }
            }
        }
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

function createMergeDeps(workspace, { unlocked = true } = {}) {
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
        commitVaultMeta: ({ vault, meta: nextMeta }) => {
            calls.commits += 1
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

function createCloudHarness({ authorRole = 'web-planner' } = {}) {
    const store = new InMemoryFirestore()
    const desktopKeys = signingKeyPair()
    const plannerKeys = signingKeyPair()
    const desktop = deviceRecord({
        deviceId: 'dev_desktop_phase27',
        role: 'desktop',
        syncScopes: ['read', 'snapshot-upload'],
        keys: desktopKeys
    })
    const planner = deviceRecord({
        deviceId: 'dev_planner_phase27',
        role: authorRole,
        syncScopes: ['read', 'patch-upload'],
        keys: plannerKeys
    })
    store.seed(`users/${UID}/devices/${desktop.deviceId}`, desktop)
    store.seed(`users/${UID}/devices/${planner.deviceId}`, planner)

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
    let plannerState = {
        ownerUid: UID,
        device: planner,
        syncRootKey: SYNC_ROOT_KEY,
        signingPrivateKey: plannerKeys.privateKey
    }
    const plannerStorage = {
        loadSessionState: () => Promise.resolve(plannerState),
        cacheEncryptedPatchEnvelope: () => Promise.resolve(),
        updateDeviceSequence: sequence => {
            plannerState = {
                ...plannerState,
                device: { ...plannerState.device, deviceSequence: sequence }
            }
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
                    : plannerState.device
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

    return {
        desktop,
        planner,
        plannerKeys,
        store,
        desktopStorage,
        plannerStorage,
        firestoreClient,
        functionsClient,
        setDesktopSyncRootKey(syncRootKey) {
            desktopState = { ...desktopState, syncRootKey }
        }
    }
}

async function seedDesktopSnapshot(harness, snapshot) {
    return uploadDesktopSanitizedSnapshot({
        storage: harness.desktopStorage,
        functionsClient: harness.functionsClient,
        snapshot,
        now: NOW
    })
}

async function seedPlannerPatch(harness, patch) {
    return uploadPhoneSafePresetPatch({
        storage: harness.plannerStorage,
        functionsClient: harness.functionsClient,
        patch,
        now: NOW + 1
    })
}

async function runAutoImport({ harness, snapshot, workspace = workspaceFixture(), unlocked = true } = {}) {
    const merge = createMergeDeps(workspace, { unlocked })
    let snapshotBuilds = 0
    const orchestrator = createTrustedAutoImportOrchestrator({
        resolveDeps: () => ({
            ...merge.deps,
            storage: harness.desktopStorage,
            firestoreClient: harness.firestoreClient,
            functionsClient: harness.functionsClient,
            buildCurrentSanitizedSnapshot: () => {
                snapshotBuilds += 1
                return snapshot
            },
            now: NOW + 10
        })
    })
    const result = await orchestrator.runAfterUnlock()
    return {
        result,
        merge,
        snapshotBuilds
    }
}

function rewriteEnvelopePayload(envelope, payload, { syncRootKey, signingPrivateKey }) {
    const salt = Buffer.from(envelope.encryption.salt, 'base64url')
    const iv = Buffer.from(envelope.encryption.iv, 'base64url')
    const info = Buffer.from(
        `wipesnap.cloud-sync.v1.${envelope.docType}.${envelope.revisionId}.keyVersion.${envelope.keyVersion}`,
        'utf8'
    )
    const contentKey = Buffer.from(hkdfSync('sha256', syncRootKey, salt, info, 32))
    const aad = Buffer.from(canonicalCloudSyncAad(envelope), 'utf8')
    const cipher = createCipheriv('aes-256-gcm', contentKey, iv, { authTagLength: 16 })
    cipher.setAAD(aad)
    const ciphertext = Buffer.concat([
        cipher.update(Buffer.from(serializeCanonicalCloudSyncMetadata(payload), 'utf8')),
        cipher.final()
    ])
    const next = {
        ...clone(envelope),
        encryption: {
            ...envelope.encryption,
            tag: cipher.getAuthTag().toString('base64url')
        },
        ciphertext: ciphertext.toString('base64url'),
        ciphertextHash: sha256Base64Url(ciphertext)
    }
    next.signature = {
        ...next.signature,
        value: signCloudSyncCanonicalMetadata({
            canonicalMetadata: canonicalCloudSyncSignatureMetadata(next),
            privateKey: signingPrivateKey
        })
    }
    return next
}

test('trusted auto-import runs after unlock, reuses trusted apply, and merges only safe metadata', async () => {
    const harness = createCloudHarness({ authorRole: 'web-planner' })
    const snapshot = snapshotFixture({ sourceDeviceId: harness.desktop.deviceId })
    await seedDesktopSnapshot(harness, snapshot)
    const upload = await seedPlannerPatch(harness, patchFixture({
        authorDeviceId: harness.planner.deviceId,
        baseSnapshotRevisionId: snapshot.revisionId
    }))

    const workspace = workspaceFixture()
    const originalCapabilityVault = clone(workspace[WORKSPACE_CAPABILITY_VAULT_KEY])
    const { result, merge, snapshotBuilds } = await runAutoImport({ harness, snapshot, workspace })

    assert.equal(result.operation, 'auto-import-trusted-patches')
    assert.equal(result.status, 'completed')
    assert.equal(result.summary.applied, 1)
    assert.equal(result.sideEffects.writesVault, true)
    assert.equal(result.sideEffects.launches, false)
    assert.equal(result.sideEffects.createsCapability, false)
    assert.equal(result.sideEffects.createsAccountSlots, false)
    assert.equal(result.sideEffects.createsBrowserProfiles, false)
    assert.equal(snapshotBuilds, 1)
    assert.equal(merge.calls.commits, 1)
    assert.equal(merge.calls.launchAttempts, 0)

    const stored = merge.storedWorkspace()
    assert.deepEqual(stored[WORKSPACE_CAPABILITY_VAULT_KEY], originalCapabilityVault)
    assert.equal(stored[WORKSPACE_SAFE_PRESET_METADATA_KEY].presets[0].name, 'Coding Phone')
    assert.equal(stored[WORKSPACE_SAFE_PRESET_METADATA_KEY].metadataOnly, true)

    const statusJson = JSON.stringify(result)
    assert.equal(statusJson.includes(upload.patchRevisionId), false)
    assert.equal(statusJson.includes(harness.planner.deviceId), false)
    assert.equal(statusJson.includes(snapshot.revisionId), false)
    assert.equal(statusJson.includes('Coding Phone'), false)
    assert.equal(statusJson.includes('cap_phase27_sentinel'), false)
    assert.equal(cloudSyncAutoImportStatusContainsForbiddenMaterial(result), false)

    const view = createCloudSyncStatusView(result)
    assert.equal(view.title, 'Trusted auto-import')
    assert.equal(view.counts.applied, 1)
    assert.equal(cloudSyncStatusViewContainsForbiddenMaterial(view), false)
})

test('trusted auto-import schedules once per unlock window and never runs concurrently', async () => {
    const scheduledCallbacks = []
    const releaseRuns = []
    let applyCalls = 0
    let activeRuns = 0
    let maxActiveRuns = 0
    const orchestrator = createTrustedAutoImportOrchestrator({
        resolveDeps: () => ({}),
        applyHandler: async () => {
            applyCalls += 1
            activeRuns += 1
            maxActiveRuns = Math.max(maxActiveRuns, activeRuns)
            await new Promise(resolve => releaseRuns.push(resolve))
            activeRuns -= 1
            return {
                success: true,
                status: 'completed',
                records: [],
                summary: { uploaded: 0, downloaded: 0, planned: 0, applied: 0, conflicts: 0, skipped: 0 },
                sideEffects: {}
            }
        },
        schedule: callback => {
            scheduledCallbacks.push(callback)
        }
    })

    const scheduled = orchestrator.scheduleAfterUnlock()
    assert.equal(scheduled.status, 'scheduled')
    assert.equal(scheduledCallbacks.length, 1)

    scheduledCallbacks[0]()
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(applyCalls, 1)

    scheduledCallbacks[0]()
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(applyCalls, 1)

    orchestrator.scheduleAfterUnlock()
    assert.equal(scheduledCallbacks.length, 2)
    scheduledCallbacks[1]()
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(applyCalls, 1)
    assert.equal(maxActiveRuns, 1)

    releaseRuns[0]()
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(scheduledCallbacks.length, 3)
    scheduledCallbacks[2]()
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(applyCalls, 2)
    assert.equal(maxActiveRuns, 1)

    releaseRuns[1]()
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(orchestrator.getStatus().status, 'completed')
})

test('trusted auto-import fails closed for locked sessions and unavailable runtime before side effects', async () => {
    let storageLoads = 0
    let cloudReads = 0
    let cloudWrites = 0
    let snapshotBuilds = 0
    const lockedOrchestrator = createTrustedAutoImportOrchestrator({
        resolveDeps: () => ({
            requireActiveSession: () => {
                throw new Error('Session is locked')
            },
            loadActiveVaultWorkspace: () => {
                snapshotBuilds += 1
                return workspaceFixture()
            },
            storage: {
                loadAfterUnlock: () => {
                    storageLoads += 1
                    return {}
                }
            },
            firestoreClient: {
                getDocument: () => {
                    cloudReads += 1
                    return null
                },
                listDocuments: () => {
                    cloudReads += 1
                    return []
                }
            },
            functionsClient: {
                callCloudSyncFunction: () => {
                    cloudWrites += 1
                    return {}
                }
            },
            buildCurrentSanitizedSnapshot: () => {
                snapshotBuilds += 1
                return snapshotFixture()
            },
            now: NOW
        })
    })
    const locked = await lockedOrchestrator.runAfterUnlock()
    assert.equal(locked.status, 'locked')
    assert.equal(storageLoads, 0)
    assert.equal(cloudReads, 0)
    assert.equal(cloudWrites, 0)
    assert.equal(snapshotBuilds, 0)
    assert.equal(locked.sideEffects.writesVault, false)
    assert.equal(cloudSyncAutoImportStatusContainsForbiddenMaterial(locked), false)

    const unavailableOrchestrator = createTrustedAutoImportOrchestrator({
        resolveDeps: () => ({
            requireActiveSession: () => {},
            loadActiveVaultWorkspace: () => {
                snapshotBuilds += 1
                return workspaceFixture()
            },
            buildCurrentSanitizedSnapshot: () => {
                snapshotBuilds += 1
                return snapshotFixture()
            },
            cloudSyncRuntime: {
                available: false,
                metadataOnly: true
            },
            now: NOW
        })
    })
    const unavailable = await unavailableOrchestrator.runAfterUnlock()
    assert.equal(unavailable.status, 'unavailable')
    assert.equal(cloudReads, 0)
    assert.equal(cloudWrites, 0)
    assert.equal(snapshotBuilds, 0)
    assert.equal(unavailable.sideEffects.writesVault, false)
    assert.equal(cloudSyncAutoImportStatusContainsForbiddenMaterial(unavailable), false)
})

test('trusted auto-import failure matrix records safe decisions without unsafe vault writes', async () => {
    const cases = [
        {
            name: 'stale',
            expectedReasons: ['stale-base'],
            mutateCurrentSnapshot: snapshot => ({
                ...snapshot,
                revisionId: 'srev_phase27_current_stale',
                baseRevisionId: snapshot.revisionId
            }),
            expectedSnapshotBuilds: 1
        },
        {
            name: 'backend-conflict',
            expectedReasons: ['stale-base'],
            beforePatchUpload: async (harness, snapshot) => {
                await seedDesktopSnapshot(harness, snapshotFixture({
                    sourceDeviceId: harness.desktop.deviceId,
                    revisionId: 'srev_phase27_conflicting_latest',
                    baseRevisionId: snapshot.revisionId
                }))
            },
            expectedSnapshotBuilds: 0
        },
        {
            name: 'revoked',
            expectedReasons: ['revoked-device'],
            afterPatchUpload: async (harness) => {
                harness.store.seed(`users/${UID}/devices/${harness.planner.deviceId}`, {
                    ...harness.store.get(`users/${UID}/devices/${harness.planner.deviceId}`),
                    status: 'revoked',
                    revokedAt: NOW + 20,
                    revokedByDeviceId: harness.desktop.deviceId
                })
            },
            expectedSnapshotBuilds: 0
        },
        {
            name: 'invalid-signature',
            expectedReasons: ['invalid-signature'],
            afterPatchUpload: async (harness, upload) => {
                const raw = harness.store.get(`users/${UID}/patches/${upload.patchRevisionId}`)
                raw.signature.value = tamperBase64Url(raw.signature.value)
                harness.store.seed(`users/${UID}/patches/${upload.patchRevisionId}`, raw)
            },
            expectedSnapshotBuilds: 0
        },
        {
            name: 'invalid-key',
            expectedReasons: ['invalid-key'],
            afterPatchUpload: async (harness) => {
                harness.setDesktopSyncRootKey(Buffer.alloc(32, 0x44))
            },
            expectedSnapshotBuilds: 0
        },
        {
            name: 'forbidden',
            expectedReasons: ['forbidden-material'],
            afterPatchUpload: async (harness, upload) => {
                const raw = harness.store.get(`users/${UID}/patches/${upload.patchRevisionId}`)
                const payload = patchFixture({
                    authorDeviceId: harness.planner.deviceId,
                    baseSnapshotRevisionId: raw.baseRevisionId,
                    patchRevisionId: upload.patchRevisionId,
                    patchId: raw.patchId
                })
                payload.sourcePath = 'C:\\Users\\Alice\\vault.json'
                harness.store.seed(`users/${UID}/patches/${upload.patchRevisionId}`, rewriteEnvelopePayload(raw, payload, {
                    syncRootKey: SYNC_ROOT_KEY,
                    signingPrivateKey: harness.plannerKeys.privateKey
                }))
            },
            expectedSnapshotBuilds: 0
        },
        {
            name: 'schema-invalid',
            expectedReasons: ['schema-rejected'],
            afterPatchUpload: async (harness, upload) => {
                const raw = harness.store.get(`users/${UID}/patches/${upload.patchRevisionId}`)
                const payload = patchFixture({
                    authorDeviceId: harness.planner.deviceId,
                    baseSnapshotRevisionId: raw.baseRevisionId,
                    patchRevisionId: upload.patchRevisionId,
                    patchId: raw.patchId
                })
                payload.schemaVersion = 999
                harness.store.seed(`users/${UID}/patches/${upload.patchRevisionId}`, rewriteEnvelopePayload(raw, payload, {
                    syncRootKey: SYNC_ROOT_KEY,
                    signingPrivateKey: harness.plannerKeys.privateKey
                }))
            },
            expectedSnapshotBuilds: 0
        }
    ]

    for (const testCase of cases) {
        const harness = createCloudHarness()
        const snapshot = snapshotFixture({
            sourceDeviceId: harness.desktop.deviceId,
            revisionId: `srev_phase27_${testCase.name.replace(/-/g, '_')}_base`
        })
        await seedDesktopSnapshot(harness, snapshot)
        if (testCase.beforePatchUpload) await testCase.beforePatchUpload(harness, snapshot)
        const upload = await seedPlannerPatch(harness, patchFixture({
            authorDeviceId: harness.planner.deviceId,
            baseSnapshotRevisionId: snapshot.revisionId,
            patchRevisionId: `patchrev_phase27_${testCase.name.replace(/-/g, '_')}`
        }))
        if (testCase.afterPatchUpload) await testCase.afterPatchUpload(harness, upload, snapshot)
        const currentSnapshot = testCase.mutateCurrentSnapshot
            ? testCase.mutateCurrentSnapshot(snapshot)
            : snapshot
        const { result, merge, snapshotBuilds } = await runAutoImport({
            harness,
            snapshot: currentSnapshot
        })

        assert.equal(merge.calls.commits, 0, testCase.name)
        assert.equal(result.sideEffects.writesVault, false, testCase.name)
        assert.equal(result.sideEffects.launches, false, testCase.name)
        assert.equal(result.sideEffects.createsCapability, false, testCase.name)
        assert.equal(result.sideEffects.createsAccountSlots, false, testCase.name)
        assert.equal(result.sideEffects.createsBrowserProfiles, false, testCase.name)
        assert.equal(snapshotBuilds, testCase.expectedSnapshotBuilds, testCase.name)
        assert.deepEqual(
            result.records.map(record => record.reason),
            testCase.expectedReasons,
            testCase.name
        )
        assert.equal(cloudSyncAutoImportStatusContainsForbiddenMaterial(result), false, testCase.name)

        const storedPatch = harness.store.get(`users/${UID}/patches/${upload.patchRevisionId}`)
        assert.equal(storedPatch.apply.reason, testCase.expectedReasons[0], testCase.name)
    }

    const duplicateHarness = createCloudHarness()
    const duplicateSnapshot = snapshotFixture({
        sourceDeviceId: duplicateHarness.desktop.deviceId,
        revisionId: 'srev_phase27_duplicate_base'
    })
    await seedDesktopSnapshot(duplicateHarness, duplicateSnapshot)
    const duplicatePatchId = 'patch_phase27_duplicate'
    await seedPlannerPatch(duplicateHarness, patchFixture({
        authorDeviceId: duplicateHarness.planner.deviceId,
        baseSnapshotRevisionId: duplicateSnapshot.revisionId,
        patchRevisionId: 'patchrev_phase27_duplicate_a',
        patchId: duplicatePatchId
    }))
    await seedPlannerPatch(duplicateHarness, patchFixture({
        authorDeviceId: duplicateHarness.planner.deviceId,
        baseSnapshotRevisionId: duplicateSnapshot.revisionId,
        patchRevisionId: 'patchrev_phase27_duplicate_b',
        patchId: duplicatePatchId
    }))
    const duplicateCurrent = {
        ...duplicateSnapshot,
        revisionId: 'srev_phase27_duplicate_current',
        baseRevisionId: duplicateSnapshot.revisionId
    }
    const duplicateResult = await runAutoImport({
        harness: duplicateHarness,
        snapshot: duplicateCurrent
    })
    assert.equal(duplicateResult.merge.calls.commits, 0)
    assert.deepEqual(
        duplicateResult.result.records.map(record => record.reason),
        ['stale-base', 'duplicate-patch']
    )
    assert.equal(duplicateResult.result.sideEffects.writesVault, false)
    assert.equal(cloudSyncAutoImportStatusContainsForbiddenMaterial(duplicateResult.result), false)
})

test('trusted auto-import sanitizer strips payloads, plans, envelopes, ids, paths, and credentials', () => {
    const sanitized = sanitizeTrustedAutoImportResult({
        success: true,
        operation: 'apply-trusted-patches',
        status: 'completed',
        summary: {
            uploaded: 9,
            downloaded: 8,
            planned: 7,
            applied: 6,
            conflicts: 5,
            skipped: 4
        },
        records: [{
            status: 'skipped',
            code: 'invalid-signature',
            reason: 'invalid-signature',
            patchRevisionId: 'patchrev_should_not_render',
            patchId: 'patch_should_not_render',
            authorDeviceId: 'dev_should_not_render',
            baseSnapshotRevisionId: 'srev_should_not_render',
            currentSnapshotRevisionId: 'srev_current_should_not_render',
            mergeStatus: 'C:\\Users\\Alice\\vault.json',
            cloudStatus: {
                status: 'applied',
                reason: 'bearer raw-token'
            },
            sideEffects: {
                writesVault: true,
                launches: true
            },
            ciphertext: 'encrypted-envelope',
            importPlan: { presetPlans: [{ next: { name: 'Leaky Phone Patch' } }] },
            vaultPath: 'C:\\Users\\Alice\\vault.json',
            capabilityId: `cap_${'a'.repeat(32)}`
        }],
        envelope: { ciphertext: 'encrypted-envelope' },
        patchPayload: { name: 'Leaky Phone Patch' },
        token: 'bearer raw-token'
    })

    const text = JSON.stringify(sanitized)
    assert.equal(sanitized.operation, 'auto-import-trusted-patches')
    assert.equal(sanitized.summary.applied, 6)
    assert.equal(sanitized.records[0].reason, 'invalid-signature')
    assert.equal(sanitized.records[0].mergeStatus, '')
    assert.equal(sanitized.records[0].cloudStatus.reason, '')
    assert.equal(text.includes('patchrev_should_not_render'), false)
    assert.equal(text.includes('dev_should_not_render'), false)
    assert.equal(text.includes('encrypted-envelope'), false)
    assert.equal(text.includes('Leaky Phone Patch'), false)
    assert.equal(text.includes('vault.json'), false)
    assert.equal(text.includes('cap_'), false)
    assert.equal(text.includes('raw-token'), false)
    assert.equal(cloudSyncAutoImportStatusContainsForbiddenMaterial(sanitized), false)
})
