import assert from 'assert/strict'
import { createHash, generateKeyPairSync } from 'crypto'
import { test } from 'node:test'
import {
    CLOUD_SYNC_DEVICE_RECORD_TYPE,
    CLOUD_SYNC_SCHEMA_VERSION,
    CLOUD_SYNC_SIGNING_ALGORITHM
} from '../src/main/cloudSyncEnvelope.js'
import {
    CLOUD_SYNC_INGESTION_OPERATIONS,
    ingestCloudSyncDocument
} from '../src/main/cloudSyncIngestion.js'
import { createDesktopCloudSyncStorage } from '../src/main/cloudSyncClientStorage.js'
import { uploadPhoneSafePresetPatch } from '../src/main/cloudSyncClientTransport.js'
import {
    applyTrustedPatchesInvocationHandlerCore,
    downloadEncryptedPatchSummariesInvocationHandlerCore,
    planSafePresetPatchesInvocationHandlerCore,
    uploadSanitizedSnapshotInvocationHandlerCore
} from '../src/main/cloudSyncInvocation.js'
import { createCloudSyncRuntimeAdapter } from '../src/main/cloudSyncRuntime.js'
import { validateCloudSyncInvocationInput } from '../src/main/ipcValidation.js'
import { validateCloudSyncInvocationPayload } from '../src/preload/cloudSyncPreloadValidation.js'
import {
    cloudSyncStatusViewContainsForbiddenMaterial,
    createCloudSyncStatusView
} from '../src/renderer/src/cloudSyncStatusUi.js'
import { SANITIZED_PRESET_SNAPSHOT_LIMITS } from '../src/main/sanitizedPresetSnapshot.js'
import { WORKSPACE_CAPABILITY_VAULT_KEY } from '../src/main/workspaceCapabilityMigration.js'

const UID = 'firebase_uid_phase24'
const NOW = 1770000000000
const SYNC_ROOT_KEY = Buffer.alloc(32, 0x24)

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

function wrapPublicKeyRecord(fill = 0x24) {
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
        wrapPublicKey: wrapPublicKeyRecord(role === 'desktop' ? 0x25 : 0x26),
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
    sourceDeviceId = 'dev_desktop_phase24',
    revisionId = 'srev_phase24_snapshot_1'
} = {}) {
    return {
        product: 'wipesnap',
        kind: 'sanitized-preset-snapshot',
        schemaVersion: 1,
        snapshotId: 'snap_phase24',
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
    authorDeviceId,
    baseSnapshotRevisionId,
    patchRevisionId = 'patchrev_phase24_phone_1'
}) {
    return {
        product: 'wipesnap',
        kind: 'safe-preset-patch',
        schemaVersion: 1,
        patchId: `patch_${patchRevisionId}`,
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
                cap_phase24_sentinel: {
                    capabilityId: 'cap_phase24_sentinel',
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

function createCloudHarness() {
    const store = new InMemoryFirestore()
    const desktopKeys = signingKeyPair()
    const phoneKeys = signingKeyPair()
    const desktop = deviceRecord({
        deviceId: 'dev_desktop_phase24',
        role: 'desktop',
        syncScopes: ['read', 'snapshot-upload'],
        keys: desktopKeys
    })
    const phone = deviceRecord({
        deviceId: 'dev_phone_phase24',
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

    return {
        desktop,
        phone,
        store,
        desktopStorage,
        phoneStorage,
        firestoreClient,
        functionsClient,
        get phoneState() {
            return phoneState
        }
    }
}

test('phase 25 explicit unlocked runtime invocation uploads, downloads, plans, and applies only summary data', async () => {
    const harness = createCloudHarness()
    const snapshot = snapshotFixture({ sourceDeviceId: harness.desktop.deviceId })
    const workspace = workspaceFixture()
    const originalCapabilityVault = clone(workspace[WORKSPACE_CAPABILITY_VAULT_KEY])
    const merge = createMergeDeps(workspace)
    let snapshotBuilds = 0
    const deps = createCloudSyncRuntimeAdapter({
        runtime: {
            storage: harness.desktopStorage,
            firestoreClient: harness.firestoreClient,
            functionsClient: harness.functionsClient,
            buildCurrentSanitizedSnapshot: () => {
                snapshotBuilds += 1
                return snapshot
            }
        },
        baseDeps: {
            ...merge.deps,
            now: NOW
        }
    })
    assert.equal(deps.cloudSyncRuntime.available, true)

    const upload = await uploadSanitizedSnapshotInvocationHandlerCore({ input: {}, deps })
    assert.equal(upload.success, true)
    assert.equal(upload.status, 'accepted')
    assert.equal(upload.summary.uploaded, 1)
    assert.equal('envelope' in upload, false)
    assert.equal(upload.sideEffects.writesVault, false)
    assert.equal(upload.sideEffects.writesCloudSnapshot, true)

    const patchUpload = await uploadPhoneSafePresetPatch({
        storage: harness.phoneStorage,
        functionsClient: harness.functionsClient,
        patch: patchFixture({
            authorDeviceId: harness.phone.deviceId,
            baseSnapshotRevisionId: snapshot.revisionId
        }),
        now: NOW + 1
    })

    const download = await downloadEncryptedPatchSummariesInvocationHandlerCore({
        input: { patchRevisionIds: [patchUpload.patchRevisionId] },
        deps
    })
    assert.equal(download.success, true)
    assert.equal(download.summary.downloaded, 1)
    assert.equal(download.records[0].encrypted, true)
    assert.equal(download.records[0].authorTrust.status, 'trusted')
    assert.equal('ciphertext' in download.records[0], false)
    assert.equal(JSON.stringify(download).includes('Coding Phone'), false)

    const plan = await planSafePresetPatchesInvocationHandlerCore({
        input: { patchRevisionIds: [patchUpload.patchRevisionId] },
        deps
    })
    assert.equal(plan.success, true)
    assert.equal(plan.summary.planned, 1)
    assert.equal(plan.records[0].planned.presets, 1)
    assert.equal('importPlan' in plan.records[0], false)
    assert.equal(plan.sideEffects.writesVault, false)
    assert.equal(plan.sideEffects.launches, false)
    assert.equal(JSON.stringify(plan).includes('Coding Phone'), false)

    const apply = await applyTrustedPatchesInvocationHandlerCore({
        input: { patchRevisionIds: [patchUpload.patchRevisionId] },
        deps
    })
    assert.equal(apply.success, true)
    assert.equal(apply.summary.applied, 1)
    assert.equal(apply.sideEffects.writesVault, true)
    assert.equal(apply.sideEffects.launches, false)
    assert.equal(merge.calls.commits, 1)
    assert.equal(merge.calls.launchAttempts, 0)
    assert.deepEqual(merge.storedWorkspace()[WORKSPACE_CAPABILITY_VAULT_KEY], originalCapabilityVault)
    assert.equal(JSON.stringify(apply).includes('Coding Phone'), false)
    assert.equal(snapshotBuilds, 3)
})

test('phase 25 runtime adapter builds a sanitized snapshot from unlocked storage when configured', async () => {
    const harness = createCloudHarness()
    const merge = createMergeDeps({
        name: 'Runtime Snapshot',
        webTabs: [{
            id: 'runtime_tab',
            url: 'https://aistudio.google.com/',
            label: 'AI Studio',
            enabled: true
        }],
        desktopApps: []
    })
    const deps = createCloudSyncRuntimeAdapter({
        runtime: {
            storage: harness.desktopStorage,
            firestoreClient: harness.firestoreClient,
            functionsClient: harness.functionsClient
        },
        baseDeps: {
            ...merge.deps,
            now: NOW
        }
    })

    assert.equal(deps.cloudSyncRuntime.available, true)
    const upload = await uploadSanitizedSnapshotInvocationHandlerCore({ input: {}, deps })
    assert.equal(upload.success, true)
    assert.equal(upload.status, 'accepted')
    assert.equal(upload.summary.uploaded, 1)
    assert.equal(upload.sideEffects.writesVault, false)
    assert.equal(upload.sideEffects.writesCloudSnapshot, true)
    assert.equal(JSON.stringify(upload).includes('AI Studio'), false)
    assert.equal(JSON.stringify(upload).includes('syncRootKey'), false)
})

test('phase 25 runtime adapter absence fails closed after the vault-session gate', async () => {
    let activeSessionChecks = 0
    const deps = createCloudSyncRuntimeAdapter({
        runtime: null,
        baseDeps: {
            requireActiveSession: () => {
                activeSessionChecks += 1
            },
            loadActiveVaultWorkspace: () => {
                throw new Error('Cloud sync must not load workspace without a configured runtime.')
            },
            now: NOW
        }
    })
    assert.equal(deps.cloudSyncRuntime.available, false)

    const upload = await uploadSanitizedSnapshotInvocationHandlerCore({ input: {}, deps })
    assert.equal(upload.success, false)
    assert.equal(upload.status, 'unavailable')
    assert.equal(upload.error, 'Cloud sync is not configured on this desktop.')
    assert.equal(upload.sideEffects.writesCloudSnapshot, false)
    assert.equal(activeSessionChecks, 1)

    let lockedChecks = 0
    const lockedDeps = createCloudSyncRuntimeAdapter({
        runtime: null,
        baseDeps: {
            requireActiveSession: () => {
                lockedChecks += 1
                throw new Error('Session is locked')
            }
        }
    })
    const locked = await downloadEncryptedPatchSummariesInvocationHandlerCore({ input: {}, deps: lockedDeps })
    assert.equal(locked.success, false)
    assert.equal(locked.status, 'locked')
    assert.equal(locked.error, 'Cloud sync requires an active unlocked vault session.')
    assert.equal(lockedChecks, 1)
})

test('phase 25 renderer cloud sync status view whitelists summary fields only', () => {
    const view = createCloudSyncStatusView({
        success: false,
        operation: 'apply-trusted-patches',
        status: 'rejected',
        error: 'C:\\Users\\Alice\\vault.json bearer raw-token',
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
            reason: 'invalid-signature',
            ciphertext: 'encrypted-envelope',
            importPlan: { presetPlans: [{ next: { name: 'Leaky Phone Patch' } }] },
            vaultPath: 'C:\\Users\\Alice\\vault.json',
            capabilityId: `cap_${'a'.repeat(32)}`
        }],
        envelope: { ciphertext: 'encrypted-envelope' },
        patchPayload: { name: 'Leaky Phone Patch' }
    })

    assert.equal(view.title, 'Trusted apply')
    assert.equal(view.message, 'Cloud sync did not complete.')
    assert.equal(view.counts.applied, 6)
    assert.equal(view.records[0].statusLabel, 'Skipped')
    assert.equal(view.records[0].reason, 'invalid-signature')
    assert.equal(cloudSyncStatusViewContainsForbiddenMaterial(view), false)
    assert.equal(JSON.stringify(view).includes('ciphertext'), false)
    assert.equal(JSON.stringify(view).includes('Leaky Phone Patch'), false)
    assert.equal(JSON.stringify(view).includes('vault.json'), false)
    assert.equal(JSON.stringify(view).includes('cap_'), false)
})

test('locked cloud sync invocations stop before cloud storage, reads, writes, or planning', async () => {
    let storageLoads = 0
    let cloudReads = 0
    let cloudWrites = 0
    let snapshotBuilds = 0
    const lockedDeps = {
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
    }

    for (const handler of [
        uploadSanitizedSnapshotInvocationHandlerCore,
        downloadEncryptedPatchSummariesInvocationHandlerCore,
        planSafePresetPatchesInvocationHandlerCore,
        applyTrustedPatchesInvocationHandlerCore
    ]) {
        const result = await handler({
            input: { patchRevisionIds: ['patchrev_phase24_locked'] },
            deps: lockedDeps
        })
        assert.equal(result.success, false)
        assert.equal(result.status, 'locked')
    }
    assert.equal(storageLoads, 0)
    assert.equal(cloudReads, 0)
    assert.equal(cloudWrites, 0)
    assert.equal(snapshotBuilds, 0)
})

test('cloud sync IPC and preload validation reject forbidden renderer material', () => {
    assert.deepEqual(
        validateCloudSyncInvocationInput({ patchRevisionIds: [' patchrev_phase24_valid '] }),
        { patchRevisionIds: ['patchrev_phase24_valid'] }
    )
    assert.deepEqual(
        validateCloudSyncInvocationPayload({ patchRevisionIds: [' patchrev_phase24_valid '] }),
        { patchRevisionIds: ['patchrev_phase24_valid'] }
    )
    assert.throws(
        () => validateCloudSyncInvocationInput({ patchRevisionIds: [`cap_${'a'.repeat(32)}`] }),
        /safe patch revision|forbidden/
    )
    assert.throws(
        () => validateCloudSyncInvocationPayload({ vaultPath: 'C:\\Users\\Alice\\vault.json' }),
        /not accepted|forbidden/
    )
    assert.throws(
        () => validateCloudSyncInvocationPayload({
            patchRevisionIds: ['patchrev_phase24_valid'],
            deviceSessionToken: 'deviceSessionToken:raw-secret'
        }),
        /not accepted/
    )
})

test('stale and revoked trusted apply invocations do not write vault metadata', async () => {
    const invalidHarness = createCloudHarness()
    const invalidSnapshot = snapshotFixture({ sourceDeviceId: invalidHarness.desktop.deviceId })
    await uploadSanitizedSnapshotInvocationHandlerCore({
        deps: {
            ...createMergeDeps(workspaceFixture()).deps,
            storage: invalidHarness.desktopStorage,
            firestoreClient: invalidHarness.firestoreClient,
            functionsClient: invalidHarness.functionsClient,
            buildCurrentSanitizedSnapshot: () => invalidSnapshot,
            now: NOW
        }
    })
    const invalidPatch = await uploadPhoneSafePresetPatch({
        storage: invalidHarness.phoneStorage,
        functionsClient: invalidHarness.functionsClient,
        patch: patchFixture({
            authorDeviceId: invalidHarness.phone.deviceId,
            baseSnapshotRevisionId: invalidSnapshot.revisionId,
            patchRevisionId: 'patchrev_phase24_invalid_signature'
        }),
        now: NOW + 1
    })
    const tamperedPatch = invalidHarness.store.get(`users/${UID}/patches/${invalidPatch.patchRevisionId}`)
    tamperedPatch.signature.value = tamperBase64Url(tamperedPatch.signature.value)
    invalidHarness.store.seed(`users/${UID}/patches/${invalidPatch.patchRevisionId}`, tamperedPatch)
    const invalidMerge = createMergeDeps(workspaceFixture())
    const invalid = await applyTrustedPatchesInvocationHandlerCore({
        input: { patchRevisionIds: [invalidPatch.patchRevisionId] },
        deps: {
            ...invalidMerge.deps,
            storage: invalidHarness.desktopStorage,
            firestoreClient: invalidHarness.firestoreClient,
            functionsClient: invalidHarness.functionsClient,
            buildCurrentSanitizedSnapshot: () => invalidSnapshot,
            now: NOW + 2
        }
    })
    assert.equal(invalid.summary.skipped, 1)
    assert.equal(invalid.records[0].reason, 'invalid-signature')
    assert.equal(invalidMerge.calls.commits, 0)
    assert.equal(invalidHarness.store.get(`users/${UID}/patches/${invalidPatch.patchRevisionId}`).apply.reason, 'invalid-signature')

    const staleHarness = createCloudHarness()
    const baseSnapshot = snapshotFixture({
        sourceDeviceId: staleHarness.desktop.deviceId,
        revisionId: 'srev_phase24_base'
    })
    await uploadSanitizedSnapshotInvocationHandlerCore({
        deps: {
            ...createMergeDeps(workspaceFixture()).deps,
            storage: staleHarness.desktopStorage,
            firestoreClient: staleHarness.firestoreClient,
            functionsClient: staleHarness.functionsClient,
            buildCurrentSanitizedSnapshot: () => baseSnapshot,
            now: NOW
        }
    })
    const stalePatch = await uploadPhoneSafePresetPatch({
        storage: staleHarness.phoneStorage,
        functionsClient: staleHarness.functionsClient,
        patch: patchFixture({
            authorDeviceId: staleHarness.phone.deviceId,
            baseSnapshotRevisionId: baseSnapshot.revisionId,
            patchRevisionId: 'patchrev_phase24_stale'
        }),
        now: NOW + 1
    })
    const staleMerge = createMergeDeps(workspaceFixture())
    const staleResult = await applyTrustedPatchesInvocationHandlerCore({
        input: { patchRevisionIds: [stalePatch.patchRevisionId] },
        deps: {
            ...staleMerge.deps,
            storage: staleHarness.desktopStorage,
            firestoreClient: staleHarness.firestoreClient,
            functionsClient: staleHarness.functionsClient,
            buildCurrentSanitizedSnapshot: () => snapshotFixture({
                sourceDeviceId: staleHarness.desktop.deviceId,
                revisionId: 'srev_phase24_current'
            }),
            now: NOW + 2
        }
    })
    assert.equal(staleResult.summary.conflicts, 1)
    assert.equal(staleResult.records[0].reason, 'stale-base')
    assert.equal(staleMerge.calls.commits, 0)
    assert.equal(staleHarness.store.get(`users/${UID}/patches/${stalePatch.patchRevisionId}`).apply.reason, 'stale-base')

    const revokedHarness = createCloudHarness()
    const revokedSnapshot = snapshotFixture({ sourceDeviceId: revokedHarness.desktop.deviceId })
    await uploadSanitizedSnapshotInvocationHandlerCore({
        deps: {
            ...createMergeDeps(workspaceFixture()).deps,
            storage: revokedHarness.desktopStorage,
            firestoreClient: revokedHarness.firestoreClient,
            functionsClient: revokedHarness.functionsClient,
            buildCurrentSanitizedSnapshot: () => revokedSnapshot,
            now: NOW
        }
    })
    const revokedPatch = await uploadPhoneSafePresetPatch({
        storage: revokedHarness.phoneStorage,
        functionsClient: revokedHarness.functionsClient,
        patch: patchFixture({
            authorDeviceId: revokedHarness.phone.deviceId,
            baseSnapshotRevisionId: revokedSnapshot.revisionId,
            patchRevisionId: 'patchrev_phase24_revoked'
        }),
        now: NOW + 3
    })
    revokedHarness.store.seed(`users/${UID}/devices/${revokedHarness.phone.deviceId}`, {
        ...revokedHarness.store.get(`users/${UID}/devices/${revokedHarness.phone.deviceId}`),
        status: 'revoked',
        revokedAt: NOW + 4,
        revokedByDeviceId: revokedHarness.desktop.deviceId
    })
    const revokedMerge = createMergeDeps(workspaceFixture())
    const revoked = await applyTrustedPatchesInvocationHandlerCore({
        input: { patchRevisionIds: [revokedPatch.patchRevisionId] },
        deps: {
            ...revokedMerge.deps,
            storage: revokedHarness.desktopStorage,
            firestoreClient: revokedHarness.firestoreClient,
            functionsClient: revokedHarness.functionsClient,
            buildCurrentSanitizedSnapshot: () => revokedSnapshot,
            now: NOW + 5
        }
    })
    assert.equal(revoked.summary.skipped, 1)
    assert.equal(revoked.records[0].reason, 'revoked-device')
    assert.equal(revokedMerge.calls.commits, 0)
    assert.equal(revokedHarness.store.get(`users/${UID}/patches/${revokedPatch.patchRevisionId}`).apply.reason, 'revoked-device')
})
