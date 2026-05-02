import assert from 'assert/strict'
import { createHash, generateKeyPairSync, webcrypto } from 'crypto'
import { test } from 'node:test'
import workerModule from '../cloudflare/src/wipesnapCloudSyncWorker.js'
import {
    createCloudflareDesktopTransportAdapters,
    validateDesktopCloudflareSyncConfig
} from '../src/main/cloudSyncCloudflareTransport.js'
import {
    approveCloudSyncDeviceEnrollmentAndGrantAfterUnlockForProvider,
    bootstrapCloudSyncDesktopDeviceAfterUnlockForProvider,
    listPendingCloudSyncDeviceEnrollmentsAfterUnlockForProvider
} from '../src/main/cloudSyncProviderEnrollment.js'
import { createCloudSyncRuntimeAdapter } from '../src/main/cloudSyncRuntime.js'
import {
    CLOUD_SYNC_DEVICE_RECORD_TYPE,
    CLOUD_SYNC_SCHEMA_VERSION,
    CLOUD_SYNC_SIGNING_ALGORITHM
} from '../src/main/cloudSyncEnvelope.js'
import { CLOUD_SYNC_INGESTION_OPERATIONS } from '../src/main/cloudSyncIngestion.js'
import {
    applyTrustedCloudSafePresetPatchesAfterUnlock,
    downloadDesktopEncryptedPatchSummaries,
    downloadDesktopPatchPlans,
    uploadDesktopSanitizedSnapshot
} from '../src/main/cloudSyncClientTransport.js'
import { WORKSPACE_CAPABILITY_VAULT_KEY } from '../src/main/workspaceCapabilityMigration.js'
import { SANITIZED_PRESET_SNAPSHOT_LIMITS } from '../src/main/sanitizedPresetSnapshot.js'
import {
    createIndexedDbAdapter,
    createPhonePlannerCloudStorage
} from '../src/phone-planner/phonePlannerCloudStorage.js'
import { createPhonePlannerCloudflareRestApp } from '../src/phone-planner/phonePlannerCloudflareRest.js'
import {
    claimCloudflareHostedPlannerDeviceSession,
    requestCloudflareHostedPlannerEnrollment
} from '../src/phone-planner/phonePlannerCloudflareWorkflow.js'
import {
    downloadLatestHostedPlannerSnapshot,
    uploadHostedPlannerSafePatch
} from '../src/phone-planner/phonePlannerCloudWorkflow.js'
import {
    createPhonePlannerState,
    importSnapshotIntoPlannerState,
    updateSnapshotPresetFields
} from '../src/phone-planner/phonePlannerCore.js'
import { generatePhonePlannerCloudKeyPair, publicKeyRecord } from '../src/phone-planner/phonePlannerCloudCrypto.js'
import { loadPhonePlannerCloudProviderConfig } from '../src/phone-planner/phonePlannerCloudProvider.js'
import { createMigratedLocalD1Database } from './helpers/cloudflareLocalD1Harness.js'

const OWNER = 'cf_owner_phase31_4_provider'
const BASE_URL = 'http://127.0.0.1:8788'
const SYNC_ROOT_KEY = Buffer.alloc(32, 0x46)

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function sha256Base64Url(bytes) {
    return createHash('sha256').update(bytes).digest('base64url')
}

function config() {
    return {
        environment: 'staging',
        provider: 'cloudflare',
        apiBaseUrl: BASE_URL,
        useLocalDev: true
    }
}

function workerFetch(db) {
    return async (url, options) => workerModule.fetch(new Request(url, options), { WIPESNAP_D1: db })
}

function publicSigningKeyRecord(publicKey) {
    const spki = publicKey.export({ type: 'spki', format: 'der' })
    return {
        alg: CLOUD_SYNC_SIGNING_ALGORITHM,
        spki: spki.toString('base64url'),
        fingerprint: sha256Base64Url(spki)
    }
}

async function createDesktopDevice() {
    const signing = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
    const wrapKeys = await generatePhonePlannerCloudKeyPair(webcrypto)
    const now = Date.now()
    return {
        signing,
        device: {
            product: 'wipesnap',
            recordType: CLOUD_SYNC_DEVICE_RECORD_TYPE,
            schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
            ownerUid: OWNER,
            deviceId: 'dev_desktop_phase31_4_provider',
            role: 'desktop',
            status: 'active',
            platform: 'windows-electron',
            syncScopes: ['read', 'snapshot-upload', 'patch-upload'],
            signingPublicKey: publicSigningKeyRecord(signing.publicKey),
            wrapPublicKey: await publicKeyRecord(wrapKeys.wrapping.publicKey, 'RSA-OAEP-256', webcrypto),
            enrollmentEpoch: 1,
            keyVersion: 1,
            deviceSequence: 1,
            createdAt: now,
            updatedAt: now,
            revokedAt: null,
            revokedByDeviceId: null
        }
    }
}

function createDesktopStorage(initialDevice, signingPrivateKey) {
    let desktopState = {
        ownerUid: OWNER,
        device: initialDevice,
        signingPrivateKey,
        syncRootKey: Buffer.from(SYNC_ROOT_KEY)
    }
    return {
        async loadAfterUnlock() {
            return desktopState
        },
        async updateDeviceSequence(sequence) {
            desktopState = {
                ...desktopState,
                device: { ...desktopState.device, deviceSequence: sequence, updatedAt: Date.now() }
            }
            return { status: 'updated', deviceSequence: sequence, metadataOnly: true }
        },
        state() {
            return desktopState
        }
    }
}

class MemoryIndexedDbAdapter {
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
        return JSON.stringify(Array.from(this.values.entries()), (_key, value) => {
            if (value && typeof value === 'object' && value.constructor?.name === 'CryptoKey') {
                return { cryptoKey: true, extractable: value.extractable, type: value.type }
            }
            return value
        })
    }
}

function snapshotFixture(sourceDeviceId) {
    return {
        product: 'wipesnap',
        kind: 'sanitized-preset-snapshot',
        schemaVersion: 1,
        snapshotId: 'snap_phase31_4_provider',
        revisionId: 'srev_phase31_4_provider_snapshot_1',
        baseRevisionId: null,
        sourceDeviceId,
        timestamp: Date.now(),
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
            records: {},
            metadataOnly: true
        }
    }
}

function createMergeDeps(workspace) {
    let storedWorkspace = clone(workspace)
    let meta = { version: '1.0.0' }
    const calls = { commits: 0 }
    return {
        calls,
        deps: {
            requireActiveSession: () => {},
            loadActiveVaultWorkspace: () => clone(storedWorkspace),
            loadVaultMeta: () => clone(meta),
            getDriveInfo: async () => ({ driveType: 2, serialNumber: 'USB1234', isRemovable: true }),
            getActiveMasterPassword: () => 'active-password',
            encryptVault: (payload, password, isHardwareBound) => ({ payload: clone(payload), password, isHardwareBound }),
            commitVaultMeta: ({ vault, meta: nextMeta }) => {
                calls.commits += 1
                storedWorkspace = clone(vault.payload)
                meta = clone(nextMeta)
            },
            honeyToken: { marker: true }
        },
        storedWorkspace: () => clone(storedWorkspace)
    }
}

test('Cloudflare provider selection is disabled by default and explicit staging config fails closed when invalid', async () => {
    const runtime = createCloudSyncRuntimeAdapter({ runtime: {} })
    assert.equal(runtime.cloudSyncRuntime.provider, 'disabled')
    assert.equal(runtime.cloudSyncRuntime.available, false)

    assert.equal(validateDesktopCloudflareSyncConfig(config()).provider, 'cloudflare-d1-spike')
    assert.throws(() => validateDesktopCloudflareSyncConfig({
        ...config(),
        apiToken: 'secret'
    }), /cannot be present|forbidden/)

    const invalid = createCloudSyncRuntimeAdapter({
        runtime: {
            storage: { loadAfterUnlock: async () => ({}) },
            cloudSyncProviderConfig: { ...config(), apiBaseUrl: 'https://api.wipesnap.com' }
        }
    })
    assert.equal(invalid.cloudSyncRuntime.provider, 'cloudflare-d1-spike')
    assert.equal(invalid.cloudSyncRuntime.available, false)
    assert.equal(invalid.cloudSyncRuntime.cloudflare.status, 'unavailable')

    const firebaseSelected = await loadPhonePlannerCloudProviderConfig({
        fetchImpl: async url => {
            if (String(url).includes('cloudflare-sync-config')) return { ok: false, status: 404 }
            return {
                ok: true,
                json: async () => ({
                    environment: 'staging',
                    projectId: 'wipesnap-stage31',
                    apiKey: 'AIzaSyStage31SafeWebKey',
                    appId: '1:123456789012:web:stage31',
                    authDomain: 'wipesnap-stage31.firebaseapp.com',
                    functionsRegion: 'us-central1',
                    allowAnonymousAuth: false
                })
            }
        }
    })
    assert.equal(firebaseSelected.provider, 'firebase-staging')

    const cloudflareSelected = await loadPhonePlannerCloudProviderConfig({
        fetchImpl: async url => {
            assert.match(String(url), /cloudflare-sync-config/)
            return { ok: true, json: async () => config() }
        }
    })
    assert.equal(cloudflareSelected.provider, 'cloudflare-d1-spike')
})

test('disabled Cloudflare provider adapters run hosted phone snapshot and patch flow through actual Worker D1', async () => {
    const db = createMigratedLocalD1Database()
    try {
        const fetchImpl = workerFetch(db)
        const desktop = await createDesktopDevice()
        const desktopStorage = createDesktopStorage(desktop.device, desktop.signing.privateKey)
        const desktopTransport = createCloudflareDesktopTransportAdapters({
            config: config(),
            storage: desktopStorage,
            fetchImpl,
            cryptoApi: webcrypto
        })
        const desktopDeps = createCloudSyncRuntimeAdapter({
            runtime: {
                storage: desktopStorage,
                cloudSyncProviderConfig: config(),
                cloudflareFetch: fetchImpl,
                cryptoApi: webcrypto
            },
            baseDeps: {}
        })
        assert.equal(desktopDeps.cloudSyncRuntime.provider, 'cloudflare-d1-spike')
        assert.equal(!!desktopDeps.cloudflareClient, true, JSON.stringify(desktopDeps.cloudSyncRuntime))
        const bootstrapped = await bootstrapCloudSyncDesktopDeviceAfterUnlockForProvider({ deps: desktopDeps })
        assert.equal(bootstrapped.success, true, JSON.stringify(bootstrapped))
        assert.equal(bootstrapped.sideEffects.launches, false)

        const phoneStorageAdapter = new MemoryIndexedDbAdapter()
        const phoneStorage = createPhonePlannerCloudStorage({
            indexedDbAdapter: phoneStorageAdapter,
            cryptoApi: webcrypto,
            now: () => Date.now()
        })
        const phoneApp = createPhonePlannerCloudflareRestApp({
            config: config(),
            storage: phoneStorage,
            fetchImpl,
            cryptoApi: webcrypto
        })
        await phoneApp.authClient.activateOwnerUid(OWNER)

        const enrollment = await requestCloudflareHostedPlannerEnrollment({
            authClient: phoneApp.authClient,
            cloudflareClient: phoneApp.cloudflareClient,
            storage: phoneStorage,
            cryptoApi: webcrypto
        })
        assert.equal(enrollment.status, 'pending')

        const pending = await listPendingCloudSyncDeviceEnrollmentsAfterUnlockForProvider({ deps: desktopDeps })
        assert.equal(pending.success, true, JSON.stringify(pending))
        assert.equal(pending.records.length, 1)
        assert.equal(pending.records[0].requestId, enrollment.requestId)
        assert.equal('wrappedKeyCiphertext' in pending.records[0], false)

        const approved = await approveCloudSyncDeviceEnrollmentAndGrantAfterUnlockForProvider({
            input: { requestId: enrollment.requestId },
            deps: desktopDeps
        })
        assert.equal(approved.success, true, JSON.stringify(approved))
        assert.equal(approved.status, 'approved')

        const originalEnrollmentRecord = await phoneStorageAdapter.get('cloudSyncEnrollmentRequests', enrollment.deviceId)
        await phoneStorageAdapter.put('cloudSyncEnrollmentRequests', enrollment.deviceId, {
            ...originalEnrollmentRecord,
            pairingChallenge: 'phase31.4 intentionally wrong pairing challenge'
        })
        await assert.rejects(() => claimCloudflareHostedPlannerDeviceSession({
            authClient: phoneApp.authClient,
            cloudflareClient: phoneApp.cloudflareClient,
            storage: phoneStorage,
            deviceId: enrollment.deviceId,
            cryptoApi: webcrypto
        }), error => error.code === 'pairing-mismatch')
        const recoveredEnrollmentRecord = await phoneStorageAdapter.get('cloudSyncEnrollmentRequests', enrollment.deviceId)
        assert.equal(
            recoveredEnrollmentRecord.device.deviceSequence,
            originalEnrollmentRecord.device.deviceSequence + 1
        )
        await phoneStorageAdapter.put('cloudSyncEnrollmentRequests', enrollment.deviceId, {
            ...recoveredEnrollmentRecord,
            pairingChallenge: originalEnrollmentRecord.pairingChallenge
        })

        const claim = await claimCloudflareHostedPlannerDeviceSession({
            authClient: phoneApp.authClient,
            cloudflareClient: phoneApp.cloudflareClient,
            storage: phoneStorage,
            deviceId: enrollment.deviceId,
            cryptoApi: webcrypto
        })
        assert.equal(claim.syncKeyActive, true)
        assert.equal(claim.deviceSequence, recoveredEnrollmentRecord.device.deviceSequence + 1)
        assert.doesNotMatch(phoneStorageAdapter.serialized(), /syncRootKey|rootKeyMaterial|privateKey":|deviceSessionToken|customToken/i)

        const sequenceBeforeRejectedDispatch = desktopStorage.state().device.deviceSequence
        await assert.rejects(() => desktopTransport.functionsClient.callCloudSyncFunction('ingestCloudSyncDocument', {
            operation: CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope,
            document: {
                docType: 'sanitized-preset-snapshot',
                ownerUid: OWNER,
                deviceId: desktopStorage.state().device.deviceId,
                deviceSequence: sequenceBeforeRejectedDispatch + 1
            }
        }), error => error.code === 'invalid-envelope')
        assert.equal(desktopStorage.state().device.deviceSequence, sequenceBeforeRejectedDispatch + 1)

        const uploadedSnapshot = await uploadDesktopSanitizedSnapshot({
            storage: desktopStorage,
            functionsClient: desktopTransport.functionsClient,
            snapshotBuilder: () => snapshotFixture(desktopStorage.state().device.deviceId),
            now: Date.now()
        })
        assert.equal(uploadedSnapshot.status, 'accepted')

        const downloaded = await downloadLatestHostedPlannerSnapshot({
            firestoreClient: phoneApp.firestoreClient,
            storage: phoneStorage
        })
        assert.equal(downloaded.status, 'downloaded')
        assert.equal(downloaded.snapshot.presets[0].name, 'Coding')
        assert.doesNotMatch(JSON.stringify(downloaded.snapshot), /[A-Za-z]:\\|cap_[a-f0-9]{32,64}|BrowserProfile|AppData[\\/]/i)

        let plannerState = createPhonePlannerState({ idFactory: prefix => `${prefix}_phase31_4_cf` })
        plannerState = importSnapshotIntoPlannerState(plannerState, downloaded.snapshot, {
            authorDeviceId: enrollment.deviceId,
            idFactory: prefix => `${prefix}_phase31_4_cf`
        })
        plannerState = updateSnapshotPresetFields(plannerState, 'preset_coding', { name: 'Coding Cloudflare' })
        const uploadedPatch = await uploadHostedPlannerSafePatch({
            functionsClient: phoneApp.functionsClient,
            storage: phoneStorage,
            editor: plannerState.snapshotEditor,
            now: Date.now(),
            cryptoApi: webcrypto
        })
        assert.equal(uploadedPatch.status, 'accepted')

        const summaries = await downloadDesktopEncryptedPatchSummaries({
            storage: desktopStorage,
            firestoreClient: desktopTransport.firestoreClient
        })
        assert.equal(summaries.summary.downloaded, 1, JSON.stringify(summaries))
        assert.equal(summaries.records[0].authorTrust.status, 'trusted')

        const planned = await downloadDesktopPatchPlans({
            storage: desktopStorage,
            firestoreClient: desktopTransport.firestoreClient,
            sanitizedSnapshot: downloaded.snapshot,
            patchRevisionIds: [uploadedPatch.patchRevisionId]
        })
        assert.equal(planned.status, 'planned')
        assert.equal(planned.plans.length, 1)
        assert.equal(planned.sideEffects.launches, false)
        assert.equal(planned.sideEffects.writesCapabilityVault, false)

        const mergeHarness = createMergeDeps(workspaceFixture())
        const applied = await applyTrustedCloudSafePresetPatchesAfterUnlock({
            storage: desktopStorage,
            firestoreClient: desktopTransport.firestoreClient,
            functionsClient: desktopTransport.functionsClient,
            deps: mergeHarness.deps,
            snapshotBuilder: () => downloaded.snapshot,
            patchRevisionIds: [uploadedPatch.patchRevisionId],
            now: Date.now
        })
        assert.equal(applied.status, 'completed')
        assert.equal(applied.summary.applied, 1, JSON.stringify(applied))
        assert.equal(applied.records[0].cloudStatus.status, 'applied')
        assert.equal(applied.sideEffects.launches, false)
        assert.equal(mergeHarness.calls.commits, 1)

        const storedPatch = db.prepare('SELECT envelope_json, status FROM cloudflare_sync_patches WHERE owner_uid = ? AND revision_id = ?')
            .bind(OWNER, uploadedPatch.patchRevisionId)
            .first()
        assert.equal(storedPatch.status, 'applied')
        assert.match(storedPatch.envelope_json, /ciphertext/)
        assert.doesNotMatch(storedPatch.envelope_json, /Coding Cloudflare|syncRootKey|rootKeyMaterial|privateKey|launchAuthority|[A-Za-z]:\\/i)

        const decidedPatchRead = await desktopTransport.firestoreClient.getDocument(`users/${OWNER}/patches/${uploadedPatch.patchRevisionId}`)
        assert.equal(decidedPatchRead, null)
        const decidedPatchPlan = await downloadDesktopPatchPlans({
            storage: desktopStorage,
            firestoreClient: desktopTransport.firestoreClient,
            sanitizedSnapshot: downloaded.snapshot,
            patchRevisionIds: [uploadedPatch.patchRevisionId]
        })
        assert.equal(decidedPatchPlan.plans.length, 0)

        const revoke = await desktopTransport.client.revokeDevice({
            deviceId: enrollment.deviceId,
            deviceState: {
                ownerUid: OWNER,
                device: desktopStorage.state().device,
                signingPrivateKey: desktop.signing.privateKey
            },
            deviceSequence: desktopStorage.state().device.deviceSequence + 1
        })
        await desktopStorage.updateDeviceSequence(revoke.deviceSequence)
        await assert.rejects(() => phoneApp.firestoreClient.getDocument(`users/${OWNER}/state/sync`), error => error.code === 'revoked-device')
    } finally {
        db.close()
    }
})
