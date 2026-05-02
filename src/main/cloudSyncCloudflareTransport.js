import { constants, createHash, createPublicKey, publicEncrypt } from 'crypto'
import { createCloudflareSyncFetchClient } from '../cloudflare-sync/cloudflareSyncFetchClient.js'
import {
    CLOUDFLARE_SYNC_PROVIDER_ID,
    CLOUDFLARE_SYNC_STAGING_CONFIG_PROVIDER_ID
} from '../cloudflare-sync/cloudflareSyncConstants.js'
import {
    CLOUD_SYNC_DEVICE_RECORD_TYPE,
    CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
    CLOUD_SYNC_SCHEMA_VERSION,
    assertNoForbiddenCloudSyncBackendPlaintext,
    signCloudSyncCanonicalMetadata,
    validateCloudSyncDeviceRecord,
    validateCloudSyncKeyGrant
} from './cloudSyncEnvelope.js'
import { CLOUD_SYNC_INGESTION_OPERATIONS } from './cloudSyncIngestion.js'
import { createCloudSyncKeyGrantIdForDevice } from './cloudSyncEnrollmentApproval.js'

const ALLOWED_CONFIG_KEYS = new Set([
    'environment',
    'provider',
    'requestedProvider',
    'apiBaseUrl',
    'useLocalDev',
    'maxEnvelopeJsonBytes'
])
const SAFE_STATUS_TEXT = /^[a-z][a-z0-9-]{0,80}$/
const HTTPS_BASE_URL = /^https:\/\/[A-Za-z0-9.-]+(?::\d{1,5})?(?:\/[A-Za-z0-9._~!$&'()*+,;=:@%-]*)?$/
const LOCAL_BASE_URL = /^http:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):\d{1,5}(?:\/[A-Za-z0-9._~!$&'()*+,;=:@%-]*)?$/

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function safeStatus(value, fallback = 'unknown') {
    if (typeof value !== 'string') return fallback
    const text = value.trim().toLowerCase()
    return SAFE_STATUS_TEXT.test(text) ? text : fallback
}

function normalizedKey(value) {
    return String(value || '').toLowerCase().replace(/[^a-z0-9]/g, '')
}

function looksForbiddenConfigKey(key) {
    const normalized = normalizedKey(key)
    return [
        'accountid',
        'apitoken',
        'authorization',
        'bearer',
        'credential',
        'deploymenttoken',
        'deviceprivatekey',
        'privatekey',
        'secret',
        'synckey',
        'syncrootkey',
        'token',
        'vault'
    ].some(marker => normalized.includes(marker))
}

function assertNoForbiddenConfigMaterial(value, path = 'desktop Cloudflare sync config') {
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoForbiddenConfigMaterial(item, `${path}[${index}]`))
        return
    }
    if (isPlainObject(value)) {
        for (const [key, nested] of Object.entries(value)) {
            if (looksForbiddenConfigKey(key)) fail(`${path}.${key} cannot be present.`)
            assertNoForbiddenConfigMaterial(nested, `${path}.${key}`)
        }
        return
    }
    if (typeof value === 'string' && /-----BEGIN [A-Z ]*PRIVATE KEY-----|syncRootKey|rootKeyMaterial|vault\.json|BrowserProfile|AppData[\\/]|cap_[A-Za-z0-9_-]{4,128}|bearer\s+|token\s*[:=]/i.test(value)) {
        fail(`${path} contains forbidden secret or authority material.`)
    }
}

function requireString(value, fieldName, pattern, max = 240) {
    if (typeof value !== 'string') fail(`${fieldName} must be a string.`)
    const text = value.trim()
    if (!text || text.length > max || (pattern && !pattern.test(text))) fail(`${fieldName} is not safe.`)
    return text
}

function requireBoolean(value, fieldName, fallback = false) {
    if (value == null) return fallback
    if (typeof value !== 'boolean') fail(`${fieldName} must be a boolean.`)
    return value
}

function normalizeApiBaseUrl(value, useLocalDev) {
    const text = requireString(value, 'desktop Cloudflare sync config.apiBaseUrl', useLocalDev ? LOCAL_BASE_URL : HTTPS_BASE_URL, 240)
        .replace(/\/+$/g, '')
    if (!useLocalDev && /(?:^|[.-])prod(?:uction)?(?:[.-]|$)|wipesnap\.com/i.test(text)) {
        fail('Desktop Cloudflare sync refuses production-looking API URLs during disabled staging integration.')
    }
    return text
}

export function validateDesktopCloudflareSyncConfig(input) {
    if (!isPlainObject(input)) fail('Desktop Cloudflare sync config must be an object.')
    assertNoForbiddenConfigMaterial(input)
    for (const key of Object.keys(input)) {
        if (!ALLOWED_CONFIG_KEYS.has(key)) {
            if (looksForbiddenConfigKey(key)) fail(`desktop Cloudflare sync config.${key} is forbidden.`)
            fail(`desktop Cloudflare sync config.${key} is not supported.`)
        }
    }
    const environment = requireString(input.environment, 'desktop Cloudflare sync config.environment', /^[a-z][a-z0-9-]{1,40}$/i, 40).toLowerCase()
    if (environment !== 'staging') fail('Desktop Cloudflare sync config must be staging.')
    const provider = requireString(input.provider, 'desktop Cloudflare sync config.provider', /^[a-z0-9-]{1,80}$/i, 80)
    if (![CLOUDFLARE_SYNC_PROVIDER_ID, CLOUDFLARE_SYNC_STAGING_CONFIG_PROVIDER_ID].includes(provider)) {
        fail('Desktop Cloudflare sync provider id is not supported.')
    }
    const requestedProvider = input.requestedProvider == null
        ? provider
        : requireString(input.requestedProvider, 'desktop Cloudflare sync config.requestedProvider', /^[a-z0-9-]{1,80}$/i, 80)
    if (![CLOUDFLARE_SYNC_PROVIDER_ID, CLOUDFLARE_SYNC_STAGING_CONFIG_PROVIDER_ID].includes(requestedProvider)) {
        fail('Desktop Cloudflare sync requested provider id is not supported.')
    }
    if (provider === CLOUDFLARE_SYNC_STAGING_CONFIG_PROVIDER_ID && requestedProvider !== provider) {
        fail('Desktop Cloudflare sync requested provider does not match the config provider.')
    }
    const useLocalDev = requireBoolean(input.useLocalDev, 'desktop Cloudflare sync config.useLocalDev', false)
    return {
        environment,
        provider: CLOUDFLARE_SYNC_PROVIDER_ID,
        requestedProvider,
        apiBaseUrl: normalizeApiBaseUrl(input.apiBaseUrl, useLocalDev),
        useLocalDev,
        maxEnvelopeJsonBytes: Number.isSafeInteger(input.maxEnvelopeJsonBytes) ? input.maxEnvelopeJsonBytes : 768 * 1024
    }
}

function syncRootKeyBytes(value) {
    if (Buffer.isBuffer(value)) return Buffer.from(value)
    if (ArrayBuffer.isView(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength)
    if (value instanceof ArrayBuffer) return Buffer.from(value)
    if (typeof value === 'string') {
        const text = value.trim()
        if (/^[A-Za-z0-9_-]{32,}={0,2}$/.test(text)) {
            const decoded = Buffer.from(text, 'base64url')
            if (decoded.length === 32) return decoded
        }
        return Buffer.from(text, 'utf8')
    }
    if (value && typeof value.export === 'function') {
        const exported = value.export()
        return Buffer.isBuffer(exported) ? Buffer.from(exported) : Buffer.from(exported)
    }
    fail('Desktop sync root key material is not available for Cloudflare key grant wrapping.')
}

function publicKeyFromWrapRecord(device) {
    return createPublicKey({
        key: Buffer.from(device.wrapPublicKey.spki, 'base64url'),
        format: 'der',
        type: 'spki'
    })
}

function wrapSyncRootKeyForDevice(syncRootKey, device) {
    const wrapped = publicEncrypt({
        key: publicKeyFromWrapRecord(device),
        oaepHash: 'sha256',
        padding: constants.RSA_PKCS1_OAEP_PADDING
    }, syncRootKey)
    return {
        ciphertext: wrapped.toString('base64url'),
        hash: createHash('sha256').update(wrapped).digest('base64url')
    }
}

function createKeyGrant({ ownerUid, desktopDevice, recipientDevice, syncRootKey, now }) {
    const wrapped = wrapSyncRootKeyForDevice(syncRootKey, recipientDevice)
    return validateCloudSyncKeyGrant({
        product: 'wipesnap',
        recordType: CLOUD_SYNC_KEY_GRANT_RECORD_TYPE,
        schemaVersion: CLOUD_SYNC_SCHEMA_VERSION,
        ownerUid,
        grantId: createCloudSyncKeyGrantIdForDevice({
            deviceId: recipientDevice.deviceId,
            keyVersion: recipientDevice.keyVersion
        }),
        recipientDeviceId: recipientDevice.deviceId,
        createdByDeviceId: desktopDevice.deviceId,
        keyVersion: desktopDevice.keyVersion,
        wrapAlg: 'RSA-OAEP-256',
        wrappedKeyCiphertext: wrapped.ciphertext,
        wrappedKeyHash: wrapped.hash,
        createdAt: now,
        revokedAt: null,
        revokedByDeviceId: null
    })
}

async function desktopState(storage) {
    if (!storage || typeof storage.loadAfterUnlock !== 'function') fail('Desktop Cloudflare transport requires unlocked storage.')
    const state = await storage.loadAfterUnlock()
    const device = validateCloudSyncDeviceRecord(state?.device)
    if (device.role !== 'desktop') fail('Desktop Cloudflare transport requires a desktop device.')
    if (state.ownerUid !== device.ownerUid) fail('Desktop Cloudflare owner must match device owner.')
    if (!state.signingPrivateKey) fail('Desktop Cloudflare signing key is required.')
    return { ...state, device }
}

function nextDeviceSequence(device) {
    if (!Number.isSafeInteger(device?.deviceSequence) || device.deviceSequence < 0) fail('Cloudflare device sequence is invalid.')
    return device.deviceSequence + 1
}

async function updateLocalSequence(storage, deviceSequence) {
    if (typeof storage.updateDeviceSequence === 'function') {
        await storage.updateDeviceSequence(deviceSequence)
    }
}

async function updateLocalSequenceFromError(storage, error) {
    if (Number.isSafeInteger(error?.deviceSequence) && error.deviceSequence >= 0) {
        await updateLocalSequence(storage, error.deviceSequence)
    }
}

function sanitizePendingEnrollment(record) {
    if (!isPlainObject(record)) fail('Pending Cloudflare enrollment record is invalid.')
    const device = validateCloudSyncDeviceRecord(record.device)
    if (!['phone', 'web-planner'].includes(device.role)) fail('Pending Cloudflare enrollment must be a phone or web planner device.')
    if (device.status !== 'pending') fail('Pending Cloudflare enrollment device must still be pending.')
    return {
        requestId: requireString(record.requestId || device.deviceId, 'requestId', /^dev_[A-Za-z0-9_-]{1,92}$/, 96),
        status: safeStatus(record.status, 'pending'),
        deviceId: device.deviceId,
        role: device.role,
        platform: device.platform,
        enrollmentEpoch: device.enrollmentEpoch,
        keyVersion: device.keyVersion,
        requestedAt: Number.isSafeInteger(record.requestedAt) ? record.requestedAt : 0,
        updatedAt: Number.isSafeInteger(record.updatedAt) ? record.updatedAt : 0,
        signingPublicKeyFingerprint: device.signingPublicKey.fingerprint,
        wrapPublicKeyFingerprint: device.wrapPublicKey.fingerprint,
        metadataOnly: true
    }
}

async function signedDesktopCall({ storage, client, method }) {
    const state = await desktopState(storage)
    const deviceSequence = nextDeviceSequence(state.device)
    try {
        const result = await method({
            deviceState: {
                ownerUid: state.ownerUid,
                device: state.device,
                signingPrivateKey: state.signingPrivateKey
            },
            deviceSequence,
            state
        })
        await updateLocalSequence(storage, result.deviceSequence || deviceSequence)
        return result
    } catch (error) {
        await updateLocalSequenceFromError(storage, error)
        throw error
    }
}

function createFunctionsClient({ storage, client }) {
    return {
        async callCloudSyncFunction(name, data) {
            if (name === 'ingestCloudSyncDocument') {
                const state = await desktopState(storage)
                const document = data?.document
                assertNoForbiddenCloudSyncBackendPlaintext(document)
                const deviceState = {
                    ownerUid: state.ownerUid,
                    device: state.device,
                    signingPrivateKey: state.signingPrivateKey
                }
                if (data.operation === CLOUD_SYNC_INGESTION_OPERATIONS.snapshotEnvelope) {
                    try {
                        return await client.uploadSnapshot({
                            document,
                            deviceState,
                            deviceSequence: data.deviceSequence || document.deviceSequence
                        })
                    } catch (error) {
                        await updateLocalSequenceFromError(storage, error)
                        throw error
                    }
                }
                if (data.operation === CLOUD_SYNC_INGESTION_OPERATIONS.patchEnvelope) {
                    try {
                        return await client.uploadPatch({
                            document,
                            deviceState,
                            deviceSequence: data.deviceSequence || document.deviceSequence
                        })
                    } catch (error) {
                        await updateLocalSequenceFromError(storage, error)
                        throw error
                    }
                }
                fail('Cloudflare desktop transport only ingests encrypted snapshot or patch envelopes.')
            }
            if (name === 'recordCloudSyncPatchApplyDecision') {
                return signedDesktopCall({
                    storage,
                    client,
                    method: ({ deviceState, deviceSequence }) => client.recordPatchDecision({
                        decision: data.document,
                        revisionId: data.document?.patchRevisionId || data.documentId,
                        deviceState,
                        deviceSequence
                    })
                })
            }
            fail(`Cloudflare desktop functions adapter cannot call ${name}.`)
        }
    }
}

function createFirestoreClient({ storage, client }) {
    const latestCache = new Map()
    return {
        async getDocument(path) {
            const parts = String(path || '').split('/').filter(Boolean)
            if (parts.length < 4 || parts[0] !== 'users') return null
            if (parts[2] === 'state' && parts[3] === 'sync') {
                const result = await signedDesktopCall({
                    storage,
                    client,
                    method: options => client.getLatestSnapshot(options)
                })
                if (!result.envelope) return null
                latestCache.set(result.envelope.revisionId, result.envelope)
                return {
                    latestSnapshotRevisionId: result.envelope.revisionId,
                    activeKeyVersion: result.envelope.keyVersion,
                    metadataOnly: true
                }
            }
            if (parts[2] === 'snapshots' && parts[3]) {
                const revisionId = parts[3]
                if (latestCache.has(revisionId)) return latestCache.get(revisionId)
                const result = await signedDesktopCall({
                    storage,
                    client,
                    method: options => client.getSnapshot({ ...options, revisionId })
                })
                return result.envelope || null
            }
            if (parts[2] === 'patches' && parts[3]) {
                const result = await signedDesktopCall({
                    storage,
                    client,
                    method: options => client.getPatch({ ...options, revisionId: parts[3] })
                })
                return result.patchStatus === 'pending' ? result.envelope || null : null
            }
            if (parts[2] === 'devices' && parts[3]) {
                return this.getTrustedDeviceRecord({ ownerUid: parts[1], deviceId: parts[3] })
            }
            return null
        },
        async listDocuments(path) {
            const parts = String(path || '').split('/').filter(Boolean)
            if (parts.length === 3 && parts[0] === 'users' && parts[2] === 'patches') {
                const result = await signedDesktopCall({
                    storage,
                    client,
                    method: options => client.listPendingPatches(options)
                })
                return Array.isArray(result.records)
                    ? result.records.map(record => record.envelope).filter(Boolean)
                    : []
            }
            return []
        },
        async getTrustedDeviceRecord({ deviceId } = {}) {
            if (!deviceId) return null
            const result = await signedDesktopCall({
                storage,
                client,
                method: options => client.getDevice({ ...options, deviceId })
            })
            return result.device || null
        }
    }
}

export function createCloudflareDesktopTransportAdapters({
    config,
    storage,
    fetchImpl = globalThis.fetch?.bind(globalThis),
    cryptoApi = globalThis.crypto,
    now = Date.now
} = {}) {
    const safeConfig = validateDesktopCloudflareSyncConfig(config)
    const client = createCloudflareSyncFetchClient({
        apiBaseUrl: safeConfig.apiBaseUrl,
        useLocalDev: safeConfig.useLocalDev,
        fetchImpl,
        cryptoApi,
        now,
        signCanonicalMetadata: ({ canonicalMetadata, privateKey }) =>
            signCloudSyncCanonicalMetadata({ canonicalMetadata, privateKey })
    })
    return {
        provider: safeConfig.provider,
        client,
        functionsClient: createFunctionsClient({ storage, client }),
        firestoreClient: createFirestoreClient({ storage, client })
    }
}

function cloudflareErrorResult(operation, error) {
    const locked = /unlock|locked|active vault session/i.test(error?.message || '')
    const unavailable = /requires|unavailable|not configured|invalid/i.test(error?.message || '')
    return {
        success: false,
        operation,
        status: locked ? 'locked' : unavailable ? 'unavailable' : 'rejected',
        error: locked
            ? 'Cloudflare sync requires an unlocked vault session.'
            : 'Cloudflare staging sync operation failed.',
        records: [],
        summary: { pending: 0, approved: 0, granted: 0, skipped: 1 },
        metadataOnly: true,
        sideEffects: {
            writesVault: false,
            writesCapabilityVault: false,
            createsCapability: false,
            createsAccountSlots: false,
            createsBrowserProfiles: false,
            launches: false,
            writesCloudDeviceEnrollment: false,
            writesCloudKeyGrant: false
        }
    }
}

export async function bootstrapCloudflareDesktopAfterUnlock({
    storage,
    cloudflareClient
} = {}) {
    const operation = 'bootstrap-cloudflare-desktop'
    try {
        const state = await desktopState(storage)
        let status = 'accepted'
        try {
            const result = await cloudflareClient.bootstrapDesktop({
                document: {
                    ...clone(state.device),
                    recordType: state.device.recordType || CLOUD_SYNC_DEVICE_RECORD_TYPE
                },
                deviceState: {
                    ownerUid: state.ownerUid,
                    device: state.device,
                    signingPrivateKey: state.signingPrivateKey
                },
                deviceSequence: state.device.deviceSequence
            })
            status = result.status || 'accepted'
        } catch (error) {
            if (error?.code !== 'device-exists') throw error
            status = 'already-active'
        }
        return {
            success: true,
            operation,
            status,
            ownerUid: state.ownerUid,
            deviceId: state.device.deviceId,
            summary: { pending: 0, approved: 0, granted: 0, skipped: 0 },
            metadataOnly: true,
            sideEffects: {
                writesVault: false,
                writesCapabilityVault: false,
                createsCapability: false,
                createsAccountSlots: false,
                createsBrowserProfiles: false,
                launches: false,
                writesCloudDeviceEnrollment: status === 'accepted',
                writesCloudKeyGrant: false
            }
        }
    } catch (error) {
        return cloudflareErrorResult(operation, error)
    }
}

export async function listPendingCloudflareSyncDeviceEnrollmentsAfterUnlock({
    storage,
    cloudflareClient,
    bootstrap = true
} = {}) {
    const operation = 'list-pending-device-enrollments'
    try {
        const listOnce = () => signedDesktopCall({
            storage,
            client: cloudflareClient,
            method: ({ deviceState, deviceSequence }) => cloudflareClient.listPendingEnrollments({
                deviceState,
                deviceSequence
            })
        })
        let result
        try {
            result = await listOnce()
        } catch (error) {
            if (!bootstrap || !['invalid-device', 'not-found'].includes(error?.code)) throw error
            const bootstrapped = await bootstrapCloudflareDesktopAfterUnlock({ storage, cloudflareClient })
            if (bootstrapped.success !== true && bootstrapped.status !== 'already-active') return bootstrapped
            result = await listOnce()
        }
        const records = Array.isArray(result.records)
            ? result.records.map(sanitizePendingEnrollment)
            : []
        const state = await desktopState(storage)
        return {
            success: true,
            operation,
            status: 'listed',
            records,
            summary: { pending: records.length, approved: 0, granted: 0, skipped: 0 },
            desktopDeviceId: state.device.deviceId,
            metadataOnly: true,
            sideEffects: {
                writesVault: false,
                writesCapabilityVault: false,
                createsCapability: false,
                createsAccountSlots: false,
                createsBrowserProfiles: false,
                launches: false,
                writesCloudDeviceEnrollment: false,
                writesCloudKeyGrant: false
            }
        }
    } catch (error) {
        return cloudflareErrorResult(operation, error)
    }
}

export async function approveCloudflareSyncEnrollmentAndGrantAfterUnlock({
    input = {},
    storage,
    cloudflareClient,
    now = Date.now
} = {}) {
    const requestId = requireString(input.requestId, 'requestId', /^dev_[A-Za-z0-9_-]{1,92}$/, 96)
    const timestamp = typeof now === 'function' ? now() : now
    let state = await desktopState(storage)
    const listPendingOnce = async () => {
        const result = await cloudflareClient.listPendingEnrollments({
            deviceState: {
                ownerUid: state.ownerUid,
                device: state.device,
                signingPrivateKey: state.signingPrivateKey
            },
            deviceSequence: nextDeviceSequence(state.device)
        })
        await updateLocalSequence(storage, result.deviceSequence)
        return result
    }
    let pendingList
    try {
        pendingList = await listPendingOnce()
    } catch (error) {
        await updateLocalSequenceFromError(storage, error)
        if (!['invalid-device', 'not-found'].includes(error?.code)) throw error
        const bootstrapped = await bootstrapCloudflareDesktopAfterUnlock({ storage, cloudflareClient })
        if (bootstrapped.success !== true && bootstrapped.status !== 'already-active') return bootstrapped
        state = await desktopState(storage)
        pendingList = await listPendingOnce()
    }
    state = await desktopState(storage)
    const pending = (Array.isArray(pendingList.records) ? pendingList.records : [])
        .find(record => record.requestId === requestId)
    if (!pending) fail('Pending Cloudflare phone planner enrollment request was not found.')
    const recipientDevice = validateCloudSyncDeviceRecord(pending.device)
    if (!['phone', 'web-planner'].includes(recipientDevice.role)) fail('Cloudflare enrollment recipient role is invalid.')
    if (recipientDevice.status !== 'pending') fail('Cloudflare enrollment recipient must still be pending.')
    if (recipientDevice.ownerUid !== state.ownerUid) fail('Cloudflare enrollment owner does not match desktop.')
    if (recipientDevice.keyVersion !== state.device.keyVersion) fail('Cloudflare enrollment key version does not match desktop.')
    const keyBytes = syncRootKeyBytes(state.syncRootKey)
    try {
        const keyGrant = createKeyGrant({
            ownerUid: state.ownerUid,
            desktopDevice: state.device,
            recipientDevice,
            syncRootKey: keyBytes,
            now: timestamp
        })
        let approved
        try {
            approved = await cloudflareClient.approveEnrollment({
                requestId,
                keyGrant,
                deviceState: {
                    ownerUid: state.ownerUid,
                    device: state.device,
                    signingPrivateKey: state.signingPrivateKey
                },
                deviceSequence: nextDeviceSequence(state.device)
            })
        } catch (error) {
            await updateLocalSequenceFromError(storage, error)
            throw error
        }
        await updateLocalSequence(storage, approved.deviceSequence)
        return {
            success: true,
            operation: 'approve-cloudflare-phone-planner-enrollment',
            status: approved.status || 'approved',
            requestId,
            deviceId: recipientDevice.deviceId,
            role: recipientDevice.role,
            keyGrantId: keyGrant.grantId,
            deviceSequence: approved.deviceSequence,
            summary: { pending: 0, approved: 1, granted: 1, skipped: 0 },
            metadataOnly: true,
            sideEffects: {
                writesVault: false,
                writesCapabilityVault: false,
                createsCapability: false,
                createsAccountSlots: false,
                createsBrowserProfiles: false,
                launches: false,
                writesCloudDeviceEnrollment: true,
                writesCloudKeyGrant: true
            }
        }
    } finally {
        keyBytes.fill(0)
    }
}
