import { createCloudflareSyncFetchClient } from '../cloudflare-sync/cloudflareSyncFetchClient.js'
import { validatePhonePlannerCloudflareConfig } from './phonePlannerCloudflareConfig.js'
import { signCloudSyncCanonicalMetadataBrowser } from './phonePlannerCloudCrypto.js'

const OWNER_UID = /^[A-Za-z0-9:_-]{1,128}$/

function fail(message) {
    throw new Error(message)
}

function normalizeOwnerUid(value) {
    if (typeof value !== 'string') fail('Cloudflare owner uid must be a string.')
    const text = value.trim()
    if (!OWNER_UID.test(text)) fail('Cloudflare owner uid is not safe.')
    return text
}

function nextDeviceSequence(device) {
    if (!Number.isSafeInteger(device?.deviceSequence) || device.deviceSequence < 0) {
        fail('Cloudflare device sequence is invalid.')
    }
    return device.deviceSequence + 1
}

function createCloudflareOwnerAuthClient() {
    let ownerUid = ''
    return {
        provider: 'cloudflare-d1-spike',
        getSafeAuthState() {
            return ownerUid
                ? { signedIn: true, uid: ownerUid, email: '', metadataOnly: true, provider: 'cloudflare-d1-spike' }
                : { signedIn: false, uid: '', email: '', metadataOnly: true, provider: 'cloudflare-d1-spike' }
        },
        async activateOwnerUid(value) {
            ownerUid = normalizeOwnerUid(value)
            return { user: this.getSafeAuthState() }
        },
        async signInWithEmailAndPassword(value) {
            return this.activateOwnerUid(value)
        },
        async createUserWithEmailAndPassword() {
            fail('Cloudflare staging sync does not create auth users from the phone.')
        },
        async signInAnonymously() {
            fail('Cloudflare staging sync requires an explicit owner uid.')
        },
        async signInWithCustomToken() {
            fail('Cloudflare staging sync does not use bearer device session tokens.')
        },
        signOut() {
            ownerUid = ''
            return this.getSafeAuthState()
        }
    }
}

function ownerFromAuth(authClient) {
    const auth = authClient?.getSafeAuthState?.()
    if (!auth?.signedIn || !auth.uid) fail('Set the Cloudflare staging owner uid first.')
    return normalizeOwnerUid(auth.uid)
}

async function activeDeviceState(storage) {
    const state = await storage.loadSessionState()
    if (!state?.device || !state.signingPrivateKey) fail('Cloudflare phone device session is not active.')
    return {
        state,
        deviceState: {
            ownerUid: state.ownerUid,
            device: state.device,
            signingPrivateKey: state.signingPrivateKey
        }
    }
}

async function updateLocalSequenceFromError(storage, error) {
    if (Number.isSafeInteger(error?.deviceSequence) && error.deviceSequence >= 0 && typeof storage.updateDeviceSequence === 'function') {
        await storage.updateDeviceSequence(error.deviceSequence)
    }
}

async function signedRead({ storage, method }) {
    const { state, deviceState } = await activeDeviceState(storage)
    const deviceSequence = nextDeviceSequence(state.device)
    try {
        const result = await method({ deviceState, deviceSequence })
        if (typeof storage.updateDeviceSequence === 'function') await storage.updateDeviceSequence(result.deviceSequence || deviceSequence)
        return result
    } catch (error) {
        await updateLocalSequenceFromError(storage, error)
        throw error
    }
}

function createFunctionsClient({ storage, client }) {
    return {
        async callCloudSyncFunction(name, data) {
            if (name !== 'ingestCloudSyncDocument') fail(`Cloudflare phone functions adapter cannot call ${name}.`)
            const document = data?.document
            if (!document || document.docType !== 'safe-preset-patch') fail('Cloudflare phone adapter only uploads encrypted safe patches.')
            const { state, deviceState } = await activeDeviceState(storage)
            const deviceSequence = data.deviceSequence || document.deviceSequence || nextDeviceSequence(state.device)
            try {
                const result = await client.uploadPatch({ document, deviceState, deviceSequence })
                if (typeof storage.updateDeviceSequence === 'function') await storage.updateDeviceSequence(result.deviceSequence || deviceSequence)
                return result
            } catch (error) {
                await updateLocalSequenceFromError(storage, error)
                throw error
            }
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
                const result = await signedRead({
                    storage,
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
                const result = await signedRead({
                    storage,
                    method: options => client.getSnapshot({ ...options, revisionId })
                })
                return result.envelope || null
            }
            if (parts[2] === 'devices' && parts[3]) {
                const result = await signedRead({
                    storage,
                    method: options => client.getDevice({ ...options, deviceId: parts[3] })
                })
                return result.device || null
            }
            return null
        },
        async getTrustedDeviceRecord({ deviceId } = {}) {
            const state = await storage.loadSessionState()
            if (!state?.ownerUid || !deviceId) return null
            return this.getDocument(`users/${state.ownerUid}/devices/${deviceId}`)
        }
    }
}

export function createPhonePlannerCloudflareRestApp({
    config,
    storage,
    fetchImpl = globalThis.fetch?.bind(globalThis),
    cryptoApi = globalThis.crypto,
    now = Date.now
} = {}) {
    const safeConfig = validatePhonePlannerCloudflareConfig(config)
    if (!storage) fail('Cloudflare phone planner transport requires phone cloud storage.')
    const authClient = createCloudflareOwnerAuthClient()
    const client = createCloudflareSyncFetchClient({
        apiBaseUrl: safeConfig.apiBaseUrl,
        useLocalDev: safeConfig.useLocalDev,
        fetchImpl,
        cryptoApi,
        now,
        signCanonicalMetadata: ({ canonicalMetadata, privateKey }) =>
            signCloudSyncCanonicalMetadataBrowser({ canonicalMetadata, privateKey, cryptoApi })
    })
    return {
        provider: safeConfig.provider,
        config: safeConfig,
        authClient,
        cloudflareClient: client,
        ownerFromAuth: () => ownerFromAuth(authClient),
        functionsClient: createFunctionsClient({ storage, client }),
        firestoreClient: createFirestoreClient({ storage, client })
    }
}
