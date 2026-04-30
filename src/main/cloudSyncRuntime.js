import { createHash } from 'crypto'
import { buildSanitizedPresetSnapshot } from './sanitizedPresetSnapshot.js'
import { createDesktopCloudSyncStorage } from './cloudSyncClientStorage.js'

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function fail(message) {
    throw new Error(message)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function callOrValue(value, context) {
    return typeof value === 'function' ? value(context) : value
}

function normalizeRuntime(runtime) {
    return isPlainObject(runtime) ? runtime : {}
}

function normalizeKeyBytes(value) {
    if (Buffer.isBuffer(value)) return Buffer.from(value)
    if (ArrayBuffer.isView(value)) return Buffer.from(value.buffer, value.byteOffset, value.byteLength)
    if (value instanceof ArrayBuffer) return Buffer.from(value)
    if (typeof value === 'string') {
        const trimmed = value.trim()
        if (/^[A-Za-z0-9_-]{32,}={0,2}$/.test(trimmed)) {
            try {
                return Buffer.from(trimmed, 'base64url')
            } catch (_) { }
        }
        return Buffer.from(trimmed, 'utf8')
    }
    if (value && typeof value.export === 'function') {
        const exported = value.export()
        return Buffer.isBuffer(exported) ? Buffer.from(exported) : Buffer.from(exported)
    }
    fail('Cloud sync runtime cannot derive sanitized snapshot ids from the configured key material.')
}

function deriveSnapshotSafeIdSecret(state) {
    const keyBytes = normalizeKeyBytes(state?.syncRootKey)
    return createHash('sha256')
        .update('wipesnap.cloud-sync.snapshot-safe-id.v1\0')
        .update(keyBytes)
        .digest()
}

function resolveStorage(runtime) {
    if (runtime.storage && typeof runtime.storage.loadAfterUnlock === 'function') {
        return runtime.storage
    }
    if (runtime.vaultAdapter && typeof runtime.vaultAdapter.loadCloudSyncState === 'function') {
        return createDesktopCloudSyncStorage({ vaultAdapter: runtime.vaultAdapter })
    }
    return null
}

function resolveFirestoreClient(runtime) {
    if (runtime.firestoreClient) return runtime.firestoreClient
    const firebase = runtime.firebase || {}
    if (!firebase.firestore || !firebase.firestoreApi) return null
    const { firestore, firestoreApi } = firebase
    const { doc, collection, getDoc, getDocs } = firestoreApi
    if ([doc, collection, getDoc, getDocs].some(fn => typeof fn !== 'function')) return null
    return {
        async getDocument(path) {
            const snapshot = await getDoc(doc(firestore, path))
            return snapshot.exists() ? snapshot.data() : null
        },
        async listDocuments(path) {
            const snapshot = await getDocs(collection(firestore, path))
            return snapshot.docs.map(document => document.data())
        }
    }
}

function resolveFunctionsClient(runtime) {
    if (runtime.functionsClient) return runtime.functionsClient
    const firebase = runtime.firebase || {}
    if (!firebase.functions || !firebase.functionsApi) return null
    const { functions, functionsApi } = firebase
    const { httpsCallable } = functionsApi
    if (typeof httpsCallable !== 'function') return null
    return {
        async callCloudSyncFunction(name, data) {
            const callable = httpsCallable(functions, name)
            const result = await callable(data)
            return result?.data
        }
    }
}

function createDefaultSnapshotBuilder(runtime, storage) {
    if (!storage || typeof storage.loadAfterUnlock !== 'function') return null
    return async ({ ownerUid, device, now, workspace } = {}) => {
        const state = await storage.loadAfterUnlock()
        const activeDevice = device || state.device
        const timestamp = typeof now === 'function' ? now() : now ?? Date.now()
        const context = {
            ownerUid: ownerUid || state.ownerUid,
            device: clone(activeDevice),
            state: clone({
                ownerUid: state.ownerUid,
                device: state.device
            }),
            now: timestamp
        }
        const snapshot = buildSanitizedPresetSnapshot({
            workspace,
            snapshotSafeIdSecret: callOrValue(runtime.snapshotSafeIdSecret, context) || deriveSnapshotSafeIdSecret(state),
            sourceDeviceId: callOrValue(runtime.sourceDeviceIdMaterial, context) || activeDevice.deviceId,
            snapshotId: callOrValue(runtime.snapshotIdMaterial, context) || `${state.ownerUid}:${activeDevice.deviceId}`,
            revisionId: callOrValue(runtime.snapshotRevisionIdMaterial, context) ||
                `${activeDevice.deviceId}:${activeDevice.deviceSequence + 1}:${timestamp}`,
            baseRevisionId: callOrValue(runtime.baseSnapshotRevisionIdMaterial, context) || state.lastSnapshotRevisionId || null,
            timestamp
        })
        return {
            ...snapshot,
            sourceDeviceId: activeDevice.deviceId,
            baseRevisionId: state.lastSnapshotRevisionId || snapshot.baseRevisionId || null
        }
    }
}

function resolveSnapshotBuilder(runtime, storage) {
    if (typeof runtime.buildCurrentSanitizedSnapshot === 'function') {
        return runtime.buildCurrentSanitizedSnapshot
    }
    return createDefaultSnapshotBuilder(runtime, storage)
}

export function createCloudSyncRuntimeAdapter({ runtime, baseDeps = {} } = {}) {
    const safeRuntime = normalizeRuntime(runtime)
    const storage = resolveStorage(safeRuntime)
    const firestoreClient = resolveFirestoreClient(safeRuntime)
    const functionsClient = resolveFunctionsClient(safeRuntime)
    const buildCurrentSanitizedSnapshot = resolveSnapshotBuilder(safeRuntime, storage)

    return {
        ...baseDeps,
        ...(storage ? { storage } : {}),
        ...(firestoreClient ? { firestoreClient } : {}),
        ...(functionsClient ? { functionsClient } : {}),
        ...(buildCurrentSanitizedSnapshot ? { buildCurrentSanitizedSnapshot } : {}),
        cloudSyncRuntime: {
            available: !!(storage && firestoreClient && functionsClient && buildCurrentSanitizedSnapshot),
            storage: !!storage,
            firestore: !!firestoreClient,
            functions: !!functionsClient,
            snapshotBuilder: !!buildCurrentSanitizedSnapshot,
            metadataOnly: true
        }
    }
}
