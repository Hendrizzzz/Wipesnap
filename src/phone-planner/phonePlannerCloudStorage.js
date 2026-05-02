import {
    createPendingWebPlannerDeviceRecord,
    createPairingChallenge,
    createWebPlannerDeviceId,
    unwrapCloudSyncRootKeyGrant,
    validateCloudSyncDeviceRecordForPhone
} from './phonePlannerCloudCrypto.js'

export const PHONE_PLANNER_CLOUD_DB_NAME = 'wipesnap-phone-planner-cloud-v1'
export const PHONE_PLANNER_CLOUD_STORAGE_VERSION = 1

const STORE_NAMES = [
    'cloudSyncCryptoKeys',
    'cloudSyncDeviceMetadata',
    'cloudSyncEnrollmentRequests',
    'cloudSyncDeviceSessions',
    'cloudSyncSyncKeys',
    'cloudSyncKeyMetadata',
    'cloudSyncEncryptedSnapshots',
    'cloudSyncEncryptedPatches'
]

function fail(message) {
    throw new Error(message)
}

function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value)
}

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function normalizeOwnerUid(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9:_-]{1,128}$/.test(value)) fail('ownerUid must be a safe Firebase uid.')
    return value
}

function normalizeSafeId(value, fieldName, prefix) {
    if (typeof value !== 'string' || !value.startsWith(prefix) || !/^[A-Za-z][A-Za-z0-9_-]{1,120}$/.test(value)) {
        fail(`${fieldName} must be a safe ${prefix} id.`)
    }
    return value
}

function normalizeInteger(value, fieldName) {
    if (!Number.isSafeInteger(value) || value < 0) fail(`${fieldName} must be a non-negative safe integer.`)
    return value
}

function assertNoRawKeyMaterial(value, path = 'phone planner cloud storage') {
    if (Array.isArray(value)) {
        value.forEach((item, index) => assertNoRawKeyMaterial(item, `${path}[${index}]`))
        return
    }
    if (isPlainObject(value)) {
        for (const [key, nested] of Object.entries(value)) {
            const normalized = key.toLowerCase().replace(/[^a-z0-9]/g, '')
            if (normalized === 'rawkeybytesstored') {
                if (nested !== false) fail(`${path}.${key} must be false.`)
                continue
            }
            if ([
                'devicesessiontoken',
                'customtoken',
                'idtoken',
                'refreshtoken',
                'accesstoken',
                'syncrootkey',
                'rootkeymaterial',
                'rawkey',
                'privatekey',
                'password',
                'credential',
                'vault',
                'capability',
                'launch'
            ].some(marker => normalized.includes(marker))) {
                fail(`${path}.${key} cannot be stored by the phone planner cloud layer.`)
            }
            assertNoRawKeyMaterial(nested, `${path}.${key}`)
        }
        return
    }
    if (typeof value === 'string' && (
        /\b(?:deviceSessionToken|custom[_\s-]*token|refresh[_\s-]*token|access[_\s-]*token|id[_\s-]*token)\b\s*[:=]/i.test(value) ||
        /\b(?:sync[_\s-]*root[_\s-]*key|root[_\s-]*key[_\s-]*material|private[_\s-]*key)\b\s*[:=]/i.test(value) ||
        /\b(?:vault\.json|vault\.meta\.json|vault\.state\.json|BrowserProfile|AppData[\\/])\b/i.test(value) ||
        /\bcap_[a-f0-9]{32,64}\b/i.test(value)
    )) {
        fail(`${path} contains forbidden cloud storage material.`)
    }
}

function openIndexedDb(indexedDb, dbName) {
    return new Promise((resolve, reject) => {
        const request = indexedDb.open(dbName, 1)
        request.onupgradeneeded = () => {
            const db = request.result
            for (const storeName of STORE_NAMES) {
                if (!db.objectStoreNames.contains(storeName)) db.createObjectStore(storeName)
            }
        }
        request.onsuccess = () => resolve(request.result)
        request.onerror = () => reject(request.error || new Error('IndexedDB open failed.'))
    })
}

export function createIndexedDbAdapter({
    indexedDb = globalThis.indexedDB,
    dbName = PHONE_PLANNER_CLOUD_DB_NAME
} = {}) {
    if (!indexedDb || typeof indexedDb.open !== 'function') fail('Hosted phone planner requires IndexedDB.')
    let dbPromise = null
    const db = () => {
        if (!dbPromise) dbPromise = openIndexedDb(indexedDb, dbName)
        return dbPromise
    }
    const transact = async (storeName, mode, callback) => {
        if (!STORE_NAMES.includes(storeName)) fail(`Unsupported IndexedDB store: ${storeName}`)
        const database = await db()
        return new Promise((resolve, reject) => {
            const tx = database.transaction(storeName, mode)
            const store = tx.objectStore(storeName)
            let result
            try {
                result = callback(store)
            } catch (error) {
                reject(error)
                return
            }
            tx.oncomplete = () => resolve(result?.result ?? result)
            tx.onerror = () => reject(tx.error || new Error('IndexedDB transaction failed.'))
            tx.onabort = () => reject(tx.error || new Error('IndexedDB transaction aborted.'))
        })
    }
    return {
        put(storeName, key, value) {
            return transact(storeName, 'readwrite', store => store.put(value, key))
        },
        get(storeName, key) {
            return transact(storeName, 'readonly', store => store.get(key))
        },
        delete(storeName, key) {
            return transact(storeName, 'readwrite', store => store.delete(key))
        }
    }
}

function keyRef(kind, deviceId) {
    return `${kind}:${deviceId}`
}

function syncKeyRef(deviceId, keyVersion) {
    return `sync:${deviceId}:v${keyVersion}`
}

export function createPhonePlannerCloudStorage({
    indexedDbAdapter,
    cryptoApi = globalThis.crypto,
    now = Date.now
} = {}) {
    if (!indexedDbAdapter || typeof indexedDbAdapter.put !== 'function' || typeof indexedDbAdapter.get !== 'function') {
        fail('Phone planner cloud storage requires an IndexedDB adapter.')
    }
    if (!cryptoApi?.subtle || typeof cryptoApi.getRandomValues !== 'function') {
        fail('Phone planner cloud storage requires WebCrypto.')
    }

    const session = {
        ownerUid: '',
        device: null,
        signingKey: null,
        wrappingKey: null,
        syncRootKey: null,
        keyGrantId: ''
    }

    async function storeCryptoKey(ref, key) {
        if (!key || key.extractable !== false) fail('Only non-extractable CryptoKeys may be stored.')
        await indexedDbAdapter.put('cloudSyncCryptoKeys', ref, key)
        return ref
    }

    async function loadCryptoKey(ref) {
        const key = await indexedDbAdapter.get('cloudSyncCryptoKeys', ref)
        if (!key || key.extractable !== false) fail('Required non-extractable CryptoKey is missing.')
        return key
    }

    return {
        async createPendingDevice({ ownerUid, keyVersion = 1 } = {}) {
            const safeOwnerUid = normalizeOwnerUid(ownerUid)
            const deviceId = createWebPlannerDeviceId(cryptoApi)
            const created = await createPendingWebPlannerDeviceRecord({
                ownerUid: safeOwnerUid,
                deviceId,
                keyVersion,
                now: now(),
                cryptoApi
            })
            const signingRef = keyRef('signing', deviceId)
            const wrappingRef = keyRef('wrapping', deviceId)
            await storeCryptoKey(signingRef, created.keyPair.signing.privateKey)
            await storeCryptoKey(wrappingRef, created.keyPair.wrapping.privateKey)
            const metadata = {
                storageVersion: PHONE_PLANNER_CLOUD_STORAGE_VERSION,
                ownerUid: safeOwnerUid,
                deviceId,
                signingKeyRef: signingRef,
                wrappingKeyRef: wrappingRef,
                createdAt: now(),
                rawKeyBytesStored: false
            }
            assertNoRawKeyMaterial(metadata)
            await indexedDbAdapter.put('cloudSyncDeviceMetadata', deviceId, metadata)
            session.ownerUid = safeOwnerUid
            session.device = created.device
            session.signingKey = created.keyPair.signing.privateKey
            session.wrappingKey = created.keyPair.wrapping.privateKey
            return { device: clone(created.device), metadata: clone(metadata) }
        },
        async storeEnrollmentRequest({ ownerUid, device, pairingChallenge, keyGrantId } = {}) {
            const normalizedDevice = validateCloudSyncDeviceRecordForPhone(device)
            const record = {
                storageVersion: PHONE_PLANNER_CLOUD_STORAGE_VERSION,
                ownerUid: normalizeOwnerUid(ownerUid || normalizedDevice.ownerUid),
                requestId: normalizedDevice.deviceId,
                device: normalizedDevice,
                pairingChallenge: typeof pairingChallenge === 'string' ? pairingChallenge : fail('pairingChallenge is required.'),
                keyGrantId: normalizeSafeId(keyGrantId, 'keyGrantId', 'grant_'),
                requestedAt: now()
            }
            assertNoRawKeyMaterial({
                ...record,
                // The pairing challenge is intentionally user-visible and one-time; do not scan it as a token.
                pairingChallenge: ''
            })
            await indexedDbAdapter.put('cloudSyncEnrollmentRequests', normalizedDevice.deviceId, record)
            return clone(record)
        },
        async loadEnrollmentRequest(deviceId) {
            const safeDeviceId = normalizeSafeId(deviceId, 'deviceId', 'dev_')
            const record = await indexedDbAdapter.get('cloudSyncEnrollmentRequests', safeDeviceId)
            if (!record) return null
            const device = validateCloudSyncDeviceRecordForPhone(record.device)
            session.ownerUid = record.ownerUid
            session.device = device
            session.signingKey = await loadCryptoKey(keyRef('signing', safeDeviceId))
            session.wrappingKey = await loadCryptoKey(keyRef('wrapping', safeDeviceId))
            return clone(record)
        },
        async updateEnrollmentRequestDeviceSequence({ deviceId, deviceSequence } = {}) {
            const safeDeviceId = normalizeSafeId(deviceId, 'deviceId', 'dev_')
            const sequence = normalizeInteger(deviceSequence, 'deviceSequence')
            const record = await indexedDbAdapter.get('cloudSyncEnrollmentRequests', safeDeviceId)
            if (!record) return { status: 'skipped', metadataOnly: true }
            const device = validateCloudSyncDeviceRecordForPhone(record.device)
            if (sequence < device.deviceSequence) {
                return { status: 'skipped', deviceSequence: device.deviceSequence, metadataOnly: true }
            }
            const nextDevice = { ...device, deviceSequence: sequence, updatedAt: now() }
            const nextRecord = { ...record, device: nextDevice, updatedAt: now() }
            assertNoRawKeyMaterial({
                ...nextRecord,
                // The pairing challenge is intentionally user-visible and one-time; do not scan it as a token.
                pairingChallenge: ''
            })
            await indexedDbAdapter.put('cloudSyncEnrollmentRequests', safeDeviceId, nextRecord)
            if (session.device?.deviceId === safeDeviceId) session.device = nextDevice
            return { status: 'updated', deviceSequence: sequence, metadataOnly: true }
        },
        async loadPendingDeviceState(deviceId) {
            const safeDeviceId = normalizeSafeId(deviceId, 'deviceId', 'dev_')
            const metadata = await indexedDbAdapter.get('cloudSyncDeviceMetadata', safeDeviceId)
            if (!metadata) return null
            const signingKey = await loadCryptoKey(metadata.signingKeyRef)
            const wrappingKey = await loadCryptoKey(metadata.wrappingKeyRef)
            return {
                ownerUid: metadata.ownerUid,
                deviceId: safeDeviceId,
                signingPrivateKey: signingKey,
                wrappingPrivateKey: wrappingKey
            }
        },
        async storeClaimedDeviceSessionMetadata({ ownerUid, device, keyGrantId } = {}) {
            const normalizedDevice = validateCloudSyncDeviceRecordForPhone(device)
            if (!['phone', 'web-planner'].includes(normalizedDevice.role) || normalizedDevice.status !== 'active') {
                fail('Claimed phone planner device session must be active.')
            }
            const metadata = {
                storageVersion: PHONE_PLANNER_CLOUD_STORAGE_VERSION,
                ownerUid: normalizeOwnerUid(ownerUid || normalizedDevice.ownerUid),
                device: normalizedDevice,
                keyGrantId: normalizeSafeId(keyGrantId, 'keyGrantId', 'grant_'),
                firebaseAuthPersistence: 'memory-only-rest-auth',
                deviceSessionStored: false
            }
            assertNoRawKeyMaterial(metadata)
            await indexedDbAdapter.put('cloudSyncDeviceSessions', normalizedDevice.deviceId, metadata)
            session.ownerUid = metadata.ownerUid
            session.device = normalizedDevice
            session.keyGrantId = metadata.keyGrantId
            return clone(metadata)
        },
        async activateKeyGrant({ ownerUid, device, keyGrant } = {}) {
            const normalizedDevice = validateCloudSyncDeviceRecordForPhone(device)
            const wrappingKey = session.wrappingKey || await loadCryptoKey(keyRef('wrapping', normalizedDevice.deviceId))
            const unwrapped = await unwrapCloudSyncRootKeyGrant({
                keyGrant,
                wrappingPrivateKey: wrappingKey,
                expectedOwnerUid: ownerUid || normalizedDevice.ownerUid,
                expectedDeviceId: normalizedDevice.deviceId,
                expectedKeyVersion: normalizedDevice.keyVersion,
                cryptoApi
            })
            const ref = syncKeyRef(normalizedDevice.deviceId, unwrapped.keyVersion)
            await indexedDbAdapter.put('cloudSyncSyncKeys', ref, unwrapped.syncRootKey)
            const metadata = {
                storageVersion: PHONE_PLANNER_CLOUD_STORAGE_VERSION,
                ownerUid: normalizeOwnerUid(ownerUid || normalizedDevice.ownerUid),
                deviceId: normalizedDevice.deviceId,
                keyVersion: unwrapped.keyVersion,
                syncKeyRef: ref,
                rawKeyBytesStored: false
            }
            assertNoRawKeyMaterial(metadata)
            await indexedDbAdapter.put('cloudSyncKeyMetadata', ref, metadata)
            session.syncRootKey = unwrapped.syncRootKey
            return clone(metadata)
        },
        async restoreSession(deviceId) {
            const safeDeviceId = normalizeSafeId(deviceId, 'deviceId', 'dev_')
            const metadata = await indexedDbAdapter.get('cloudSyncDeviceMetadata', safeDeviceId)
            const sessionMetadata = await indexedDbAdapter.get('cloudSyncDeviceSessions', safeDeviceId)
            if (!metadata || !sessionMetadata) return null
            const device = validateCloudSyncDeviceRecordForPhone(sessionMetadata.device)
            const signingKey = await loadCryptoKey(metadata.signingKeyRef)
            const wrappingKey = await loadCryptoKey(metadata.wrappingKeyRef)
            const ref = syncKeyRef(device.deviceId, device.keyVersion)
            const syncRootKey = await indexedDbAdapter.get('cloudSyncSyncKeys', ref)
            if (!syncRootKey) fail('Phone planner sync key is not active on this browser.')
            session.ownerUid = sessionMetadata.ownerUid
            session.device = device
            session.signingKey = signingKey
            session.wrappingKey = wrappingKey
            session.syncRootKey = syncRootKey
            session.keyGrantId = sessionMetadata.keyGrantId
            return {
                ownerUid: session.ownerUid,
                device: clone(device),
                keyGrantId: session.keyGrantId,
                hasSyncKeyInMemory: true,
                metadataOnly: true
            }
        },
        async loadSessionState() {
            if (!session.device || !session.signingKey || !session.syncRootKey) return null
            return {
                ownerUid: session.ownerUid,
                device: clone(session.device),
                signingPrivateKey: session.signingKey,
                syncRootKey: session.syncRootKey,
                keyGrantId: session.keyGrantId
            }
        },
        async updateDeviceSequence(deviceSequence) {
            if (!session.device) return { status: 'skipped', metadataOnly: true }
            const sequence = normalizeInteger(deviceSequence, 'deviceSequence')
            session.device = { ...session.device, deviceSequence: sequence, updatedAt: now() }
            const sessionMetadata = await indexedDbAdapter.get('cloudSyncDeviceSessions', session.device.deviceId)
            if (sessionMetadata) {
                await indexedDbAdapter.put('cloudSyncDeviceSessions', session.device.deviceId, {
                    ...sessionMetadata,
                    device: session.device
                })
            }
            return { status: 'updated', deviceSequence: sequence, metadataOnly: true }
        },
        async cacheEncryptedSnapshotEnvelope(envelope) {
            await indexedDbAdapter.put('cloudSyncEncryptedSnapshots', envelope.revisionId, envelope)
            return { status: 'cached', revisionId: envelope.revisionId, metadataOnly: true }
        },
        async cacheEncryptedPatchEnvelope(envelope) {
            await indexedDbAdapter.put('cloudSyncEncryptedPatches', envelope.revisionId, envelope)
            return { status: 'cached', revisionId: envelope.revisionId, metadataOnly: true }
        },
        debugSnapshot() {
            return {
                storageVersion: PHONE_PLANNER_CLOUD_STORAGE_VERSION,
                storage: 'indexeddb-webcrypto',
                hasDevice: !!session.device,
                hasSyncKeyInMemory: !!session.syncRootKey,
                rawKeyBytesStored: false,
                metadataOnly: true
            }
        }
    }
}
