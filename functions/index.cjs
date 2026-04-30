'use strict'

const admin = require('firebase-admin')
const { onCall, HttpsError } = require('firebase-functions/v2/https')

if (!admin.apps.length) admin.initializeApp()

function httpsCodeForIngestionCode(code) {
    if (code === 'unauthenticated') return 'unauthenticated'
    if (code === 'permission-denied') return 'permission-denied'
    if (code === 'already-exists') return 'already-exists'
    if (code === 'resource-exhausted') return 'resource-exhausted'
    if (code === 'failed-precondition') return 'failed-precondition'
    if (code === 'invalid-argument') return 'invalid-argument'
    return 'internal'
}

function authIssuer() {
    return {
        createCustomToken(uid, claims) {
            return admin.auth().createCustomToken(uid, claims)
        }
    }
}

function adminStore() {
    return import('./shared/main/cloudSyncIngestion.js')
        .then(({ createFirestoreAdminStore }) => createFirestoreAdminStore(admin.firestore()))
}

async function mapCloudSyncErrors(callback) {
    try {
        return await callback()
    } catch (error) {
        throw new HttpsError(
            httpsCodeForIngestionCode(error.code),
            error.message || 'Cloud sync operation failed closed.'
        )
    }
}

exports.ingestCloudSyncDocument = onCall({ region: 'us-central1' }, async request => {
    const {
        createFirestoreAdminStore,
        ingestCloudSyncDocument
    } = await import('./shared/main/cloudSyncIngestion.js')

    return mapCloudSyncErrors(() =>
        ingestCloudSyncDocument({
            auth: request.auth
                ? { uid: request.auth.uid, token: request.auth.token || {} }
                : null,
            operation: request.data?.operation,
            documentId: request.data?.documentId,
            document: request.data?.document,
            signature: request.data?.signature,
            deviceSequence: request.data?.deviceSequence,
            requestedAt: request.data?.requestedAt,
            store: createFirestoreAdminStore(admin.firestore()),
            now: Date.now()
        })
    )
})

exports.bootstrapCloudSyncDesktopDevice = onCall({ region: 'us-central1' }, async request => {
    const { bootstrapCloudSyncDesktopDevice } = await import('./shared/main/cloudSyncIngestion.js')
    return mapCloudSyncErrors(async () =>
        bootstrapCloudSyncDesktopDevice({
            auth: request.auth
                ? { uid: request.auth.uid, token: request.auth.token || {} }
                : null,
            documentId: request.data?.documentId,
            document: request.data?.document,
            signature: request.data?.signature,
            requestedAt: request.data?.requestedAt,
            store: await adminStore(),
            authIssuer: authIssuer(),
            now: Date.now()
        })
    )
})

exports.requestCloudSyncDeviceEnrollment = onCall({ region: 'us-central1' }, async request => {
    const { requestCloudSyncDeviceEnrollment } = await import('./shared/main/cloudSyncIngestion.js')
    return mapCloudSyncErrors(async () =>
        requestCloudSyncDeviceEnrollment({
            auth: request.auth
                ? { uid: request.auth.uid, token: request.auth.token || {} }
                : null,
            requestId: request.data?.requestId,
            documentId: request.data?.documentId,
            document: request.data?.document,
            pairingChallenge: request.data?.pairingChallenge,
            signature: request.data?.signature,
            requestedAt: request.data?.requestedAt,
            store: await adminStore(),
            now: Date.now()
        })
    )
})

exports.approveCloudSyncDeviceEnrollment = onCall({ region: 'us-central1' }, async request => {
    const { approveCloudSyncDeviceEnrollment } = await import('./shared/main/cloudSyncIngestion.js')
    return mapCloudSyncErrors(async () =>
        approveCloudSyncDeviceEnrollment({
            auth: request.auth
                ? { uid: request.auth.uid, token: request.auth.token || {} }
                : null,
            requestId: request.data?.requestId,
            documentId: request.data?.documentId,
            signature: request.data?.signature,
            deviceSequence: request.data?.deviceSequence,
            requestedAt: request.data?.requestedAt,
            store: await adminStore(),
            now: Date.now()
        })
    )
})

exports.claimApprovedCloudSyncDeviceSession = onCall({ region: 'us-central1' }, async request => {
    const { claimApprovedCloudSyncDeviceSession } = await import('./shared/main/cloudSyncIngestion.js')
    return mapCloudSyncErrors(async () =>
        claimApprovedCloudSyncDeviceSession({
            auth: request.auth
                ? { uid: request.auth.uid, token: request.auth.token || {} }
                : null,
            requestId: request.data?.requestId,
            deviceId: request.data?.deviceId,
            keyGrantId: request.data?.keyGrantId,
            pairingChallenge: request.data?.pairingChallenge,
            signature: request.data?.signature,
            deviceSequence: request.data?.deviceSequence,
            requestedAt: request.data?.requestedAt,
            store: await adminStore(),
            authIssuer: authIssuer(),
            now: Date.now()
        })
    )
})

exports.approveCloudSyncKeyGrant = onCall({ region: 'us-central1' }, async request => {
    const { approveCloudSyncKeyGrant } = await import('./shared/main/cloudSyncIngestion.js')
    return mapCloudSyncErrors(async () =>
        approveCloudSyncKeyGrant({
            auth: request.auth
                ? { uid: request.auth.uid, token: request.auth.token || {} }
                : null,
            documentId: request.data?.documentId,
            document: request.data?.document,
            signature: request.data?.signature,
            deviceSequence: request.data?.deviceSequence,
            requestedAt: request.data?.requestedAt,
            store: await adminStore(),
            now: Date.now()
        })
    )
})

exports.recordCloudSyncPatchApplyDecision = onCall({ region: 'us-central1' }, async request => {
    const { recordCloudSyncPatchApplyDecision } = await import('./shared/main/cloudSyncIngestion.js')
    return mapCloudSyncErrors(async () =>
        recordCloudSyncPatchApplyDecision({
            auth: request.auth
                ? { uid: request.auth.uid, token: request.auth.token || {} }
                : null,
            documentId: request.data?.documentId,
            document: request.data?.document,
            signature: request.data?.signature,
            deviceSequence: request.data?.deviceSequence,
            requestedAt: request.data?.requestedAt,
            store: await adminStore(),
            now: Date.now()
        })
    )
})

exports.revokeCloudSyncDevice = onCall({ region: 'us-central1' }, async request => {
    const { revokeCloudSyncDevice } = await import('./shared/main/cloudSyncIngestion.js')
    return mapCloudSyncErrors(async () =>
        revokeCloudSyncDevice({
            auth: request.auth
                ? { uid: request.auth.uid, token: request.auth.token || {} }
                : null,
            targetDeviceId: request.data?.targetDeviceId,
            signature: request.data?.signature,
            deviceSequence: request.data?.deviceSequence,
            requestedAt: request.data?.requestedAt,
            store: await adminStore(),
            now: Date.now()
        })
    )
})

exports._cloudSyncTestHooks = {
    httpsCodeForIngestionCode
}
