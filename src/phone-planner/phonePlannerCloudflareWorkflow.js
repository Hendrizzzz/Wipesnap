import {
    createCloudSyncKeyGrantIdForDevice,
    createPairingChallenge,
    sha256Base64Url,
    validateCloudSyncDeviceRecordForPhone
} from './phonePlannerCloudCrypto.js'

function fail(message) {
    throw new Error(message)
}

function metadataResult(extra = {}) {
    return { metadataOnly: true, ...extra }
}

function authStateOrFail(authClient) {
    if (!authClient || typeof authClient.getSafeAuthState !== 'function') fail('Cloudflare owner auth is not initialized.')
    const state = authClient.getSafeAuthState()
    if (!state?.signedIn || !state.uid) fail('Set the Cloudflare staging owner uid first.')
    return state
}

async function persistPendingClaimSequence({ storage, deviceId, error } = {}) {
    if (!Number.isSafeInteger(error?.deviceSequence) || error.deviceSequence < 0) return
    if (typeof storage.updateEnrollmentRequestDeviceSequence === 'function') {
        await storage.updateEnrollmentRequestDeviceSequence({
            deviceId,
            deviceSequence: error.deviceSequence
        })
        return
    }
    if (typeof storage.updateDeviceSequence === 'function') {
        await storage.updateDeviceSequence(error.deviceSequence)
    }
}

export async function requestCloudflareHostedPlannerEnrollment({
    authClient,
    cloudflareClient,
    storage,
    keyVersion = 1,
    cryptoApi = globalThis.crypto
} = {}) {
    const auth = authStateOrFail(authClient)
    if (!storage || typeof storage.createPendingDevice !== 'function') fail('Phone planner cloud storage is not initialized.')
    const { device } = await storage.createPendingDevice({
        ownerUid: auth.uid,
        keyVersion
    })
    const pendingState = await storage.loadPendingDeviceState(device.deviceId)
    if (!pendingState?.signingPrivateKey) fail('Phone planner signing key is not active.')
    const pairingChallenge = createPairingChallenge(cryptoApi)
    const pairingChallengeHash = await sha256Base64Url(pairingChallenge, cryptoApi)
    const keyGrantId = createCloudSyncKeyGrantIdForDevice({
        deviceId: device.deviceId,
        keyVersion: device.keyVersion
    })
    const result = await cloudflareClient.requestEnrollment({
        document: device,
        pairingChallengeHash,
        deviceState: {
            ownerUid: auth.uid,
            device,
            signingPrivateKey: pendingState.signingPrivateKey
        },
        deviceSequence: device.deviceSequence
    })
    await storage.storeEnrollmentRequest({
        ownerUid: auth.uid,
        device,
        pairingChallenge,
        keyGrantId
    })
    return metadataResult({
        status: result.status || 'pending',
        requestId: device.deviceId,
        deviceId: device.deviceId,
        role: device.role,
        keyGrantId,
        pairingChallenge,
        pairingChallengeDisplay: pairingChallenge,
        deviceSessionClaimRequired: true,
        provider: 'cloudflare-d1-spike'
    })
}

export async function claimCloudflareHostedPlannerDeviceSession({
    authClient,
    cloudflareClient,
    storage,
    deviceId,
    cryptoApi = globalThis.crypto
} = {}) {
    const auth = authStateOrFail(authClient)
    const request = await storage.loadEnrollmentRequest(deviceId)
    if (!request) fail('No pending Cloudflare planner enrollment request is stored on this browser.')
    const pendingDevice = validateCloudSyncDeviceRecordForPhone(request.device)
    const keyGrantId = request.keyGrantId || createCloudSyncKeyGrantIdForDevice({
        deviceId: pendingDevice.deviceId,
        keyVersion: pendingDevice.keyVersion
    })
    if (typeof storage.restoreSession === 'function') {
        await storage.restoreSession(pendingDevice.deviceId).catch(() => null)
    }
    const pendingState = await storage.loadPendingDeviceState(pendingDevice.deviceId)
    if (!pendingState?.signingPrivateKey) fail('Phone planner signing key is not active.')
    const deviceSequence = pendingDevice.deviceSequence + 1
    const pairingChallengeHash = await sha256Base64Url(request.pairingChallenge, cryptoApi)
    let claim
    try {
        claim = await cloudflareClient.claimEnrollment({
            requestId: request.requestId,
            keyGrantId,
            pairingChallengeHash,
            deviceState: {
                ownerUid: auth.uid,
                device: { ...pendingDevice, status: 'active' },
                signingPrivateKey: pendingState.signingPrivateKey
            },
            deviceSequence
        })
    } catch (error) {
        await persistPendingClaimSequence({ storage, deviceId: pendingDevice.deviceId, error })
        throw error
    }
    const activeDevice = validateCloudSyncDeviceRecordForPhone({
        ...pendingDevice,
        ...(claim.device || {}),
        status: 'active',
        deviceSequence: claim.device?.deviceSequence || claim.deviceSequence || deviceSequence
    })
    await storage.storeClaimedDeviceSessionMetadata({
        ownerUid: auth.uid,
        device: activeDevice,
        keyGrantId
    })
    if (!claim.keyGrant) fail('Approved Cloudflare sync key grant is not readable yet.')
    await storage.activateKeyGrant({
        ownerUid: auth.uid,
        device: activeDevice,
        keyGrant: claim.keyGrant
    })
    return metadataResult({
        status: claim.status || 'accepted',
        deviceId: activeDevice.deviceId,
        keyGrantId,
        keyVersion: activeDevice.keyVersion,
        deviceSequence: activeDevice.deviceSequence,
        syncKeyActive: true,
        provider: 'cloudflare-d1-spike'
    })
}
