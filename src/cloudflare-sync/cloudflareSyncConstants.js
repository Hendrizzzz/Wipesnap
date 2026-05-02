export const CLOUDFLARE_SYNC_PROVIDER_ID = 'cloudflare-d1-spike'
export const CLOUDFLARE_SYNC_STAGING_CONFIG_PROVIDER_ID = 'cloudflare'
export const CLOUDFLARE_SYNC_SCHEMA_VERSION = 1
export const CLOUDFLARE_SYNC_CANONICAL_REQUEST_VERSION = 1

export const CLOUDFLARE_SYNC_SIGNING_HEADERS = Object.freeze({
    ownerUid: 'x-wipesnap-owner-uid',
    deviceId: 'x-wipesnap-device-id',
    deviceRole: 'x-wipesnap-device-role',
    enrollmentEpoch: 'x-wipesnap-enrollment-epoch',
    keyVersion: 'x-wipesnap-key-version',
    deviceSequence: 'x-wipesnap-device-sequence',
    requestedAt: 'x-wipesnap-requested-at',
    bodyHash: 'x-wipesnap-body-sha256',
    signatureAlg: 'x-wipesnap-signature-alg',
    signatureKeyId: 'x-wipesnap-signature-key-id',
    signature: 'x-wipesnap-signature'
})

export const CLOUDFLARE_SYNC_OPERATIONS = Object.freeze({
    bootstrapDesktop: 'bootstrap-desktop',
    requestEnrollment: 'request-enrollment',
    listPendingEnrollments: 'list-pending-enrollments',
    approveEnrollment: 'approve-enrollment',
    claimEnrollment: 'claim-enrollment',
    uploadSnapshot: 'upload-snapshot',
    getLatestSnapshot: 'get-latest-snapshot',
    getSnapshot: 'get-snapshot',
    uploadPatch: 'upload-patch',
    listPendingPatches: 'list-pending-patches',
    getPatch: 'get-patch',
    getDevice: 'get-device',
    recordPatchDecision: 'record-patch-decision',
    revokeDevice: 'revoke-device'
})

export const CLOUDFLARE_SYNC_ROUTES = Object.freeze({
    'POST /v1/bootstrap/desktop': CLOUDFLARE_SYNC_OPERATIONS.bootstrapDesktop,
    'POST /v1/enrollments/request': CLOUDFLARE_SYNC_OPERATIONS.requestEnrollment,
    'GET /v1/enrollments/pending': CLOUDFLARE_SYNC_OPERATIONS.listPendingEnrollments,
    'POST /v1/enrollments/approve': CLOUDFLARE_SYNC_OPERATIONS.approveEnrollment,
    'POST /v1/enrollments/claim': CLOUDFLARE_SYNC_OPERATIONS.claimEnrollment,
    'POST /v1/snapshots': CLOUDFLARE_SYNC_OPERATIONS.uploadSnapshot,
    'GET /v1/snapshots/latest': CLOUDFLARE_SYNC_OPERATIONS.getLatestSnapshot,
    'GET /v1/snapshots/:revisionId': CLOUDFLARE_SYNC_OPERATIONS.getSnapshot,
    'POST /v1/patches': CLOUDFLARE_SYNC_OPERATIONS.uploadPatch,
    'GET /v1/patches': CLOUDFLARE_SYNC_OPERATIONS.listPendingPatches,
    'GET /v1/patches/:revisionId': CLOUDFLARE_SYNC_OPERATIONS.getPatch,
    'GET /v1/devices/:deviceId': CLOUDFLARE_SYNC_OPERATIONS.getDevice,
    'POST /v1/patches/:revisionId/decision': CLOUDFLARE_SYNC_OPERATIONS.recordPatchDecision,
    'POST /v1/devices/:deviceId/revoke': CLOUDFLARE_SYNC_OPERATIONS.revokeDevice
})

export const CLOUDFLARE_SYNC_LIMITS = Object.freeze({
    maxRequestJsonBytes: 900 * 1024,
    maxEnvelopeJsonBytes: 768 * 1024,
    maxCiphertextBytes: 512 * 1024,
    maxDevicesPerOwner: 8,
    maxPendingEnrollmentsPerOwner: 8,
    maxSnapshotsRetainedPerOwner: 24,
    maxPendingPatchesPerOwner: 64,
    rateWindowMs: 60_000,
    maxBootstrapRequestsPerWindow: 6,
    maxSignedRequestsPerWindow: 30,
    maxEnrollmentRequestsPerWindow: 12,
    maxFailedSignaturesPerWindow: 10,
    maxClockSkewMs: 10 * 60_000
})

export const CLOUDFLARE_SYNC_STORAGE_DECISION = Object.freeze({
    authoritativeStore: 'd1',
    rejectKvAsAuthoritative: true,
    durableObjectsRequiredNow: false,
    reason: 'Replay, revocation, device sequence, and rate-limit state require SQL constraints and atomic writes. Workers KV is eventually consistent and must not authorize Wipesnap cloud sync operations.'
})
