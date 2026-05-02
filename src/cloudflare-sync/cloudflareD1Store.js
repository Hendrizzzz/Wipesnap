import { CloudflareSyncError } from './cloudflareSyncWorkerCore.js'
import { CLOUDFLARE_SYNC_LIMITS } from './cloudflareSyncConstants.js'

function clone(value) {
    return value == null ? value : JSON.parse(JSON.stringify(value))
}

function encode(value) {
    return JSON.stringify(value ?? null)
}

function decode(value, fallback = null) {
    if (value == null || value === '') return fallback
    try {
        return JSON.parse(value)
    } catch (_) {
        return fallback
    }
}

function requireDb(db) {
    if (!db || typeof db.prepare !== 'function') {
        throw new Error('Cloudflare sync D1 store requires a D1 database binding.')
    }
    return db
}

function fail(status, code, message) {
    throw new CloudflareSyncError(status, code, message)
}

function changedRows(result) {
    return Number(result?.meta?.changes ?? result?.changes ?? result?.meta?.rows_written ?? 0)
}

function rowToDevice(row) {
    if (!row) return null
    return {
        product: 'wipesnap',
        recordType: 'cloud-sync-device',
        schemaVersion: 1,
        ownerUid: row.owner_uid,
        deviceId: row.device_id,
        role: row.role,
        status: row.status,
        platform: row.platform,
        syncScopes: decode(row.sync_scopes_json, []),
        signingPublicKey: decode(row.signing_public_key_json, {}),
        wrapPublicKey: decode(row.wrap_public_key_json, {}),
        enrollmentEpoch: row.enrollment_epoch,
        keyVersion: row.key_version,
        deviceSequence: row.device_sequence,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        revokedAt: row.revoked_at ?? null,
        revokedByDeviceId: row.revoked_by_device_id ?? null
    }
}

function rowToEnrollment(row) {
    if (!row) return null
    return {
        requestId: row.request_id,
        deviceId: row.device_id,
        ownerUid: row.owner_uid,
        role: row.role,
        status: row.status,
        pairingChallengeHash: row.pairing_challenge_hash,
        requestedAt: row.requested_at,
        approvedAt: row.approved_at ?? null,
        claimedAt: row.claimed_at ?? null,
        approvedByDeviceId: row.approved_by_device_id ?? null,
        keyGrantId: row.key_grant_id ?? null,
        device: decode(row.device_json, null),
        metadataOnly: true
    }
}

function rowToEnvelope(row) {
    return row ? decode(row.envelope_json, null) : null
}

function rowToPatch(row) {
    if (!row) return null
    return {
        ownerUid: row.owner_uid,
        patchRevisionId: row.revision_id,
        baseRevisionId: row.base_revision_id ?? null,
        status: row.status,
        receivedAt: row.received_at,
        envelope: rowToEnvelope(row),
        metadataOnly: true
    }
}

export function createCloudflareD1Store({ db } = {}) {
    const database = requireDb(db)

    async function run(sql, ...params) {
        return database.prepare(sql).bind(...params).run()
    }

    async function first(sql, ...params) {
        return database.prepare(sql).bind(...params).first()
    }

    async function all(sql, ...params) {
        const result = await database.prepare(sql).bind(...params).all()
        return Array.isArray(result?.results) ? result.results : []
    }

    async function batch(statements) {
        if (typeof database.batch === 'function') return database.batch(statements)
        const results = []
        for (const statement of statements) results.push(await statement.run())
        return results
    }

    async function atomicBatch(statements) {
        if (typeof database.batch !== 'function') {
            throw new Error('Cloudflare sync D1 store requires batch transactions for this operation.')
        }
        return database.batch(statements)
    }

    function statement(sql, ...params) {
        return database.prepare(sql).bind(...params)
    }

    function guardExists(sql, ...params) {
        return statement(
            `INSERT INTO cloudflare_sync_owners
             (owner_uid, schema_version, status, active_key_version, created_at, updated_at)
             SELECT '__approval_guard__', 1, 'invalid', 1, 0, 0
             WHERE NOT EXISTS (${sql})`,
            ...params
        )
    }

    async function createOwner(ownerUid, now) {
        const result = await run(
            `INSERT INTO cloudflare_sync_owners (owner_uid, schema_version, status, active_key_version, created_at, updated_at)
             VALUES (?, 1, 'active', 1, ?, ?)
             ON CONFLICT(owner_uid) DO NOTHING`,
            ownerUid,
            now,
            now
        )
        if (changedRows(result) !== 1) fail(409, 'owner-exists', 'Cloudflare sync owner is already bootstrapped.')
    }

    async function requireOwner(ownerUid) {
        const owner = await first(
            `SELECT owner_uid, status FROM cloudflare_sync_owners WHERE owner_uid = ?`,
            ownerUid
        )
        if (!owner || owner.status !== 'active') fail(404, 'owner-not-found', 'Cloudflare sync owner is not bootstrapped.')
        return owner
    }

    async function countActiveDevices(ownerUid) {
        const row = await first(
            `SELECT COUNT(*) AS count FROM cloudflare_sync_devices
             WHERE owner_uid = ? AND status = 'active'`,
            ownerUid
        )
        return Number(row?.count || 0)
    }

    async function createDevice(device, now) {
        const result = await run(
            `INSERT INTO cloudflare_sync_devices (
                owner_uid, device_id, role, status, platform, sync_scopes_json,
                signing_public_key_json, wrap_public_key_json, enrollment_epoch, key_version,
                device_sequence, created_at, updated_at, revoked_at, revoked_by_device_id, last_seen_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(owner_uid, device_id) DO NOTHING`,
            device.ownerUid,
            device.deviceId,
            device.role,
            device.status,
            device.platform,
            encode(device.syncScopes),
            encode(device.signingPublicKey),
            encode(device.wrapPublicKey),
            device.enrollmentEpoch,
            device.keyVersion,
            device.deviceSequence,
            device.createdAt,
            device.updatedAt || now,
            device.revokedAt,
            device.revokedByDeviceId,
            now
        )
        if (changedRows(result) !== 1) fail(409, 'device-exists', 'Cloudflare sync device already exists.')
    }

    async function assertActiveDesktop(ownerUid, desktopDeviceId) {
        const desktop = await first(
            `SELECT device_id FROM cloudflare_sync_devices
             WHERE owner_uid = ? AND device_id = ? AND role = 'desktop' AND status = 'active' AND revoked_at IS NULL`,
            ownerUid,
            desktopDeviceId
        )
        if (!desktop) fail(403, 'desktop-required', 'Cloudflare sync mutation requires an active desktop device.')
    }

    return {
        async getDevice(ownerUid, deviceId) {
            const row = await first(
                `SELECT * FROM cloudflare_sync_devices WHERE owner_uid = ? AND device_id = ?`,
                ownerUid,
                deviceId
            )
            const device = rowToDevice(row)
            if (!device) fail(403, 'wrong-device', 'Cloudflare sync device is not enrolled.')
            return device
        },

        async recordFailedSignature({
            ownerUid = 'unknown',
            deviceId = 'unknown',
            ipHash = 'unknown',
            bucketMs = Math.floor(Date.now() / CLOUDFLARE_SYNC_LIMITS.rateWindowMs) * CLOUDFLARE_SYNC_LIMITS.rateWindowMs,
            max = CLOUDFLARE_SYNC_LIMITS.maxFailedSignaturesPerWindow,
            now = Date.now()
        } = {}) {
            await run(
                `INSERT INTO cloudflare_sync_failed_signatures (owner_uid, device_id, ip_hash, bucket_ms, count, first_seen_at, updated_at)
                 VALUES (?, ?, ?, ?, 1, ?, ?)
                 ON CONFLICT(owner_uid, device_id, ip_hash, bucket_ms) DO UPDATE SET
                    count = count + 1,
                    updated_at = excluded.updated_at`,
                ownerUid || 'unknown',
                deviceId || 'unknown',
                ipHash || 'unknown',
                bucketMs,
                now,
                now
            )
            const row = await first(
                `SELECT count FROM cloudflare_sync_failed_signatures
                 WHERE owner_uid = ? AND device_id = ? AND ip_hash = ? AND bucket_ms = ?`,
                ownerUid || 'unknown',
                deviceId || 'unknown',
                ipHash || 'unknown',
                bucketMs
            )
            if (Number(row?.count || 0) > max) fail(429, 'failed-signature-rate-limited', 'Cloudflare sync failed-signature limit exceeded.')
        },

        async advanceDeviceSequence({ ownerUid, deviceId, deviceSequence, operation, documentId, now }) {
            const accepted = await first(
                `UPDATE cloudflare_sync_devices
                 SET device_sequence = ?, updated_at = ?, last_seen_at = ?
                 WHERE owner_uid = ? AND device_id = ? AND status = 'active' AND revoked_at IS NULL AND device_sequence < ?
                 RETURNING device_sequence`,
                deviceSequence,
                now,
                now,
                ownerUid,
                deviceId,
                deviceSequence
            )
            if (!accepted) {
                const current = await first(
                    `SELECT device_sequence, status, revoked_at FROM cloudflare_sync_devices WHERE owner_uid = ? AND device_id = ?`,
                    ownerUid,
                    deviceId
                )
                if (!current || current.status !== 'active' || current.revoked_at != null) {
                    fail(403, 'revoked-device', 'Cloudflare sync device is not active.')
                }
                fail(403, 'duplicate-sequence', 'Cloudflare sync device sequence was already used.')
            }
            await run(
                `INSERT OR IGNORE INTO cloudflare_sync_device_sequences
                 (owner_uid, device_id, device_sequence, operation, document_id, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)`,
                ownerUid,
                deviceId,
                deviceSequence,
                operation,
                documentId,
                now
            )
        },

        async recordRateLimit({
            ownerUid,
            deviceId,
            ipHash = 'unknown',
            action = 'signed-request',
            bucketMs,
            max,
            now = bucketMs
        }) {
            await run(
                `INSERT INTO cloudflare_sync_rate_limits (owner_uid, device_id, ip_hash, action, bucket_ms, count, first_seen_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                 ON CONFLICT(owner_uid, device_id, ip_hash, action, bucket_ms) DO UPDATE SET
                    count = count + 1,
                    updated_at = excluded.updated_at`,
                ownerUid,
                deviceId,
                ipHash || 'unknown',
                action,
                bucketMs,
                now,
                now
            )
            const row = await first(
                `SELECT count FROM cloudflare_sync_rate_limits
                 WHERE owner_uid = ? AND device_id = ? AND ip_hash = ? AND action = ? AND bucket_ms = ?`,
                ownerUid,
                deviceId,
                ipHash || 'unknown',
                action,
                bucketMs
            )
            if (Number(row?.count || 0) > max) fail(429, 'rate-limited', 'Cloudflare sync request rate limit exceeded.')
        },

        async bootstrapDesktop({ ownerUid, device, now }) {
            await createOwner(ownerUid, now)
            await createDevice(device, now)
            await run(
                `INSERT INTO cloudflare_sync_state (owner_uid, active_key_version, updated_at)
                 VALUES (?, ?, ?)`,
                ownerUid,
                device.keyVersion,
                now
            )
        },

        async requestEnrollment({ ownerUid, requestId, device, pairingChallengeHash, now }) {
            await requireOwner(ownerUid)
            if (await countActiveDevices(ownerUid) >= CLOUDFLARE_SYNC_LIMITS.maxDevicesPerOwner) {
                fail(429, 'device-limit', 'Cloudflare sync device limit reached.')
            }
            const pending = await first(
                `SELECT COUNT(*) AS count FROM cloudflare_sync_enrollment_requests
                 WHERE owner_uid = ? AND status = 'pending'`,
                ownerUid
            )
            if (Number(pending?.count || 0) >= CLOUDFLARE_SYNC_LIMITS.maxPendingEnrollmentsPerOwner) {
                fail(429, 'enrollment-rate-limited', 'Too many pending Cloudflare sync enrollments.')
            }
            await createDevice(device, now)
            const result = await run(
                `INSERT INTO cloudflare_sync_enrollment_requests
                 (owner_uid, request_id, device_id, role, status, pairing_challenge_hash, device_json, requested_at, expires_at)
                 VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?)
                 ON CONFLICT(owner_uid, request_id) DO NOTHING`,
                ownerUid,
                requestId,
                device.deviceId,
                device.role,
                pairingChallengeHash,
                encode(device),
                now,
                now + 30 * 60_000
            )
            if (changedRows(result) !== 1) fail(409, 'enrollment-exists', 'Cloudflare sync enrollment already exists.')
        },

        async listPendingEnrollments(ownerUid) {
            const rows = await all(
                `SELECT * FROM cloudflare_sync_enrollment_requests
                 WHERE owner_uid = ? AND status = 'pending'
                 ORDER BY requested_at ASC
                 LIMIT ?`,
                ownerUid,
                CLOUDFLARE_SYNC_LIMITS.maxPendingEnrollmentsPerOwner
            )
            return rows.map(rowToEnrollment)
        },

        async approveEnrollment({ ownerUid, requestId, desktopDeviceId, keyGrant, now }) {
            await assertActiveDesktop(ownerUid, desktopDeviceId)
            const request = await first(
                `SELECT * FROM cloudflare_sync_enrollment_requests
                 WHERE owner_uid = ? AND request_id = ? AND status = 'pending'`,
                ownerUid,
                requestId
            )
            if (!request) fail(404, 'not-found', 'Pending Cloudflare sync enrollment was not found.')
            if (keyGrant.recipientDeviceId !== request.device_id) {
                fail(403, 'wrong-device', 'Cloudflare sync key grant recipient does not match enrollment.')
            }
            const device = { ...decode(request.device_json, {}), status: 'active', updatedAt: now }
            try {
                await atomicBatch([
                    statement(
                        `UPDATE cloudflare_sync_devices
                         SET status = 'active', updated_at = ?
                         WHERE owner_uid = ? AND device_id = ? AND status = 'pending' AND revoked_at IS NULL`,
                        now,
                        ownerUid,
                        request.device_id
                    ),
                    guardExists(
                        `SELECT 1 FROM cloudflare_sync_devices
                         WHERE owner_uid = ? AND device_id = ? AND status = 'active' AND revoked_at IS NULL`,
                        ownerUid,
                        request.device_id
                    ),
                    statement(
                        `INSERT INTO cloudflare_sync_key_grants
                         (owner_uid, grant_id, recipient_device_id, created_by_device_id, key_version, wrap_alg,
                          wrapped_key_ciphertext, wrapped_key_hash, grant_json, created_at, revoked_at, revoked_by_device_id)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                        ownerUid,
                        keyGrant.grantId,
                        keyGrant.recipientDeviceId,
                        desktopDeviceId,
                        keyGrant.keyVersion,
                        keyGrant.wrapAlg,
                        keyGrant.wrappedKeyCiphertext,
                        keyGrant.wrappedKeyHash,
                        encode(keyGrant),
                        keyGrant.createdAt,
                        keyGrant.revokedAt,
                        keyGrant.revokedByDeviceId
                    ),
                    guardExists(
                        `SELECT 1 FROM cloudflare_sync_key_grants
                         WHERE owner_uid = ? AND grant_id = ? AND recipient_device_id = ?`,
                        ownerUid,
                        keyGrant.grantId,
                        keyGrant.recipientDeviceId
                    ),
                    statement(
                        `UPDATE cloudflare_sync_enrollment_requests
                         SET status = 'approved', approved_at = ?, approved_by_device_id = ?, key_grant_id = ?
                         WHERE owner_uid = ? AND request_id = ? AND status = 'pending'`,
                        now,
                        desktopDeviceId,
                        keyGrant.grantId,
                        ownerUid,
                        requestId
                    ),
                    guardExists(
                        `SELECT 1 FROM cloudflare_sync_enrollment_requests
                         WHERE owner_uid = ? AND request_id = ? AND status = 'approved'
                           AND approved_by_device_id = ? AND key_grant_id = ?`,
                        ownerUid,
                        requestId,
                        desktopDeviceId,
                        keyGrant.grantId
                    )
                ])
            } catch (_) {
                fail(409, 'approval-conflict', 'Cloudflare sync enrollment approval did not commit atomically.')
            }
            return { device: clone(device), keyGrant: clone(keyGrant) }
        },

        async claimEnrollment({ ownerUid, requestId, deviceId, keyGrantId, pairingChallengeHash, now }) {
            const row = await first(
                `SELECT * FROM cloudflare_sync_enrollment_requests
                 WHERE owner_uid = ? AND request_id = ? AND device_id = ? AND key_grant_id = ?`,
                ownerUid,
                requestId,
                deviceId,
                keyGrantId
            )
            if (!row || row.status !== 'approved') fail(404, 'not-found', 'Approved Cloudflare sync enrollment was not found.')
            if (row.pairing_challenge_hash !== pairingChallengeHash) fail(403, 'pairing-mismatch', 'Pairing challenge does not match.')
            const grantRow = await first(
                `SELECT grant_json FROM cloudflare_sync_key_grants
                 WHERE owner_uid = ? AND grant_id = ? AND recipient_device_id = ? AND revoked_at IS NULL`,
                ownerUid,
                keyGrantId,
                deviceId
            )
            if (!grantRow) fail(404, 'not-found', 'Cloudflare sync key grant was not found.')
            await run(
                `UPDATE cloudflare_sync_enrollment_requests
                 SET status = 'claimed', claimed_at = ?
                 WHERE owner_uid = ? AND request_id = ?`,
                now,
                ownerUid,
                requestId
            )
            return {
                device: await this.getDevice(ownerUid, deviceId),
                keyGrant: decode(grantRow.grant_json, null)
            }
        },

        async insertSnapshot({ ownerUid, envelope, now }) {
            await batch([
                statement(
                    `INSERT INTO cloudflare_sync_snapshots
                     (owner_uid, revision_id, snapshot_id, device_id, device_sequence, key_version, status,
                      created_at, updated_at, received_at, ciphertext_hash, envelope_json)
                     VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?, ?)`,
                    ownerUid,
                    envelope.revisionId,
                    envelope.snapshotId,
                    envelope.deviceId,
                    envelope.deviceSequence,
                    envelope.keyVersion,
                    envelope.createdAt,
                    envelope.updatedAt,
                    now,
                    envelope.ciphertextHash,
                    encode(envelope)
                ),
                statement(
                    `INSERT INTO cloudflare_sync_state (owner_uid, latest_snapshot_revision_id, active_key_version, updated_at)
                     VALUES (?, ?, ?, ?)
                     ON CONFLICT(owner_uid) DO UPDATE SET
                        latest_snapshot_revision_id = excluded.latest_snapshot_revision_id,
                        active_key_version = excluded.active_key_version,
                        updated_at = excluded.updated_at`,
                    ownerUid,
                    envelope.revisionId,
                    envelope.keyVersion,
                    now
                ),
                statement(
                    `DELETE FROM cloudflare_sync_snapshots
                     WHERE owner_uid = ?
                       AND revision_id NOT IN (
                         SELECT revision_id FROM cloudflare_sync_snapshots
                         WHERE owner_uid = ?
                         ORDER BY received_at DESC, revision_id DESC
                         LIMIT ?
                       )`,
                    ownerUid,
                    ownerUid,
                    CLOUDFLARE_SYNC_LIMITS.maxSnapshotsRetainedPerOwner
                )
            ])
        },

        async getLatestSnapshot(ownerUid) {
            const row = await first(
                `SELECT s.envelope_json
                 FROM cloudflare_sync_state st
                 JOIN cloudflare_sync_snapshots s
                    ON s.owner_uid = st.owner_uid AND s.revision_id = st.latest_snapshot_revision_id
                 WHERE st.owner_uid = ?`,
                ownerUid
            )
            return rowToEnvelope(row)
        },

        async getSnapshot(ownerUid, revisionId) {
            const row = await first(
                `SELECT envelope_json FROM cloudflare_sync_snapshots
                 WHERE owner_uid = ? AND revision_id = ?`,
                ownerUid,
                revisionId
            )
            return rowToEnvelope(row)
        },

        async insertPatch({ ownerUid, envelope, now }) {
            const pending = await first(
                `SELECT COUNT(*) AS count FROM cloudflare_sync_patches
                 WHERE owner_uid = ? AND status = 'pending'`,
                ownerUid
            )
            if (Number(pending?.count || 0) >= CLOUDFLARE_SYNC_LIMITS.maxPendingPatchesPerOwner) {
                fail(429, 'patch-limit', 'Too many pending Cloudflare sync patches.')
            }
            await run(
                `INSERT INTO cloudflare_sync_patches
                 (owner_uid, revision_id, patch_id, base_revision_id, device_id, device_sequence, key_version,
                  status, created_at, updated_at, received_at, ciphertext_hash, envelope_json)
                 VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)`,
                ownerUid,
                envelope.revisionId,
                envelope.patchId,
                envelope.baseRevisionId,
                envelope.deviceId,
                envelope.deviceSequence,
                envelope.keyVersion,
                envelope.createdAt,
                envelope.updatedAt,
                now,
                envelope.ciphertextHash,
                encode(envelope)
            )
        },

        async listPatches(ownerUid, status = 'pending') {
            const rows = await all(
                `SELECT * FROM cloudflare_sync_patches
                 WHERE owner_uid = ? AND status = ?
                 ORDER BY received_at ASC
                 LIMIT ?`,
                ownerUid,
                status,
                CLOUDFLARE_SYNC_LIMITS.maxPendingPatchesPerOwner
            )
            return rows.map(rowToPatch)
        },

        async getPatch(ownerUid, revisionId, status = null) {
            const row = status
                ? await first(
                    `SELECT * FROM cloudflare_sync_patches
                     WHERE owner_uid = ? AND revision_id = ? AND status = ?`,
                    ownerUid,
                    revisionId,
                    status
                )
                : await first(
                    `SELECT * FROM cloudflare_sync_patches
                     WHERE owner_uid = ? AND revision_id = ?`,
                    ownerUid,
                    revisionId
                )
            return rowToPatch(row)
        },

        async recordPatchDecision({ ownerUid, decision, now }) {
            await batch([
                statement(
                    `INSERT INTO cloudflare_sync_patch_apply_decisions
                     (owner_uid, patch_revision_id, desktop_device_id, source_patch_device_id, status,
                      reason, decided_at, decision_json)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                     ON CONFLICT(owner_uid, patch_revision_id) DO UPDATE SET
                        desktop_device_id = excluded.desktop_device_id,
                        source_patch_device_id = excluded.source_patch_device_id,
                        status = excluded.status,
                        reason = excluded.reason,
                        decided_at = excluded.decided_at,
                        decision_json = excluded.decision_json`,
                    ownerUid,
                    decision.patchRevisionId,
                    decision.desktopDeviceId,
                    decision.sourcePatchDeviceId,
                    decision.status,
                    decision.reason,
                    decision.decidedAt,
                    encode(decision)
                ),
                statement(
                    `UPDATE cloudflare_sync_patches
                     SET status = ?, updated_at = ?
                     WHERE owner_uid = ? AND revision_id = ?`,
                    decision.status,
                    now,
                    ownerUid,
                    decision.patchRevisionId
                )
            ])
        },

        async revokeDevice({ ownerUid, targetDeviceId, revokedByDeviceId, now }) {
            if (targetDeviceId === revokedByDeviceId) fail(403, 'wrong-device', 'Desktop cannot revoke itself through phone sync.')
            await assertActiveDesktop(ownerUid, revokedByDeviceId)
            const revoked = await first(
                `UPDATE cloudflare_sync_devices
                 SET status = 'revoked', revoked_at = ?, revoked_by_device_id = ?, updated_at = ?
                 WHERE owner_uid = ? AND device_id = ? AND status != 'revoked'
                 RETURNING device_id`,
                now,
                revokedByDeviceId,
                now,
                ownerUid,
                targetDeviceId
            )
            if (!revoked) fail(404, 'not-found', 'Cloudflare sync device was not found or is already revoked.')
        }
    }
}
