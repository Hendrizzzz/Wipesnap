import assert from 'assert/strict'
import { test } from 'node:test'
import { createCapabilityRecord } from '../src/main/capabilityStore.js'
import {
    WORKSPACE_CAPABILITY_VAULT_KEY
} from '../src/main/workspaceCapabilityMigration.js'
import {
    SAFE_PRESET_METADATA_VERSION,
    WORKSPACE_SAFE_PRESET_METADATA_KEY
} from '../src/main/safePresetMetadata.js'
import { buildSanitizedPresetSnapshot } from '../src/main/sanitizedPresetSnapshot.js'
import {
    SAFE_PRESET_PATCH_KIND,
    planSafePresetPatchImport
} from '../src/main/safePresetPatch.js'
import { mergeSafePresetPatchPlanAfterUnlock } from '../src/main/safePresetPatchMerge.js'

const SECRET = Buffer.from('phase-22-safe-preset-merge-secret-32-bytes')
const NOW = 1770000000000
const ACCOUNT_ID = `acct_${'f6'.repeat(24)}`
const PROFILE_ID = 'profile_personal'

function clone(value) {
    return JSON.parse(JSON.stringify(value))
}

function bytes(hexByte) {
    return (size) => Buffer.alloc(size, hexByte)
}

function hostExeRecord(hexByte = 0x51) {
    return createCapabilityRecord({
        type: 'host-exe',
        provenance: 'browse-exe',
        displayName: 'Cursor',
        launch: {
            path: 'C:\\Program Files\\Cursor\\Cursor.exe'
        },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: true,
            ownership: 'owned-process'
        }
    }, {
        randomBytes: bytes(hexByte),
        now: '2026-04-29T00:00:00.000Z'
    })
}

function hostFolderRecord(hexByte = 0x52) {
    return createCapabilityRecord({
        type: 'host-folder',
        provenance: 'browse-folder',
        displayName: 'Projects',
        launch: {
            path: 'C:\\Users\\Alice\\Projects'
        },
        policy: {
            allowedArgs: 'none',
            canCloseFromWipesnap: false,
            ownership: 'external'
        }
    }, {
        randomBytes: bytes(hexByte),
        now: '2026-04-29T00:00:00.000Z'
    })
}

function workspaceFixture() {
    const appRecord = hostExeRecord()
    const folderRecord = hostFolderRecord()
    return {
        id: 'desktop-workspace-raw-id',
        name: 'Coding',
        defaultPresetId: 'coding-preset',
        nextPresetId: 'coding-preset',
        webTabs: [{
            id: 'raw-tab-ai-studio',
            url: 'https://aistudio.google.com/',
            label: 'AI Studio',
            enabled: true,
            accountSlotId: ACCOUNT_ID,
            profileSlotId: PROFILE_ID
        }],
        desktopApps: [
            {
                id: 'raw-app-cursor',
                capabilityId: appRecord.capabilityId,
                displayName: 'Cursor',
                enabled: true
            },
            {
                id: 'raw-folder-projects',
                capabilityId: folderRecord.capabilityId,
                displayName: 'Projects',
                enabled: true
            }
        ],
        accountSlots: [{
            id: ACCOUNT_ID,
            provider: 'google',
            label: 'Personal Google',
            identifierHint: 'p***@gmail.com',
            state: 'needs-recheck',
            lastCheckedAt: 0,
            notes: ''
        }],
        browserProfileSlots: [{
            id: PROFILE_ID,
            provider: 'google',
            label: 'Personal'
        }],
        [WORKSPACE_CAPABILITY_VAULT_KEY]: {
            version: 1,
            records: {
                [appRecord.capabilityId]: appRecord,
                [folderRecord.capabilityId]: folderRecord
            }
        }
    }
}

function buildSnapshot(workspace, { revisionId = 'desktop-revision-raw-id' } = {}) {
    return buildSanitizedPresetSnapshot({
        snapshotSafeIdSecret: SECRET,
        sourceDeviceId: 'desktop-device-raw-id',
        snapshotId: 'desktop-snapshot-raw-id',
        revisionId,
        baseRevisionId: 'desktop-base-revision-raw-id',
        timestamp: NOW,
        workspace,
        presets: [
            {
                id: 'coding-preset',
                name: 'Coding',
                order: 0,
                enabled: true,
                itemRefs: [{
                    browserTabId: 'raw-tab-ai-studio',
                    order: 0,
                    enabled: true,
                    accountSlotId: ACCOUNT_ID,
                    profileSlotId: PROFILE_ID
                }]
            }
        ]
    })
}

function itemOf(snapshot, type) {
    const item = snapshot.availableItems.find(entry => entry.type === type && entry.status !== 'redacted')
    assert.ok(item, `Missing ${type}`)
    return item
}

function idsFor(snapshot) {
    return {
        preset: snapshot.presets[0],
        browser: itemOf(snapshot, 'browser-tab'),
        desktop: itemOf(snapshot, 'desktop-app'),
        folder: itemOf(snapshot, 'host-folder'),
        account: itemOf(snapshot, 'account-intention'),
        profile: itemOf(snapshot, 'profile-intention')
    }
}

function validPatch(snapshot, mutator = () => {}) {
    const ids = idsFor(snapshot)
    const patch = {
        product: 'wipesnap',
        kind: SAFE_PRESET_PATCH_KIND,
        schemaVersion: 1,
        patchId: 'patch_phase22_merge',
        patchRevisionId: 'patchrev_phase22_merge_1',
        baseSnapshotRevisionId: snapshot.revisionId,
        authorDeviceId: 'dev_phone_phase22',
        createdAt: NOW,
        updatedAt: NOW + 1,
        selection: {
            defaultPresetId: ids.preset.id,
            nextPresetId: ids.preset.id,
            metadataOnly: true,
            selectionKind: 'metadata-only'
        },
        newBrowserItems: [],
        presets: [{
            id: ids.preset.id,
            name: 'Coding Phone',
            order: 2,
            enabled: false,
            itemRefs: [
                {
                    itemId: ids.desktop.id,
                    order: 0,
                    enabled: false,
                    metadataOnly: true
                },
                {
                    itemId: ids.browser.id,
                    order: 1,
                    enabled: true,
                    accountIntentionId: ids.account.id,
                    profileIntentionId: ids.profile.id,
                    metadataOnly: true
                },
                {
                    itemId: ids.folder.id,
                    order: 2,
                    enabled: true,
                    metadataOnly: true
                }
            ],
            metadataOnly: true
        }]
    }
    mutator(patch, ids)
    return patch
}

function patchWithNewTab(snapshot, mutator = () => {}) {
    return validPatch(snapshot, (patch, ids) => {
        patch.newBrowserItems = [{
            id: 'patch_item_docs_phone',
            url: 'docs.google.com',
            label: 'Docs',
            notes: 'Class notes',
            enabled: true,
            accountIntentionId: ids.account.id,
            profileIntentionId: ids.profile.id,
            metadataOnly: true
        }]
        patch.presets[0].itemRefs.push({
            itemId: 'patch_item_docs_phone',
            order: 3,
            enabled: true,
            accountIntentionId: ids.account.id,
            profileIntentionId: ids.profile.id,
            metadataOnly: true
        })
        mutator(patch, ids)
    })
}

function planFor(snapshot, patch = validPatch(snapshot)) {
    return planSafePresetPatchImport({
        sanitizedSnapshot: snapshot,
        patch
    })
}

function callerContext() {
    return {
        unlocked: true,
        vaultBacked: true,
        authority: 'desktop-main'
    }
}

function createHarness(workspace, {
    unlocked = true,
    includeCommit = true,
    failCommit = false
} = {}) {
    let storedWorkspace = clone(workspace)
    let activePassword = unlocked ? 'active-password' : ''
    let meta = { version: '1.0.0' }
    const calls = {
        activeSessionChecks: 0,
        commits: [],
        vaultWrites: 0,
        metaWrites: 0
    }
    const encryptedVault = (payload, password, isHardwareBound = false) => ({
        payload: clone(payload),
        password,
        isHardwareBound
    })
    const deps = {
        requireActiveSession: () => {
            calls.activeSessionChecks += 1
            if (!activePassword) throw new Error('Session is locked')
        },
        loadActiveVaultWorkspace: () => {
            if (!activePassword) throw new Error('Session is locked')
            const workspaceCopy = clone(storedWorkspace)
            delete workspaceCopy._honeyToken
            return workspaceCopy
        },
        loadVaultMeta: () => clone(meta),
        getDriveInfo: async () => ({ driveType: 2, serialNumber: 'USB1234', isRemovable: true }),
        getActiveMasterPassword: () => activePassword,
        encryptVault: encryptedVault,
        writeVault: () => {
            calls.vaultWrites += 1
        },
        saveVaultMeta: () => {
            calls.metaWrites += 1
        },
        honeyToken: { marker: true }
    }
    if (includeCommit) {
        deps.commitVaultMeta = ({ vault, meta: nextMeta, operation }) => {
            calls.commits.push({ vault: clone(vault), meta: clone(nextMeta), operation })
            if (failCommit) throw new Error('transaction failed')
            storedWorkspace = clone(vault.payload)
            meta = clone(nextMeta)
        }
    }
    return {
        calls,
        deps,
        storedWorkspace: () => clone(storedWorkspace)
    }
}

test('valid safe patch plan merges preset metadata after unlock without mutating capability vault authority', async () => {
    const workspace = workspaceFixture()
    const snapshot = buildSnapshot(workspace)
    const plan = planFor(snapshot, validPatch(snapshot))
    const harness = createHarness(workspace)
    const originalCapabilityVault = clone(workspace[WORKSPACE_CAPABILITY_VAULT_KEY])

    const result = await mergeSafePresetPatchPlanAfterUnlock({
        importPlan: plan,
        sanitizedSnapshot: snapshot,
        callerContext: callerContext(),
        deps: harness.deps,
        now: NOW + 2
    })

    assert.equal(result.success, true)
    assert.equal(result.status, 'merged')
    assert.equal(result.sideEffects.writesVault, true)
    assert.equal(result.sideEffects.writesCapabilityVault, false)
    assert.equal(result.sideEffects.launches, false)
    assert.equal(harness.calls.commits.length, 1)
    assert.equal(harness.calls.commits[0].operation, 'safe-preset-patch-merge')

    const stored = harness.storedWorkspace()
    assert.deepEqual(stored[WORKSPACE_CAPABILITY_VAULT_KEY], originalCapabilityVault)
    const metadata = stored[WORKSPACE_SAFE_PRESET_METADATA_KEY]
    assert.equal(metadata.version, SAFE_PRESET_METADATA_VERSION)
    assert.equal(metadata.metadataOnly, true)
    assert.equal(metadata.presets[0].name, 'Coding Phone')
    assert.equal(metadata.presets[0].enabled, false)
    assert.deepEqual(metadata.presets[0].itemRefs.map(ref => ref.itemId), plan.presetPlans[0].next.itemRefs.map(ref => ref.itemId))

    const metadataJson = JSON.stringify(metadata)
    const resultJson = JSON.stringify(result)
    for (const forbidden of [
        'C:\\',
        'Program Files',
        'Users\\Alice',
        Object.keys(originalCapabilityVault.records)[0],
        'password=',
        'launchCapabilityVault'
    ]) {
        assert.equal(metadataJson.includes(forbidden), false, `metadata leaked ${forbidden}`)
        assert.equal(resultJson.includes(forbidden), false, `result leaked ${forbidden}`)
    }
})

test('locked sessions and missing caller context fail before vault writes', async () => {
    const workspace = workspaceFixture()
    const snapshot = buildSnapshot(workspace)
    const plan = planFor(snapshot)

    const lockedHarness = createHarness(workspace, { unlocked: false })
    const locked = await mergeSafePresetPatchPlanAfterUnlock({
        importPlan: plan,
        sanitizedSnapshot: snapshot,
        callerContext: callerContext(),
        deps: lockedHarness.deps
    })
    assert.equal(locked.success, false)
    assert.equal(locked.status, 'locked')
    assert.equal(lockedHarness.calls.commits.length, 0)
    assert.deepEqual(lockedHarness.storedWorkspace(), workspace)

    const contextHarness = createHarness(workspace)
    const missingContext = await mergeSafePresetPatchPlanAfterUnlock({
        importPlan: plan,
        sanitizedSnapshot: snapshot,
        callerContext: { unlocked: true, authority: 'desktop-main' },
        deps: contextHarness.deps
    })
    assert.equal(missingContext.success, false)
    assert.equal(missingContext.status, 'rejected')
    assert.equal(contextHarness.calls.activeSessionChecks, 0)
    assert.equal(contextHarness.calls.commits.length, 0)
})

test('merge requires transactional commit and commit failure leaves workspace unchanged', async () => {
    const workspace = workspaceFixture()
    const snapshot = buildSnapshot(workspace)
    const plan = planFor(snapshot)
    const originalCapabilityVault = clone(workspace[WORKSPACE_CAPABILITY_VAULT_KEY])

    const missingCommitHarness = createHarness(workspace, { includeCommit: false })
    const missingCommit = await mergeSafePresetPatchPlanAfterUnlock({
        importPlan: plan,
        sanitizedSnapshot: snapshot,
        callerContext: callerContext(),
        deps: missingCommitHarness.deps
    })
    assert.equal(missingCommit.success, false)
    assert.equal(missingCommit.status, 'rejected')
    assert.match(missingCommit.error, /transactional commitVaultMeta/)
    assert.equal(missingCommitHarness.calls.activeSessionChecks, 0)
    assert.equal(missingCommitHarness.calls.vaultWrites, 0)
    assert.equal(missingCommitHarness.calls.metaWrites, 0)
    assert.deepEqual(missingCommitHarness.storedWorkspace(), workspace)

    const failingCommitHarness = createHarness(workspace, { failCommit: true })
    const failedCommit = await mergeSafePresetPatchPlanAfterUnlock({
        importPlan: plan,
        sanitizedSnapshot: snapshot,
        callerContext: callerContext(),
        deps: failingCommitHarness.deps
    })
    assert.equal(failedCommit.success, false)
    assert.equal(failedCommit.status, 'rejected')
    assert.match(failedCommit.error, /transaction failed/)
    assert.equal(failingCommitHarness.calls.commits.length, 1)
    assert.equal(failingCommitHarness.calls.vaultWrites, 0)
    assert.equal(failingCommitHarness.calls.metaWrites, 0)

    const stored = failingCommitHarness.storedWorkspace()
    assert.deepEqual(stored, workspace)
    assert.deepEqual(stored[WORKSPACE_CAPABILITY_VAULT_KEY], originalCapabilityVault)
    assert.equal(stored[WORKSPACE_SAFE_PRESET_METADATA_KEY], undefined)
})

test('stale base revisions conflict without partial vault writes', async () => {
    const workspace = workspaceFixture()
    const originalSnapshot = buildSnapshot(workspace)
    const currentSnapshot = buildSnapshot(workspace, { revisionId: 'desktop-revision-raw-id-new' })
    const plan = planFor(originalSnapshot)
    const harness = createHarness(workspace)

    const result = await mergeSafePresetPatchPlanAfterUnlock({
        importPlan: plan,
        sanitizedSnapshot: currentSnapshot,
        callerContext: callerContext(),
        deps: harness.deps
    })

    assert.equal(result.success, false)
    assert.equal(result.status, 'conflict')
    assert.equal(result.conflicts.some(entry => entry.code === 'stale-base'), true)
    assert.equal(harness.calls.commits.length, 0)
    assert.deepEqual(harness.storedWorkspace(), workspace)
})

test('unknown safe item ids and duplicate preset refs conflict without writes', async () => {
    const workspace = workspaceFixture()
    const snapshot = buildSnapshot(workspace)
    const unknownPlan = planFor(snapshot)
    unknownPlan.presetPlans[0].next.itemRefs[0].itemId = 'item_missing_safe_item'
    const duplicatePlan = planFor(snapshot)
    duplicatePlan.presetPlans[0].next.itemRefs.push(clone(duplicatePlan.presetPlans[0].next.itemRefs[0]))

    for (const [plan, expectedCode] of [
        [unknownPlan, 'unknown-safe-item'],
        [duplicatePlan, 'duplicate-item-ref']
    ]) {
        const harness = createHarness(workspace)
        const result = await mergeSafePresetPatchPlanAfterUnlock({
            importPlan: plan,
            sanitizedSnapshot: snapshot,
            callerContext: callerContext(),
            deps: harness.deps
        })
        assert.equal(result.success, false)
        assert.equal(result.status, 'conflict')
        assert.equal(result.conflicts.some(entry => entry.code === expectedCode), true)
        assert.equal(harness.calls.commits.length, 0)
    }
})

test('malicious import-plan fields and launch side effects are rejected before writes', async () => {
    const workspace = workspaceFixture()
    const snapshot = buildSnapshot(workspace)
    const cases = [
        plan => {
            plan.presetPlans[0].next.itemRefs[0].path = 'C:\\Windows\\System32\\notepad.exe'
        },
        plan => {
            plan.sideEffects.launches = true
        },
        plan => {
            plan.newBrowserItems = [{
                id: 'patch_item_bad',
                type: 'browser-tab',
                source: 'phone-patch',
                url: 'https://example.com/',
                label: 'Bearer abcdefghijklmnopqrstuvwxyz',
                notes: '',
                enabled: true,
                metadataOnly: true,
                createsCapability: false,
                createsDesktopAppAuthority: false,
                createsHostFolderAuthority: false,
                launchable: false
            }]
        }
    ]

    for (const mutate of cases) {
        const plan = planFor(snapshot)
        mutate(plan)
        const harness = createHarness(workspace)
        const result = await mergeSafePresetPatchPlanAfterUnlock({
            importPlan: plan,
            sanitizedSnapshot: snapshot,
            callerContext: callerContext(),
            deps: harness.deps
        })
        assert.equal(result.success, false)
        assert.equal(result.status, 'rejected')
        assert.equal(harness.calls.commits.length, 0)
    }
})

test('phone-created browser tabs and account/profile mappings remain metadata only', async () => {
    const workspace = workspaceFixture()
    const snapshot = buildSnapshot(workspace)
    const ids = idsFor(snapshot)
    const plan = planFor(snapshot, patchWithNewTab(snapshot))
    const harness = createHarness(workspace)

    const result = await mergeSafePresetPatchPlanAfterUnlock({
        importPlan: plan,
        sanitizedSnapshot: snapshot,
        callerContext: callerContext(),
        deps: harness.deps,
        now: NOW + 2
    })

    assert.equal(result.success, true)
    const stored = harness.storedWorkspace()
    const metadata = stored[WORKSPACE_SAFE_PRESET_METADATA_KEY]
    const newItem = metadata.newBrowserItems[0]
    assert.equal(newItem.id, 'patch_item_docs_phone')
    assert.equal(newItem.url, 'https://docs.google.com/')
    assert.equal(newItem.accountIntentionId, ids.account.id)
    assert.equal(newItem.profileIntentionId, ids.profile.id)
    assert.equal(newItem.metadataOnly, true)
    assert.deepEqual(stored.accountSlots, workspace.accountSlots)

    const newSnapshot = buildSanitizedPresetSnapshot({
        snapshotSafeIdSecret: SECRET,
        sourceDeviceId: 'desktop-device-raw-id',
        snapshotId: 'desktop-snapshot-after-merge',
        revisionId: 'desktop-revision-after-merge',
        baseRevisionId: 'desktop-revision-raw-id',
        timestamp: NOW + 3,
        workspace: (() => {
            const copy = clone(stored)
            delete copy._honeyToken
            return copy
        })()
    })
    assert.equal(newSnapshot.availableItems.some(item => item.id === 'patch_item_docs_phone'), true)
    assert.equal(newSnapshot.presets[0].itemRefs.some(ref => ref.itemId === 'patch_item_docs_phone'), true)
    const futurePatch = validPatch(newSnapshot, candidate => {
        candidate.patchId = 'patch_phase22_followup'
        candidate.patchRevisionId = 'patchrev_phase22_followup_1'
        candidate.presets[0].itemRefs = newSnapshot.presets[0].itemRefs.map(ref => ({
            itemId: ref.itemId,
            order: ref.order,
            enabled: ref.enabled,
            ...(ref.accountIntentionId ? { accountIntentionId: ref.accountIntentionId } : {}),
            ...(ref.profileIntentionId ? { profileIntentionId: ref.profileIntentionId } : {}),
            metadataOnly: true
        }))
    })
    assert.equal(
        planSafePresetPatchImport({ sanitizedSnapshot: newSnapshot, patch: futurePatch }).presetPlans[0].next.itemRefs.some(ref => ref.itemId === 'patch_item_docs_phone'),
        true
    )
    assert.equal(JSON.stringify(newSnapshot).includes('C:\\'), false)
    assert.equal(JSON.stringify(newSnapshot).includes(Object.keys(workspace[WORKSPACE_CAPABILITY_VAULT_KEY].records)[0]), false)
})

test('raw phone patch input is replanned against the current snapshot before merge', async () => {
    const workspace = workspaceFixture()
    const snapshot = buildSnapshot(workspace)
    const patch = validPatch(snapshot)
    const harness = createHarness(workspace)

    const result = await mergeSafePresetPatchPlanAfterUnlock({
        patch,
        sanitizedSnapshot: snapshot,
        callerContext: callerContext(),
        deps: harness.deps
    })

    assert.equal(result.success, true)
    assert.equal(harness.storedWorkspace()[WORKSPACE_SAFE_PRESET_METADATA_KEY].lastMergedPatchRevisionId, patch.patchRevisionId)
})
