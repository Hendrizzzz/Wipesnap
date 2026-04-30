import assert from 'assert/strict'
import { test } from 'node:test'
import { validateTrustedAutoLaunchSettingPayload } from '../src/preload/autoLaunchPreloadValidation.js'

test('auto-launch preload validation accepts only the narrow safe setting schema', () => {
    assert.deepEqual(validateTrustedAutoLaunchSettingPayload({
        version: 1,
        enabled: true,
        advancedPersonalMode: true,
        localDesktopOverridePresetId: 'preset_local',
        acceptValidatedSelectionMetadata: true,
        countdownSeconds: 5
    }), {
        version: 1,
        enabled: true,
        advancedPersonalMode: true,
        localDesktopOverridePresetId: 'preset_local',
        acceptValidatedSelectionMetadata: true,
        countdownSeconds: 5
    })

    assert.deepEqual(validateTrustedAutoLaunchSettingPayload({
        enabled: false,
        localDesktopOverridePresetId: null
    }), {
        enabled: false,
        localDesktopOverridePresetId: null
    })
})

test('auto-launch preload validation rejects renderer-supplied authority or cloud material', () => {
    assert.throws(() => validateTrustedAutoLaunchSettingPayload(null), /must be an object/)
    assert.throws(() => validateTrustedAutoLaunchSettingPayload({ enabled: true }), /advancedPersonalMode/)
    assert.throws(() => validateTrustedAutoLaunchSettingPayload({
        enabled: true,
        advancedPersonalMode: true,
        defaultPresetId: 'preset_cloud'
    }), /not accepted/)
    assert.throws(() => validateTrustedAutoLaunchSettingPayload({
        enabled: true,
        advancedPersonalMode: true,
        localDesktopOverridePresetId: 'https://example.com/?token=secret'
    }), /safe preset id|forbidden material/)
    assert.throws(() => validateTrustedAutoLaunchSettingPayload({
        enabled: false,
        launchPlan: { path: 'C:\\Users\\Alice\\AppData\\Local\\app.exe' }
    }), /not accepted|forbidden material/)
    assert.throws(() => validateTrustedAutoLaunchSettingPayload({
        enabled: false,
        localDesktopOverridePresetId: `cap_${'ab'.repeat(32)}`
    }), /safe preset id|forbidden material/)
    assert.throws(() => validateTrustedAutoLaunchSettingPayload({
        enabled: false,
        patchPayload: { revisionId: 'patchrev_phase30_secret' }
    }), /not accepted|forbidden material/)
    assert.throws(() => validateTrustedAutoLaunchSettingPayload({
        enabled: false,
        countdownSeconds: 31
    }), /integer from 3 to 30/)
})
