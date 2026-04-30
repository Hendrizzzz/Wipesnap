import assert from 'assert/strict'
import { test } from 'node:test'
import {
    autoLaunchFlagForDashboardSave,
    shouldAutoStartRendererLaunch
} from '../src/renderer/src/rendererAutoLaunchPolicy.js'

test('renderer session save and relaunch routes cannot auto-call launchWorkspace', () => {
    assert.equal(autoLaunchFlagForDashboardSave({ forceRelaunch: true }), false)
    assert.equal(autoLaunchFlagForDashboardSave({ forceRelaunch: false }), false)
    assert.equal(shouldAutoStartRendererLaunch({ autoLaunch: true, total: 3 }), false)
    assert.equal(shouldAutoStartRendererLaunch({ autoLaunch: false, total: 3 }), false)
})
