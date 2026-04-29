const { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, copyFileSync } = require('fs')
const { basename, join, relative, resolve, sep } = require('path')

const repoRoot = resolve(__dirname, '..')
const sourceDir = join(repoRoot, 'src', 'main')
const targetDir = join(repoRoot, 'functions', 'shared', 'main')
const sharedFiles = [
    'package.json',
    'accountSlots.js',
    'appAdapters.js',
    'appManifest.js',
    'capabilityStore.js',
    'cloudDraftSchema.js',
    'cloudSyncEnvelope.js',
    'cloudSyncIngestion.js',
    'ipcValidation.js',
    'safePresetMetadata.js',
    'safePresetPatch.js',
    'sanitizedPresetSnapshot.js',
    'workspaceCapabilityMigration.js'
]

function fail(message) {
    console.error(message)
    process.exitCode = 1
}

function assertSafeTarget() {
    const functionsRoot = resolve(repoRoot, 'functions')
    const resolvedTarget = resolve(targetDir)
    const relativeTarget = relative(functionsRoot, resolvedTarget)
    if (
        relativeTarget === '' ||
        relativeTarget.startsWith('..') ||
        relativeTarget.includes(`..${sep}`) ||
        resolvedTarget.toLowerCase() === functionsRoot.toLowerCase()
    ) {
        fail(`Refusing to sync cloud functions shared modules outside functions/: ${resolvedTarget}`)
        process.exit()
    }
}

function readFile(path) {
    return readFileSync(path, 'utf8')
}

function expectedTargets() {
    return new Set(sharedFiles.map(file => join(targetDir, file)))
}

function listExistingTargetFiles() {
    if (!existsSync(targetDir)) return []
    return readdirSync(targetDir, { withFileTypes: true })
        .filter(entry => entry.isFile())
        .map(entry => join(targetDir, entry.name))
}

function check() {
    let ok = true
    for (const file of sharedFiles) {
        const sourcePath = join(sourceDir, file)
        const targetPath = join(targetDir, file)
        if (!existsSync(targetPath)) {
            console.error(`Missing Functions shared module: ${relative(repoRoot, targetPath)}`)
            ok = false
            continue
        }
        if (readFile(sourcePath) !== readFile(targetPath)) {
            console.error(`Stale Functions shared module: ${relative(repoRoot, targetPath)}`)
            ok = false
        }
    }

    const expected = expectedTargets()
    for (const targetPath of listExistingTargetFiles()) {
        if (!expected.has(targetPath)) {
            console.error(`Unexpected Functions shared module: ${relative(repoRoot, targetPath)}`)
            ok = false
        }
    }

    if (!ok) {
        fail('Run npm run sync:functions-package to refresh the deploy-local cloud sync modules.')
        return
    }
    console.log('Cloud sync Functions shared modules are in sync.')
}

function sync() {
    assertSafeTarget()
    rmSync(targetDir, { recursive: true, force: true })
    mkdirSync(targetDir, { recursive: true })
    for (const file of sharedFiles) {
        copyFileSync(join(sourceDir, file), join(targetDir, basename(file)))
    }
    console.log('Synced cloud sync Functions shared modules.')
}

if (process.argv.includes('--check')) {
    check()
} else {
    sync()
}
