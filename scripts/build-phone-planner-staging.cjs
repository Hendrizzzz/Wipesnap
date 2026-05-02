const { copyFileSync, existsSync, mkdirSync, readdirSync, rmSync, statSync } = require('fs')
const { basename, join, relative, resolve, sep } = require('path')

const repoRoot = resolve(__dirname, '..')
const sourceDir = join(repoRoot, 'src', 'phone-planner')
const cloudflareSyncSourceDir = join(repoRoot, 'src', 'cloudflare-sync')
const targetDir = join(repoRoot, 'out', 'phone-planner-staging')

const PHONE_PLANNER_STAGING_FILES = Object.freeze([
    'app.js',
    'index.html',
    'manifest.webmanifest',
    'phonePlannerCloudCrypto.js',
    'phonePlannerCloudProvider.js',
    'phonePlannerCloudStorage.js',
    'phonePlannerCloudWorkflow.js',
    'phonePlannerCloudflareConfig.js',
    'phonePlannerCloudflareRest.js',
    'phonePlannerCloudflareWorkflow.js',
    'phonePlannerCore.js',
    'phonePlannerFirebaseConfig.js',
    'phonePlannerFirebaseRest.js',
    'phonePlannerStorage.js',
    'service-worker.js',
    'styles.css',
    'cloudflare-sync-config.example.json',
    'firebase-staging-config.example.json'
])

const CLOUDFLARE_SYNC_STAGING_FILES = Object.freeze([
    'cloudflareCanonicalRequest.js',
    'cloudflareSyncConstants.js',
    'cloudflareSyncFetchClient.js'
])

const OPTIONAL_STAGING_CONFIGS = Object.freeze([
    'firebase-staging-config.json',
    'cloudflare-sync-config.json'
])
const OPTIONAL_STAGING_CONFIG = OPTIONAL_STAGING_CONFIGS[0]
const FORBIDDEN_ARTIFACT_NAMES = new Set([
    'vault.json',
    'vault.meta.json',
    'vault.state.json',
    'package.json',
    'firebase.json'
])
const FORBIDDEN_ARTIFACT_SEGMENTS = new Set([
    'Apps',
    'AppData',
    'BrowserProfile',
    'dist',
    'functions',
    'tests',
    '_planning'
])

function fail(message) {
    throw new Error(message)
}

function isWithin(parent, candidate) {
    const relativePath = relative(parent, candidate)
    return relativePath === '' || !!relativePath && !relativePath.startsWith('..') && !relativePath.includes(`..${sep}`)
}

function assertSafeTarget(candidateTarget = targetDir) {
    const outRoot = resolve(repoRoot, 'out')
    const resolvedTarget = resolve(candidateTarget)
    if (!isWithin(outRoot, resolvedTarget) || resolvedTarget.toLowerCase() === outRoot.toLowerCase()) {
        fail(`Refusing to build phone planner outside the out/ staging artifact root: ${resolvedTarget}`)
    }
}

function copyAllowlistedFile(fileName, options = {}) {
    const fromDir = options.sourceRoot || sourceDir
    const toDir = options.targetRoot || targetDir
    const targetName = options.targetName || basename(fileName)
    const sourcePath = resolve(fromDir, fileName)
    const targetPath = resolve(toDir, targetName)
    if (!isWithin(fromDir, sourcePath)) fail(`Refusing to copy outside phone planner source: ${fileName}`)
    if (!isWithin(toDir, targetPath)) fail(`Refusing to write outside phone planner staging artifact: ${fileName}`)
    if (!existsSync(sourcePath) || !statSync(sourcePath).isFile()) {
        fail(`Missing phone planner staging source file: ${fileName}`)
    }
    mkdirSync(resolve(targetPath, '..'), { recursive: true })
    copyFileSync(sourcePath, targetPath)
}

function copyOptionalStagingConfigs(options = {}) {
    const fromDir = options.sourceRoot || sourceDir
    const warn = options.warn || console.warn
    const copied = []
    for (const fileName of OPTIONAL_STAGING_CONFIGS) {
        const configPath = resolve(fromDir, fileName)
        if (existsSync(configPath)) {
            copyAllowlistedFile(fileName, options)
            copied.push(fileName)
        } else {
            warn(`No src/phone-planner/${fileName} found; hosted artifact will require config before that provider can initialize.`)
        }
    }
    return copied
}

function assertSafeArtifactFiles(root = targetDir) {
    if (!existsSync(root)) return true
    for (const entry of readdirSync(root, { withFileTypes: true })) {
        const fullPath = join(root, entry.name)
        if (FORBIDDEN_ARTIFACT_NAMES.has(entry.name)) {
            fail(`Forbidden file in phone planner staging artifact: ${entry.name}`)
        }
        if (FORBIDDEN_ARTIFACT_SEGMENTS.has(entry.name)) {
            fail(`Forbidden directory in phone planner staging artifact: ${entry.name}`)
        }
        if (entry.isDirectory()) assertSafeArtifactFiles(fullPath)
    }
    return true
}

function buildPhonePlannerStaging() {
    assertSafeTarget()
    rmSync(targetDir, { recursive: true, force: true })
    mkdirSync(targetDir, { recursive: true })
    for (const fileName of PHONE_PLANNER_STAGING_FILES) copyAllowlistedFile(fileName)
    for (const fileName of CLOUDFLARE_SYNC_STAGING_FILES) {
        copyAllowlistedFile(fileName, {
            sourceRoot: cloudflareSyncSourceDir,
            targetName: join('cloudflare-sync', fileName)
        })
    }
    copyOptionalStagingConfigs()
    assertSafeArtifactFiles()
    console.log(`Built hosted phone planner staging artifact: ${targetDir}`)
}

if (require.main === module) {
    try {
        buildPhonePlannerStaging()
    } catch (error) {
        console.error(error.message || error)
        process.exitCode = 1
    }
}

module.exports = {
    FORBIDDEN_ARTIFACT_NAMES,
    FORBIDDEN_ARTIFACT_SEGMENTS,
    CLOUDFLARE_SYNC_STAGING_FILES,
    OPTIONAL_STAGING_CONFIG,
    OPTIONAL_STAGING_CONFIGS,
    PHONE_PLANNER_STAGING_FILES,
    sourceDir,
    targetDir,
    assertSafeArtifactFiles,
    copyAllowlistedFile,
    copyOptionalStagingConfigs,
    buildPhonePlannerStaging
}
