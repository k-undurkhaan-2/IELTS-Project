function defineBundle(outputPath, inputs) {
    return Object.freeze({
        outputPath,
        inputs: Object.freeze([...inputs]),
        tracked: true,
        runtimeRequired: true,
        publicSourcesOnly: true
    });
}

const inputs = Object.freeze({
    runtimeEntry: Object.freeze([
        'js/presentation/threeBackground.js',
        'js/runtime/bootScreen.js',
        'js/runtime/lazyLoader.js',
        'js/utils/suitePreference.js',
        'js/presentation/app-actions.js'
    ]),
    coreFoundation: Object.freeze([
        'js/utils/environmentDetector.js',
        'js/utils/logger.js',
        'js/utils/storage.js',
        'js/core/storageProviderRegistry.js',
        'js/data/dataSources/storageDataSource.js',
        'js/data/remoteApiClient.js',
        'js/data/dataSources/remotePracticeDataSource.js',
        'js/data/authOverlay.js',
        'js/data/repositories/baseRepository.js',
        'js/data/repositories/dataRepositoryRegistry.js',
        'js/data/repositories/practiceRepository.js',
        'js/data/repositories/settingsRepository.js',
        'js/data/repositories/backupRepository.js',
        'js/data/repositories/metaRepository.js',
        'js/data/index.js',
        'js/core/practiceCore.js',
        'js/core/practiceStore.js',
        'js/core/resourceCore.js',
        'assets/generated/reading-exams/manifest.js',
        'js/utils/stateSerializer.js',
        'js/utils/simpleStorageWrapper.js',
        'js/app/state-service.js',
        'js/services/libraryDiscovery.js',
        'js/services/libraryManager.js'
    ]),
    uiShell: Object.freeze([
        'js/utils/dom.js',
        'js/utils/practiceTimerPreferences.js',
        'js/services/overviewStats.js',
        'js/views/overviewView.js',
        'js/presentation/navigation-controller.js',
        'js/presentation/message-center.js',
        'js/app/main-entry.js',
        'js/presentation/indexInteractions.js',
        'js/presentation/emojiIconizer.js'
    ]),
    legacyApp: Object.freeze([
        'js/boot-fallbacks.js',
        'js/patches/runtime-fixes.js',
        'js/app.js',
        'js/components/onboardingTour.js'
    ]),
    browse: Object.freeze([
        'js/views/legacyViewBundle.js',
        'js/app/examActions.js',
        'js/app/spellingErrorCollector.js',
        'js/app/examSessionMixin.js',
        'js/app/browseController.js',
        'js/components/PDFHandler.js',
        'js/components/BrowseStateManager.js',
        'js/utils/suiteBackGuard.js',
        'js/utils/answerMatchCore.js',
        'js/utils/answerComparisonUtils.js',
        'js/utils/BrowsePreferencesUtils.js',
        'js/main.js'
    ]),
    diagnostics: Object.freeze([
        'js/components/SystemDiagnostics.js',
        'js/components/PerformanceOptimizer.js',
        'js/utils/dataConsistencyManager.js',
        'js/utils/performance.js',
        'js/utils/typeChecker.js',
        'js/utils/codeStandards.js'
    ]),
    settings: Object.freeze([
        'js/components/DataIntegrityManager.js',
        'js/utils/dataBackupManager.js'
    ]),
    practice: Object.freeze([
        'js/app/spellingErrorCollector.js',
        'js/utils/markdownExporter.js',
        'js/components/practiceRecordModal.js',
        'js/components/practiceHistoryEnhancer.js',
        'js/core/scoreStorage.js',
        'js/utils/answerSanitizer.js',
        'js/core/practiceRecorder.js'
    ]),
    session: Object.freeze([
        'js/app/suitePracticeMixin.js'
    ]),
    readingPage: Object.freeze([
        'js/runtime/readingExamRegistry.js',
        'js/runtime/readingExplanationRegistry.js',
        'js/runtime/readingHighlightShared.js',
        'js/utils/practiceTimerPreferences.js',
        'js/utils/answerSanitizer.js',
        'js/utils/answerMatchCore.js',
        'assets/wordlists/ielts_core.bundle.js',
        'assets/wordlists/ecdict_reading.bundle.js',
        'js/core/dictionaryService.js',
        'js/runtime/reviewHighlightDictionary.js',
        'js/runtime/unifiedReadingPage.js'
    ]),
    practicePageEnhancer: Object.freeze([
        'js/utils/suiteBackGuard.js',
        'js/utils/answerMatchCore.js',
        'js/app/spellingErrorCollector.js',
        'js/practice-page-enhancer.js'
    ]),
    listeningRecordBridge: Object.freeze([
        'js/utils/answerMatchCore.js',
        'js/app/spellingErrorCollector.js',
        'js/listeningRecordBridge.js'
    ]),
    listeningWrapper: Object.freeze([
        'js/utils/practiceTimerPreferences.js',
        'js/listeningUnifiedWrapper.js'
    ]),
    more: Object.freeze([
        'assets/wordlists/ielts_core.bundle.js',
        'js/utils/vocabDataIO.js',
        'js/core/vocabScheduler.js',
        'js/core/vocabStore.js',
        'js/app/vocabListSwitcher.js',
        'js/components/vocabDashboardCards.js',
        'js/components/vocabSessionView.js',
        'js/presentation/moreView.js',
        'js/presentation/miniGames.js',
        'js/services/achievementManager.js'
    ]),
    theme: Object.freeze([
        'js/theme-switcher.js'
    ])
});

const vipCoreFoundation = inputs.coreFoundation.filter((inputPath) => ![
    'js/data/remoteApiClient.js',
    'js/data/dataSources/remotePracticeDataSource.js'
].includes(inputPath));

const vipReadingPage = inputs.readingPage.filter((inputPath) => ![
    'assets/wordlists/ielts_core.bundle.js',
    'assets/wordlists/ecdict_reading.bundle.js'
].includes(inputPath));

const defaultBundleInputs = Object.freeze({
    'js/bundles/runtime-entry.bundle.js': inputs.runtimeEntry,
    'js/bundles/core-foundation.bundle.js': inputs.coreFoundation,
    'js/bundles/ui-shell.bundle.js': inputs.uiShell,
    'js/bundles/legacy-app.bundle.js': inputs.legacyApp,
    'js/bundles/browse.bundle.js': inputs.browse,
    'js/bundles/diagnostics.bundle.js': inputs.diagnostics,
    'js/bundles/settings.bundle.js': inputs.settings,
    'js/bundles/practice.bundle.js': inputs.practice,
    'js/bundles/session.bundle.js': inputs.session,
    'js/bundles/reading-page.bundle.js': inputs.readingPage,
    'js/bundles/practice-page-enhancer.bundle.js': inputs.practicePageEnhancer,
    'js/bundles/listening-record-bridge.bundle.js': inputs.listeningRecordBridge,
    'js/bundles/listening-wrapper.bundle.js': inputs.listeningWrapper,
    'js/bundles/more.bundle.js': inputs.more,
    'js/bundles/theme.bundle.js': inputs.theme
});

const vipBundleInputs = Object.freeze({
    'js/bundles/runtime-entry.bundle.js': inputs.runtimeEntry,
    'js/bundles/core-foundation.bundle.js': vipCoreFoundation,
    'js/bundles/ui-shell.bundle.js': inputs.uiShell,
    'js/bundles/legacy-app.bundle.js': inputs.legacyApp,
    'js/bundles/browse.bundle.js': inputs.browse,
    'js/bundles/diagnostics.bundle.js': inputs.diagnostics,
    'js/bundles/settings.bundle.js': inputs.settings,
    'js/bundles/practice.bundle.js': inputs.practice,
    'js/bundles/session.bundle.js': inputs.session,
    'js/bundles/reading-page.bundle.js': vipReadingPage,
    'js/bundles/practice-page-enhancer.bundle.js': inputs.practicePageEnhancer,
    'js/bundles/listening-record-bridge.bundle.js': inputs.listeningRecordBridge,
    'js/bundles/more.bundle.js': inputs.more,
    'js/bundles/theme.bundle.js': inputs.theme
});

function defineProfile(name, outputRoot, bundleInputs, retiredOutputs = []) {
    return Object.freeze({
        name,
        outputRoot,
        allowUndeclaredOutputs: false,
        retiredOutputs: Object.freeze([...retiredOutputs]),
        bundles: Object.freeze(Object.entries(bundleInputs).map(([outputPath, bundleInputsForOutput]) => (
            defineBundle(outputPath, bundleInputsForOutput)
        )))
    });
}

export const BUNDLE_PROFILES = Object.freeze({
    default: defineProfile('default', '.', defaultBundleInputs),
    vip: defineProfile(
        'vip',
        'ListeningPractice/vip special',
        vipBundleInputs,
        ['js/bundles/listening-wrapper.bundle.js']
    )
});

export function getBundleProfile(name) {
    const profile = BUNDLE_PROFILES[name];
    if (!profile) {
        throw new Error(`Unsupported bundle profile: ${name}`);
    }
    return profile;
}
