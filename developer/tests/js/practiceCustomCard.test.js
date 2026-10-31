#!/usr/bin/env node
import fs from 'fs';
import path from 'path';
import assert from 'assert';
import vm from 'vm';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..', '..');

function read(relativePath) {
    return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8').replace(/\r\n/g, '\n');
}

const checks = [];

function record(name, detail = {}) {
    checks.push({ name, detail });
}

function assertContains(source, snippet, message) {
    assert(source.includes(snippet), message);
}

function assertNotContains(source, snippet, message) {
    assert(!source.includes(snippet), message);
}

function stripCssComments(source) {
    return source.replace(/\/\*[\s\S]*?\*\//g, '');
}

function cssDeclarations(source, selector) {
    const declarations = {};
    let selectors = [];
    let depth = 0;

    // Inspect base rules only; a media-query override cannot supply a missing base layout.
    // Match complete selectors, including grouped rules, without depending on formatting.
    for (const [, text, brace] of stripCssComments(source).matchAll(/([^{}]*)([{}])/g)) {
        if (brace === '{') {
            if (depth === 0) {
                selectors = text.split(',').map((value) => value.trim().replace(/\s+/g, ' '));
            }
            depth += 1;
        } else {
            depth -= 1;
            if (depth !== 0 || !selectors.includes(selector)) continue;
            for (const declaration of text.split(';')) {
                const colon = declaration.indexOf(':');
                if (colon === -1) continue;
                const property = declaration.slice(0, colon).trim();
                declarations[property] = declaration.slice(colon + 1).trim().replace(/\s+/g, ' ')
                    .replace(/\s*,\s*/g, ', ').replace(/\(\s*/g, '(').replace(/\s*\)/g, ')');
            }
        }
    }
    return declarations;
}

function assertCssDeclarations(source, selector, expected, message) {
    const declarations = cssDeclarations(source, selector);
    for (const [property, value] of Object.entries(expected)) {
        assert.strictEqual(declarations[property], value, `${message}: ${selector} 的 ${property}`);
    }
    return declarations;
}

function loadCustomCardCalculators(source) {
    const injected = source.replace(
        '})(window);',
        [
            'global.__testCalculateReadingRadarData = calculateReadingRadarData;',
            'global.__testCalculatePracticeHeatmapData = calculatePracticeHeatmapData;',
            '})(window);'
        ].join('\n')
    );
    const sandboxWindow = {};
    const context = vm.createContext({
        window: sandboxWindow,
        console,
        Date,
        Math,
        Number,
        String,
        Boolean,
        Array,
        Object,
        RegExp,
        Set,
        Map
    });
    vm.runInContext(injected, context, { filename: 'legacyViewBundle.js' });
    return {
        calculateReadingRadarData: sandboxWindow.__testCalculateReadingRadarData,
        calculatePracticeHeatmapData: sandboxWindow.__testCalculatePracticeHeatmapData
    };
}

try {
    const indexHtml = read('index.html');
    const css = read('src/styles/components.css');
    const onboardingCss = stripCssComments(read('css/onboarding.css'));
    const source = read('js/views/legacyViewBundle.js');
    const bundle = read('js/bundles/browse.bundle.js');

    assertNotContains(indexHtml, 'id="practice-custom-widget-label"', '自定义胶囊按钮不应存在');
    assertNotContains(indexHtml, 'role="button"\n                            tabindex="0"\n                            aria-label="打开自定义练习组件选择"', '整卡不应伪装为按钮');
    assertNotContains(indexHtml, '<p class="practice-trend-card__eyebrow">Trend</p>', '练习趋势正面不应显示 Trend 英文标签');
    assertNotContains(indexHtml, '<p class="practice-trend-card__eyebrow">Focus</p>', '练习热力图正面不应显示 Focus 英文标签');
    assertContains(indexHtml, 'id="practice-heatmap"', '练习热力图容器应存在');
    assertContains(indexHtml, 'data-widget-type="heatmap"', '默认组件内容应包含热力图');
    assertContains(indexHtml, 'data-practice-widget="heatmap"', '背面组件选择入口应包含热力图');
    assertContains(indexHtml, 'practice-custom-option__icon', '背面组件选项应包含图标槽');
    assertContains(indexHtml, 'practice-custom-option__body', '背面组件选项应包含文本槽');
    assertContains(indexHtml, 'practice-custom-option__check', '背面组件选项应包含激活指示');
    assertContains(indexHtml, 'data-practice-heatmap-month="prev"', '热力图应提供上个月按钮');
    assertContains(indexHtml, 'data-practice-heatmap-month="next"', '热力图应提供下个月按钮');
    assertContains(indexHtml, 'id="practice-radar-canvas"', '阅读雷达 canvas 应存在');
    assertContains(indexHtml, 'id="practice-radar-summary"', '阅读雷达摘要应保留在共享组件布局中');
    assertContains(indexHtml, 'data-practice-widget="radar"', '背面组件选择入口应包含阅读雷达');
    assertContains(indexHtml, 'practice-custom-card__flip-btn practice-custom-card__icon-btn', '翻转按钮应复用同尺寸图标按钮');
    record('自定义卡片 DOM 结构守卫');

    const activeHtml = indexHtml.replace(/<!--[\s\S]*?-->/g, '');
    const bodyClasses = activeHtml.match(/<body\b[^>]*\bclass\s*=\s*["']([^"']*)["']/i);
    assert(bodyClasses && bodyClasses[1].split(/\s+/).includes('ds-learning'), '页面应启用学习端设计系统作用域');
    const stylesheetLinks = Array.from(activeHtml.matchAll(/<link\b[^>]*>/gi), ([tag]) => tag);
    assert(stylesheetLinks.some((tag) => /\brel\s*=\s*["']stylesheet["']/i.test(tag)
        && /\bhref\s*=\s*["']css\/onboarding\.css["']/i.test(tag)), '页面应加载设计系统样式入口');
    for (const stylesheet of ['tokens', 'components']) {
        assert.match(onboardingCss, new RegExp(`@import\\s+url\\(\\s*["']\\.\\./src/styles/${stylesheet}\\.css["']\\s*\\)\\s*;`),
            `设计系统入口应加载 ${stylesheet}.css`);
    }

    assertCssDeclarations(css, '.ds-learning .practice-custom-card__icon-btn', {
        width: 'var(--control-height)', 'min-width': 'var(--control-height)',
        'min-height': 'var(--control-height)', padding: '0'
    }, '图标按钮应使用统一控件尺寸');
    const options = assertCssDeclarations(css, '.ds-learning .practice-custom-options', {
        display: 'grid', width: '100%'
    }, '背面组件选择区应使用单列 grid，避免横向挤压');
    // With no explicit columns and row auto-placement, Grid creates one implicit column.
    assert(['none', '1fr', 'minmax(0, 1fr)'].includes(options['grid-template-columns'] || 'none'),
        '背面组件选择区应使用单列布局');
    assert.strictEqual(options['grid-auto-flow'] || 'row', 'row', '背面组件选择区应逐行排列');
    assertCssDeclarations(css, '.ds-learning .practice-custom-options .practice-custom-option', {
        display: 'grid', 'grid-template-columns': 'auto minmax(0, 1fr) auto', 'align-items': 'center'
    }, '组件选项应保留图标/可收缩文本/状态三列');
    assertCssDeclarations(css, '.ds-learning .practice-custom-option__body', {
        'min-width': '0'
    }, '组件选项文本应允许收缩');
    assertCssDeclarations(css, '.ds-learning .practice-custom-option__icon', {
        display: 'inline-flex', 'align-items': 'center', 'justify-content': 'center'
    }, '组件选项图标应居中');
    assertCssDeclarations(css, '.ds-learning .practice-custom-option__check', {
        display: 'inline-flex', 'border-radius': 'var(--radius-pill)'
    }, '组件选项应保留激活指示器样式');
    for (const state of ['.active', '[aria-pressed="true"]']) {
        assertCssDeclarations(css, `.ds-learning .practice-custom-option${state} .practice-custom-option__check`, {
            background: 'var(--accent)'
        }, '组件选项激活指示应使用强调色');
    }

    for (const face of ['.practice-trend-card__face', '.practice-custom-card__face']) {
        assertCssDeclarations(css, `.ds-learning ${face}`, {
            display: 'grid', gap: 'var(--space-4)', padding: 'var(--space-5)'
        }, '两张洞察卡片应共享间距与内边距');
    }
    const front = cssDeclarations(css, '.ds-learning .practice-custom-card__front');
    assert(!Object.keys(front).some((property) => /^(?:padding(?:-.+)?|height|min-height)$/.test(property)),
        '自定义卡片正面不能单独设置内边距或高度破坏共享布局');
    assertCssDeclarations(css, '.ds-learning .practice-trend-card__header', {
        display: 'flex', 'justify-content': 'space-between'
    }, '洞察卡片头部应分开排列标题和操作区');
    assertCssDeclarations(css, '.ds-learning .practice-custom-card__front .practice-trend-card__header', {
        'align-items': 'center'
    }, '热力图标题与月份操作区应垂直居中');
    assertCssDeclarations(css, '.ds-learning .practice-trend-card__title-line', {
        display: 'grid', gap: 'var(--space-1)'
    }, '趋势标题和指标应使用设计系统的紧凑网格布局');
    assertCssDeclarations(css, '.ds-learning .practice-custom-widget-content:not([hidden])', {
        display: 'grid', gap: 'var(--space-3)'
    }, '热力图和雷达应复用可见组件布局');

    const heatmap = assertCssDeclarations(css, '.ds-learning .practice-heatmap', {
        'box-sizing': 'border-box', 'overflow-x': 'auto'
    }, '热力图应在窄容器内允许滚动');
    assert.match(heatmap['--practice-heatmap-cell'] || '', /^clamp\(\d+px, [\d.]+vw, \d+px\)$/,
        '热力块应使用有上下界的响应式尺寸');
    assertCssDeclarations(css, '.ds-learning .practice-heatmap__body', {
        display: 'grid', 'max-width': '100%'
    }, '热力图主体不应超出容器宽度');
    for (const selector of ['.practice-heatmap__weekdays', '.practice-heatmap__grid']) {
        assertCssDeclarations(css, `.ds-learning ${selector}`, {
            display: 'grid', 'grid-template-columns': 'repeat(7, var(--practice-heatmap-cell))',
            gap: 'var(--practice-heatmap-gap)'
        }, '星期标题和日期网格应使用相同的横向七列布局');
    }
    assertCssDeclarations(css, '.ds-learning .practice-heatmap__grid', {
        'grid-template-rows': 'repeat(var(--practice-heatmap-weeks, 5), var(--practice-heatmap-cell))'
    }, '热力图行数应随月份周数变化');
    assertCssDeclarations(css, '.ds-learning .practice-heatmap__cell', {
        width: 'var(--practice-heatmap-cell)', height: 'var(--practice-heatmap-cell)'
    }, '热力块应保持正方形并使用网格尺寸');
    assertCssDeclarations(css, '.ds-learning .practice-heatmap__cell[data-level="4"]', {
        '--practice-heatmap-level': 'var(--accent)'
    }, '热力图深色等级应使用强调色');
    assertCssDeclarations(css, '.ds-learning .practice-heatmap__cell::after', {
        content: 'attr(data-tooltip)', opacity: '0'
    }, '热力图提示应使用日期文案并默认隐藏');
    for (const state of [':hover', ':focus-visible']) {
        assertCssDeclarations(css, `.ds-learning .practice-heatmap__cell${state}::after`, {
            opacity: '1'
        }, '热力图提示应支持鼠标悬浮和键盘聚焦');
    }
    record('自定义卡片 CSS 守卫');

    assertContains(source, "this.activeWidget = options.defaultWidget || 'heatmap'", '自定义卡片默认组件应为热力图');
    assertContains(source, 'function calculatePracticeHeatmapData(records, monthDate)', '热力图数据聚合函数应存在');
    assertContains(source, 'aggregatePracticeHeatmapSets(records, monthStart)', '热力图应按套数聚合练习记录');
    assertContains(source, "event.target.closest('[data-practice-heatmap-month]')", '月份按钮事件应单独绑定');
    assertContains(source, 'button.dataset.tooltip = cell.label', '热力图块应写入悬浮提示文案');
    assertContains(source, 'button.style.gridColumn = String(cell.weekday + 1);', '热力图应按星期横向铺开');
    assertContains(source, 'button.style.gridRow = String(cell.week + 1);', '热力图应按周数纵向换行');
    assertNotContains(source, 'button.style.gridColumn = String(cell.week + 1);', '热力图不能继续使用竖向周列布局');
    assertContains(source, 'averageSetsPerActiveDay', '热力图深浅应按用户每日平均做题套数动态渲染');
    assertNotContains(source, 'resolvePracticeHeatmapQuestionCount(record)', '热力图不能继续按题目数量聚合');
    assertContains(source, 'function calculateReadingRadarData(records)', '雷达数据聚合函数应存在');
    assertContains(source, 'buildReadingQuestionTypeMap(record)', '雷达应从阅读题组建立题型映射');
    assertContains(source, 'window.__READING_EXAM_DATA__', '雷达应使用阅读题库注册数据兜底');
    assertContains(source, 'record.questionTypeMap', '雷达应优先读取记录自带 questionTypeMap');
    assertContains(source, 'getDetailSources(record)', '雷达应从 answerDetails/scoreInfo.details 提取错题');
    assertContains(source, 'addPerformanceCounts(counts, performanceMap)', '雷达应优先使用 questionTypePerformance');
    assertContains(source, "questionTypeAliases[compact] || questionTypeAliases[token] || 'other'", '未知题型必须归入固定 other 枚举，不能生成不可渲染分类');
    assertContains(source, "event.target.closest('.practice-custom-card__flip-btn')", '翻转只应绑定右上角按钮');
    assertContains(source, 'event.stopPropagation();', '整卡其他区域点击应阻止冒泡且不翻转');
    record('自定义卡片业务逻辑守卫');

    const { calculateReadingRadarData, calculatePracticeHeatmapData } = loadCustomCardCalculators(source);
    assert.strictEqual(typeof calculatePracticeHeatmapData, 'function', '热力图聚合函数应可被测试提取');
    const heatmapData = calculatePracticeHeatmapData([
        { id: 'h1', date: '2026-05-01T08:00:00', totalQuestions: 13 },
        { id: 'h2', startTime: '2026-05-01T11:00:00', scoreInfo: { total: 7 } },
        { id: 'h3', endTime: '2026-05-12T16:00:00', realData: { totalQuestions: 5 } },
        { id: 'h4', realData: { completedAt: '2026-04-30T23:00:00', totalQuestions: 9 } }
    ], new Date('2026-05-15T00:00:00.000Z'));
    const mayFirst = heatmapData.cells.find((cell) => cell.dateKey === '2026-05-01');
    const mayTwelfth = heatmapData.cells.find((cell) => cell.dateKey === '2026-05-12');
    assert.strictEqual(heatmapData.monthStart.getFullYear(), 2026, '热力图月份年份应来自选中月份');
    assert.strictEqual(heatmapData.monthStart.getMonth(), 4, '热力图月份应来自选中月份');
    assert.strictEqual(heatmapData.total, 3, '热力图应只统计选中月份的做题套数');
    assert.strictEqual(heatmapData.activeDays, 2, '热力图应统计活跃天数');
    assert.strictEqual(mayFirst.count, 2, '同一天多条记录的做题套数应累加');
    assert.strictEqual(mayTwelfth.count, 1, '单日做题套数应写入对应热力块');
    assert.strictEqual(heatmapData.averageSetsPerActiveDay, 4 / 3, '热力图颜色基准应使用全局活跃日每日平均套数');
    assert(mayFirst.level > mayTwelfth.level, '做题量更多的日期颜色等级应更深');
    record('热力图月份聚合回归守卫');

    assert.strictEqual(typeof calculateReadingRadarData, 'function', '雷达聚合函数应可被测试提取');
    const radarData = calculateReadingRadarData([{
        id: 'radar_question_type_regression',
        type: 'reading',
        examId: 'p1-low-radar',
        date: '2026-05-24T00:00:00.000Z',
        questionTypeMap: {
            q1: 'true_false_not_given',
            q2: 'short_answer',
            q3: 'sentence_completion'
        },
        scoreInfo: {
            details: {
                q1: { questionId: 'q1', userAnswer: 'FALSE', correctAnswer: 'TRUE', isCorrect: false },
                q2: { questionId: 'q2', userAnswer: 'museum', correctAnswer: 'library', isCorrect: false },
                q3: { questionId: 'q3', userAnswer: 'river', correctAnswer: 'river', isCorrect: true }
            }
        }
    }]);
    const radarCounts = Object.fromEntries(radarData.dataPoints.map((point) => [point.label, point.value]));
    assert.strictEqual(radarCounts['判断题'], 1, 'q1 应按 questionTypeMap 计入判断题错题');
    assert.strictEqual(radarCounts['简答题'], 1, 'q2 应按 questionTypeMap 计入简答题错题');
    assert.strictEqual(radarCounts['其他题型'] || 0, 0, '已定义题型不应落入其他题型');
    assert.strictEqual(radarData.totalErrors, 2, '雷达应只统计两道错题');
    record('雷达题型映射回归守卫');

    [
        "this.activeWidget = options.defaultWidget || 'heatmap'",
        'function calculatePracticeHeatmapData(records, monthDate)',
        'aggregatePracticeHeatmapSets(records, monthStart)',
        'averageSetsPerActiveDay',
        'practice-heatmap__cell',
        "event.target.closest('[data-practice-heatmap-month]')",
        'function calculateReadingRadarData(records)',
        'buildReadingQuestionTypeMap(record)',
        'record.questionTypeMap',
        'practice-radar-summary',
        "event.target.closest('.practice-custom-card__flip-btn')"
    ].forEach((snippet) => {
        assertContains(bundle, snippet, `browse bundle 缺少同步片段: ${snippet}`);
    });
    record('browse bundle 同步守卫');

    console.log(JSON.stringify({
        status: 'pass',
        detail: `${checks.length}/${checks.length} 测试通过`,
        passed: checks.length,
        total: checks.length
    }, null, 2));
} catch (error) {
    console.log(JSON.stringify({
        status: 'fail',
        detail: error.message,
        checks
    }, null, 2));
    process.exit(1);
}
