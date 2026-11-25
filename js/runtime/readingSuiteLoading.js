(function (global) {
    'use strict';

    const params = new URLSearchParams(global.location.search);
    if (!params.get('suiteSessionId') || !params.has('suiteExamIds')) return;
    let examIds;
    try {
        examIds = JSON.parse(params.get('suiteExamIds'));
        if (!Array.isArray(examIds) || examIds.length !== 3
            || new Set(examIds).size !== 3
            || examIds.some(id => typeof id !== 'string' || !id || id.length > 200)) return;
    } catch (_) {
        return;
    }

    document.documentElement.classList.add('reading-suite-loading');
    const progress = new Map(examIds.map(id => [id, { value: 0, label: '等待加载', title: '' }]));
    function render() {
        const list = document.getElementById('suite-loading-items');
        if (!list) return;
        list.replaceChildren(...examIds.map((id, index) => {
            const item = progress.get(id);
            const row = document.createElement('li');
            const title = document.createElement('strong');
            title.textContent = `Passage ${index + 1}${item.title ? ' · ' + item.title : ''}`;
            const label = document.createElement('span');
            label.textContent = item.label;
            const bar = document.createElement('progress');
            bar.max = 100;
            bar.value = item.value;
            bar.setAttribute('aria-label', `Passage ${index + 1} 加载进度`);
            row.append(title, label, bar);
            return row;
        }));
        const items = [...progress.values()];
        const percent = Math.floor(items.reduce((sum, item) => sum + item.value, 0) / items.length);
        document.getElementById('suite-loading-progress').value = percent;
        document.getElementById('suite-loading-status').textContent =
            `已就绪 ${items.filter(item => item.value === 100).length} / ${examIds.length} · ${percent}%`;
    }

    global.ReadingSuiteLoading = {
        examIds,
        update(id, value, label, title = '') {
            const item = progress.get(id);
            if (!item) return;
            Object.assign(item, { value, label, title: title || item.title });
            render();
        },
        async retry() {
            const message = document.getElementById('suite-loading-message');
            const button = document.getElementById('suite-loading-retry');
            message.textContent = '部分题目未能加载，请检查网络后重试。计时尚未开始。';
            button.hidden = false;
            button.focus();
            await new Promise(resolve => button.addEventListener('click', resolve, { once: true }));
            button.hidden = true;
            message.textContent = '三篇题目全部就绪后，将自动显示第一篇并开始计时。';
        },
        complete() {
            document.documentElement.classList.remove('reading-suite-loading');
            document.getElementById('suite-loading-dialog')?.remove();
        }
    };
    document.addEventListener('DOMContentLoaded', render, { once: true });
})(window);
