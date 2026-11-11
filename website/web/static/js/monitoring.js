"use strict";
// Admin monitoring page (admin/monitoring.html): the folded sections
// (<details data-lk-mon-url>) request their body each time they are opened,
// so nothing is read from the backend for a section nobody looks at.
// The body is an HTML fragment rendered (and escaped) by Flask.
// Doc: doc/ui/monitoring.md

document.querySelectorAll('details[data-lk-mon-url]').forEach(section => {
    let controller = null;
    section.addEventListener('toggle', async () => {
        if (!section.open) {
            if (controller) {
                controller.abort();
            }
            return;
        }
        const body = section.querySelector('.lk-mon-panel-body');
        body.replaceChildren(lkLoader('Loading', 'md', true));
        controller = new AbortController();
        try {
            const response = await fetch(section.dataset.lkMonUrl, {
                credentials: 'same-origin', signal: controller.signal,
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            body.innerHTML = await response.text();
        } catch (error) {
            if (error.name === 'AbortError') {
                return;
            }
            const message = document.createElement('p');
            message.className = 'lk-mon-error';
            message.textContent = `Unable to load this section (${error.message}). Close and open it again to retry.`;
            body.replaceChildren(message);
        }
    });
});

// Ongoing captures (#lk-mon-captures): requested again every 10 s
// (data-lk-mon-every), the seconds left shown in [data-lk-mon-countdown].
// Paused while the tab is hidden, checked at once when it is shown again.
// The fragment carries the totals (.lk-mon-totals data-*) to update the counter
// of the panel, its sub-title and the "Being captured" / "Waiting" figures.
(() => {
    const body = document.getElementById('lk-mon-captures');
    if (!body) {
        return;
    }
    const every = Number(body.dataset.lkMonEvery) || 10;
    const panel = body.closest('.lk-mon-panel');
    let left = every;
    let loading = false;

    const applyTotals = () => {
        const totals = body.querySelector('.lk-mon-totals');
        if (!totals) {
            return;
        }
        const ongoing = Number(totals.dataset.ongoing);
        const queued = Number(totals.dataset.queued);
        const format = value => value.toLocaleString('en');
        const count = panel.querySelector('.lk-mon-count');
        if (count) {
            count.textContent = format(ongoing + queued);
        }
        const sub = panel.querySelector('.lk-mon-panel-sub');
        if (sub) {
            sub.textContent = totals.dataset.sub;
        }
        const capturing = document.querySelector('[data-lk-mon-kpi="1"]');
        const waiting = document.querySelector('[data-lk-mon-kpi="2"]');
        if (capturing) {
            capturing.textContent = format(ongoing);
        }
        if (waiting) {
            waiting.textContent = format(queued);
            waiting.closest('.lk-mon-kpi')?.classList.toggle('is-amber', queued > 0);
            waiting.closest('.lk-mon-kpi')?.classList.toggle('is-slate', queued === 0);
        }
    };

    const check = async () => {
        if (loading) {
            return;
        }
        loading = true;
        try {
            const response = await fetch(body.dataset.lkMonUrl, {credentials: 'same-origin'});
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            body.innerHTML = await response.text();
            applyTotals();
        } catch (error) {
            const countdown = body.querySelector('[data-lk-mon-countdown]')?.parentElement;
            if (countdown) {
                countdown.textContent = `Check failed (${error.message}), retrying in ${every} s.`;
            }
        } finally {
            loading = false;
            left = every;
        }
    };

    setInterval(() => {
        if (document.hidden || loading) {
            return;
        }
        left -= 1;
        const countdown = body.querySelector('[data-lk-mon-countdown]');
        if (countdown) {
            countdown.textContent = String(Math.max(left, 0));
        }
        if (left <= 0) {
            check();
        }
    }, 1000);
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) {
            check();
        }
    });
})();
