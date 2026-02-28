// ==UserScript==
// @name         SIEM monkey
// @version      1.0
// @author       KausAustra
// @match        https://*
// @icon         data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==
// @grant        GM_xmlhttpRequest
// ==/UserScript==

(function() {
    'use strict';
	
	// ФИЛЬТРЫ
    const templates = [
        {"description":"События subject.name = '${subject.name}'","filter":"subject.name = '${subject.name}'"},
        {"description":"События subject.name = '${subject.name}' or object.name = '${subject.name}'","filter":"subject.name = '${subject.name}' or object.name = '${subject.name}'"},
        {"description":"События subject.account.name = '${subject.account.name}'","filter":"subject.account.name = '${subject.account.name}'"},
        {"description":"Сетевые соединения для ${src.ip}","filter":"object in ['flow', 'connection'] and  protocol in ['TCP', 'tcp', '6'] and src.ip = '${src.ip}' or dst.ip = '${src.ip}'"},
        {"description":"Сетевые соединения для ${dst.ip}","filter":"object in ['flow', 'connection'] and  protocol in ['TCP', 'tcp', '6'] and src.ip = '${dst.ip}' or dst.ip = '${dst.ip}'"},
        {"description":"События x.x.x.x:${src.port} ⇄ ${dst.ip}:${dst.port}","filter":"src.port = '${src.port}' and dst.ip = '${dst.ip}' and dst.port=${dst.port}"},
        {"description":"Процесс ${subject.process.guid} (sysmon)","filter":"event_src.host = '${event_src.host}' and (subject.process.guid = '${subject.process.guid}' or object.process.guid = '${subject.process.guid}')"},
        {"description":"Процесс ${object.process.guid} (sysmon)","filter":"event_src.host = '${event_src.host}' and (subject.process.guid = '${object.process.guid}' or object.process.guid = '${object.process.guid}')"},
        {"description":"Файл ${object.name} на хосте ${event_src.host} (с хешем)", "filter":"(event_src.host = '${event_src.host}') and (object.name = '${object.name}') AND (object.hash)"},
        {"description":"Сетевые коннекты файла ${object.process.fullpath}", "filter":"event_src.host = '${event_src.host}' and msgid = 3 AND (object.process.fullpath = '${object.process.fullpath}')"},
        {"description":"Логины и сессии УЗ ${subject.name}", "filter":"subject.name = '${subject.name}' AND (action = 'login' or msgid in [1149,4778])"},
        {"description":"RDP сессии пользователя ${subject.account.name}", "filter":"subject.account.name = '${subject.account.name}' and msgid in [4778,4779]"},
        {"description":"RDP сессии для хоста ${event_src.host}", "filter":"event_src.host = '${event_src.host}' and msgid in [4778,4779]"},
        {"description":"RDP сессии с адреса ${src.ip}", "filter":"src.ip = '${src.ip}' and msgid in [4778,4779]"},
        {"description":"Запуски процессов для ${subject.account.name}", "filter":"msgid in [1,4688] and subject.account.name = '${subject.account.name}'"},
        {"description":"Запуск файла с хешем ${object.hash}","filter": "msgid=1 and object.process.hash = '${object.hash}'"},
        {"description":"NAD: поиск соединений к ${nad_dst_ip}:${nad_dst_port}", "filter":"dst.ip = ${nad_dst_ip} and dst.port = ${nad_dst_port}"},
        {"description":"NAD: поиск потока ${nad_src_ip}:${nad_src_port} ⇄ ${nad_dst_ip}:${nad_dst_port}", "filter":"src.ip = ${nad_src_ip} and src.port = ${nad_src_port} and dst.ip = ${nad_dst_ip} and dst.port = ${nad_dst_port}"}
    ];

    // КНОПКА
    const monkeyBtn = document.createElement('div');
    monkeyBtn.innerHTML = '🐒';
    Object.assign(monkeyBtn.style, {
        position: 'fixed', bottom: '20px', left: '20px', width: '50px', height: '50px',
        backgroundColor: '#ff8200', borderRadius: '50%', zIndex: '10001',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        fontSize: '24px', cursor: 'pointer', boxShadow: '0 4px 15px rgba(0,0,0,0.5)',
        transition: 'all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275)'
    });
    document.body.appendChild(monkeyBtn);

    // ПАНЕЛЬ
    const panel = document.createElement('div');
    Object.assign(panel.style, {
        position: 'fixed', bottom: '80px', left: '20px', width: '380px',
        maxHeight: '500px', zIndex: '10000', backgroundColor: '#171717',
        border: '1px solid #333', borderLeft: '4px solid #ff8200',
        borderRadius: '4px', fontFamily: 'Segoe UI, sans-serif',
        display: 'none', flexDirection: 'column',
        boxShadow: '0 10px 30px rgba(0,0,0,0.8)', overflowY: 'auto'
    });
    panel.innerHTML = `
        <div style="padding:10px 15px; background:#212121; font-size:11px; font-weight:bold; color:#ff8200; border-bottom:1px solid #333; display:flex; justify-content:space-between;">
            <span>SIEM MONKEY</span>
            <span id="mp-stat" style="color:#666; font-size:9px;">V4.0</span>
        </div>
        <div id="mp-content" style="padding:10px; display:flex; flex-direction:column; gap:8px;"></div>
    `;
    document.body.appendChild(panel);

    let isVisible = false;
    monkeyBtn.onclick = () => {
        isVisible = !isVisible;
        panel.style.display = isVisible ? 'flex' : 'none';
        monkeyBtn.style.transform = isVisible ? 'rotate(360deg) scale(0.9)' : 'rotate(0) scale(1)';
        monkeyBtn.style.backgroundColor = isVisible ? '#333' : '#ff8200';
        if (isVisible) update();
    };

    const applyFilter = async (query) => {
        navigator.clipboard.writeText(query);
        const pipeline = document.querySelector('.filter-pipeline, [class*="filter-pipeline"]');
        if (pipeline) {
            pipeline.click();
            await new Promise(r => setTimeout(r, 250));
            const input = document.querySelector('.ace_text-input, textarea, .cdk-overlay-container input');
            if (input) {
                input.focus();
                document.execCommand('selectAll', false, null);
                document.execCommand('insertText', false, query);
                setTimeout(() => {
                    input.dispatchEvent(new KeyboardEvent('keydown', { bubbles: true, keyCode: 13, key: 'Enter', ctrlKey: true }));
                }, 150);
            }
        }
    };

    const update = () => {
        if (!isVisible) return;
        const labels = document.querySelectorAll('.mc-dt.pt-text-overflow.ng-star-inserted');
        const data = {};
        labels.forEach(lbl => {
            const valEl = lbl.nextElementSibling;
            if (valEl && valEl.innerText.trim() !== '—') data[lbl.innerText.trim()] = valEl.innerText.trim();
        });

        const host = data['event_src.host'];
        let html = '';

        // ДЕРЕВО ПРОЦЕССОВ
        Object.keys(data).forEach((key, idx) => {
            // ВВЕРХ
            if (key.includes('.parent.') && host) {
                const childField = key.replace('.parent.', '.');
                const q = `event_src.host = '${host}' and ${childField} = '${data[key]}'`;
                html += createBtnHtml(`up_${idx}`, `⬆️ [UP] Найти родителя (${key.split('.').pop()})`, q, '#1a324a', '#1e88e5');
            }
            // ВНИЗ
//             if ((key.endsWith('.guid') || key.endsWith('.id')) && !key.includes('.parent.') && host) {
//                 const parentField = key.replace('.process.', '.process.parent.');
//                 const q = `event_src.host = '${host}' and ${parentField} = '${data[key]}'`;
//                 html += createBtnHtml(`down_${idx}`, `⬇️ [DOWN] Найти потомка (${key.split('.').pop()})`, q, '#2a3a2a', '#4caf50');
//             }
        });

        // Применение фильтров
        templates.forEach((tpl, idx) => {
            const matches = (tpl.filter.match(/\${(.*?)}/g) || []).map(m => m.replace(/[${}]/g, ''));
            if (matches.length > 0 && matches.every(f => data[f])) {
                let q = tpl.filter, d = tpl.description;
                matches.forEach(f => {
                    q = q.split(`\${${f}}`).join(data[f]);
                    d = d.split(`\${${f}}`).join(data[f]);
                });
                html += createBtnHtml(`std_${idx}`, d, q, '#262626', '#3c3c3c');
            }
        });

        panel.querySelector('#mp-content').innerHTML = html || '<div style="color:#666; font-size:11px; text-align:center; padding:20px;">🐒 Выберите событие в MP...</div>';

        panel.querySelectorAll('[data-q]').forEach(btn => {
            btn.onclick = () => applyFilter(decodeURIComponent(btn.getAttribute('data-q')));
        });
    };

    function createBtnHtml(id, desc, q, bg, border) {
        return `
            <div id="${id}" data-q="${encodeURIComponent(q)}" style="background:${bg}; border:1px solid ${border}; padding:10px; cursor:pointer; border-radius:3px; transition:0.2s;">
                <div style="color:#ff8200; font-size:10px; font-weight:bold; margin-bottom:4px;">${desc}</div>
                <code style="color:#bbb; font-size:11px; word-break:break-all; display:block;">${q}</code>
            </div>`;
    }

    let timer;
    new MutationObserver(() => {
        clearTimeout(timer);
        timer = setTimeout(update, 600);
    }).observe(document.body, { childList: true, subtree: true });

    monkeyBtn.onmouseenter = () => monkeyBtn.style.boxShadow = '0 0 20px #ff8200';
    monkeyBtn.onmouseleave = () => monkeyBtn.style.boxShadow = '0 4px 15px rgba(0,0,0,0.5)';
})();
