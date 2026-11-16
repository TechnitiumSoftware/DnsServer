// PLAYWRIGHT_MODULE=/path/to/playwright CHROME_PATH=/path/to/chrome node tests/app-record-editor.browser.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.join(__dirname, '..');

(async () => {
    const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH, headless: true });
    try {
        const page = await browser.newPage({ viewport: { width: 1100, height: 1100 } });
        const errors = [];
        page.on('pageerror', error => errors.push(error.message));
        const html = fs.readFileSync(path.join(root, 'DnsServerCore/www/index.html'), 'utf8')
            .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<link\b[^>]*>/gi, '');
        await page.route('http://app-editor.test/**', route => route.fulfill({ contentType: 'text/html', body: html }));
        await page.goto('http://app-editor.test/');
        await page.addStyleTag({ path: path.join(root, 'DnsServerCore/www/css/bootstrap.min.css') });
        for (const script of ['jquery.min.js', 'bootstrap.min.js', 'common.js', 'zone.js'])
            await page.addScriptTag({ path: path.join(root, 'DnsServerCore/www/js', script) });
        const editor = fs.readFileSync(path.join(root, 'Apps/FailoverApp/record-editor.html'), 'utf8');
        await page.evaluate(editor => {
            window.sessionData = { token: 'test-token-not-shared-with-frame', info: { defaultRecordTtl: 300 } };
            clearAddEditRecordForm();
            $('#optAddEditRecordType').val('APP');
            modifyAddRecordFormByType(false);
            window.appsList = [{ name: 'Any app name', dnsApps: [{ classPath: 'Any.Component', recordDataEditor: editor }] }];
            $('#optAddEditRecordDataAppName').html('<option>Any app name</option>');
            $('#optAddEditRecordDataClassPath').html('<option>Any.Component</option>');
            $('#txtAddEditRecordDataData').val(JSON.stringify({
                primary: ['192.0.2.1', { address: '2001:db8::1', enabled: false, note: '<keep>' }],
                secondary: ['198.51.100.1'], serverDown: ['203.0.113.1'],
                healthCheck: 'https', healthCheckUrl: null, extra: { preserved: true }
            }));
            $('#divAddEditRecordDataApplication').show();
            $('#modalAddEditRecord').removeClass('fade').modal({ backdrop: false });
            loadAppRecordEditor();
        }, editor);
        await page.waitForFunction(() => appRecordEditorReady);
        let frame = page.frameLocator('#frameAppRecordEditor');
        assert.equal(await frame.locator('#primary .row').count(), 2);
        assert.equal(await frame.locator('#primary input[type=checkbox]').nth(1).isChecked(), false);
        await frame.locator('#primary input[type=checkbox]').first().uncheck();
        await frame.locator('#primary input[type=checkbox]').nth(1).check();
        let data = JSON.parse(await page.evaluate(() => getAppRecordData()));
        assert.deepEqual(data.primary, [{ address: '192.0.2.1', enabled: false }, { address: '2001:db8::1', enabled: true, note: '<keep>' }]);
        assert.deepEqual(data.extra, { preserved: true });

        // Verify isolation: the app cannot access the console or its session token.
        const childFrame = page.frames().find(f => f !== page.mainFrame());
        assert.equal(await childFrame.evaluate(() => document.compatMode), 'CSS1Compat');
        assert.equal(await childFrame.evaluate(() => {
            try { return parent.sessionData.token; } catch { return 'blocked'; }
        }), 'blocked');
        assert.equal(await childFrame.evaluate(() => {
            try { return localStorage.getItem('token'); } catch { return 'blocked'; }
        }), 'blocked');

        await frame.getByRole('button', { name: 'Add secondary IP', exact: true }).click();
        await frame.locator('#secondary input[type=text]').last().fill('not-an-ip');
        assert.equal(await page.evaluate(() => getAppRecordData()), null);
        await frame.locator('#secondary input[type=text]').last().fill('2001:db8::2');
        await frame.locator('#serverDown input[type=checkbox]').uncheck();
        data = JSON.parse(await page.evaluate(() => getAppRecordData()));
        assert.deepEqual(data.secondary, ['198.51.100.1', '2001:db8::2']);
        assert.deepEqual(data.serverDown, [{ address: '203.0.113.1', enabled: false }]);
        await frame.locator('#healthCheckUrl').fill('javascript:alert(1)');
        assert.equal(await page.evaluate(() => getAppRecordData()), null);
        await frame.locator('#healthCheckUrl').fill('https://example.com/health');

        await page.locator('#chkAppRecordRawData').scrollIntoViewIfNeeded();
        await page.locator('#chkAppRecordRawData').click();
        await page.waitForFunction(() => $('#chkAppRecordRawData').prop('checked'));
        assert.equal(JSON.parse(await page.locator('#txtAddEditRecordDataData').inputValue()).healthCheckUrl, 'https://example.com/health');
        await page.locator('#chkAppRecordRawData').click();
        await page.waitForFunction(() => appRecordEditorReady);
        frame = page.frameLocator('#frameAppRecordEditor');
        assert.equal(await frame.locator('#primary input[type=checkbox]').first().isChecked(), false);

        // Both save APIs must await fresh data from the component, including the final keystroke.
        await page.evaluate(() => {
            $('#titleEditZone').attr('data-zone', 'example.com').attr('data-zone-type', 'Primary');
            $('#txtAddEditRecordName').val('www');
            $('#optAddEditRecordType').val('APP');
            window.HTTPRequest = options => { window.lastRequest = options; };
        });
        await frame.locator('#primary input[type=text]').first().fill('192.0.2.99');
        await page.evaluate(() => addRecord());
        let request = await page.evaluate(() => ({ url: lastRequest.url, data: lastRequest.data }));
        assert.match(request.url, /records\/add/);
        assert.equal(JSON.parse(new URLSearchParams(request.data).get('recordData')).primary[0].address, '192.0.2.99');
        await page.evaluate(() => {
            $('<div id="data0"></div>').attr({
                'data-record-name': 'www.example.com', 'data-record-type': 'APP', 'data-record-index': '0',
                'data-record-app-name': 'Any app name', 'data-record-classpath': 'Any.Component',
                'data-record-disabled': 'false'
            }).appendTo(document.body);
            $('#btnAddEditRecord').attr('data-id', '0');
        });
        await frame.locator('#primary input[type=text]').first().fill('192.0.2.100');
        await page.evaluate(() => updateRecord());
        request = await page.evaluate(() => ({ url: lastRequest.url, data: lastRequest.data }));
        assert.match(request.url, /records\/update/);
        assert.equal(JSON.parse(new URLSearchParams(request.data).get('recordData')).primary[0].address, '192.0.2.100');

        await page.setViewportSize({ width: 375, height: 950 });
        await page.evaluate(() => { $('#modalAddEditRecord .modal-body').scrollTop(0); $('#divAddEditRecordAlert').empty(); });
        assert.equal(await page.frames().find(f => f !== page.mainFrame()).evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        assert.equal(await page.locator('#modalAddEditRecord .modal-dialog').evaluate(el => el.getBoundingClientRect().right <= innerWidth), true);
        await frame.locator('#primary input[type=checkbox]').first().check();
        await frame.locator('#primary input[type=checkbox]').first().uncheck();
        await page.screenshot({ path: '/tmp/failover-editor-mobile.png' });
        await page.setViewportSize({ width: 1100, height: 1100 });
        await page.screenshot({ path: '/tmp/failover-editor-desktop.png' });

        // Unsupported JSON and apps without an editor must retain raw data verbatim.
        const raw = '{ /* preserve this comment */ "primary": [] }';
        await page.evaluate(raw => { $('#txtAddEditRecordDataData').val(raw); loadAppRecordEditor(); }, raw);
        await page.waitForFunction(() => $('#chkAppRecordRawData').prop('checked'));
        assert.equal(await page.evaluate(() => getAppRecordData()), raw);
        await page.evaluate(() => {
            appsList[0].dnsApps[0].recordDataEditor = null;
            $('#txtAddEditRecordDataData').val('non-JSON app data');
            loadAppRecordEditor();
        });
        assert.equal(await page.evaluate(() => getAppRecordData()), 'non-JSON app data');
        assert.equal(await page.locator('#divAppRecordEditorOptions').isVisible(), false);

        // An unrelated app can supply a completely different UI and non-JSON format.
        await page.evaluate(() => {
            appsList[0].dnsApps[0].recordDataEditor = '<!DOCTYPE html><input id="value" aria-label="Custom value"><script>' +
                'window.onmessage = e => { if (e.source !== parent || !e.ports[0]) return; const port = e.ports[0];' +
                'value.value = e.data.data; port.onmessage = e => { if (e.data.type === "save") port.postMessage({type:"save",requestId:e.data.requestId,data:value.value}); };' +
                'port.postMessage({type:"ready"}); };<\/script>';
            loadAppRecordEditor();
        });
        await page.waitForFunction(() => appRecordEditorReady);
        await page.frameLocator('#frameAppRecordEditor').getByLabel('Custom value').fill('custom-format::changed');
        assert.equal(await page.evaluate(() => getAppRecordData()), 'custom-format::changed');

        // Closing/changing the editor cancels a pending save and cannot overwrite raw data.
        assert.equal(await page.evaluate(async () => {
            const pending = getAppRecordData();
            resetAppRecordEditor();
            return await pending;
        }), null);
        assert.equal(await page.locator('#txtAddEditRecordDataData').inputValue(), 'custom-format::changed');
        assert.deepEqual(errors, []);
        console.log('App injection, isolation, per-IP edits, validation, raw fallback, and add/update save checks passed.');
    }
    finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
