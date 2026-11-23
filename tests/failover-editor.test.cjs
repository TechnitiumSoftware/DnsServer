const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const context = vm.createContext({
    URL, window: { addEventListener() {} }, document: { querySelectorAll: () => [], body: {} },
    ResizeObserver: class { observe() {} }
});
const editor = fs.readFileSync(path.join(__dirname, '../Apps/FailoverApp/record-editor.html'), 'utf8');
vm.runInContext(editor.match(/<script>([\s\S]*?)<\/script>/)[1], context);
const plain = value => JSON.parse(JSON.stringify(value));

test('legacy strings stay enabled and disabled IPv4/IPv6 entries round trip', () => {
    assert.equal(typeof context.readFailoverRecordData, 'function');
    const data = context.readFailoverRecordData(JSON.stringify({
        primary: ['192.0.2.1', { address: '2001:db8::1', enabled: false, note: 'maintenance' }],
        secondary: ['198.51.100.1'], serverDown: ['203.0.113.1'], healthCheck: 'https', custom: 42
    }));
    assert.equal(data.custom, 42);
    assert.equal(context.createFailoverAddressData(data.primary[0], '192.0.2.1', true), '192.0.2.1');
    assert.deepEqual(plain(context.createFailoverAddressData(data.primary[0], '192.0.2.1', false)),
        { address: '192.0.2.1', enabled: false });
    assert.deepEqual(plain(context.createFailoverAddressData(data.primary[1], '2001:db8::2', true)),
        { address: '2001:db8::2', enabled: true, note: 'maintenance' });
    assert.equal(data.primary[1].enabled, false, 'editing must not mutate the original');
});

test('reject unsupported shapes rather than losing data when opening the form', () => {
    for (const data of [null, [], { primary: '192.0.2.1' }, { primary: [123] },
        { secondary: [{ enabled: false }] }, { primary: [{ address: '192.0.2.1', enabled: 'false' }] },
        { healthCheck: {} }, { healthCheckUrl: [] }, { allowTxtStatus: 'false' }]) {
        assert.throws(() => context.readFailoverRecordData(JSON.stringify(data)));
    }
    assert.throws(() => context.readFailoverRecordData('{ /* comment */ "primary": [] }'));
    assert.deepEqual(plain(context.readFailoverRecordData('{"primary":[],"healthCheckUrl":null}')),
        { primary: [], healthCheckUrl: null });
});

test('validate individual backend IPs including IPv6 and reject URLs or hostnames', () => {
    for (const address of ['0.0.0.0', '255.255.255.255', '192.0.2.1', '::1', '2001:db8::1', '::ffff:192.0.2.1'])
        assert.equal(context.createFailoverAddressData('', address, true), address);
    for (const address of ['', 'example.com', '192.0.2', '256.0.0.1', '1.2.3.4/path', '[::1]', ':::1', 'https://192.0.2.1', '::1]/', '2001:db8::1]:443/', '::1]#bad'])
        assert.throws(() => context.createFailoverAddressData('', address, true), /IP address/);
});
