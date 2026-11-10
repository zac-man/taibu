import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { NextRequest } from 'next/server';
import { localSingleUserEnabled, localSingleUserIdentity } from '../lib/runtime-env';
import { GET as localSessionRoute } from '../app/api/local-session/route';
import { proxy } from '../proxy';

const SECRET = 'a'.repeat(64);

function environment(t: TestContext, overrides: Record<string, string | undefined>) {
    const values: Record<string, string | undefined> = {
        APP_ORIGIN: 'http://127.0.0.1:3080',
        BETTER_AUTH_SECRET: SECRET,
        TAIBU_LOCAL_SINGLE_USER: 'true',
        TAIBU_LOCAL_USER_EMAIL: undefined,
        ...overrides,
    };
    const previous = Object.fromEntries(Object.keys(values).map(key => [key, process.env[key]]));
    for (const [key, value] of Object.entries(values)) {
        if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    t.after(() => {
        for (const [key, value] of Object.entries(previous)) {
            if (value === undefined) delete process.env[key]; else process.env[key] = value;
        }
    });
}

test('本地单用户模式默认关闭', (t) => {
    environment(t, { TAIBU_LOCAL_SINGLE_USER: undefined });
    assert.equal(localSingleUserEnabled(), false);
    assert.equal(localSingleUserEnabled(), false);
});

test('本地单用户模式派生出固定的本地账号密码', (t) => {
    environment(t, {});
    const identity = localSingleUserIdentity();
    assert.equal(identity.email, 'local@taibu.local');
    assert.deepEqual(identity, localSingleUserIdentity());
    assert.ok(identity.password.length >= 8);
    assert.ok(!identity.password.includes(SECRET));
});

test('本地单用户模式接受自定义小写邮箱', (t) => {
    environment(t, { TAIBU_LOCAL_USER_EMAIL: 'me@local.test' });
    assert.equal(localSingleUserIdentity().email, 'me@local.test');
});

test('本地单用户模式拒绝非 loopback 地址', (t) => {
    environment(t, { APP_ORIGIN: 'https://mingai.fun' });
    assert.throws(() => localSingleUserIdentity(), /loopback/);
});

test('本地单用户模式拒绝非小写邮箱与缺失密钥', async (t) => {
    environment(t, { TAIBU_LOCAL_USER_EMAIL: 'Local@Taibu.local' });
    assert.throws(() => localSingleUserIdentity(), /小写邮箱/);
    environment(t, { BETTER_AUTH_SECRET: undefined });
    assert.throws(() => localSingleUserIdentity(), /BETTER_AUTH_SECRET/);
});

/** 跳转地址只比较路径与查询串：Next 在服务端会把同源地址规范成相对 Location。 */
function redirectTarget(response: Response): string {
    const url = new URL(response.headers.get('location') ?? '', 'http://127.0.0.1:3080');
    return `${url.pathname}${url.search}`;
}

function mockModules(t: TestContext, options: { enabled: boolean; signedIn: boolean; cookies?: string[] }) {
    const runtimeEnv = require('../lib/runtime-env') as { localSingleUserEnabled: () => boolean };
    const auth = require('../lib/identity/auth.server') as { getAuthState: (headers: Headers) => Promise<unknown> };
    const localUser = require('../lib/identity/local-user.server') as {
        ensureLocalSingleUserSession: (headers: Headers) => Promise<string[]>;
    };
    t.mock.method(runtimeEnv, 'localSingleUserEnabled', () => options.enabled);
    t.mock.method(auth, 'getAuthState', async () => (options.signedIn
        ? { session: { id: 'session-1' }, user: { id: 'user-1', email: 'local@taibu.local' } }
        : null) as never);
    return t.mock.method(localUser, 'ensureLocalSingleUserSession', async () => options.cookies ?? []);
}

test('未开启本地单用户模式时引导接口不存在', async (t) => {
    mockModules(t, { enabled: false, signedIn: false });
    const response = await localSessionRoute(new NextRequest('http://127.0.0.1:3080/api/local-session'));
    assert.equal(response.status, 404);
    assert.equal((await response.json()).success, false);
});

test('首次访问引导接口建会话并跳回原路径', async (t) => {
    const ensure = mockModules(t, { enabled: true, signedIn: false, cookies: ['taibu.session_token=tok; Path=/'] });
    const response = await localSessionRoute(
        new NextRequest('http://127.0.0.1:3080/api/local-session?next=%2Fbazi%3Ftab%3D1'),
    );
    assert.equal(response.status, 307);
    assert.equal(redirectTarget(response), '/bazi?tab=1');
    assert.deepEqual(response.headers.getSetCookie(), ['taibu.session_token=tok; Path=/']);
    assert.equal(ensure.mock.callCount(), 1);
});

test('已有会话时不再建号', async (t) => {
    const ensure = mockModules(t, { enabled: true, signedIn: true });
    const response = await localSessionRoute(
        new NextRequest('http://127.0.0.1:3080/api/local-session?next=/chat'),
    );
    assert.equal(response.status, 307);
    assert.equal(redirectTarget(response), '/chat');
    assert.equal(ensure.mock.callCount(), 0);
});

test('不带 next 时只回 JSON，供浏览器自愈', async (t) => {
    mockModules(t, { enabled: true, signedIn: false, cookies: ['taibu.session_token=tok; Path=/'] });
    const response = await localSessionRoute(new NextRequest('http://127.0.0.1:3080/api/local-session'));
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { signedIn: true });
    assert.equal(response.headers.get('cache-control'), 'no-store');
});

for (const [name, value] of [
    ['协议相对地址', '//evil.test/steal'],
    ['绝对地址', 'https://evil.test/steal'],
    ['反斜杠变体', '/\\evil.test'],
] as const) {
    test(`引导接口拒绝开放重定向：${name}`, async (t) => {
        mockModules(t, { enabled: true, signedIn: false });
        const request = new NextRequest(
            `http://127.0.0.1:3080/api/local-session?next=${encodeURIComponent(value)}`,
        );
        const response = await localSessionRoute(request);
        assert.equal(redirectTarget(response), '/');
    });
}

test('引导失败返回 500 与错误信息', async (t) => {
    mockModules(t, { enabled: true, signedIn: false });
    const localUser = require('../lib/identity/local-user.server') as {
        ensureLocalSingleUserSession: (headers: Headers) => Promise<string[]>;
    };
    t.mock.method(localUser, 'ensureLocalSingleUserSession', async () => {
        throw new Error('本地账号登录失败（403）');
    });
    const response = await localSessionRoute(
        new NextRequest('http://127.0.0.1:3080/api/local-session?next=/bazi'),
    );
    assert.equal(response.status, 500);
    assert.equal((await response.json()).error, '本地账号登录失败（403）');
});

test('代理在没有会话 Cookie 时把首访导到引导接口', (t) => {
    mockModules(t, { enabled: true, signedIn: false });
    const response = proxy(new NextRequest('http://127.0.0.1:3080/bazi?tab=1'));
    assert.equal(response.status, 307);
    assert.equal(redirectTarget(response), '/api/local-session?next=%2Fbazi%3Ftab%3D1');
});

test('代理放行带会话 Cookie、静态资源与健康检查', (t) => {
    mockModules(t, { enabled: true, signedIn: false });
    const withCookie = new NextRequest('http://127.0.0.1:3080/bazi', {
        headers: { cookie: 'taibu.session_token=tok' },
    });
    assert.equal(proxy(withCookie).headers.get('location'), null);
    for (const path of ['/api/health', '/api/auth/get-session', '/api/local-session', '/_next/static/app.js', '/favicon.ico']) {
        assert.equal(proxy(new NextRequest(`http://127.0.0.1:3080${path}`)).headers.get('location'), null, path);
    }
});

test('代理在未开启本地单用户模式时不介入', (t) => {
    mockModules(t, { enabled: false, signedIn: false });
    assert.equal(proxy(new NextRequest('http://127.0.0.1:3080/bazi')).headers.get('location'), null);
});
