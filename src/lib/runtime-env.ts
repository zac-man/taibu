import { createHash } from 'node:crypto';

/** Server/build-time deployment settings; never derive trust from request headers. */
export function parseConfiguredOrigin(value: string | undefined, name: string): URL {
    if (!value) throw new Error(`Missing ${name} configuration`);
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.hostname.includes('*')
        || (value !== url.origin && value !== `${url.origin}/`)) {
        throw new Error(`${name} must be an HTTP(S) origin without credentials, path, query or fragment`);
    }
    return url;
}

export function shouldSecureAuthCookies(): boolean {
    const origin = parseConfiguredOrigin(process.env.APP_ORIGIN, 'APP_ORIGIN');
    if (process.env.AUTH_ALLOW_INSECURE_LOCAL_HTTP === 'true') {
        if (origin.protocol !== 'http:'
            || !LOOPBACK_HOSTS.includes(origin.hostname)) {
            throw new Error('Insecure auth cookies require an exact loopback HTTP APP_ORIGIN');
        }
        return false;
    }
    return origin.protocol === 'https:' || process.env.NODE_ENV === 'production';
}

const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '[::1]'];

/** 本地单用户开关本身只读环境变量；未配置凭据的情景由 {@link localSingleUserIdentity} 拒绝。 */
export function localSingleUserEnabled(): boolean {
    return process.env.TAIBU_LOCAL_SINGLE_USER === 'true';
}

/**
 * 本地单用户模式的账号：免注册免登录时由服务端自行创建并登录的唯一账号。
 *
 * 只允许 loopback APP_ORIGIN —— 该模式会跳过邮箱验证、自动补会话，并把这个账号
 * 设为管理员，暴露到非本机地址等于把管理后台公开。密码由 BETTER_AUTH_SECRET 派生，
 * 不落盘也不进环境变量。
 */
export function localSingleUserIdentity(): { email: string; password: string } {
    const origin = parseConfiguredOrigin(process.env.APP_ORIGIN, 'APP_ORIGIN');
    if (!LOOPBACK_HOSTS.includes(origin.hostname)) {
        throw new Error('TAIBU_LOCAL_SINGLE_USER 只允许 loopback APP_ORIGIN（localhost/127.0.0.1/[::1]）');
    }
    const email = (process.env.TAIBU_LOCAL_USER_EMAIL ?? 'local@taibu.local').trim();
    // identity.users 要求邮箱小写；这里提前失败，避免数据库约束报错。
    if (email !== email.toLowerCase() || !/^[^\s@]+@[^\s@]+$/u.test(email)) {
        throw new Error('TAIBU_LOCAL_USER_EMAIL 必须是小写邮箱地址');
    }
    const secret = process.env.BETTER_AUTH_SECRET;
    if (!secret) throw new Error('Missing BETTER_AUTH_SECRET configuration');
    return {
        email,
        password: `taibu-local:${createHash('sha256').update(`taibu-local-single-user\n${secret}`).digest('base64url')}`,
    };
}

/**
 * Origins Better Auth may accept in this environment. A development loopback
 * APP_ORIGIN also accepts the other loopback spelling (localhost ↔ 127.0.0.1)
 * on the same port, so opening the dev server under either name can sign in.
 * Production trusts only the configured origin.
 */
export function trustedAuthOrigins(origin: URL, nodeEnv = process.env.NODE_ENV): string[] {
    const origins = [origin.origin];
    const loopback = LOOPBACK_HOSTS.includes(origin.hostname);
    if (nodeEnv !== 'production' && loopback) {
        for (const host of ['localhost', '127.0.0.1']) {
            origins.push(`${origin.protocol}//${host}${origin.port ? `:${origin.port}` : ''}`);
        }
    }
    return [...new Set(origins)];
}
