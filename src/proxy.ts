import { NextResponse, type NextRequest } from 'next/server';
import { localSingleUserEnabled } from '@/lib/runtime-env';

/**
 * 本地单用户模式的会话引导入口（Next 16 的 Proxy，旧称 Middleware）。
 *
 * 只有在 `TAIBU_LOCAL_SINGLE_USER=true` 时才生效：浏览器没有会话 Cookie 时先把
 * 请求导到 /api/local-session 建号并登录，再回到原地址；之后每个请求都带 Cookie，
 * 和普通登录用户走完全相同的鉴权链路。
 */

/** Better Auth 的会话 Cookie（cookiePrefix 'taibu'，HTTPS 时带 __Secure- 前缀）。 */
const SESSION_COOKIE_NAMES = ['taibu.session_token', '__Secure-taibu.session_token'];

/** 引导接口自身与健康检查不能重定向，否则会自指或让探针拿到 307。 */
const EXCLUDED_PREFIXES = ['/api/auth', '/api/local-session', '/api/health', '/_next/'];

export function proxy(request: NextRequest) {
    if (!localSingleUserEnabled()) return NextResponse.next();

    const { pathname, search } = request.nextUrl;
    if (EXCLUDED_PREFIXES.some((prefix) => pathname.startsWith(prefix))) return NextResponse.next();
    // 静态资源（含 public/ 下的文件名带后缀的资源）与页面路由不会带 Cookie，跳过。
    if (/\.[a-z0-9]+$/iu.test(pathname)) return NextResponse.next();
    if (SESSION_COOKIE_NAMES.some((name) => request.cookies.has(name))) return NextResponse.next();

    // 目标地址由 nextUrl 构造，Next 会把它规范化成相对 Location（已验证）。
    const target = new URL('/api/local-session', request.nextUrl.origin);
    target.searchParams.set('next', `${pathname}${search}`);
    return NextResponse.redirect(target);
}
