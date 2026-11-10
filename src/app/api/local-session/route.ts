import { NextRequest, NextResponse } from 'next/server';
import { jsonError, jsonOk } from '@/lib/api-utils';
import { getAuthState } from '@/lib/identity/auth.server';
import { ensureLocalSingleUserSession } from '@/lib/identity/local-user.server';
import { localSingleUserEnabled } from '@/lib/runtime-env';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * 本地单用户模式的会话引导（免注册免登录）。
 *
 * `GET /api/local-session?next=/path`：没有会话时建号并登录，然后带着 Cookie 跳回
 * `next`（Proxy 在没有会话 Cookie 时把首访导到这里）。不带 `next` 时只回 JSON，
 * 供浏览器在会话失效后自愈，不产生跳转。
 */

/** 只接受同源相对路径，并返回已编码的相对地址，避免开放重定向。 */
function safeNextTarget(value: string | null): string {
    if (!value) return '/';
    let parsed: URL;
    try {
        parsed = new URL(value, 'http://localhost');
    } catch {
        return '/';
    }
    // 绝对地址与协议相对地址（//evil.test）会解析出别的 origin。
    if (parsed.origin !== 'http://localhost') return '/';
    return `${parsed.pathname}${parsed.search}`;
}

/**
 * 跳转要写绝对地址，而容器里 `nextUrl.origin` 是 0.0.0.0:3000（Next 用 HOSTNAME/PORT
 * 构造），浏览器连不上。用请求自己的 Host，反向代理再叠加协议头。
 */
function requestOrigin(request: NextRequest): string {
    const host = request.headers.get('host');
    if (!host) return request.nextUrl.origin;
    const forwarded = request.headers.get('x-forwarded-proto')?.split(',')[0]?.trim();
    return `${forwarded || request.nextUrl.protocol.replace(':', '')}://${host}`;
}

export async function GET(request: NextRequest) {
    if (!localSingleUserEnabled()) return jsonError('本地单用户模式未启用', 404);

    const next = request.nextUrl.searchParams.get('next');
    try {
        const state = await getAuthState(request.headers);
        const cookies = state?.user ? [] : await ensureLocalSingleUserSession(request.headers);
        const response = next
            ? NextResponse.redirect(new URL(safeNextTarget(next), requestOrigin(request)))
            : jsonOk({ signedIn: true });
        response.headers.set('Cache-Control', 'no-store');
        for (const cookie of cookies) response.headers.append('set-cookie', cookie);
        return response;
    } catch (error) {
        console.error('[local-session] 本地账号引导失败:', error);
        return jsonError(error instanceof Error ? error.message : '本地账号引导失败', 500);
    }
}
