import 'server-only';

import { isAPIError } from 'better-auth/api';
import { getAuth } from '@/lib/identity/auth.server';
import { systemDb } from '@/lib/db/context.server';
import { localSingleUserIdentity } from '@/lib/runtime-env';

/**
 * 本地单用户模式的账号引导（免注册免登录，见 docs/manual/Self-Hosting.md）。
 *
 * 只在 `TAIBU_LOCAL_SINGLE_USER=true` 且 APP_ORIGIN 是 loopback 时生效：第一次
 * 访问时创建唯一账号、把它设为管理员，并返回一个新的会话 Cookie。之后浏览器
 * 就是「已登录」状态，所有鉴权入口（RLS 的 userDb、requireUserContext、客户端
 * 会话）都按普通登录用户处理，不再有旁路。
 */

const LOCAL_NICKNAME = '本地用户';

/** 管理员权限写在 public.users，只有系统主体能改；本地模式由服务端自己授予。 */
async function grantAdmin(userId: string): Promise<void> {
  await systemDb().tx((trx) => trx
    .insertInto('users')
    .values({ id: userId, nickname: LOCAL_NICKNAME, is_admin: true })
    .onConflict((conflict) => conflict.column('id').doUpdateSet({ is_admin: true }))
    .execute());
}

/** Better Auth 的端点返回形状（returnHeaders + returnStatus），或者抛出 APIError。 */
type AuthAttempt = { headers: Headers; status: number; response: unknown };

function attemptFailed(attempt: AuthAttempt): boolean {
  return attempt.status >= 400 || isAPIError(attempt.response);
}

function attemptDetail(attempt: AuthAttempt): string {
  return isAPIError(attempt.response) ? attempt.response.message : `HTTP ${attempt.status}`;
}

/**
 * 创建（或复用）本地账号并登录，返回应当写给浏览器的 Set-Cookie 列表。
 * 调用方负责把它们附加到自己的响应上。
 */
export async function ensureLocalSingleUserSession(requestHeaders: Headers): Promise<string[]> {
  const identity = localSingleUserIdentity();
  const auth = getAuth();
  const body = { email: identity.email, password: identity.password };

  // 首次访问建号（本地模式下注册即登录）；账号已存在时改为直接登录。
  // 失败判定同时看状态码与 isAPIError：Better Auth 的错误类与这里导入的未必是同一份。
  let signed: AuthAttempt | null = null;
  try {
    signed = await auth.api.signUpEmail({
      body: { ...body, name: LOCAL_NICKNAME },
      headers: requestHeaders,
      returnHeaders: true,
      returnStatus: true,
    });
  } catch (error) {
    if (!isAPIError(error)) throw error;
    console.warn('[local-user] 本地账号注册未通过，改为直接登录:', error.status);
  }

  if (!signed || attemptFailed(signed)) {
    signed = await auth.api.signInEmail({
      body,
      headers: requestHeaders,
      returnHeaders: true,
      returnStatus: true,
    });
  }
  if (attemptFailed(signed)) throw new Error(`本地账号登录失败：${attemptDetail(signed)}`);

  const userId = (signed.response as { user?: { id?: string } } | null)?.user?.id ?? null;
  if (!userId) throw new Error('本地账号登录失败：响应缺少用户标识');
  await grantAdmin(userId);
  return signed.headers.getSetCookie();
}
