import { timingSafeEqual } from 'node:crypto'

/**
 * Constant-time comparison of the caller's X-Origin-Verify header against
 * the expected shared secret. Length is checked first because
 * timingSafeEqual throws on mismatched buffer lengths rather than returning
 * false.
 */
export function isOriginVerified(
  headers: Record<string, string | undefined> | undefined,
  expectedSecret: string,
): boolean {
  const provided = headers?.['x-origin-verify']
  if (!provided) {
    return false
  }

  const providedBuf = Buffer.from(provided)
  const expectedBuf = Buffer.from(expectedSecret)
  if (providedBuf.length !== expectedBuf.length) {
    return false
  }

  return timingSafeEqual(providedBuf, expectedBuf)
}
