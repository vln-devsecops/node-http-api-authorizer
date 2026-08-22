import type { APIGatewayRequestAuthorizerEventV2 } from 'aws-lambda'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { JwtVerificationError } from './shared/jwt-verify'

const verifyJwtMock = vi.hoisted(() => vi.fn())
vi.mock('./shared/jwt-verify', async () => {
  const actual = await vi.importActual<typeof import('./shared/jwt-verify')>('./shared/jwt-verify')
  return { ...actual, verifyJwt: verifyJwtMock }
})

const { handler } = await import('./handler')

const ORIGIN_SECRET = 'shared-secret'

function event(headers: Record<string, string | undefined>): APIGatewayRequestAuthorizerEventV2 {
  return {
    headers,
  } as unknown as APIGatewayRequestAuthorizerEventV2
}

describe('handler', () => {
  const originalEnv = { ...process.env }

  beforeEach(() => {
    process.env = { ...originalEnv }
    process.env.ORIGIN_VERIFY_SECRET = ORIGIN_SECRET
    delete process.env.REQUIRE_JWT
    verifyJwtMock.mockReset()
  })

  afterEach(() => {
    process.env = originalEnv
  })

  it('rejects a request with no X-Origin-Verify header', async () => {
    const result = await handler(event({}))
    expect(result).toEqual({ isAuthorized: false, context: {} })
  })

  it('rejects a request with the wrong X-Origin-Verify value', async () => {
    const result = await handler(event({ 'x-origin-verify': 'wrong' }))
    expect(result).toEqual({ isAuthorized: false, context: {} })
  })

  it('authorizes on a matching header when REQUIRE_JWT is unset', async () => {
    const result = await handler(event({ 'x-origin-verify': ORIGIN_SECRET }))
    expect(result).toEqual({ isAuthorized: true, context: {} })
    expect(verifyJwtMock).not.toHaveBeenCalled()
  })

  describe('when REQUIRE_JWT=true', () => {
    beforeEach(() => {
      process.env.REQUIRE_JWT = 'true'
      process.env.JWT_ISSUER_URL = 'https://issuer.example.com'
      process.env.JWT_AUDIENCE = 'client-id'
      process.env.JWT_FORWARD_CLAIMS = 'tenantId,permissions'
    })

    it('rejects when the Authorization header is missing', async () => {
      const result = await handler(event({ 'x-origin-verify': ORIGIN_SECRET }))
      expect(result).toEqual({ isAuthorized: false, context: {} })
      expect(verifyJwtMock).not.toHaveBeenCalled()
    })

    it('rejects when the Authorization header is not a Bearer token', async () => {
      const result = await handler(
        event({ 'x-origin-verify': ORIGIN_SECRET, authorization: 'Basic dXNlcjpwYXNz' }),
      )
      expect(result).toEqual({ isAuthorized: false, context: {} })
      expect(verifyJwtMock).not.toHaveBeenCalled()
    })

    it('authorizes with forwarded claims on a valid token', async () => {
      verifyJwtMock.mockResolvedValue({ tenantId: 't1', permissions: 'read,write' })

      const result = await handler(
        event({ 'x-origin-verify': ORIGIN_SECRET, authorization: 'Bearer a.b.c' }),
      )

      expect(result).toEqual({
        isAuthorized: true,
        context: { tenantId: 't1', permissions: 'read,write' },
      })
      expect(verifyJwtMock).toHaveBeenCalledWith('a.b.c', {
        issuerUrl: 'https://issuer.example.com',
        audience: 'client-id',
        forwardClaims: ['tenantId', 'permissions'],
      })
    })

    it('rejects when JWT verification fails', async () => {
      verifyJwtMock.mockRejectedValue(new JwtVerificationError('bad token'))

      const result = await handler(
        event({ 'x-origin-verify': ORIGIN_SECRET, authorization: 'Bearer a.b.c' }),
      )

      expect(result).toEqual({ isAuthorized: false, context: {} })
    })

    it('rethrows unexpected errors from JWT verification', async () => {
      verifyJwtMock.mockRejectedValue(new Error('network blip'))

      await expect(
        handler(event({ 'x-origin-verify': ORIGIN_SECRET, authorization: 'Bearer a.b.c' })),
      ).rejects.toThrow('network blip')
    })
  })
})
