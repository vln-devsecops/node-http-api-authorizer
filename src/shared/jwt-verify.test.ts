import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { JwtVerificationError, verifyJwt } from './jwt-verify'

const AUDIENCE = 'test-client-id'

// jose's Node runtime fetches JWKS via node:http/https directly (not global
// fetch), so a real local HTTP server is the only reliable way to exercise
// createRemoteJWKSet hermetically. Each test gets its own server/port, which
// also means each test gets its own cache key in jwt-verify's module-level
// jwksCache -- no cross-test cache collisions to worry about.
async function startJwksServer(jwks: unknown): Promise<{ issuerUrl: string; server: Server }> {
  const server = createServer((req, res) => {
    if (req.url === '/.well-known/jwks.json') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify(jwks))
      return
    }
    res.writeHead(404)
    res.end()
  })
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address() as AddressInfo
  return { issuerUrl: `http://127.0.0.1:${port}`, server }
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())))
}

describe('verifyJwt', () => {
  let server: Server | undefined

  afterEach(async () => {
    if (server) {
      await closeServer(server)
      server = undefined
    }
  })

  it('returns the requested string claims for a valid token', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256')
    const jwk = { ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' }
    const started = await startJwksServer({ keys: [jwk] })
    server = started.server

    const token = await new SignJWT({ tenantId: 'tenant-1', permissions: 'a,b' })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(started.issuerUrl)
      .setAudience(AUDIENCE)
      .setExpirationTime('5m')
      .sign(privateKey)

    const context = await verifyJwt(token, {
      issuerUrl: started.issuerUrl,
      audience: AUDIENCE,
      forwardClaims: ['tenantId', 'permissions', 'missingClaim'],
    })

    expect(context).toEqual({ tenantId: 'tenant-1', permissions: 'a,b' })
  })

  it('drops non-string claims', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256')
    const jwk = { ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' }
    const started = await startJwksServer({ keys: [jwk] })
    server = started.server

    const token = await new SignJWT({ count: 5 })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(started.issuerUrl)
      .setAudience(AUDIENCE)
      .setExpirationTime('5m')
      .sign(privateKey)

    const context = await verifyJwt(token, {
      issuerUrl: started.issuerUrl,
      audience: AUDIENCE,
      forwardClaims: ['count'],
    })

    expect(context).toEqual({})
  })

  it('throws JwtVerificationError for a wrong audience', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256')
    const jwk = { ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' }
    const started = await startJwksServer({ keys: [jwk] })
    server = started.server

    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(started.issuerUrl)
      .setAudience('someone-else')
      .setExpirationTime('5m')
      .sign(privateKey)

    await expect(
      verifyJwt(token, { issuerUrl: started.issuerUrl, audience: AUDIENCE, forwardClaims: [] }),
    ).rejects.toThrow(JwtVerificationError)
  })

  it('throws JwtVerificationError for an expired token', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256')
    const jwk = { ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' }
    const started = await startJwksServer({ keys: [jwk] })
    server = started.server

    const now = Math.floor(Date.now() / 1000)
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(started.issuerUrl)
      .setAudience(AUDIENCE)
      .setIssuedAt(now - 3600)
      .setExpirationTime(now - 1800)
      .sign(privateKey)

    await expect(
      verifyJwt(token, { issuerUrl: started.issuerUrl, audience: AUDIENCE, forwardClaims: [] }),
    ).rejects.toThrow(JwtVerificationError)
  })

  it('throws JwtVerificationError for a token signed by an unknown key', async () => {
    const { publicKey } = await generateKeyPair('RS256')
    const jwk = { ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' }
    const started = await startJwksServer({ keys: [jwk] })
    server = started.server

    const { privateKey: otherPrivateKey } = await generateKeyPair('RS256')
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(started.issuerUrl)
      .setAudience(AUDIENCE)
      .setExpirationTime('5m')
      .sign(otherPrivateKey)

    await expect(
      verifyJwt(token, { issuerUrl: started.issuerUrl, audience: AUDIENCE, forwardClaims: [] }),
    ).rejects.toThrow(JwtVerificationError)
  })
})
