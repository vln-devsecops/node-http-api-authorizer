import { createRemoteJWKSet, jwtVerify, type JWTPayload } from 'jose'

// One remote JWK set per issuer, created lazily and kept for the life of the
// execution environment. jose's createRemoteJWKSet already caches keys
// in-process (and re-fetches on an unrecognized kid) -- reusing one instance
// per issuer across invocations avoids re-fetching the JWKS document on
// every warm invocation.
const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>()

function getJwks(issuerUrl: string): ReturnType<typeof createRemoteJWKSet> {
  let jwks = jwksCache.get(issuerUrl)
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${issuerUrl}/.well-known/jwks.json`))
    jwksCache.set(issuerUrl, jwks)
  }
  return jwks
}

export class JwtVerificationError extends Error {}

export interface VerifyJwtOptions {
  issuerUrl: string
  /**
   * Expected `aud` claim. Optional: Amazon Cognito only ever accepts an
   * `aud` claim on an access token whose value equals the app client ID of
   * the authenticating session (confirmed against AWS's own Pre Token
   * Generation docs, node-vlinder-auth#142) -- it can't be used to
   * distinguish which downstream API a token is meant for when every client
   * shares one Cognito app client. `resource` below is the claim for that.
   */
  audience?: string
  /**
   * Expected value of a custom `resource` claim, checked manually below
   * (not via jose's `audience` option, which only ever validates the
   * registered `aud` claim) -- see the doc comment on `audience` for why
   * `aud` can't serve this purpose against a Cognito-issued token.
   */
  resource?: string
  /** Claim names to copy into the returned context; non-string claims are dropped. */
  forwardClaims: string[]
}

/**
 * Verifies a bearer token's signature and issuer against issuerUrl's JWKS
 * (and its `aud` claim, when `audience` is given), then returns only the
 * string-valued claims named in forwardClaims. API Gateway Lambda authorizer
 * context values must be strings, so anything else on the token (numbers,
 * arrays, nested objects) is silently dropped rather than risk a context
 * value the authorizer response format would reject.
 */
export async function verifyJwt(
  token: string,
  { issuerUrl, audience, resource, forwardClaims }: VerifyJwtOptions,
): Promise<Record<string, string>> {
  let payload: JWTPayload
  try {
    ;({ payload } = await jwtVerify(token, getJwks(issuerUrl), {
      issuer: issuerUrl,
      audience,
    }))
  } catch (error) {
    throw new JwtVerificationError(
      error instanceof Error ? error.message : 'JWT verification failed',
    )
  }

  if (resource !== undefined && payload['resource'] !== resource) {
    throw new JwtVerificationError('Token resource claim does not match the expected value.')
  }

  const context: Record<string, string> = {}
  for (const claim of forwardClaims) {
    const value = payload[claim]
    if (typeof value === 'string') {
      context[claim] = value
    }
  }
  return context
}
