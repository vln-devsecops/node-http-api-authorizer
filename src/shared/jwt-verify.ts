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
  audience: string
  /** Claim names to copy into the returned context; non-string claims are dropped. */
  forwardClaims: string[]
}

/**
 * Verifies a bearer token's signature, issuer, and audience against
 * issuerUrl's JWKS, then returns only the string-valued claims named in
 * forwardClaims. API Gateway Lambda authorizer context values must be
 * strings, so anything else on the token (numbers, arrays, nested objects)
 * is silently dropped rather than risk a context value the authorizer
 * response format would reject.
 */
export async function verifyJwt(
  token: string,
  { issuerUrl, audience, forwardClaims }: VerifyJwtOptions,
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

  const context: Record<string, string> = {}
  for (const claim of forwardClaims) {
    const value = payload[claim]
    if (typeof value === 'string') {
      context[claim] = value
    }
  }
  return context
}
