import type {
  APIGatewayRequestAuthorizerEventV2,
  APIGatewaySimpleAuthorizerWithContextResult,
} from 'aws-lambda'
import { isOriginVerified } from './shared/origin-verify'
import { JwtVerificationError, verifyJwt } from './shared/jwt-verify'

type AuthorizerResult = APIGatewaySimpleAuthorizerWithContextResult<Record<string, string>>

function requireEnv(key: string): string {
  const value = process.env[key]
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`)
  }
  return value
}

function unauthorized(): AuthorizerResult {
  return { isAuthorized: false, context: {} }
}

/**
 * Generic API Gateway v2 REQUEST authorizer. Always rejects requests missing
 * (or mismatching) the shared X-Origin-Verify secret -- pair this with a CDN
 * that injects that header as an origin custom header so direct calls to the
 * API's own endpoint, bypassing the CDN, are rejected here.
 *
 * When REQUIRE_JWT=true, also verifies the Authorization bearer token and
 * forwards the claims named in JWT_FORWARD_CLAIMS into the authorizer
 * context, so a downstream integration Lambda can read
 * event.requestContext.authorizer.lambda.<claim> the same way it would read
 * a native JWT authorizer's claims.
 */
export async function handler(
  event: APIGatewayRequestAuthorizerEventV2,
): Promise<AuthorizerResult> {
  if (!isOriginVerified(event.headers, requireEnv('ORIGIN_VERIFY_SECRET'))) {
    return unauthorized()
  }

  if (process.env.REQUIRE_JWT !== 'true') {
    return { isAuthorized: true, context: {} }
  }

  const authHeader = event.headers?.['authorization']
  const token = authHeader?.startsWith('Bearer ') ? authHeader.slice('Bearer '.length) : undefined
  if (!token) {
    return unauthorized()
  }

  try {
    const context = await verifyJwt(token, {
      issuerUrl: requireEnv('JWT_ISSUER_URL'),
      audience: requireEnv('JWT_AUDIENCE'),
      forwardClaims: requireEnv('JWT_FORWARD_CLAIMS').split(',').filter(Boolean),
    })
    return { isAuthorized: true, context }
  } catch (error) {
    if (error instanceof JwtVerificationError) {
      return unauthorized()
    }
    throw error
  }
}
