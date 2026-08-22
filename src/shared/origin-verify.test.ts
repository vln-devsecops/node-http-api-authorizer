import { describe, expect, it } from 'vitest'
import { isOriginVerified } from './origin-verify'

describe('isOriginVerified', () => {
  it('returns true when the header matches the secret', () => {
    expect(isOriginVerified({ 'x-origin-verify': 'shh' }, 'shh')).toBe(true)
  })

  it('returns false when the header is missing', () => {
    expect(isOriginVerified({}, 'shh')).toBe(false)
    expect(isOriginVerified(undefined, 'shh')).toBe(false)
  })

  it('returns false when the header value is wrong', () => {
    expect(isOriginVerified({ 'x-origin-verify': 'nope' }, 'shh')).toBe(false)
  })

  it('returns false without throwing when lengths differ', () => {
    expect(isOriginVerified({ 'x-origin-verify': 'short' }, 'a-much-longer-secret')).toBe(false)
  })
})
