import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import test from 'node:test'

import worker, {
  createVerifiedDownloadToken,
  createDownloadGateResponse,
  decodeAndNormalizePath,
  encodeObjectPath,
  getVerifiedDownloadLifetime,
  getObjectPath,
  readTurnstileToken,
  verifyDownloadToken,
  verifyTurnstileToken,
  verifyAlistSignature,
} from './index.js'

const TOKEN = 'test-alist-token'

function sign(path, expiration) {
  const digest = createHmac('sha256', TOKEN)
    .update(`${path}:${expiration}`)
    .digest('base64url')
  return `${digest}=:${expiration}`
}

test('accepts an unexpired AList signature', async () => {
  const path = '/b2/video file.mp4'
  assert.equal(
    await verifyAlistSignature(path, sign(path, 2000), TOKEN, 1000),
    true,
  )
})

test('rejects expired, permanent, and path-tampered signatures', async () => {
  const path = '/b2/video.mp4'
  assert.equal(
    await verifyAlistSignature(path, sign(path, 999), TOKEN, 1000),
    false,
  )
  assert.equal(
    await verifyAlistSignature(path, sign(path, 0), TOKEN, 1000),
    false,
  )
  assert.equal(
    await verifyAlistSignature('/b2/other.mp4', sign(path, 2000), TOKEN, 1000),
    false,
  )
})

test('limits a verified download URL to the remaining AList lifetime', () => {
  assert.equal(getVerifiedDownloadLifetime('digest=:1600', 1000), 600)
  assert.equal(
    getVerifiedDownloadLifetime('digest=:9999999', 1000),
    7 * 24 * 60 * 60,
  )
  assert.equal(getVerifiedDownloadLifetime('digest=:999', 1000), null)
})

test('creates a path-bound, expiring verified download token', async () => {
  const token = await createVerifiedDownloadToken('/b2/file.zip', 1600, TOKEN)

  assert.equal(
    await verifyDownloadToken('/b2/file.zip', token, TOKEN, 1000),
    true,
  )
  assert.equal(
    await verifyDownloadToken('/b2/other.zip', token, TOKEN, 1000),
    false,
  )
  assert.equal(
    await verifyDownloadToken('/b2/file.zip', token, TOKEN, 1600),
    false,
  )
})

test('matches AList path decoding and removes only the configured mount', () => {
  const path = decodeAndNormalizePath('/b2/video%20file.mp4')
  assert.equal(path, '/b2/video file.mp4')
  assert.equal(getObjectPath(path, '/b2'), '/video file.mp4')
  assert.equal(getObjectPath(path, '/other'), null)
})

test('percent-encodes the decoded object path for Backblaze', () => {
  assert.equal(
    encodeObjectPath('/[Nekomoe kissaten]/video file.mp4'),
    '/%5BNekomoe%20kissaten%5D/video%20file.mp4',
  )
})

test('opens the direct URL immediately when Invisible Turnstile verification completes', async () => {
  const response = createDownloadGateResponse(
    '/b2/video file.mp4',
    'test-site-key',
  )
  const html = await response.text()

  assert.equal(response.headers.get('cache-control'), 'no-store')
  assert.doesNotMatch(html, /countdown/i)
  assert.doesNotMatch(html, /setInterval/)
  assert.match(html, /api\.js\?render=explicit&onload=onTurnstileLoad/)
  assert.match(html, /action: 'download'/)
  assert.match(html, /Verification complete\. Opening your download/)
  assert.match(html, /fetch\(window\.location\.href/)
  assert.match(html, /window\.location\.replace\(downloadUrl\.href\)/)
  assert.match(
    response.headers.get('content-security-policy'),
    /connect-src 'self'/,
  )
  assert.doesNotMatch(html, /TURNSTILE_SECRET/)
})

test('reads one bounded Turnstile token from a form request', async () => {
  const request = new Request('https://b2.127631.xyz/b2/file.zip', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ 'cf-turnstile-response': 'token-value' }),
  })

  assert.equal(await readTurnstileToken(request), 'token-value')
})

test('rejects duplicate Turnstile token fields', async () => {
  const request = new Request('https://b2.127631.xyz/b2/file.zip', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'cf-turnstile-response=one&cf-turnstile-response=two',
  })

  assert.equal(await readTurnstileToken(request), null)
})

test('validates Turnstile success, action, and exact request hostname', async () => {
  const request = new Request('https://b2.127631.xyz/b2/file.zip', {
    headers: { 'CF-Connecting-IP': '203.0.113.10' },
  })
  const env = {
    TURNSTILE_HOSTNAMES: 'b2.127631.xyz',
    TURNSTILE_SECRET: 'test-secret',
  }
  let verificationBody
  const fetcher = async (_url, options) => {
    verificationBody = options.body
    return Response.json({
      success: true,
      action: 'download',
      hostname: 'b2.127631.xyz',
    })
  }

  assert.equal(
    await verifyTurnstileToken(request, env, 'test-token', fetcher),
    true,
  )
  assert.equal(verificationBody.get('secret'), 'test-secret')
  assert.equal(verificationBody.get('response'), 'test-token')
  assert.equal(verificationBody.get('remoteip'), '203.0.113.10')
})

test('fails closed when Siteverify returns the wrong action or a replay', async () => {
  const request = new Request('https://b2.127631.xyz/b2/file.zip')
  const env = {
    TURNSTILE_HOSTNAMES: 'b2.127631.xyz',
    TURNSTILE_SECRET: 'test-secret',
  }

  const wrongAction = async () =>
    Response.json({
      success: true,
      action: 'login',
      hostname: 'b2.127631.xyz',
    })
  const replay = async () =>
    Response.json({
      success: false,
      'error-codes': ['timeout-or-duplicate'],
    })

  assert.equal(
    await verifyTurnstileToken(request, env, 'test-token', wrongAction),
    false,
  )
  assert.equal(
    await verifyTurnstileToken(request, env, 'test-token', replay),
    false,
  )
})

test('gates a signed download, keeps ranged traffic on Cloudflare, and rejects replay', async () => {
  const path = '/b2/file.zip'
  const expiration = Math.floor(Date.now() / 1000) + 60
  const signedUrl = `https://b2.127631.xyz${path}?sign=${encodeURIComponent(sign(path, expiration))}`
  const env = {
    ALIST_MOUNT_PATH: '/b2',
    ALIST_SIGNING_TOKEN: TOKEN,
    ALLOW_LIST_BUCKET: 'false',
    B2_APPLICATION_KEY: 'test-b2-secret',
    B2_APPLICATION_KEY_ID: 'test-b2-key-id',
    B2_ENDPOINT: 's3.us-west-004.backblazeb2.com',
    BUCKET_NAME: 'test-bucket',
    RCLONE_DOWNLOAD: 'false',
    TURNSTILE_HOSTNAMES: 'b2.127631.xyz',
    TURNSTILE_SECRET: 'test-turnstile-secret',
    TURNSTILE_SITE_KEY: 'test-site-key',
  }

  const gate = await worker.fetch(new Request(signedUrl), env)
  assert.equal(gate.status, 200)
  assert.match(gate.headers.get('content-type'), /^text\/html/)

  const originalFetch = globalThis.fetch
  let siteverifyCalls = 0
  let b2Calls = 0
  globalThis.fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : input.url
    if (url.includes('/turnstile/v0/siteverify')) {
      siteverifyCalls += 1
      if (siteverifyCalls > 1) {
        return Response.json({
          success: false,
          'error-codes': ['timeout-or-duplicate'],
        })
      }
      return Response.json({
        success: true,
        action: 'download',
        hostname: 'b2.127631.xyz',
      })
    }
    if (url.startsWith('https://test-bucket.s3.us-west-004.backblazeb2.com/')) {
      b2Calls += 1
      const headers =
        typeof input === 'string' ? new Headers(init?.headers) : input.headers
      assert.equal(headers.get('range'), 'bytes=0-3')
      assert.equal(new URL(url).searchParams.has('download'), false)
      return new Response('file', {
        status: 206,
        headers: {
          'Accept-Ranges': 'bytes',
          'Content-Range': 'bytes 0-3/4',
        },
      })
    }
    throw new Error(`Unexpected fetch URL: ${url}`)
  }

  try {
    const createPost = () =>
      new Request(signedUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          'cf-turnstile-response': 'single-use-test-token',
        }),
      })

    const download = await worker.fetch(createPost(), env)
    assert.equal(download.status, 200)
    assert.equal(download.headers.get('cache-control'), 'no-store')
    const location = new URL((await download.json()).location)
    assert.equal(location.origin, 'https://b2.127631.xyz')
    assert.equal(location.pathname, '/b2/file.zip')
    assert.equal(location.searchParams.has('sign'), false)
    assert.equal(location.searchParams.has('X-Amz-Signature'), false)
    assert.ok(location.searchParams.get('download'))

    const rangedDownload = await worker.fetch(
      new Request(location, { headers: { Range: 'bytes=0-3' } }),
      env,
    )
    assert.equal(rangedDownload.status, 206)
    assert.equal(await rangedDownload.text(), 'file')
    assert.equal(b2Calls, 1)

    const replay = await worker.fetch(createPost(), env)
    assert.equal(replay.status, 403)
    assert.equal(siteverifyCalls, 2)
  } finally {
    globalThis.fetch = originalFetch
  }
})
