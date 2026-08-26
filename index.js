//
// Proxy Backblaze S3 compatible API requests, sending notifications to a webhook
//
// Adapted from https://github.com/obezuk/worker-signed-s3-template
//
import { AwsClient } from 'aws4fetch'

const UNSIGNABLE_HEADERS = [
  // These headers appear in the request, but are never passed upstream
  'x-forwarded-proto',
  'x-real-ip',
  // We can't include accept-encoding in the signature because Cloudflare
  // sets the incoming accept-encoding header to "gzip, br", then modifies
  // the outgoing request to set accept-encoding to "gzip".
  // Not cool, Cloudflare!
  'accept-encoding',
  // Conditional headers are not consistently passed upstream
  'if-match',
  'if-modified-since',
  'if-none-match',
  'if-range',
  'if-unmodified-since',
]

// URL needs colon suffix on protocol, and port as a string
const HTTPS_PROTOCOL = 'https:'
const HTTPS_PORT = '443'

// How many times to retry a range request where the response is missing content-range
const RANGE_RETRY_ATTEMPTS = 3

const TURNSTILE_ACTION = 'download'
const TURNSTILE_BODY_MAX_BYTES = 4096
const TURNSTILE_SITEVERIFY_URL =
  'https://challenges.cloudflare.com/turnstile/v0/siteverify'
const TURNSTILE_TOKEN_MAX_LENGTH = 2048
const PRESIGNED_URL_MAX_SECONDS = 7 * 24 * 60 * 60

const textEncoder = new TextEncoder()

function normalizePath(path) {
  path = path.replaceAll('\\', '/')
  const segments = []

  for (const segment of path.split('/')) {
    if (segment === '' || segment === '.') {
      continue
    }
    if (segment === '..') {
      segments.pop()
      continue
    }
    segments.push(segment)
  }

  return `/${segments.join('/')}`
}

export function decodeAndNormalizePath(pathname) {
  try {
    return normalizePath(decodeURIComponent(pathname))
  } catch {
    return null
  }
}

function decodeBase64Url(value) {
  try {
    const base64 = value.replaceAll('-', '+').replaceAll('_', '/')
    const decoded = atob(base64)
    return Uint8Array.from(decoded, (char) => char.charCodeAt(0))
  } catch {
    return null
  }
}

export async function verifyAlistSignature(
  path,
  signature,
  secret,
  now = Math.floor(Date.now() / 1000),
) {
  if (!signature || !secret) {
    return false
  }

  const separator = signature.lastIndexOf(':')
  if (separator <= 0) {
    return false
  }

  const digest = decodeBase64Url(signature.slice(0, separator))
  const expirationText = signature.slice(separator + 1)
  if (!digest || !/^(0|[1-9]\d*)$/.test(expirationText)) {
    return false
  }

  const expiration = Number(expirationText)
  // AList uses zero for links that never expire. This proxy only accepts expiring links.
  if (
    !Number.isSafeInteger(expiration) ||
    expiration === 0 ||
    expiration < now
  ) {
    return false
  }

  const key = await crypto.subtle.importKey(
    'raw',
    textEncoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify'],
  )

  return crypto.subtle.verify(
    'HMAC',
    key,
    digest,
    textEncoder.encode(`${path}:${expirationText}`),
  )
}

export function getPresignedUrlLifetime(
  signature,
  now = Math.floor(Date.now() / 1000),
) {
  if (typeof signature !== 'string') {
    return null
  }

  const separator = signature.lastIndexOf(':')
  const expirationText = signature.slice(separator + 1)
  if (separator <= 0 || !/^[1-9]\d*$/.test(expirationText)) {
    return null
  }

  const expiration = Number(expirationText)
  if (!Number.isSafeInteger(expiration) || expiration <= now) {
    return null
  }

  return Math.min(expiration - now, PRESIGNED_URL_MAX_SECONDS)
}

export function getObjectPath(alistPath, mountPath) {
  const normalizedMountPath = normalizePath(mountPath)
  if (normalizedMountPath === '/') {
    return alistPath
  }
  if (!alistPath.startsWith(`${normalizedMountPath}/`)) {
    return null
  }
  return alistPath.slice(normalizedMountPath.length)
}

export function encodeObjectPath(objectPath) {
  return objectPath.split('/').map(encodeURIComponent).join('/')
}

// Filter out cf-* and any other headers we don't want to include in the signature
function filterHeaders(headers, env) {
  // Suppress irrelevant IntelliJ warning
  // noinspection JSCheckFunctionSignatures
  return new Headers(
    Array.from(headers.entries()).filter(
      (pair) =>
        !(
          UNSIGNABLE_HEADERS.includes(pair[0]) ||
          pair[0].startsWith('cf-') ||
          ('ALLOWED_HEADERS' in env &&
            !env['ALLOWED_HEADERS'].includes(pair[0]))
        ),
    ),
  )
}

function createHeadResponse(response) {
  return new Response(null, {
    headers: response.headers,
    status: response.status,
    statusText: response.statusText,
  })
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;')
}

function jsonForInlineScript(value) {
  return JSON.stringify(value)
    .replaceAll('<', '\\u003c')
    .replaceAll('>', '\\u003e')
    .replaceAll('&', '\\u0026')
}

function createCspNonce() {
  const bytes = new Uint8Array(18)
  crypto.getRandomValues(bytes)
  return btoa(String.fromCharCode(...bytes))
}

export function createDownloadGateResponse(path, sitekey) {
  const filename = path.split('/').at(-1) || 'your file'
  const nonce = createCspNonce()
  const sitekeyJson = jsonForInlineScript(sitekey)

  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Preparing download</title>
  <link rel="preconnect" href="https://challenges.cloudflare.com">
  <style nonce="${nonce}">
    :root { color-scheme: light dark; font-family: system-ui, sans-serif; }
    body { min-height: 100vh; margin: 0; display: grid; place-items: center; background: #0b1020; color: #f8fafc; }
    main { width: min(30rem, calc(100% - 2rem)); padding: 2rem; text-align: center; background: #151c32; border: 1px solid #2b3658; border-radius: 1rem; box-shadow: 0 1rem 3rem #0006; }
    .file { overflow-wrap: anywhere; color: #b8c5e8; }
    .error { color: #fca5a5; }
  </style>
</head>
<body>
  <main>
    <h1>Preparing your download</h1>
    <p class="file">${escapeHtml(filename)}</p>
    <p id="status">Checking your browser…</p>
    <div id="turnstile-container"></div>
    <noscript><p class="error">JavaScript is required to verify this download.</p></noscript>
  </main>
  <script nonce="${nonce}">
    (() => {
      const status = document.getElementById('status')
      let submitted = false

      const fail = (message) => {
        status.textContent = message
        status.className = 'error'
      }

      window.onTurnstileLoad = () => {
        window.turnstile.render('#turnstile-container', {
          sitekey: ${sitekeyJson},
          action: '${TURNSTILE_ACTION}',
          callback: async (token) => {
            if (submitted) return
            submitted = true
            status.textContent = 'Verification complete. Opening your download…'

            try {
              const response = await fetch(window.location.href, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ 'cf-turnstile-response': token }),
                credentials: 'same-origin',
              })
              if (!response.ok) throw new Error('verification request failed')

              const result = await response.json()
              const downloadUrl = new URL(result.location)
              if (downloadUrl.protocol !== 'https:') throw new Error('invalid download URL')
              window.location.replace(downloadUrl.href)
            } catch {
              fail('Could not open the download. Reload the page to try again.')
            }
          },
          'error-callback': () => fail('Browser verification failed. Reload the page to try again.'),
          'expired-callback': () => fail('Browser verification expired. Reload the page to try again.'),
        })
      }
    })()
  </script>
  <script nonce="${nonce}" src="https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=onTurnstileLoad" defer></script>
</body>
</html>`

  return new Response(html, {
    headers: {
      'Cache-Control': 'no-store',
      'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}' https://challenges.cloudflare.com; style-src 'nonce-${nonce}'; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; base-uri 'none'; form-action 'none'`,
      'Content-Type': 'text/html; charset=utf-8',
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
    },
  })
}

export async function readTurnstileToken(request) {
  const contentType = request.headers.get('content-type') ?? ''
  if (!contentType.startsWith('application/x-www-form-urlencoded')) {
    return null
  }

  const reader = request.body?.getReader()
  if (!reader) {
    return null
  }

  const chunks = []
  let totalBytes = 0
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) {
        break
      }
      totalBytes += value.byteLength
      if (totalBytes > TURNSTILE_BODY_MAX_BYTES) {
        await reader.cancel()
        return null
      }
      chunks.push(value)
    }
  } catch {
    return null
  }

  const body = new Uint8Array(totalBytes)
  let offset = 0
  for (const chunk of chunks) {
    body.set(chunk, offset)
    offset += chunk.byteLength
  }

  const params = new URLSearchParams(new TextDecoder().decode(body))
  const tokens = params.getAll('cf-turnstile-response')
  if (tokens.length !== 1) {
    return null
  }
  const token = tokens[0]
  if (token.length === 0 || token.length > TURNSTILE_TOKEN_MAX_LENGTH) {
    return null
  }
  return token
}

function getTurnstileHostnames(env) {
  return new Set(
    String(env['TURNSTILE_HOSTNAMES'] ?? '')
      .split(',')
      .map((hostname) => hostname.trim())
      .filter(Boolean),
  )
}

export async function verifyTurnstileToken(
  request,
  env,
  token,
  fetcher = fetch,
) {
  const secret = env['TURNSTILE_SECRET']
  const expectedHostnames = getTurnstileHostnames(env)
  const requestHostname = new URL(request.url).hostname
  if (
    typeof secret !== 'string' ||
    secret.length === 0 ||
    expectedHostnames.size === 0 ||
    !expectedHostnames.has(requestHostname)
  ) {
    return false
  }

  const body = new URLSearchParams({
    secret,
    response: token,
  })
  const clientIp = request.headers.get('CF-Connecting-IP')
  if (clientIp) {
    body.set('remoteip', clientIp)
  }

  let result
  try {
    const response = await fetcher(TURNSTILE_SITEVERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(10_000),
    })
    if (!response.ok) {
      return false
    }
    result = await response.json()
  } catch {
    return false
  }

  return (
    result?.success === true &&
    result.action === TURNSTILE_ACTION &&
    result.hostname === requestHostname &&
    expectedHostnames.has(result.hostname)
  )
}

function isListBucketRequest(env, path) {
  const pathSegments = path.split('/')

  return (
    (env['BUCKET_NAME'] === '$path' && pathSegments.length < 2) || // https://endpoint/bucket-name/
    (env['BUCKET_NAME'] !== '$path' && path.length === 0)
  ) // https://bucket-name.endpoint/ or https://endpoint/
}

// Supress IntelliJ's "unused default export" warning
// noinspection JSUnusedGlobalSymbols
export default {
  async fetch(request, env) {
    // GET renders the verification gate, POST redeems it, and HEAD remains
    // available for metadata checks.
    if (!['GET', 'HEAD', 'POST'].includes(request.method)) {
      return new Response(null, {
        headers: { Allow: 'GET, HEAD, POST' },
        status: 405,
        statusText: 'Method Not Allowed',
      })
    }

    const url = new URL(request.url)

    if (!env['ALIST_SIGNING_TOKEN'] || !env['ALIST_MOUNT_PATH']) {
      console.error(
        'ALIST_SIGNING_TOKEN and ALIST_MOUNT_PATH must be configured',
      )
      return new Response(null, {
        status: 500,
        statusText: 'Internal Server Error',
      })
    }

    const alistPath = decodeAndNormalizePath(url.pathname)
    const alistSignature = url.searchParams.get('sign')
    const signatureValid =
      alistPath !== null &&
      (await verifyAlistSignature(
        alistPath,
        alistSignature,
        env['ALIST_SIGNING_TOKEN'],
      ))
    if (!signatureValid) {
      return new Response(null, {
        status: 401,
        statusText: 'Unauthorized',
      })
    }

    const objectPath = getObjectPath(alistPath, env['ALIST_MOUNT_PATH'])
    if (objectPath === null) {
      return new Response(null, {
        status: 404,
        statusText: 'Not Found',
      })
    }

    const turnstileHostnames = getTurnstileHostnames(env)
    if (
      !env['TURNSTILE_SITE_KEY'] ||
      !env['TURNSTILE_SECRET'] ||
      turnstileHostnames.size === 0
    ) {
      console.error(
        JSON.stringify({
          message: 'Turnstile bindings are not fully configured',
        }),
      )
      return new Response(null, {
        status: 500,
        statusText: 'Internal Server Error',
      })
    }

    if (!turnstileHostnames.has(url.hostname)) {
      return new Response(null, {
        status: 403,
        statusText: 'Forbidden',
      })
    }

    if (request.method === 'GET') {
      return createDownloadGateResponse(alistPath, env['TURNSTILE_SITE_KEY'])
    }

    if (request.method === 'POST') {
      const token = await readTurnstileToken(request)
      if (!token || !(await verifyTurnstileToken(request, env, token))) {
        return new Response(
          'Browser verification failed. Reload and try again.',
          {
            headers: {
              'Cache-Control': 'no-store',
              'Content-Type': 'text/plain; charset=utf-8',
            },
            status: 403,
            statusText: 'Forbidden',
          },
        )
      }
    }

    // AList signs its virtual mount path. B2 receives only the path within that mount.
    url.pathname = encodeObjectPath(objectPath)
    url.searchParams.delete('sign')
    url.searchParams.delete('alist_ts')

    // Incoming protocol and port is taken from the worker's environment.
    // Local dev mode uses plain http on 8787, and it's possible to deploy
    // a worker on plain http. B2 only supports https on 443
    url.protocol = HTTPS_PROTOCOL
    url.port = HTTPS_PORT

    // Remove leading slashes from path
    let path = url.pathname.replace(/^\//, '')
    // Remove trailing slashes
    path = path.replace(/\/$/, '')

    // Reject list bucket requests unless configuration allows it
    if (
      isListBucketRequest(env, path) &&
      String(env['ALLOW_LIST_BUCKET']) !== 'true'
    ) {
      return new Response(null, {
        status: 404,
        statusText: 'Not Found',
      })
    }

    // Set RCLONE_DOWNLOAD to "true" to use rclone with --b2-download-url
    // See https://rclone.org/b2/#b2-download-url
    const rcloneDownload = String(env['RCLONE_DOWNLOAD']) === 'true'

    // Set upstream target hostname.
    switch (env['BUCKET_NAME']) {
      case '$path':
        // Bucket name is initial segment of URL path
        url.hostname = env['B2_ENDPOINT']
        break
      case '$host':
        // Bucket name is initial subdomain of the incoming hostname
        url.hostname = url.hostname.split('.')[0] + '.' + env['B2_ENDPOINT']
        break
      default:
        // Bucket name is specified in the BUCKET_NAME variable
        url.hostname = env['BUCKET_NAME'] + '.' + env['B2_ENDPOINT']
        break
    }

    // Create an S3 API client that can sign the outgoing request
    const client = new AwsClient({
      accessKeyId: env['B2_APPLICATION_KEY_ID'],
      secretAccessKey: env['B2_APPLICATION_KEY'],
      service: 's3',
    })

    // Save the request method, so we can process responses for HEAD requests appropriately
    const requestMethod = request.method

    if (rcloneDownload) {
      if (env['BUCKET_NAME'] === '$path') {
        // Remove leading file/ prefix from the path
        url.pathname = path.replace(/^file\//, '')
      } else {
        // Remove leading file/{bucket_name}/ prefix from the path
        url.pathname = path.replace(/^file\/[^/]+\//, '')
      }
    }

    if (request.method === 'POST') {
      const expires = getPresignedUrlLifetime(alistSignature)
      if (expires === null) {
        return new Response(null, {
          status: 401,
          statusText: 'Unauthorized',
        })
      }

      // The browser and external download managers follow this URL directly.
      // Only the host header is signed, so independent Range requests work.
      url.searchParams.set('X-Amz-Expires', String(expires))
      const presignedRequest = await client.sign(url.toString(), {
        method: 'GET',
        aws: { signQuery: true },
      })

      return Response.json(
        { location: presignedRequest.url },
        {
          headers: {
            'Cache-Control': 'no-store',
            'Referrer-Policy': 'no-referrer',
            'X-Content-Type-Options': 'nosniff',
          },
        },
      )
    }

    // Certain headers, such as x-real-ip, appear in the incoming request but
    // are removed from the outgoing request. If they are in the outgoing
    // signed headers, B2 can't validate the signature.
    const headers = filterHeaders(request.headers, env)

    // Sign the outgoing request
    //
    // For HEAD requests Cloudflare appears to change the method on the outgoing request to GET (#18), which
    // breaks the signature, resulting in a 403. So, change all HEADs to GETs. This is not too inefficient,
    // since we won't read the body of the response if the original request was a HEAD.
    const signedRequest = await client.sign(url.toString(), {
      method: 'GET',
      headers: headers,
    })

    // For large files, Cloudflare will return the entire file, rather than the requested range
    // So, if there is a range header in the request, check that the response contains the
    // content-range header. If not, abort the request and try again.
    // See https://community.cloudflare.com/t/cloudflare-worker-fetch-ignores-byte-request-range-on-initial-request/395047/4
    if (signedRequest.headers.has('range')) {
      let attempts = RANGE_RETRY_ATTEMPTS
      let response
      do {
        let controller = new AbortController()
        response = await fetch(signedRequest.url, {
          method: signedRequest.method,
          headers: signedRequest.headers,
          signal: controller.signal,
        })
        if (response.headers.has('content-range')) {
          // Only log if it didn't work first time
          if (attempts < RANGE_RETRY_ATTEMPTS) {
            console.log(
              `Retry for ${signedRequest.url} succeeded - response has content-range header`,
            )
          }
          // Break out of loop and return the response
          break
        } else if (response.ok) {
          attempts -= 1
          console.error(
            `Range header in request for ${signedRequest.url} but no content-range header in response. Will retry ${attempts} more times`,
          )
          // Do not abort on the last attempt, as we want to return the response
          if (attempts > 0) {
            controller.abort()
          }
        } else {
          // Response is not ok, so don't retry
          break
        }
      } while (attempts > 0)

      if (attempts <= 0) {
        console.error(
          `Tried range request for ${signedRequest.url} ${RANGE_RETRY_ATTEMPTS} times, but no content-range in response.`,
        )
      }

      if (requestMethod === 'HEAD') {
        // Original request was HEAD, so return a new Response without a body
        return createHeadResponse(response)
      }

      // Return whatever response we have rather than an error response
      // This response cannot be aborted, otherwise it will raise an exception
      return response
    }

    // Send the signed request to B2
    const fetchPromise = fetch(signedRequest)

    if (requestMethod === 'HEAD') {
      const response = await fetchPromise
      // Original request was HEAD, so return a new Response without a body
      return createHeadResponse(response)
    }

    // Return the upstream response unchanged
    return fetchPromise
  },
}
