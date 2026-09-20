const http = require('node:http');

/**
 * Sentinel Local Fixture Target Server
 * Runs a mock web application with controllable security configurations:
 * - Route / : Missing CSP, Missing HSTS, Insecure cookie, Missing nosniff
 * - Route /fixed : Full security headers (CSP, HSTS, SameSite, Secure, HttpOnly, nosniff, frame-ancestors)
 * - Route /search?q=XYZ : Inert reflection test endpoint reflecting q into body and attribute
 * - Route /api/cors : Permissive wildcard CORS with credentials
 */

function createFixtureServer(port = 4567) {
  const server = http.createServer((req, res) => {
    const parsedUrl = new URL(req.url, `http://127.0.0.1:${port}`);
    const pathname = parsedUrl.pathname;

    if (pathname === '/fixed') {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; frame-ancestors 'none';",
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=(), microphone=()',
        'Cross-Origin-Resource-Policy': 'same-origin',
        'Set-Cookie': ['__Host-auth=secret_token_12345; Secure; Path=/; SameSite=Lax; HttpOnly'],
      });
      res.end(`<!DOCTYPE html>
<html>
<head><title>Sentinel Remediated Target</title></head>
<body>
  <h1>Hardened Secure Route</h1>
  <p>All defensive security headers and cookie flags are active.</p>
</body>
</html>`);
      return;
    }

    if (pathname === '/search') {
      const q = parsedUrl.searchParams.get('q') || '';
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Set-Cookie': ['session_id=insecure_token_98765'],
      });
      res.end(`<!DOCTYPE html>
<html>
<head><title>Search Page</title></head>
<body>
  <h1>Search Results</h1>
  <div id="results">Showing results for: ${q}</div>
  <input type="text" value="${q}" name="q" />
</body>
</html>`);
      return;
    }

    if (pathname === '/api/cors') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Credentials': 'true',
      });
      res.end(JSON.stringify({ status: 'authenticated', user: 'mock_user' }));
      return;
    }

    // Default vulnerable / baseline route
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Set-Cookie': ['auth_token=raw_session_abc12345'],
    });
    res.end(`<!DOCTYPE html>
<html>
<head><title>Sentinel Mock Vulnerable Target</title></head>
<body>
  <h1>Welcome to the Local Lab Target</h1>
  <p>This is a local fixture for testing Sentinel rules, canary reflections, and replay verification.</p>
  <a href="/search?q=test">Search</a>
</body>
</html>`);
  });

  return server;
}

if (require.main === module) {
  const PORT = process.env.PORT || 4567;
  const srv = createFixtureServer(PORT);
  srv.listen(PORT, '127.0.0.1', () => {
    console.log(`[Sentinel Fixture Server] Listening on http://127.0.0.1:${PORT}`);
  });
}

module.exports = { createFixtureServer };
