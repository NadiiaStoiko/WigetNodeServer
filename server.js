const http = require('http');
const https = require('https');
const { URL } = require('url');
const { Buffer } = require('buffer');
const { IncomingMessage, ServerResponse } = require('http');

const PORT = 3000;
const MAX_URL_LENGTH = 255;

const knownHosts = new Set([
  "czo.gov.ua", "zc.bank.gov.ua", "acskidd.gov.ua", "ca.informjust.ua", "csk.uz.gov.ua",
  "masterkey.ua", "ocsp.masterkey.ua", "tsp.masterkey.ua", "csk.uss.gov.ua", "csk.ukrsibbank.com",
  "acsk.privatbank.ua", "ca.mil.gov.ua", "acsk.dpsu.gov.ua", "acsk.er.gov.ua", "ca.mvs.gov.ua",
  "canbu.bank.gov.ua", "uakey.com.ua", "altersign.com.ua", "ca.altersign.com.ua", "ocsp.altersign.com.ua",
  "acsk.treasury.gov.ua", "ocsp.treasury.gov.ua", "ca.oschadbank.ua", "ca.gp.gov.ua", "acsk.oree.com.ua",
  "ca.treasury.gov.ua", "ca.depositsign.com", "csk.pivdenny.ua", "xca.credit-agricole.com.ua",
  "ca.iit.com.ua", "ca.tascombank.com.ua", "ca.tascombank.ua", "ssign.diia.gov.ua",
  "test2-ssign.diia.org.ua", "depositsign.com", "pki.pumb.ua", "ca.alfabank.kiev.ua",
  "cesaris.itsway.kiev.ua", "ca.credit-agricole.ua", "sserver2.iit.com.ua", "192.168.30.10",
  "skey.fozzy.ua", "skey-test.fozzy.ua", "microservice.alfabank.kiev.ua", "ca.e-life.com.ua",
  "ocsp.e-life.com.ua", "tsp.e-life.com.ua", "cmp.e-life.com.ua", "cabinet.e-life.com.ua",
  "ca.bankalliance.ua", "ca.vchasno.ua", "cs.vchasno.ua", "qca.ukrgasbank.com",
  "kepserver.ukrtransnafta.com", "root-test.czo.gov.ua", "ca-test.czo.gov.ua",
  "smart-sign.tax.gov.ua", "ca.tax.gov.ua", "apiext.pumb.ua", "ca.pravex.com.ua",
  "ca.diia.gov.ua", "cihsm-dev-api.cipher.com.ua", "test2-ca.diia.org.ua",
  "vtms-api-csk.ukrgasbank.com", "ca.sensebank.com.ua", "vtms-api-qca.ukrgasbank.com",
  "cihsm-api.bankalliance.ua"
]);

function isKnownHost(rawUrl) {
  try {
    if (!rawUrl || rawUrl.length > MAX_URL_LENGTH) return false;
    const parsed = new URL(rawUrl);
    const host = parsed.hostname;
    const protocol = parsed.protocol;

    if (!['http:', 'https:'].includes(protocol)) return false;
    return knownHosts.has(host);
  } catch {
    return false;
  }
}

function getContentType(address) {
  const path = new URL(address).pathname;

  if (
    path.includes('/cloud/api/back/') ||
    path.includes('/ss/') ||
    path.includes('/api/EDG/Sign') ||
    path.includes('/smartid/iit/') ||
    path.includes('/hogsmeade/striga/v1') ||
    path.includes('/iit-signer/api/v1')
  ) return 'application/json';

  const ocspPaths = ['/services/ocsp', '/public/ocsp', '/ocsp', '/ocsp-rsa', '/ocsp-ecdsa', '/OCSPsrv/ocsp', '/queries/ocsp/'];
  const tspPaths = ['/services/tsp', '/services/tsp/dstu', '/services/tsp/rsa', '/services/tsp/ecdsa', '/public/tsa', '/public/tsp', '/tsp', '/tsp-rsa', '/tsp-ecdsa', '/TspHTTPServer/tsp'];
  const cmpPaths = ['/services/cmp', '/public/x509/cmp', '/cmp', '/api/PKI/CMP'];

  if (ocspPaths.includes(path)) return 'application/ocsp-request';
  if (tspPaths.includes(path)) return 'application/timestamp-query';
  if (cmpPaths.includes(path)) return '';

  return 'text/plain';
}

function proxyRequest(method, targetUrl, bodyData, clientRes) {
  const parsed = new URL(targetUrl);
  const isHttps = parsed.protocol === 'https:';
  const transport = isHttps ? https : http;

  const contentType = getContentType(targetUrl);
  const requestOptions = {
    hostname: parsed.hostname,
    port: parsed.port || (isHttps ? 443 : 80),
    path: parsed.pathname + parsed.search,
    method: method,
    headers: {
      'User-Agent': 'signature.proxy',
      'Content-Type': contentType || 'application/octet-stream',
      'Content-Length': bodyData.length
    },
    rejectUnauthorized: false
  };

  const proxyReq = transport.request(requestOptions, (proxyRes) => {
    const chunks = [];
    proxyRes.on('data', (chunk) => chunks.push(chunk));
    proxyRes.on('end', () => {
      const responseData = Buffer.concat(chunks);

      clientRes.writeHead(200, {
        'Content-Type': 'X-user/base64-data; charset=utf-8',
        'Cache-Control': 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0'
      });
      clientRes.end(Buffer.from(responseData).toString('base64'));
    });
  });

  proxyReq.on('error', (err) => {
    clientRes.writeHead(500, { 'Content-Type': 'text/plain' });
    clientRes.end('Proxy error: ' + err.message);
  });

  proxyReq.write(bodyData);
  proxyReq.end();
}

http.createServer((req, res) => {
  const { method, url: reqUrl } = req;
  const parsedUrl = new URL(reqUrl, `http://${req.headers.host}`);
  const address = parsedUrl.searchParams.get('address');

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    });
    return res.end();
  }

  res.setHeader('Access-Control-Allow-Origin', '*');

  if (!['GET', 'POST'].includes(method)) {
    res.writeHead(400);
    return res.end('Bad Request');
  }

  if (!address || !isKnownHost(address)) {
    res.writeHead(403);
    return res.end('403 Forbidden – Invalid or untrusted address');
  }

  if (method === 'POST') {
    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      try {
        const base64data = Buffer.concat(chunks).toString();
        const decodedBody = Buffer.from(base64data, 'base64');
        proxyRequest('POST', address, decodedBody, res);
      } catch (err) {
        res.writeHead(400);
        res.end('Invalid base64 payload');
      }
    });
  } else {
    proxyRequest('GET', address, Buffer.alloc(0), res);
  }
}).listen(PORT, () => {
  console.log(`Proxy server running on http://localhost:${PORT}`);
});
