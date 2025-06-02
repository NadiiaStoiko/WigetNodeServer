const http = require('http')
const https = require('https')
const express = require('express')
const cors = require('cors')
const path = require('path')
const { URL } = require('url')
const { Buffer } = require('buffer')

const app = express()
const PORT = process.env.PORT || 10000
const MAX_URL_LENGTH = 255

app.use(cors())
app.use(express.static(path.join(__dirname, 'test3'))) // 👈 віддаємо index.html і скрипти

// Проксі функції:
const knownHosts = new Set([
	'czo.gov.ua',
	'zc.bank.gov.ua',
	'acskidd.gov.ua',
	'ca.informjust.ua',
	'csk.uz.gov.ua',
	'masterkey.ua',
	'ocsp.masterkey.ua',
	'tsp.masterkey.ua',
	'csk.uss.gov.ua',
	'csk.ukrsibbank.com',
	'acsk.privatbank.ua',
	'ca.mil.gov.ua',
	'acsk.dpsu.gov.ua',
	'acsk.er.gov.ua',
	'ca.mvs.gov.ua',
	'canbu.bank.gov.ua',
	'uakey.com.ua',
	'altersign.com.ua',
	'ca.altersign.com.ua',
	'ocsp.altersign.com.ua',
	'acsk.treasury.gov.ua',
	'ocsp.treasury.gov.ua',
	'ca.oschadbank.ua',
	'ca.gp.gov.ua',
	'acsk.oree.com.ua',
	'ca.treasury.gov.ua',
	'ca.depositsign.com',
	'csk.pivdenny.ua',
	'xca.credit-agricole.com.ua',
	'ca.iit.com.ua',
	'ca.tascombank.com.ua',
	'ca.tascombank.ua',
	'ssign.diia.gov.ua',
	'test2-ssign.diia.org.ua',
	'depositsign.com',
	'pki.pumb.ua',
	'ca.alfabank.kiev.ua',
	'cesaris.itsway.kiev.ua',
	'ca.credit-agricole.ua',
	'sserver2.iit.com.ua',
	'192.168.30.10',
	'skey.fozzy.ua',
	'skey-test.fozzy.ua',
	'microservice.alfabank.kiev.ua',
	'ca.e-life.com.ua',
	'ocsp.e-life.com.ua',
	'tsp.e-life.com.ua',
	'cmp.e-life.com.ua',
	'cabinet.e-life.com.ua',
	'ca.bankalliance.ua',
	'ca.vchasno.ua',
	'cs.vchasno.ua',
	'qca.ukrgasbank.com',
	'kepserver.ukrtransnafta.com',
	'root-test.czo.gov.ua',
	'ca-test.czo.gov.ua',
	'smart-sign.tax.gov.ua',
	'ca.tax.gov.ua',
	'apiext.pumb.ua',
	'ca.pravex.com.ua',
	'ca.diia.gov.ua',
	'cihsm-dev-api.cipher.com.ua',
	'test2-ca.diia.org.ua',
	'vtms-api-csk.ukrgasbank.com',
	'ca.sensebank.com.ua',
	'vtms-api-qca.ukrgasbank.com',
	'cihsm-api.bankalliance.ua',
])

function isKnownHost(rawUrl) {
	try {
		if (!rawUrl || rawUrl.length > MAX_URL_LENGTH) return false
		const parsed = new URL(rawUrl)
		return (
			['http:', 'https:'].includes(parsed.protocol) &&
			knownHosts.has(parsed.hostname)
		)
	} catch {
		return false
	}
}

function getContentType(address) {
	const path = new URL(address).pathname
	if (path.includes('/ocsp')) return 'application/ocsp-request'
	if (path.includes('/tsp')) return 'application/timestamp-query'
	return 'application/octet-stream'
}

function proxyRequest(method, targetUrl, bodyData, clientRes) {
	const parsed = new URL(targetUrl)
	const transport = parsed.protocol === 'https:' ? https : http

	const options = {
		hostname: parsed.hostname,
		port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
		path: parsed.pathname + parsed.search,
		method,
		headers: {
			'User-Agent': 'signature.proxy',
			'Content-Type': getContentType(targetUrl),
			'Content-Length': bodyData.length,
		},
		rejectUnauthorized: false,
	}

	const req = transport.request(options, res => {
		const chunks = []
		res.on('data', chunk => chunks.push(chunk))
		res.on('end', () => {
			const responseBody = Buffer.concat(chunks)
			clientRes.writeHead(200, {
				'Content-Type': 'X-user/base64-data; charset=utf-8',
				'Cache-Control': 'no-store',
				'Access-Control-Allow-Origin': '*',
				'Access-Control-Allow-Headers': 'Content-Type',
				'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
			})
			clientRes.end(responseBody.toString('base64'))
		})
	})

	req.on('error', err => {
		clientRes.writeHead(500, { 'Content-Type': 'text/plain' })
		clientRes.end('Proxy error: ' + err.message)
	})

	req.write(bodyData)
	req.end()
}

// Обробка запитів
http
	.createServer((req, res) => {
		const parsedUrl = new URL(req.url, `http://${req.headers.host}`)

		if (req.method === 'OPTIONS') {
			res.writeHead(204, {
				'Access-Control-Allow-Origin': '*',
				'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
				'Access-Control-Allow-Headers': 'Content-Type',
			})
			return res.end()
		}

		const address = parsedUrl.searchParams.get('address')
		if (!address) {
			// Дозволяємо доступ до index.html, .js, .css тощо
			return res.end() // Express вже віддає файли
		}

		if (!isKnownHost(address)) {
			res.writeHead(403, { 'Content-Type': 'text/plain' })
			return res.end('Forbidden: Invalid or unknown address')
		}

		if (req.method === 'GET') {
			return proxyRequest('GET', address, Buffer.alloc(0), res)
		}

		if (req.method === 'POST') {
			const chunks = []
			req.on('data', chunk => chunks.push(chunk))
			req.on('end', () => {
				const base64Body = Buffer.concat(chunks).toString()
				const body = Buffer.from(base64Body, 'base64')
				proxyRequest('POST', address, body, res)
			})
		}
	})
	.listen(PORT, () => {
		console.log(`Proxy server is running on http://localhost:${PORT}`)
	})
