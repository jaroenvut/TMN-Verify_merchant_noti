/*
 * Verify GitHub webhook signature header in Node.js
 * Written by stigok and others (see gist link for contributor comments)
 * https://gist.github.com/stigok/57d075c1cf2a609cb758898c0b202428
 * Licensed CC0 1.0 Universal
 */

const crypto = require('crypto')
const express = require('express')
const bodyParser = require('body-parser')
const fs = require("fs")
//const replace = require("replace");

const secret = fs.readFileSync('private.pem', 'utf-8');

// For these headers, a sigHashAlg of sha1 must be used instead of sha256
// GitHub: X-Hub-Signature
// Gogs:   X-Gogs-Signature
const sigHeaderName = 'content-signature'
console.log (sigHeaderName)
const sigHashAlg = 'sha256'

const app = express()

// Saves a valid raw JSON body to req.rawBody
// Credits to https://stackoverflow.com/a/35651853/90674
app.use(bodyParser.json({
  verify: (req, res, buf, encoding) => {
    if (buf && buf.length) {
      req.rawBody = buf.toString(encoding || 'utf8');
    }
  },
}))

function verifyPostData(req, res, next) {
  if (!req.rawBody) {
    return next('Request body empty')
  }

  const sig1 = Buffer.from(req.get(sigHeaderName) || '', 'utf8')
  //const sigfile = fs.writeFileSync('sig.txt', sig1, 'utf-8');
  fs.writeFileSync('sig.txt', sig1, 'utf-8');
  const sig2 = 'digest-alg=RSA-SHA; key-id=KEY:RSA:rsf.org; data='
  const presig = fs.readFileSync('sig.txt', 'utf-8')
  const newsig = presig.replace(new RegExp(sig2), '')
  const sigfinal = fs.writeFileSync('sigfinal.txt', newsig, 'utf-8');
  //const sig1 = req.getHeader('Content-Signature')
  //const sig1 = req.get('content-signature')
  //const sig2 = 'digest-alg=RSA-SHA; key-id=KEY:RSA:rsf.org; data=';
  //sig1 = sig1.toString().replace(sig2,"");
  //sig1 = sig1.replace(sig2,"")
  const sig = fs.readFileSync('sigfinal.txt', 'utf-8')
  //console.log (sig1)

  const hmac = crypto.createHmac(sigHashAlg, secret)
  //const digest = Buffer.from(sigHashAlg + '=' + hmac.update(req.rawBody).digest('hex'), 'utf8')
  const reqtimestamp = req.headers.timestamp
  const reqdata = JSON.stringify(req.body,null,2)
  const digest = reqtimestamp+reqdata;
  if (sig.length !== digest.length || !crypto.timingSafeEqual(digest, sig)) {
    return next(`Request body digest ${digest} did not match ${sigHeaderName} ${sig}`)
  }

  return next()
}

app.post('/', verifyPostData, function (req, res) {
  res.status(200).send('Request body was signed')
})

app.use((err, req, res, next) => {
  if (err) console.error(err)
  res.status(403).send('Request body was not signed or verification failed')
})

app.listen(3000, () => console.log("Listening on port 3000"))