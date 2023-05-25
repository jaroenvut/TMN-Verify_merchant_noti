//Require function from npm.com
const { request } = require('express')
const express = require('express')
const app = express()
const fs = require("fs")
const crypto = require("crypto")
const bodyParser = require('body-parser');
const { json } = require('body-parser')
const sigHeaderName = 'content-signature'
const http = require("http");


const TMW_PUBLIC_KEY = fs.readFileSync('tmnpubkey.pem', 'utf-8')

//Create timestamp in epoch format
const timestamp = Math.floor(new Date().getTime() / 1000);

// Used same private key of create order
const private_key = fs.readFileSync('private.pem', 'utf-8');
const port = process.env.PORT || 3000

//app.use(express.json())
app.use(express.json())
app.use(bodyParser.text())
app.post('/', (req, res) => {
    // Step 1: Extract Data from request
//const TMW_PUBLIC_KEY = fs.readFileSync('tmnpubkey.pem', 'utf-8')
const TMW_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs/pJ8qlcSeBKCGLIuEDx
68AlwS4dEDyahG8gBdLjih2ACXM3CKGH9mriDTn6Mx9cIm3VdXDF6muDlQpCmAzL
NpnC3fpvwZ1Cnvuu2PbaNkZWP5BFwYxmuZ9k2NoAMmqDB1MyFJsMCZl/UIn76eAJ
FftDxRhPyZcUSfffQIk91F4U6BTxwT/+qjSQJG92u24+5upnYlMjfqDbhc+8ZOvB
rtD9nKk3hmSjMealJCVjj5DJB8aH+CfR+fv0rW+t5JO8Ra5z2sG9kLA/0aX3ePMk
0sjIwY2W8RVu9vXalg4JJmRbjEQBRHFHuSOyjFaE+pV6iZ8Uvx1299DyK+YFtTNm
/wIDAQAB
-----END PUBLIC KEY-----`;

    const reqtimestamp = req.headers.timestamp
    const reqsignature = Buffer.from(req.get(sigHeaderName) || '', 'utf8')
    const presig = reqsignature.toString()
    const encodedSignature = presig.replace('digest-alg=RSA-SHA; key-id=KEY:RSA:rsf.org; data=', '')
    console.log (`encodedSignature is : `, encodedSignature)

// Step 2: Prepare data for verification
//const data = reqtimestamp.concat(JSON.stringify(req.body,null,1));
const data = reqtimestamp.concat(JSON.stringify(req.body));
//const reqbody = JSON.stringify(req.body)
//const data = (reqtimestamp)+(reqbody);
console.log (`data is : `, data)
const verifysignature = Buffer.from(encodedSignature, 'base64');

// Step 3: Verify signature
const verifier = crypto.createVerify('RSA-SHA256')
verifier.update(data);
const valid = verifier.verify(TMW_PUBLIC_KEY, verifysignature, 'base64');
console.log(`valid is : `, valid);

    //const data = JSON.stringify(req.body,null,2)
    //console.log (data)
    const notifyId = req.body.notify_id
    const body = {"status":{"code":"11111","message":"success","description":"Product has been checked out"},"data":{"notify_id":(notifyId)}}
    const body_stringify = (JSON.stringify(body))
    const data_signature = (timestamp)+(body_stringify);
    //Signing with RSA-SHA256
    const signer = crypto.createSign('RSA-SHA256');
    signer.write(data_signature);
    signer.end();

    //Returns the signature in output_format which 'base64'
    const signature = signer.sign(private_key, 'base64')
    //console.log(signature)
    //console.log (timestamp+data)
    //End sign signature

    res.header({
    'Content-type' : 'application/json',
    'timestamp' : (timestamp),
    'content-signature' : (`digest-alg=RSA-SHA; key-id=KEY:RSA:rsf.org; data=${signature}`)
      })
    //response status 200=success, 400=auto refund, 404= auto refund
    res.status(200).send(body_stringify)
})

  app.listen(port, () => {
    console.log('Server is running on '+`https://localhost:${port}`)
  })


  