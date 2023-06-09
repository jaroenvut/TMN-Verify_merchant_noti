const { request } = require('express')
const express = require('express')
const app = express()
const fs = require("fs")
const crypto = require("crypto")
const bodyParser = require('body-parser');
const { json } = require('body-parser')
const sigHeaderName = 'content-signature'


const http = require("http");

const server = http.createServer((request, response) => {
  // custom body-parser for POST request starts
  // http request object is a readable stream,
  // i.e. data arrives in parts/chunks.

  let chunks = [];
  // 'data' event is emitted on every chunk received
  request.on("data", (chunk) => {
    // collecting the chunks in array
    chunks.push(chunk);
  });

  // when all chunks are received, 'end' event is emitted.
  request.on("end", () => {
    // joining all the chunks received
    const data = Buffer.concat(chunks);
    console.log(data)
    // data.toString() converts Buffer data to querystring format
    const querystring = data.toString();
    console.log(querystring)
    // URLSearchParams: takes querystring
    // & returns a URLSearchParams object instance.
    const parsedData = new URLSearchParams(querystring);
    console.log(parsedData)
    const dataObj = {};
    console.log(dataObj)
    // entries() method returns an iterator
    // allowing iteration through all key/value pairs
    for (var pair of parsedData.entries()) {
      dataObj[pair[0]] = pair[1];
    }
    // Now request data is accessible using dataObj

    response.end();
  });
  // custom body-parser for POST request ends
});

server.listen(3000, () => {
  console.log("Server is running on Port 3000");
});