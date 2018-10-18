'use strict';
const crypto = require('crypto');
const fs = require('fs');

const HEADER_TYPE = 'JWT';
const HASH_ALG = 'sha256';
const HS256_KEY_1 = 'secret1';
const HS256_KEY_2 = 'secret2';
const RS256_KEY_1_PUBLIC = fs.readFileSync('./keys/public.key.1');
const RS256_KEY_1_PRIVATE = fs.readFileSync('./keys/private.key.1');
const RS256_KEY_2_PUBLIC = fs.readFileSync('./keys/public.key.2');
const RS256_KEY_2_PRIVATE = fs.readFileSync('./keys/private.key.2');
const SUPPORTED_ALGORITHMS = {HS256 : 'HS256' , RS256 : 'RS256'};

const CONFIG_SIGN = {
  HS256 : {type : SUPPORTED_ALGORITHMS.HS256, hashAlg : HASH_ALG, keys : [HS256_KEY_1, HS256_KEY_2]},
  RS256 : {type : SUPPORTED_ALGORITHMS.RS256, hashAlg : HASH_ALG, keys : [RS256_KEY_1_PRIVATE, RS256_KEY_2_PRIVATE]},
}

const CONFIG_VERIFY = {
  HS256 : {type : SUPPORTED_ALGORITHMS.HS256, hashAlg : HASH_ALG, keys : [HS256_KEY_1, HS256_KEY_2]},
  RS256 : {type : SUPPORTED_ALGORITHMS.RS256, hashAlg : HASH_ALG, keys : [RS256_KEY_1_PUBLIC, RS256_KEY_2_PUBLIC]},
}

function base64UrlEncode(str, fmt) {
  let result = Buffer.from(str, fmt ? fmt : 'utf8').toString('base64');
  return result.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=+$/, '');
}

function base64Decode(str, fmt) {
  return Buffer.from(str, fmt ? fmt : 'base64').toString('utf8');
}

function generateHeader(alg, kid) {
  return {alg : alg ? alg : CONFIG_SIGN.HS256.type, type : HEADER_TYPE, kid : kid ? kid : 0};
}

function generatePayload(sub, name, admin) {
  return {sub : sub, name : name, admin : admin, iat : Math.floor(Date.now() / 1000)};
}

function getKid(header, type) {
  const kid = header.kid;
  if(kid === undefined) {
    throw ({name : 'Invalid Key ID', message : 'Key ID is not defined'});
  }
  if(kid >= type.keys.length) {
    throw ({name : 'Invalid Key ID', message : JSON.stringify(header.kid)});
  }
  return kid;
}

function sign(header, payload, config) {
  let signatureBase64;
  const signConfig = config[header.alg];
  if(signConfig === undefined) {
    throw ({name : 'Unsupported algorithm', message : header.alg});
  }

  const kid = getKid(header, signConfig);
  console.log(`-----------------`);
  console.log(`Sign ${signConfig.type} kid(${kid})`);
  console.log(`-----------------`);

  const headerBase64 = base64UrlEncode(JSON.stringify(header));
  const payloadBase64 = base64UrlEncode(JSON.stringify(payload));
  const signatureData = `${headerBase64}.${payloadBase64}`;

  switch(signConfig.type) {   
    case SUPPORTED_ALGORITHMS.HS256 :
      const hmac = crypto.createHmac(signConfig.hashAlg, signConfig.keys[kid]);
      hmac.update(signatureData);
      signatureBase64 = base64UrlEncode(hmac.digest('hex'), 'hex');
      break;
    case SUPPORTED_ALGORITHMS.RS256 :
      const sign = crypto.createSign(signConfig.hashAlg);
      sign.update(signatureData);
      signatureBase64 = base64UrlEncode(sign.sign(signConfig.keys[kid], 'hex'), 'hex');
      break;
  }

  const token = `${headerBase64}.${payloadBase64}.${signatureBase64}`;

  console.log(`header          : ${JSON.stringify(header)}`);
  console.log(`payload         : ${JSON.stringify(payload)}`);
  console.log(`headerBase64    : ${headerBase64}`);
  console.log(`payloadBase64   : ${payloadBase64}`);
  console.log(`signatureBase64 : ${signatureBase64}`);
  console.log(`token           : ${token}`);
  return token;
}

function verify(token, config) {
  let result;
  let header;
  let payload;
  let tokenComponents = token.split('.');
  const headerBase64 = tokenComponents[0];
  const payloadBase64 = tokenComponents[1];
  const signatureBase64 = tokenComponents[2];

  try {
    header = JSON.parse(base64Decode(headerBase64));
    payload = JSON.parse(base64Decode(payloadBase64));  
  } catch (err) {
    throw ({name : 'Token parse error', message : err.toString()});
  }

  const verifyConfig = config[header.alg];
  if(verifyConfig === undefined) {
    throw ({name : 'Unsupported algorithm', message : header.alg});
  }

  const kid = getKid(header, verifyConfig);
  console.log(`-----------------`);
  console.log(`Verify ${verifyConfig.type} kid(${kid})`);
  console.log(`-----------------`);

  const signatureData = `${headerBase64}.${payloadBase64}`;
  switch(verifyConfig.type) {    
    case SUPPORTED_ALGORITHMS.HS256 :
      const hmac = crypto.createHmac(verifyConfig.hashAlg, verifyConfig.keys[kid]);
      hmac.update(signatureData);
      const signatureComputedBase64 = base64UrlEncode(hmac.digest('hex'), 'hex');
      result = (signatureComputedBase64 === signatureBase64);
      break;
    case SUPPORTED_ALGORITHMS.RS256 :
      const verify = crypto.createVerify(verifyConfig.hashAlg);
      verify.update(signatureData);
      result = verify.verify(verifyConfig.keys[kid], signatureBase64, 'base64');
      break;
  }

  console.log(`token           : ${token}`);
  console.log(`header          : ${JSON.stringify(header)}`);
  console.log(`payload         : ${JSON.stringify(payload)}`);
  console.log(`result          : ${result}`);

  if(!result) {
    throw ({name : 'Token verify failed', message : 'Signature verify failed'});
  }
  return payload;
}

const headerHS256Key1 = generateHeader('HS256', 0);
const headerHS256Key2 = generateHeader('HS256', 1);
const headerRS256Key1 = generateHeader('RS256', 0);
const headerRS256Key2 = generateHeader('RS256', 1);
const headerDefault = generateHeader();
const headerHS256DefaultKid = generateHeader('HS256');
const headerRS256DefaultKid = generateHeader('RS256');
const payload = generatePayload('1234567890', 'Jane Doe', true);

let token;
try {
  token = sign(headerHS256Key1, payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);
  token = sign(headerHS256Key2, payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);
  token = sign(headerRS256Key1, payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);
  token = sign(headerRS256Key2, payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);
  token = sign(headerDefault, payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);
  token = sign(headerHS256DefaultKid, payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);
  token = sign(headerRS256DefaultKid, payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);  
} catch (err) {
  console.log(JSON.stringify(err));
}

try {
  let badToken = token.slice(0, -1);
  verify(badToken, CONFIG_VERIFY);  
} catch (err) {
  console.log(JSON.stringify(err));
}

try {
  token = sign(generateHeader('HS256', 2), payload, CONFIG_SIGN);
} catch (err) {
  console.log(JSON.stringify(err));
}

try {
  token = sign(generateHeader('BLAH256', 0), payload, CONFIG_SIGN);
} catch (err) {
  console.log(JSON.stringify(err));
}
