'use strict';
const crypto = require('crypto');
const fs = require('fs');

const HEADER_TYPE = 'JWT';
const HS_KEY_1 = 'secret1';
const HS_KEY_2 = 'secret2';
const RS_KEY_1_PUBLIC = fs.readFileSync('./keys/public.key.rsa.1');
const RS_KEY_1_PRIVATE = fs.readFileSync('./keys/private.key.rsa.1');
const RS_KEY_2_PUBLIC = fs.readFileSync('./keys/public.key.rsa.2');
const RS_KEY_2_PRIVATE = fs.readFileSync('./keys/private.key.rsa.2');

const ES256_PUBLIC = fs.readFileSync('./keys/public.key.ec256.1');
const ES256_PRIVATE = fs.readFileSync('./keys/private.key.ec256.1');
const ES384_PUBLIC = fs.readFileSync('./keys/public.key.ec384.1');
const ES384_PRIVATE = fs.readFileSync('./keys/private.key.ec384.1');
const ES512_PUBLIC = fs.readFileSync('./keys/public.key.ec521.1');
const ES512_PRIVATE = fs.readFileSync('./keys/private.key.ec521.1');

const SUPPORTED_ALGORITHMS = {
  HS256 : {name : 'HS256', hash :  'sha256'},
  HS384 : {name : 'HS384', hash :  'sha384'},
  HS512 : {name : 'HS512', hash :  'sha512'},
  RS256 : {name : 'RS256', hash :  'sha256', padding : crypto.constants.RSA_PKCS1_PADDING},
  RS384 : {name : 'RS384', hash :  'sha384', padding : crypto.constants.RSA_PKCS1_PADDING},
  RS512 : {name : 'RS512', hash :  'sha512', padding : crypto.constants.RSA_PKCS1_PADDING},
  ES256 : {name : 'ES256', hash :  'sha256'},
  ES384 : {name : 'ES384', hash :  'sha384'},
  ES512 : {name : 'ES512', hash :  'sha512'},
  PS256 : {name : 'PS256', hash :  'sha256', padding : crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength : crypto.constants.RSA_PSS_SALTLEN_DIGEST},
  PS384 : {name : 'PS384', hash :  'sha384', padding : crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength : crypto.constants.RSA_PSS_SALTLEN_DIGEST},
  PS512 : {name : 'PS512', hash :  'sha512', padding : crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength : crypto.constants.RSA_PSS_SALTLEN_DIGEST},
};

const CONFIG_SIGN = {
  HS256 : {type : SUPPORTED_ALGORITHMS.HS256, keys : [HS_KEY_1, HS_KEY_2]},
  HS384 : {type : SUPPORTED_ALGORITHMS.HS384, keys : [HS_KEY_1, HS_KEY_2]},
  HS512 : {type : SUPPORTED_ALGORITHMS.HS512, keys : [HS_KEY_1, HS_KEY_2]},
  RS256 : {type : SUPPORTED_ALGORITHMS.RS256, keys : [RS_KEY_1_PRIVATE, RS_KEY_2_PRIVATE]},
  RS384 : {type : SUPPORTED_ALGORITHMS.RS384, keys : [RS_KEY_1_PRIVATE, RS_KEY_2_PRIVATE]},
  RS512 : {type : SUPPORTED_ALGORITHMS.RS512, keys : [RS_KEY_1_PRIVATE, RS_KEY_2_PRIVATE]},
  ES256 : {type : SUPPORTED_ALGORITHMS.ES256, keys : [ES256_PRIVATE]},
  ES384 : {type : SUPPORTED_ALGORITHMS.ES384, keys : [ES384_PRIVATE]},
  ES512 : {type : SUPPORTED_ALGORITHMS.ES512, keys : [ES512_PRIVATE]},
  PS256 : {type : SUPPORTED_ALGORITHMS.PS256, keys : [RS_KEY_1_PRIVATE]},
  PS384 : {type : SUPPORTED_ALGORITHMS.PS384, keys : [RS_KEY_1_PRIVATE]},
  PS512 : {type : SUPPORTED_ALGORITHMS.PS512, keys : [RS_KEY_1_PRIVATE]},
}

const CONFIG_VERIFY = {
  HS256 : {type : SUPPORTED_ALGORITHMS.HS256, keys : [HS_KEY_1, HS_KEY_2]},
  HS384 : {type : SUPPORTED_ALGORITHMS.HS384, keys : [HS_KEY_1, HS_KEY_2]},
  HS512 : {type : SUPPORTED_ALGORITHMS.HS512, keys : [HS_KEY_1, HS_KEY_2]},
  RS256 : {type : SUPPORTED_ALGORITHMS.RS256, keys : [RS_KEY_1_PUBLIC, RS_KEY_2_PUBLIC]},
  RS384 : {type : SUPPORTED_ALGORITHMS.RS384, keys : [RS_KEY_1_PUBLIC, RS_KEY_2_PUBLIC]},
  RS512 : {type : SUPPORTED_ALGORITHMS.RS512, keys : [RS_KEY_1_PUBLIC, RS_KEY_2_PUBLIC]},
  ES256 : {type : SUPPORTED_ALGORITHMS.ES256, keys : [ES256_PUBLIC]},
  ES384 : {type : SUPPORTED_ALGORITHMS.ES384, keys : [ES384_PUBLIC]},
  ES512 : {type : SUPPORTED_ALGORITHMS.ES512, keys : [ES512_PUBLIC]},
  PS256 : {type : SUPPORTED_ALGORITHMS.PS256, keys : [RS_KEY_1_PUBLIC]},
  PS384 : {type : SUPPORTED_ALGORITHMS.PS384, keys : [RS_KEY_1_PUBLIC]},
  PS512 : {type : SUPPORTED_ALGORITHMS.PS512, keys : [RS_KEY_1_PUBLIC]},
 }

function base64UrlEncode(str, fmt) {
  let result = Buffer.from(str, fmt ? fmt : 'utf8').toString('base64');
  return result.replace(/\+/g, '-').replace(/\//g, '_').replace(/\=+$/, '');
}

function base64Decode(str, fmt) {
  return Buffer.from(str, fmt ? fmt : 'base64').toString('utf8');
}

function generateHeader(alg, kid) {
  return {alg : alg ? alg : SUPPORTED_ALGORITHMS.HS256.name, type : HEADER_TYPE, kid : kid ? kid : 0};
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

function rawFromASN1(buffer) {
  let start;
  if(buffer[1] & 0x80) {
    start = 5;
  } else {
    start = 4;
  }
  let ls = buffer[start - 1];
  let r = buffer.slice(start, ls + start);
  let s = buffer.slice(start + ls + 2);
  if(!r[0]) {
    r = r.slice(1);
  }
  if(!s[0]) {
    s = s.slice(1);
  }

  if(r.length != s.length) {
    let maxLength = (r.length > s.length) ? r.length : s.length;
    let padding = Buffer.alloc((Math.abs(r.length - s.length)));
    if(r.length != maxLength) {
      r = Buffer.concat([padding, r]);
    }
    if(s.length != maxLength) {
      s = Buffer.concat([padding, s]);
    }
  }

  return Buffer.concat([r, s]);
}

function rawToASN1(signatureBase64) {
  let rawBuffer =  Buffer.from(signatureBase64, 'base64');
  let keySize = rawBuffer.length / 2;
  let r = rawBuffer.slice(0, keySize);
  let s = rawBuffer.slice(keySize);
  if(!r[0]) {
    r = r.slice(1);
  }
  if(!s[0]) {
    s = s.slice(1);
  }

  if(r[0] & 0x80) {
    r = Buffer.concat([Buffer.alloc(1), r]);
  }
  if(s[0] & 0x80) {
    s = Buffer.concat([Buffer.alloc(1), s]);
  }

  let h = Buffer.alloc(1, 48);
  let length = r.length + s.length + 4;
  let l = Buffer.alloc(1, length);
  let li = Buffer.alloc(1, 0x81);
  let header;
  if(length > 0x7F) {
    header = Buffer.concat([h, li, l]);
  } else {
    header = Buffer.concat([h, l]);
  }
  return Buffer.concat([header, 
    Buffer.alloc(1, 2),  
    Buffer.alloc(1, r.length), 
    r, 
    Buffer.alloc(1, 2),  
    Buffer.alloc(1, s.length),
    s]);
}

function sign(header, payload, config) {
  let signatureBase64;
  const signConfig = config[header.alg];
  if(signConfig === undefined) {
    throw ({name : 'Unsupported algorithm', message : header.alg});
  }

  const kid = getKid(header, signConfig);
  console.log(`-----------------`);
  console.log(`Sign ${signConfig.type.name} kid(${kid})`);
  console.log(`-----------------`);

  const headerBase64 = base64UrlEncode(JSON.stringify(header));
  const payloadBase64 = base64UrlEncode(JSON.stringify(payload));
  const signatureData = `${headerBase64}.${payloadBase64}`;

  let sign;
  switch(signConfig.type) {   
    case SUPPORTED_ALGORITHMS.HS256 :
    case SUPPORTED_ALGORITHMS.HS384 :
    case SUPPORTED_ALGORITHMS.HS512 :
      const hmac = crypto.createHmac(signConfig.type.hash, signConfig.keys[kid]);
      hmac.update(signatureData);
      signatureBase64 = base64UrlEncode(hmac.digest('hex'), 'hex');
      break;

    case SUPPORTED_ALGORITHMS.RS256 :
    case SUPPORTED_ALGORITHMS.RS384 :
    case SUPPORTED_ALGORITHMS.RS512 :
      sign = crypto.createSign(signConfig.type.hash);
      sign.update(signatureData);
      signatureBase64 = base64UrlEncode(sign.sign({
        key : signConfig.keys[kid], 
        padding : signConfig.type.padding
      }, 'hex'), 'hex');
      break;

    case SUPPORTED_ALGORITHMS.ES256 :
    case SUPPORTED_ALGORITHMS.ES384 :
    case SUPPORTED_ALGORITHMS.ES512 :
      sign = crypto.createSign(signConfig.type.hash);
      sign.update(signatureData);
      signatureBase64 = base64UrlEncode(rawFromASN1(sign.sign(signConfig.keys[kid])).toString('hex'), 'hex');
      break;

    case SUPPORTED_ALGORITHMS.PS256 :
    case SUPPORTED_ALGORITHMS.PS384 :
    case SUPPORTED_ALGORITHMS.PS512 :
      sign = crypto.createSign(signConfig.type.hash);
      sign.update(signatureData);
      signatureBase64 = base64UrlEncode(sign.sign({
        key : signConfig.keys[kid], 
        padding : signConfig.type.padding,
        saltLength : signConfig.type.saltLength
      }, 'hex'), 'hex');
      break;  
  }

  const token = `${headerBase64}.${payloadBase64}.${signatureBase64}`;

  console.log(`header          : ${JSON.stringify(header)}`);
  console.log(`payload         : ${JSON.stringify(payload)}`);
  console.log(`headerBase64    : ${headerBase64}`);
  console.log(`payloadBase64   : ${payloadBase64}`);
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
  console.log(`Verify ${verifyConfig.type.name} kid(${kid})`);
  console.log(`-----------------`);

  const signatureData = `${headerBase64}.${payloadBase64}`;
  let verify;
  switch(verifyConfig.type) {    
    case SUPPORTED_ALGORITHMS.HS256 :
    case SUPPORTED_ALGORITHMS.HS384 :
    case SUPPORTED_ALGORITHMS.HS512 :
      const hmac = crypto.createHmac(verifyConfig.type.hash, verifyConfig.keys[kid]);
      hmac.update(signatureData);
      result = (base64UrlEncode(hmac.digest('hex'), 'hex') === signatureBase64);
      break;

    case SUPPORTED_ALGORITHMS.RS256 :
    case SUPPORTED_ALGORITHMS.RS384 :
    case SUPPORTED_ALGORITHMS.RS512 :
      verify = crypto.createVerify(verifyConfig.type.hash);
      verify.update(signatureData);
      result = verify.verify({
        key : verifyConfig.keys[kid], 
        padding : verifyConfig.type.padding 
      },
      signatureBase64, 'base64');
      break;

    case SUPPORTED_ALGORITHMS.ES256 :
    case SUPPORTED_ALGORITHMS.ES384 :
    case SUPPORTED_ALGORITHMS.ES512 :
      verify = crypto.createVerify(verifyConfig.type.hash);
      verify.update(signatureData);
      result = verify.verify(verifyConfig.keys[kid], rawToASN1(signatureBase64));
      break;

    case SUPPORTED_ALGORITHMS.PS256 :
    case SUPPORTED_ALGORITHMS.PS384 :
    case SUPPORTED_ALGORITHMS.PS512 :
      verify = crypto.createVerify(verifyConfig.type.hash);
      verify.update(signatureData);
      result = verify.verify({
        key : verifyConfig.keys[kid], 
        padding : verifyConfig.type.padding, 
        saltLength : verifyConfig.type.saltLength
      },
      signatureBase64, 'base64');
      break;
    }

  console.log(`token           : ${token}`);
  console.log(`header          : ${JSON.stringify(header)}`);
  console.log(`payload         : ${JSON.stringify(payload)}`);
  console.log(`verified        : ${result}`);

  if(!result) {
    throw ({name : 'Token verify failed', message : 'Signature verify failed'});
  }
  return payload;
}

const payload = generatePayload('1234567890', 'Jane Doe', true);
let token;
try {
  //Default
  token = sign(generateHeader(), payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);
  
  //HS
  token = sign(generateHeader(SUPPORTED_ALGORITHMS.HS256.name), payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);
  token = sign(generateHeader(SUPPORTED_ALGORITHMS.HS384.name), payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);  
  token = sign(generateHeader(SUPPORTED_ALGORITHMS.HS512.name), payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);  

  //RS
  token = sign(generateHeader(SUPPORTED_ALGORITHMS.RS256.name), payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);  
  token = sign(generateHeader(SUPPORTED_ALGORITHMS.RS384.name), payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);  
  token = sign(generateHeader(SUPPORTED_ALGORITHMS.RS512.name), payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);  

  //ES
  token = sign(generateHeader(SUPPORTED_ALGORITHMS.ES256.name), payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);  
  token = sign(generateHeader(SUPPORTED_ALGORITHMS.ES384.name), payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);  
  token = sign(generateHeader(SUPPORTED_ALGORITHMS.ES512.name), payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);  

  //PS
  token = sign(generateHeader(SUPPORTED_ALGORITHMS.PS256.name), payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);  
  token = sign(generateHeader(SUPPORTED_ALGORITHMS.PS384.name), payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);  
  token = sign(generateHeader(SUPPORTED_ALGORITHMS.PS512.name), payload, CONFIG_SIGN);
  verify(token, CONFIG_VERIFY);
} catch (err) {
  console.log(JSON.stringify(err));
}
