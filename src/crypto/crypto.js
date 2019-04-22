/* eslint-disable import/named */
/* eslint-disable no-undef */
/* eslint-disable no-param-reassign */
import aesjs from './aes';
import { MD5 } from './md5';

const bigInt = require('./big-integer');


// Create Base64 Object
function base64_encode(str){
    var c1, c2, c3;
    var base64EncodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var i = 0, len= str.length, string = '';
 
    while (i < len){
        c1 = str.charCodeAt(i++) & 0xff;
        if (i == len){
            string += base64EncodeChars.charAt(c1 >> 2);
            string += base64EncodeChars.charAt((c1 & 0x3) << 4);
            string += "==";
            break;
        }
        c2 = str.charCodeAt(i++);
        if (i == len){
            string += base64EncodeChars.charAt(c1 >> 2);
            string += base64EncodeChars.charAt(((c1 & 0x3) << 4) | ((c2 & 0xF0) >> 4));
            string += base64EncodeChars.charAt((c2 & 0xF) << 2);
            string += "=";
            break;
        }
        c3 = str.charCodeAt(i++);
        string += base64EncodeChars.charAt(c1 >> 2);
        string += base64EncodeChars.charAt(((c1 & 0x3) << 4) | ((c2 & 0xF0) >> 4));
        string += base64EncodeChars.charAt(((c2 & 0xF) << 2) | ((c3 & 0xC0) >> 6));
        string += base64EncodeChars.charAt(c3 & 0x3F)
    }
        return string
}



function aesEncrypt(text, secKey, ivString) {
  const pad = 16 - (text.length % 16);
  for (let i = 0; i < pad; i += 1) {
    text += String.fromCharCode(pad);
  }
  const key = aesjs.util.convertStringToBytes(secKey);
  // The initialization vector, which must be 16 bytes
  const iv = aesjs.util.convertStringToBytes(ivString);
  let textBytes = aesjs.util.convertStringToBytes(text);
  // eslint-disable-next-line new-cap
  const aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);
  const cipherArray = [];
  while (textBytes.length !== 0) {
    const block = aesCbc.encrypt(textBytes.slice(0, 16));
    Array.prototype.push.apply(cipherArray, block);
    textBytes = textBytes.slice(16);
  }
  let ciphertext = '';
  for (let i = 0; i < cipherArray.length; i += 1) {
    ciphertext += String.fromCharCode(cipherArray[i]);
  }
  ciphertext = base64_encode(ciphertext);

  return ciphertext;
}

function hexify(text) {
  return text.split('').map(x => x.charCodeAt(0).toString(16)).join('');
}

function zfill(num, size) {
  let s = `${num}`;
  while (s.length < size) s = `0${s}`;
  return s;
}

function expmod(base, exp, mymod) {
  let result;
  if (exp.eq(0)) return bigInt(1, 10);
  if (exp.mod(bigInt(2, 10)).eq(0)) {
    let newexp = bigInt(exp);
    newexp = newexp.shiftRight(1);
    result = expmod(base, newexp, mymod).modPow(2, mymod);
    return result;
  }
  result = expmod(base, exp.subtract(bigInt(1, 10)), mymod).multiply(base).mod(mymod);
  return result;
}

function rsaEncrypt(text, pubKey, modulus) {
  const reversedText = text.split('').reverse().join('');
  const base = bigInt(hexify(reversedText), 16);
  const exp = bigInt(pubKey, 16);
  const mod = bigInt(modulus, 16);
  const bigNumber = expmod(base, exp, mod);
  const rs = bigNumber.toString(16);
  return zfill(rs, 256).toLowerCase();
}

export default { aesEncrypt, rsaEncrypt, MD5 };
