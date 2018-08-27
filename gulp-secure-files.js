const map = require('map-stream');
const crypto = require('crypto')
const PluginError = require('plugin-error');
const log = require('fancy-log');

const encryptionAlgorithm = 'aes-256-cbc';
const encodingScheme = 'base64';
const characterEncoding = 'utf8';

function encryptData(plainText, encodedAesKey) {
  const iv = crypto.randomBytes(16);
  const key = Buffer.from(encodedAesKey, encodingScheme);
  const cipher = crypto.createCipheriv(encryptionAlgorithm, key, iv);
  var cipherText = cipher.update(plainText, characterEncoding, encodingScheme);
  cipherText += cipher.final(encodingScheme);
  return iv.toString(encodingScheme) + "_" + cipherText;
}

function decryptData(encryptedData, encodedAesKey) {
  const encryptedDataParts = encryptedData.split("_");
  const iv = Buffer.from(encryptedDataParts[0], encodingScheme);
  const key = Buffer.from(encodedAesKey, encodingScheme);
  const cipherText = encryptedDataParts[1];
  const decipher = crypto.createDecipheriv(encryptionAlgorithm, key, iv);
  var plainText = decipher.update(cipherText, encodingScheme, characterEncoding);
  plainText += decipher.final(characterEncoding);
  return plainText;
}

function processConfigFile(file, exclude, encodedAesKey, process) {
  const jsonFileContents = file.contents.toString(characterEncoding);
  const jsonRepresentation = JSON.parse(jsonFileContents);
  let excludeKeys = exclude[file.relative] || {};
  for (var jsonKey in jsonRepresentation) {
    if (excludeKeys[jsonKey] !== true) {
      const jsonValue = jsonRepresentation[jsonKey];
      const processedJsonValue = process(jsonValue, encodedAesKey);
      jsonRepresentation[jsonKey] = processedJsonValue;
    }
  }
  const processedJsonString = JSON.stringify(jsonRepresentation, null, 2);
  file.contents = new Buffer(processedJsonString);
}

exports.decrypt = function(encodedAesKey, exclude) {
  if (typeof encodedAesKey == 'undefined' || encodedAesKey == null) {
    const err = new PluginError({
      plugin: 'gulp-secure-files',
      message: 'AES key passed to decrypt(..) must be non-null'
    });
    throw err;
  }
  return map(function(file, cb) {
    log('Decrypting: ' + file.path);
    processConfigFile(file, exclude, encodedAesKey, decryptData);
    cb(null, file);
  });
};

exports.encrypt = function(encodedAesKey, exclude) {
  if (typeof encodedAesKey == 'undefined' || encodedAesKey == null) {
    const err = new PluginError({
      plugin: 'gulp-secure-files',
      message: 'AES key passed to encrypt(..) must be non-null'
    });
    throw err;
  }
  return map(function(file, cb) {
    log('Encrypting: ' + file.path);
    processConfigFile(file, exclude, encodedAesKey, encryptData);
    cb(null, file);
  });
}
