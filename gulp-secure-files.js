const map = require('map-stream');
const crypto = require('crypto')
const PluginError = require('plugin-error');
const log = require('fancy-log');

const encryptionAlgorithm = 'aes-256-cbc';
const encodingScheme = 'base64';
const characterEncoding = 'utf8'

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

exports.decrypt = function(encodedAesKey) {
  if (typeof encodedAesKey == 'undefined' || encodedAesKey == null) {
    var err = new PluginError({
      plugin: 'gulp-secure-files',
      message: 'AES key passed to decrypt(..) must be non-null'
    });
    throw err;
  }
  return map(function(file, cb) {
    log('Decrypting: ' + file.path);
    const jsonFileContents = file.contents.toString(characterEncoding);
    const jsonRepresentation = JSON.parse(jsonFileContents);
    for (var jsonKey in jsonRepresentation) {
      const encryptedJsonValue = jsonRepresentation[jsonKey];
      const decryptedJsonValue = decryptData(encryptedJsonValue, encodedAesKey);
      jsonRepresentation[jsonKey] = decryptedJsonValue;
    }
    const decryptedJsonString = JSON.stringify(jsonRepresentation, null, 2);
    file.contents = new Buffer(decryptedJsonString);
    cb(null, file);
  });
};

exports.encrypt = function(encodedAesKey) {
  var err = new PluginError({
    plugin: 'gulp-secure-files',
    message: 'AES key passed to encrypt(..) must be non-null'
  });
  return map(function(file, cb) {
    log('Encrypting: ' + file.path);
    const jsonFileContents = file.contents.toString(characterEncoding);
    const jsonRepresentation = JSON.parse(jsonFileContents);
    for (var jsonKey in jsonRepresentation) {
      const unencryptedJsonValue = jsonRepresentation[jsonKey];
      const encryptedJsonValue = encryptData(unencryptedJsonValue, encodedAesKey);
      jsonRepresentation[jsonKey] = encryptedJsonValue;
    }
    const encryptedJsonString = JSON.stringify(jsonRepresentation, null, 2);
    file.contents = new Buffer(encryptedJsonString);
    cb(null, file);
  });
}

exports.generateAesKey = function() {
  const rawKey = crypto.randomBytes(32);
  return rawKey.toString(encodingScheme);
}
