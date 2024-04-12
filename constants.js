const { readFileSync } = require('fs');

const defaultIdpConfig = {
    privateKey: readFileSync('./test/key/idp/privkey.pem'),
    privateKeyPass: 'q9ALNhGT5EhfcRmp8Pg7e9zTQeP2x1bW',
    isAssertionEncrypted: true,
    encPrivateKey: readFileSync('./test/key/idp/encryptKey.pem'),
    encPrivateKeyPass: 'g7hGcRmp8PxT5QeP2q9Ehf1bWe9zTALN',
    metadata: readFileSync('./test/misc/idpmeta.xml'),
};
  
  
const defaultSpConfig = {
    privateKey: readFileSync('./test/key/sp/privkey.pem'),
    privateKeyPass: 'VHOSp5RUiBcrsjrcAuXFwU1NKCkGA8px',
    isAssertionEncrypted: true, // for logout purpose
    encPrivateKey: readFileSync('./test/key/sp/encryptKey.pem'),
    encPrivateKeyPass: 'BXFNKpxrsjrCkGA8cAu5wUVHOSpci1RU',
    metadata: readFileSync('./test/misc/spmeta.xml'),
  };

module.exports = {
    defaultIdpConfig,
    defaultSpConfig,
}