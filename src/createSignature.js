const pkcs11js = require("pkcs11js");

const libraryPath = "C:\\Windows\\System32\\etpkcs11.dll";
const PIN = process.env.PKCS11_PIN || "2945"; // PIN'i ortam değişkeninden al

function createSignature(dataHash) {
  const pkcs11 = new pkcs11js.PKCS11();
  pkcs11.load(libraryPath);
  pkcs11.C_Initialize();

  try {
    const slots = pkcs11.C_GetSlotList(true);
    if (slots.length === 0) throw new Error("Token takılı değil");

    const session = pkcs11.C_OpenSession(slots[0], pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
    pkcs11.C_Login(session, pkcs11js.CKU_USER, PIN);

    // Özel anahtarı bul
    pkcs11.C_FindObjectsInit(session, [
      { type: pkcs11js.CKA_CLASS, value: Buffer.from([pkcs11js.CKO_PRIVATE_KEY]) },
      { type: pkcs11js.CKA_SIGN, value: Buffer.from([1]) },
    ]);
    
    let privateKeyObj;
    while (true) {
      const obj = pkcs11.C_FindObjects(session);
      if (!obj) break;
      privateKeyObj = obj;
    }
    pkcs11.C_FindObjectsFinal(session);

    if (!privateKeyObj) throw new Error("Uygun özel anahtar bulunamadı");

    // İmza mekanizmasını başlat
    pkcs11.C_SignInit(session, { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS }, privateKeyObj);

    // Dinamik buffer boyutu (2048-bit RSA için 256 bayt, 4096-bit için 512 bayt)
    const keyAttrs = pkcs11.C_GetAttributeValue(session, privateKeyObj, [{ type: pkcs11js.CKA_MODULUS }]);
    const modulusSize = keyAttrs[0].value.length; // Anahtar boyutunu al
    const outputBuffer = Buffer.alloc(modulusSize);

    // İmzalama
    const sigLen = pkcs11.C_Sign(session, Buffer.from(dataHash), outputBuffer);
    const signature = outputBuffer.slice(0, sigLen);

    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);

    return signature;

  } catch (err) {
    throw new Error(`İmzalama hatası: ${err.message}`);
  } finally {
    try { pkcs11.C_Finalize(); } catch {}
  }
}

// module.exports = { createSignature };


function getCertificate() {
  const pkcs11 = new pkcs11js.PKCS11();
  pkcs11.load(libraryPath);
  pkcs11.C_Initialize();

  try {
    const slots = pkcs11.C_GetSlotList(true);
    if (slots.length === 0) throw new Error("Token takılı değil");

    const session = pkcs11.C_OpenSession(slots[0], pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
    pkcs11.C_Login(session, pkcs11js.CKU_USER, PIN);

    pkcs11.C_FindObjectsInit(session, [
      { type: pkcs11js.CKA_CLASS, value: Buffer.from([pkcs11js.CKO_CERTIFICATE]) },
    ]);
    
    let certObj;
    while (true) {
      const obj = pkcs11.C_FindObjects(session);
      if (!obj) break;
      certObj = obj;
    }
    pkcs11.C_FindObjectsFinal(session);

    if (!certObj) throw new Error("Sertifika bulunamadı");

    const certAttrs = pkcs11.C_GetAttributeValue(session, certObj, [{ type: pkcs11js.CKA_VALUE }]);
    const certDer = certAttrs[0].value;
    const certPem = forge.pki.certificateToPem(forge.pki.certificateFromDer(certDer));

    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);

    return certPem;

  } catch (err) {
    throw new Error(`Sertifika alma hatası: ${err.message}`);
  } finally {
    try { pkcs11.C_Finalize(); } catch {}
  }
}

module.exports = { createSignature, getCertificate };