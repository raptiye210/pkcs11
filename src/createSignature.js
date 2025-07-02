const pkcs11js = require("pkcs11js");

const libraryPath = "C:\\Windows\\System32\\etpkcs11.dll";
const PIN = "2945";

function createSignature(dataHash) {
  const pkcs11 = new pkcs11js.PKCS11();
  pkcs11.load(libraryPath);
  pkcs11.C_Initialize();

  try {
    const slots = pkcs11.C_GetSlotList(true);
    if (slots.length === 0) throw new Error("Token takılı değil");

    const session = pkcs11.C_OpenSession(slots[0], pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
    pkcs11.C_Login(session, pkcs11js.CKU_USER, PIN);

    // Objeleri bul
    pkcs11.C_FindObjectsInit(session, []);
    const objs = pkcs11.C_FindObjects(session, 100);
    pkcs11.C_FindObjectsFinal(session);

    const privateKeyObj = objs.find((obj) => {
      try {
        const attr = pkcs11.C_GetAttributeValue(session, obj, [{ type: pkcs11js.CKA_CLASS }]);
        return attr[0].value.readUInt32LE(0) === pkcs11js.CKO_PRIVATE_KEY;
      } catch {
        return false;
      }
    });

    if (!privateKeyObj) throw new Error("Private key bulunamadı");

    // İmza başlat
    pkcs11.C_SignInit(session, { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS }, privateKeyObj);

    // Çıkış buffer'ı ve imzalama
    const outputBuffer = Buffer.alloc(256); // token'a göre büyüklük değişebilir
    const sigLen = pkcs11.C_Sign(session, Buffer.from(dataHash), outputBuffer);
    const signature = outputBuffer.slice(0, sigLen);

    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);

    return signature;

  } finally {
    try { pkcs11.C_Finalize(); } catch {}
  }
}

module.exports = { createSignature };
