const forge = require("node-forge");
const pkcs11js = require("pkcs11js");
const fs = require("fs");

const libraryPath = "C:\\Windows\\System32\\etpkcs11.dll";
const PIN = "2945";

// Sertifikan PEM formatında buraya koy (PKCS#11’den çıkarman lazım)
const certPem = `-----BEGIN CERTIFICATE-----
...sertifikan buraya...
-----END CERTIFICATE-----`;

function bufferToForgeBuffer(buffer) {
  return forge.util.createBuffer(buffer.toString("binary"));
}

async function createCmsSignature(dataHash) {
  const pkcs11 = new pkcs11js.PKCS11();
  pkcs11.load(libraryPath);
  pkcs11.C_Initialize();

  try {
    const slots = pkcs11.C_GetSlotList(true);
    if (slots.length === 0) throw new Error("Slot bulunamadı");

    const slot = slots[0];
    const session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
    pkcs11.C_Login(session, pkcs11js.CKU_USER, PIN);

    pkcs11.C_FindObjectsInit(session, []);
    const objs = pkcs11.C_FindObjects(session, 100);
    pkcs11.C_FindObjectsFinal(session);

    const privateKeyObj = objs.find(o => {
      try {
        const attrs = pkcs11.C_GetAttributeValue(session, o, [{ type: pkcs11js.CKA_CLASS }]);
        return attrs[0].value.readUInt32LE(0) === 3;
      } catch {
        return false;
      }
    });

    if (!privateKeyObj) throw new Error("Private key bulunamadı");

    const mechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS };
    pkcs11.C_SignInit(session, mechanism, privateKeyObj);

    const signature = pkcs11.C_Sign(session, Buffer.from(dataHash));

    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);

    // CMS yapısını oluştur
    const cert = forge.pki.certificateFromPem(certPem);
    const p7 = forge.pkcs7.createSignedData();

    p7.content = bufferToForgeBuffer(dataHash);
    p7.addCertificate(cert);
    p7.addSigner({
      key: null,
      certificate: cert,
      digestAlgorithm: forge.pki.oids.sha256,
      authenticatedAttributes: [
        { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
        { type: forge.pki.oids.messageDigest, value: dataHash.toString("binary") },
        { type: forge.pki.oids.signingTime, value: new Date() }
      ]
    });

    // Dışarıdan imza veriyoruz, key boş
    p7.signers[0].signature = forge.util.createBuffer(signature.toString("binary"));

    const cmsDer = forge.asn1.toDer(p7.toAsn1()).getBytes();
    const cmsBuffer = Buffer.from(cmsDer, "binary");

    return cmsBuffer;

  } finally {
    try { pkcs11.C_Finalize(); } catch {}
  }
}

module.exports = { createCmsSignature };
