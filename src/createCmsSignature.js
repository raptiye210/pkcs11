const forge = require("node-forge");
const pkcs11js = require("pkcs11js");

const libraryPath = "C:\\Windows\\System32\\etpkcs11.dll";
const PIN = "2945";

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

    // Tüm objeleri getir
    pkcs11.C_FindObjectsInit(session, []);
    const objs = pkcs11.C_FindObjects(session, 100);
    pkcs11.C_FindObjectsFinal(session);

    // Özel anahtarı bul
    const privateKeyObj = objs.find(o => {
      try {
        const attrs = pkcs11.C_GetAttributeValue(session, o, [{ type: pkcs11js.CKA_CLASS }]);
        return attrs[0].value.readUInt32LE(0) === pkcs11js.CKO_PRIVATE_KEY;
      } catch {
        return false;
      }
    });

    if (!privateKeyObj) throw new Error("Private key bulunamadı");

    // Sertifikayı bul
    const certificateObject = objs.find(o => {
      try {
        const attrs = pkcs11.C_GetAttributeValue(session, o, [{ type: pkcs11js.CKA_CLASS }]);
        return attrs[0].value.readUInt32LE(0) === pkcs11js.CKO_CERTIFICATE;
      } catch {
        return false;
      }
    });

    if (!certificateObject) throw new Error("Sertifika bulunamadı");

    // Sertifikayı DER formatında al
    const certDer = pkcs11.C_GetAttributeValue(session, certificateObject, [
      { type: pkcs11js.CKA_VALUE },
    ])[0].value;

    // DER'den PEM'e çevir
    const certBase64 = certDer.toString("base64");
    const pemBody = certBase64.match(/.{1,64}/g).join("\n");
    const certPem = `-----BEGIN CERTIFICATE-----\n${pemBody}\n-----END CERTIFICATE-----`;

    const cert = forge.pki.certificateFromPem(certPem);

    // İmza oluştur
    const mechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS };
    pkcs11.C_SignInit(session, mechanism, privateKeyObj);

    const signatureBuffer = Buffer.alloc(256); // Token’a göre değişebilir
    const sigLen = pkcs11.C_Sign(session, Buffer.from(dataHash), signatureBuffer);
    const signature = signatureBuffer.slice(0, sigLen);

    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);

    // CMS oluştur
    const p7 = forge.pkcs7.createSignedData();
    p7.content = bufferToForgeBuffer(dataHash);
    p7.addCertificate(cert);

    const attrs = [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest, value: dataHash.toString("binary") },
      { type: forge.pki.oids.signingTime, value: new Date() },
    ];

    p7.signers.push({
      version: 1,
      sid: {
        type: forge.pki.oids.issuerAndSerialNumber,
        issuer: cert.issuer,
        serialNumber: cert.serialNumber,
      },
      digestAlgorithm: forge.pki.oids.sha256,
      authenticatedAttributes: attrs,
      signatureAlgorithm: forge.pki.oids.sha256WithRSAEncryption,
      signature: forge.util.createBuffer(signature.toString("binary")),
    });

    const cmsDer = forge.asn1.toDer(p7.toAsn1({ skipSignerSigning: true })).getBytes();

    const cmsBuffer = Buffer.from(cmsDer, "binary");

    return cmsBuffer;

  } finally {
    try { pkcs11.C_Finalize(); } catch {}
  }
}

module.exports = { createCmsSignature };
