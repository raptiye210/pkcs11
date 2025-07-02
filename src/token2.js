const pkcs11js = require("pkcs11js");
const pkcs11 = new pkcs11js.PKCS11();
const fs = require("fs");
const crypto = require("crypto");

const libraryPath = process.env.PKCS11_LIB || "C:\\Windows\\System32\\etpkcs11.dll";
const PIN = process.env.PIN || "2945";
const pdfPath = process.env.PDF_PATH || "C:\\proje\\pkcs11\\src\\a.pdf";

const pdfData = fs.readFileSync(pdfPath);
const hash = crypto.createHash("sha256").update(pdfData).digest();

try {
  pkcs11.load(libraryPath);
  pkcs11.C_Initialize();

  const slots = pkcs11.C_GetSlotList(true);
  if (slots.length === 0) {
    console.log("Cihaza bağlı slot bulunamadı.");
    process.exit(1);
  }

  const slot = slots[0];
  const session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
  pkcs11.C_Login(session, pkcs11js.CKU_USER, PIN);

  // Find private key
  pkcs11.C_FindObjectsInit(session, [{ type: pkcs11js.CKA_CLASS, value: Buffer.from([pkcs11js.CKO_PRIVATE_KEY]) }]);
  const keyObjects = pkcs11.C_FindObjects(session, 100);
  pkcs11.C_FindObjectsFinal(session);

  // Find certificate
  pkcs11.C_FindObjectsInit(session, [{ type: pkcs11js.CKA_CLASS, value: Buffer.from([pkcs11js.CKO_CERTIFICATE]) }]);
  const certObjects = pkcs11.C_FindObjects(session, 100);
  pkcs11.C_FindObjectsFinal(session);

  const filteredObjects = [];
  for (const obj of [...keyObjects, ...certObjects]) {
    try {
      const attrs = pkcs11.C_GetAttributeValue(session, obj, [
        { type: pkcs11js.CKA_CLASS },
        { type: pkcs11js.CKA_LABEL },
      ]);
      const clazz = attrs[0]?.value ? attrs[0].value.readUInt32LE(0) : null;
      if (clazz === pkcs11js.CKO_CERTIFICATE || clazz === pkcs11js.CKO_PRIVATE_KEY) {
        filteredObjects.push({
          obj,
          clazz,
          label: attrs[1]?.value ? attrs[1].value.toString() : "<Etiket yok>",
        });
      }
    } catch (err) {
      console.log("Nesne okunamadı:", err.message);
    }
  }

  console.log(`Toplam Sertifika ve Anahtar sayısı: ${filteredObjects.length}`);
  for (const { obj, clazz, label } of filteredObjects) {
    const className = clazz === pkcs11js.CKO_CERTIFICATE ? "Sertifika" : "Özel Anahtar";
    console.log(`Nesne: label="${label}", class=${clazz} (${className})`);
  }

  const privateKeyObj = filteredObjects.find(o => o.clazz === pkcs11js.CKO_PRIVATE_KEY)?.obj;
  if (!privateKeyObj) {
    throw new Error("Private key bulunamadı!");
  }
  console.log("Özel anahtar bulundu:", filteredObjects.find(o => o.clazz === pkcs11js.CKO_PRIVATE_KEY).label);

  // Get modulus length for signature buffer
  const modulusAttrs = pkcs11.C_GetAttributeValue(session, privateKeyObj, [
    { type: pkcs11js.CKA_MODULUS },
  ]);
  const signatureBuffer = Buffer.alloc(modulusAttrs[0]?.value?.length || 256);

  // Sign
  const mechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS };
  pkcs11.C_SignInit(session, mechanism, privateKeyObj);
  const signature = pkcs11.C_Sign(session, hash, signatureBuffer).slice(0, signatureBuffer.length);
  console.log("İmzalanan veri (Base64):", signature.toString("base64"));

  // Verify signature (optional)
  const certObj = filteredObjects.find(o => o.clazz === pkcs11js.CKO_CERTIFICATE)?.obj;
  if (certObj) {
    const certAttrs = pkcs11.C_GetAttributeValue(session, certObj, [{ type: pkcs11js.CKA_VALUE }]);
    const certData = certAttrs[0]?.value;
    const publicKey = crypto.createPublicKey({ key: certData, format: "der", type: "x509" });
    const verify = crypto.createVerify("sha256");
    verify.update(pdfData);
    verify.end();
    console.log("Signature valid:", verify.verify(publicKey, signature));
  }

  pkcs11.C_Logout(session);
  pkcs11.C_CloseSession(session);
} catch (e) {
  console.error("Hata:", e);
} finally {
  try {
    pkcs11.C_Finalize();
  } catch {}
}