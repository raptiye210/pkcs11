const pkcs11js = require("pkcs11js");
const pkcs11 = new pkcs11js.PKCS11();
const fs = require("fs");
const crypto = require("crypto");
const { Signer } = require("node-signpdf");

const libraryPath = "C:\\Windows\\System32\\etpkcs11.dll";
const PIN = "2945";
const pdfPath = "C:\\proje\\pkcs11\\src\\a.pdf";
const outputPath = "C:\\proje\\pkcs11\\src\\signed_a.pdf";

try {
  const pdfData = fs.readFileSync(pdfPath);
  const hash = crypto.createHash("sha256").update(pdfData).digest();

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

  const CKO_CERTIFICATE = 1;
  const CKO_PRIVATE_KEY = 3;

  pkcs11.C_FindObjectsInit(session, [{ type: pkcs11js.CKA_CLASS, value: Buffer.from([CKO_PRIVATE_KEY]) }]);
  const keyObjects = pkcs11.C_FindObjects(session, 100);
  pkcs11.C_FindObjectsFinal(session);

  pkcs11.C_FindObjectsInit(session, [{ type: pkcs11js.CKA_CLASS, value: Buffer.from([CKO_CERTIFICATE]) }]);
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
      if (clazz === CKO_CERTIFICATE || clazz === CKO_PRIVATE_KEY) {
        filteredObjects.push({
          obj,
          clazz,
          label: attrs[1]?.value ? attrs[1].value.toString() : "<Etiket yok>",
        });
      }
    } catch (err) {
      console.log("Nesne okunamadı:", err.message);
      continue;
    }
  }

  console.log(`Toplam Sertifika ve Anahtar sayısı: ${filteredObjects.length}`);
  for (const { obj, clazz, label } of filteredObjects) {
    const className = clazz === CKO_CERTIFICATE ? "Sertifika" : "Özel Anahtar";
    console.log(`Nesne: label="${label}", class=${clazz} (${className})`);
  }

  const privateKeyObj = filteredObjects.find(o => o.clazz === CKO_PRIVATE_KEY)?.obj;
  if (!privateKeyObj) {
    throw new Error("Özel anahtar bulunamadı!");
  }
  console.log("Özel anahtar bulundu:", filteredObjects.find(o => o.clazz === CKO_PRIVATE_KEY).label);

  const certObj = filteredObjects.find(o => o.clazz === CKO_CERTIFICATE)?.obj;
  if (!certObj) {
    throw new Error("Sertifika bulunamadı!");
  }
  let certData;
  try {
    const certAttrs = pkcs11.C_GetAttributeValue(session, certObj, [{ type: pkcs11js.CKA_VALUE }]);
    certData = certAttrs[0]?.value;
    if (!certData) throw new Error("Sertifika verisi alınamadı!");
  } catch (err) {
    console.log("Sertifika verisi alınamadı:", err.message);
    throw err;
  }

  const signatureBuffer = Buffer.alloc(256); // RSA-2048 için varsayılan

  const mechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS };
  pkcs11.C_SignInit(session, mechanism, privateKeyObj);
  const signature = pkcs11.C_Sign(session, hash, signatureBuffer).slice(0, signatureBuffer.length);
  console.log("İmzalanan veri (Base64):", signature.toString("base64"));

  const signer = new Signer({
    cert: certData,
    signature: signature,
    signatureLength: signature.length,
  });
  const signedPdf = signer.sign(pdfData);
  fs.writeFileSync(outputPath, signedPdf);
  console.log(`İmzalı PDF kaydedildi: ${outputPath}`);

  const publicKey = crypto.createPublicKey({ key: certData, format: "der", type: "x509" });
  const verify = crypto.createVerify("sha256");
  verify.update(pdfData);
  verify.end();
  console.log("İmza doğruluğu:", verify.verify(publicKey, signature));

  pkcs11.C_Logout(session);
  pkcs11.C_CloseSession(session);
} catch (e) {
  console.error("Hata:", e.message);
} finally {
  try {
    pkcs11.C_Finalize();
  } catch {}
}