const pkcs11js = require("pkcs11js");
const pkcs11 = new pkcs11js.PKCS11();
const libraryPath = "C:\\Windows\\System32\\etpkcs11.dll";
const PIN = "2945";
const fs = require("fs");
const crypto = require("crypto");
// const { plainAddPlaceholder, SignPdf } = require("node-signpdf");

// const pdfPath = "a.pdf";
// const pdfData = fs.readFileSync(pdfPath);
// console.log("Kütüphaneler ve dosyalar hazırlandı.");
// console.log("---------------------------");

// const pdfBuffer = fs.readFileSync(pdfPath);
// const pdfWithPlaceholder = plainAddPlaceholder({
//   pdfBuffer,
//   reason: "Test İmzalama",
//   signatureLength: 8192,
// });
// fs.writeFileSync("a-prepared.pdf", pdfWithPlaceholder);
// console.log("İmza alanı hazırlandı ve kaydedildi: a-prepared.pdf");
// console.log("---------------------------");

// const hash = crypto.createHash("sha256").update(pdfData).digest();
// console.log("PDF'nin SHA-256 hash'i hesaplandı.");
// console.log("---------------------------");

try {
  pkcs11.load(libraryPath);
  pkcs11.C_Initialize();
  console.log("PKCS#11 kütüphanesi yüklendi ve başlatıldı.");
  console.log("---------------------------");

  const slots = pkcs11.C_GetSlotList(true);
  if (slots.length === 0) {
    console.log("Cihaza bağlı slot bulunamadı.");
    process.exit(1);
  }
  console.log(`Bulunan slot sayısı: ${slots.length}`);
  console.log("---------------------------");

  const slot = slots[0];
  const session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
  pkcs11.C_Login(session, pkcs11js.CKU_USER, PIN);
  console.log("Oturum açıldı ve PIN ile giriş yapıldı.");
  console.log("---------------------------");

  pkcs11.C_FindObjectsInit(session, []);
  const objects = pkcs11.C_FindObjects(session, 100);
  pkcs11.C_FindObjectsFinal(session);
  console.log("Nesneler tarandı.");
  console.log("---------------------------");

  const CKO_CERTIFICATE = 1;
  const CKO_PRIVATE_KEY = 3;
  const filteredObjects = [];

  for (const obj of objects) {
    try {
      const attrs = pkcs11.C_GetAttributeValue(session, obj, [
        { type: pkcs11js.CKA_LABEL },
        { type: pkcs11js.CKA_CLASS },
      ]);
      const clazz = attrs[1]?.value ? attrs[1].value.readUInt32LE(0) : null;
      if (clazz === CKO_CERTIFICATE || clazz === CKO_PRIVATE_KEY) {
        filteredObjects.push({
          obj,
          clazz,
          label: attrs[0]?.value ? attrs[0].value.toString() : "<Etiket yok>",
        });
      }
    } catch (err) {
      console.log("Nesne okunamadı:", err.message);
    }
  }

  console.log(`Toplam Sertifika ve Anahtar sayısı: ${filteredObjects.length}`);
  for (const { obj, clazz, label } of filteredObjects) {
    const className = clazz === CKO_CERTIFICATE ? "Sertifika" : "Özel Anahtar";
    console.log(`Nesne: label="${label}", class=${clazz} (${className})`);
  }
  console.log("---------------------------");

  const privateKeyObj = filteredObjects.find((o) => o.clazz === CKO_PRIVATE_KEY)?.obj;
  if (!privateKeyObj) {
    throw new Error("Özel anahtar bulunamadı!");
  }
  console.log("Özel anahtar bulundu:", filteredObjects.find((o) => o.clazz === CKO_PRIVATE_KEY).label);
  console.log("---------------------------");

  const certObj = filteredObjects.find((o) => o.clazz === CKO_CERTIFICATE)?.obj;
  if (!certObj) {
    throw new Error("Sertifika bulunamadı!");
  }
  console.log("Sertifika bulundu:", filteredObjects.find((o) => o.clazz === CKO_CERTIFICATE).label);
  console.log("---------------------------");

//   const certAttrs = pkcs11.C_GetAttributeValue(session, certObj, [
//     { type: pkcs11js.CKA_VALUE },
//   ]);
//   const certificate = certAttrs[0].value;




//   fs.writeFileSync("C:\\proje\\pkcs11\\src\\certificate.der", certificate);
//   console.log("Sertifika DER formatında kaydedildi: certificate.der");
//   console.log("---------------------------");

  // Sertifikayı PEM formatına dönüştür
//   const certificatePem = `-----BEGIN CERTIFICATE-----\n${certificate.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;
//   fs.writeFileSync("C:\\proje\\pkcs11\\src\\certificate.pem", certificatePem);
//   console.log("Sertifika PEM formatında kaydedildi: certificate.pem");
//   console.log("---------------------------");

//   const mechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS };
//   pkcs11.C_SignInit(session, mechanism, privateKeyObj);
//   console.log("İmza işlemi başlatıldı.");
//   console.log("---------------------------");

//   const MAX_SIGNATURE_LENGTH = 256;
//   const signatureBuffer = Buffer.alloc(MAX_SIGNATURE_LENGTH);
//   const signature = pkcs11.C_Sign(session, hash, signatureBuffer);
//   console.log("İmza uzunluğu:", signature.length);
//   console.log("İmzalanan veri (Base64):", signature.toString("base64"));
//   console.log("---------------------------");

//   const signPdf = new SignPdf();
//   const signedPdf = signPdf.sign(pdfWithPlaceholder, signature, {
//   //   certificate: fs.readFileSync("C:\\proje\\pkcs11\\src\\certificate.pem"),
//   });
//   // fs.writeFileSync("C:\\proje\\pkcs11\\src\\a-signed.pdf", signedPdf);
//   // console.log("PDF başarıyla imzalandı ve kaydedildi: a-signed.pdf");
//   // console.log("---------------------------");

//   pkcs11.C_Logout(session);
//   pkcs11.C_CloseSession(session);
//   console.log("Oturum kapatıldı.");
//   console.log("---------------------------");
} catch (e) {
  console.error("Hata:", e);
  console.log("---------------------------");
} finally {
  try {
    pkcs11.C_Finalize();
    console.log("PKCS#11 kütüphanesi kapatıldı.");
    console.log("---------------------------");
  } catch {}
}