const pkcs11js = require("pkcs11js");
const pkcs11 = new pkcs11js.PKCS11();
const fs = require("fs");
const crypto = require("crypto");
const { Signer } = require("node-signpdf");

const libraryPath = "C:\\Windows\\System32\\etpkcs11.dll";
const PIN = "2945";
const pdfPath = "C:\\proje\\pkcs11\\src\\a.pdf";
const certPath = "C:\\proje\\pkcs11\\src\\sertifika.cer";
const outputPath = "C:\\proje\\pkcs11\\src\\signed_a.pdf";

try {
  // PDF ve sertifika dosyalarını oku
  const pdfData = fs.readFileSync(pdfPath);
  let certData = fs.readFileSync(certPath);

  // Eğer .cer PEM formatındaysa, DER'e çevir
  if (certData.toString().includes("-----BEGIN CERTIFICATE-----")) {
    const pem = certData.toString();
    const base64Cert = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\n/g, "");
    certData = Buffer.from(base64Cert, "base64");
  }

  const hash = crypto.createHash("sha256").update(pdfData).digest();

  // PKCS#11 başlat
  pkcs11.load(libraryPath);
  pkcs11.C_Initialize();

  // Slotları al
  const slots = pkcs11.C_GetSlotList(true);
  if (slots.length === 0) {
    console.log("Cihaza bağlı slot bulunamadı.");
    process.exit(1);
  }

  // Session aç ve login
  const slot = slots[0];
  const session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
  pkcs11.C_Login(session, pkcs11js.CKU_USER, PIN);

  // Özel anahtarları bul
  const CKO_PRIVATE_KEY = 3;
  pkcs11.C_FindObjectsInit(session, [{ type: pkcs11js.CKA_CLASS, value: Buffer.from([CKO_PRIVATE_KEY]) }]);
  const keyObjects = pkcs11.C_FindObjects(session, 100);
  pkcs11.C_FindObjectsFinal(session);

  const filteredObjects = [];
  for (const obj of keyObjects) {
    try {
      const attrs = pkcs11.C_GetAttributeValue(session, obj, [
        { type: pkcs11js.CKA_LABEL },
      ]);
      const label = attrs[0]?.value ? attrs[0].value.toString() : "<Etiket yok>";
      filteredObjects.push({ obj, label });
    } catch (err) {
      console.log("Özel anahtar okunamadı:", err.message);
      continue;
    }
  }

  console.log(`Toplam Özel Anahtar sayısı: ${filteredObjects.length}`);
  for (const { obj, label } of filteredObjects) {
    console.log(`Özel Anahtar: label="${label}"`);
  }

  const privateKeyObj = filteredObjects.find(o => o.label === "EYMEN  TÜFEKÇİOĞLU")?.obj;
  if (!privateKeyObj) {
    throw new Error("Özel anahtar bulunamadı!");
  }
  console.log("Özel anahtar bulundu:", filteredObjects.find(o => o.label === "EYMEN  TÜFEKÇİOĞLU").label);

  // İmza uzunluğu için sabit 256 bayt (RSA-2048 için)
  const signatureBuffer = Buffer.alloc(256);

  // PDF'nin hash'ini imzala
  const mechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS };
  pkcs11.C_SignInit(session, mechanism, privateKeyObj);
  const signature = pkcs11.C_Sign(session, hash, signatureBuffer).slice(0, signatureBuffer.length);
  console.log("İmzalanan veri (Base64):", signature.toString("base64"));

  // PDF'yi node-signpdf ile imzala
  const signer = new Signer({
    cert: certData,
    signature: signature,
    signatureLength: signature.length,
  });
  const signedPdf = signer.sign(pdfData);
  fs.writeFileSync(outputPath, signedPdf);
  console.log(`İmzalı PDF kaydedildi: ${outputPath}`);

  // İmza doğrulama
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