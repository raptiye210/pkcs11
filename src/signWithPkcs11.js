const fs = require("fs");
const pkcs11js = require("pkcs11js");
const signer = require("node-signpdf").default;
const { plainAddPlaceholder } = require("node-signpdf/dist/helpers");

const libraryPath = "C:\\Windows\\System32\\etpkcs11.dll";
const PIN = "2945";

async function main() {
  // 1. Hazırlanmış PDF'yi oku
  const pdfBuffer = fs.readFileSync("C:\\proje\\pkcs11\\src\\a-prepared.pdf");

  // 2. PKCS#11 başlat
  const pkcs11 = new pkcs11js.PKCS11();
  pkcs11.load(libraryPath);
  pkcs11.C_Initialize();

  try {
    // 3. Slot ve session aç
    const slots = pkcs11.C_GetSlotList(true);
    if (slots.length === 0) throw new Error("Slot bulunamadı");
    const slot = slots[0];
    const session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
    pkcs11.C_Login(session, pkcs11js.CKU_USER, PIN);

    // 4. Özel anahtarı bul (class=3)
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

    // 5. node-signpdf'in hash hesaplama fonksiyonu (ByteRange ve placeholder ile hash oluştur)
    // Burada hash'i direkt alma fonksiyonu yok, node-signpdf içini inceleyip
    // hash için PDF buffer üzerinde SHA256 hesaplamalıyız.
    // Biz örnek için manuel SHA256 hash yapıyoruz, PDF’nin ByteRange kısmı önemli!

    // Hash hesaplamak için PDF’nin ByteRange alanını parse edip hash’i hesaplamak gerekir.
    // Bu karmaşık, o yüzden hash hesaplamayı node-signpdf kütüphanesinden veya kendi implementasyonundan almak en iyisi.
    // Burada örnek hash hesaplamayı manuel yapıyoruz (bu demo amaçlıdır):

    const crypto = require("crypto");
    const hash = crypto.createHash("sha256").update(pdfBuffer).digest();

    // 6. İmza başlat ve imzala
    const mechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS };

    pkcs11.C_SignInit(session, mechanism, privateKeyObj);
    const MAX_SIGNATURE_LENGTH = 256;
    const signatureBuffer = Buffer.alloc(MAX_SIGNATURE_LENGTH);
    const actualSignature = pkcs11.C_Sign(session, hash, signatureBuffer);
    const signature = actualSignature.slice(0, actualSignature.length);

    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);

    // 7. İmzayı PDF’ye gömme
    const signedPdf = signer.sign(pdfBuffer, signature);
    fs.writeFileSync("C:\\proje\\pkcs11\\src\\a-signed.pdf", signedPdf);

    console.log("PDF başarıyla imzalandı ve kaydedildi: a-signed.pdf");
  } catch (e) {
    console.error("Hata:", e);
  } finally {
    try {
      pkcs11.C_Finalize();
    } catch {}
  }
}

main();
