const fs = require("fs");
const signer = require("node-signpdf").default;

const pdfBuffer = fs.readFileSync("C:\\proje\\pkcs11\\src\\a-prepared.pdf");

// PKCS#11 ile ürettiğin imza (base64 değil, Buffer olmalı)
// Burada sadece örnek için boş Buffer kullanıyoruz, sen PKCS#11’den aldığın imzayı koyacaksın
const fakeSignature = Buffer.alloc(256, 0); 

try {
  const signedPdf = signer.sign(pdfBuffer, fakeSignature);
  fs.writeFileSync("C:\\proje\\pkcs11\\src\\a-signed.pdf", signedPdf);
  console.log("PDF imzalandı ve kaydedildi.");
} catch (error) {
  console.error("İmzalama sırasında hata:", error);
}
