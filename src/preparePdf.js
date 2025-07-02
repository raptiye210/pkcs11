const fs = require("fs");
const { plainAddPlaceholder } = require("node-signpdf/dist/helpers");

const pdfBuffer = fs.readFileSync("C:\\proje\\pkcs11\\src\\a.pdf");

const pdfWithPlaceholder = plainAddPlaceholder({
  pdfBuffer,
  reason: "Test İmzalama",
  signatureLength: 8192,
});

fs.writeFileSync("C:\\proje\\pkcs11\\src\\a-prepared.pdf", pdfWithPlaceholder);

console.log("İmza alanı hazırlandı ve kaydedildi: a-prepared.pdf");
