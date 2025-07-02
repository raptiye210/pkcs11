const fs = require("fs");
const crypto = require("crypto");
const { PDFDocument } = require("pdf-lib");
const SignPdf = require("node-signpdf").default;
const { plainAddPlaceholder } = require("node-signpdf/dist/helpers/plainAddPlaceholder");
const { createSignature } = require("./createSignature");

// Girdi PDF dosyası
const inputPdfPath = "a.pdf"; // orijinal PDF
const preparedPdfPath = "a-prepared.pdf";
const signedPdfPath = "a-signed.pdf";

async function sign() {
  // PDF'e imza alanı ekle
  const existingPdfBytes = fs.readFileSync(inputPdfPath);
  const pdfDoc = await PDFDocument.load(existingPdfBytes);
  const pdfWithPlaceholder = plainAddPlaceholder({
    pdfBuffer: existingPdfBytes,
    reason: "PKCS#11 donanım imzası",
    contactInfo: "basar@example.com",
    name: "Başar Sönmez",
    location: "İzmir",
    signatureLength: 8192, // CMS formatı kullanılmıyor, ama güvenli olsun
  });

  fs.writeFileSync(preparedPdfPath, pdfWithPlaceholder);
  console.log(`İmza alanı eklendi: ${preparedPdfPath}`);

  // Hash hesapla
  const pdfBuffer = fs.readFileSync(preparedPdfPath);
  const pdfHash = crypto.createHash("sha256").update(pdfBuffer).digest();

  // İmza al
  const signature = createSignature(pdfHash);

  // PDF'i imzala
  const signer = new SignPdf();
  const signedPdf = signer.sign(pdfBuffer, signature);

  fs.writeFileSync(signedPdfPath, signedPdf);
  console.log(`PDF imzalandı: ${signedPdfPath}`);
}

sign().catch((err) => {
  console.error("İmzalama sırasında hata:", err);
});
