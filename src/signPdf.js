const fs = require("fs");
const crypto = require("crypto");
const { PDFDocument } = require("pdf-lib");
const SignPdf = require("node-signpdf").default;
const { plainAddPlaceholder } = require("node-signpdf/dist/helpers/plainAddPlaceholder");
const { createSignature, getCertificate } = require("./createSignature");
const forge = require("node-forge");

const inputPdfPath = "a.pdf";
const preparedPdfPath = "a-prepared.pdf";
const signedPdfPath = "a-signed.pdf";

async function sign() {
  try {
    // Sertifikayı token'dan al
    console.log("Sertifika alınıyor...");
    const certPem = getCertificate();
    console.log("Sertifika alındı:", certPem.slice(0, 50) + "...");

    // PDF'e imza alanı ekle
    const existingPdfBytes = fs.readFileSync(inputPdfPath);
    const pdfWithPlaceholder = plainAddPlaceholder({
      pdfBuffer: existingPdfBytes,
      reason: "PKCS#11 donanım imzası",
      contactInfo: "basar@example.com",
      name: "Başar Sönmez",
      location: "İzmir",
      signatureLength: 2048,
    });

    fs.writeFileSync(preparedPdfPath, pdfWithPlaceholder);
    console.log(`İmza alanı eklendi: ${preparedPdfPath}`);

    // PDF'nin hash'ini hesapla
    const pdfBuffer = fs.readFileSync(preparedPdfPath);
    const pdfHash = crypto.createHash("sha256").update(pdfBuffer).digest();

    // Hash'i token ile imzala
    console.log("PDF hash'i imzalanıyor...");
    const rawSignature = createSignature(pdfHash);

    // PKCS#7/CMS imzasını oluştur
    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(pdfHash);
    const cert = forge.pki.certificateFromPem(certPem);
    p7.addCertificate(cert);
    p7.addSigner({
      key: rawSignature, // Token'dan gelen ham imza
      certificate: cert,
      digestAlgorithm: forge.pki.oids.sha256,
      authenticatedAttributes: [
        { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
        { type: forge.pki.oids.messageDigest },
        { type: forge.pki.oids.signingTime, value: new Date() },
      ],
    });

    const p7Der = forge.asn1.toDer(p7.toAsn1()).getBytes();
    const p7Buffer = Buffer.from(p7Der, "binary");

    // PDF'i imzala
    const signer = new SignPdf();
    const signedPdf = signer.sign(pdfBuffer, p7Buffer);

    fs.writeFileSync(signedPdfPath, signedPdf);
    console.log(`PDF imzalandı: ${signedPdfPath}`);
  } catch (err) {
    console.error("İmzalama sırasında hata:", err.message);
    throw err; // Hata detaylarını görmek için
  }
}

sign();