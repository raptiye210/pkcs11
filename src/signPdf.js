const fs = require("fs");
const crypto = require("crypto");
const { PDFDocument } = require("pdf-lib");
const SignPdf = require("node-signpdf").default;
const { plainAddPlaceholder } = require("node-signpdf/dist/helpers/plainAddPlaceholder");
// const { createSignature } = require("./createSignature");
const forge = require("node-forge"); // PKCS#7 için

// Girdi PDF dosyası
const inputPdfPath = "a.pdf";
const preparedPdfPath = "a-prepared.pdf";
const signedPdfPath = "a-signed.pdf";

// Sertifika dosyasını oku (token'dan veya dosya sisteminden alınmalı)
// const certPath = "certificate.pem"; // Sertifika dosyanızı belirtin
// const certPem = fs.readFileSync(certPath, "utf8");


const { createSignature, getCertificate } = require("./createSignature");
const certPem = getCertificate(); // Sertifikayı token'dan al

async function sign() {
  try {
    // PDF'e imza alanı ekle
    const existingPdfBytes = fs.readFileSync(inputPdfPath);
    const pdfDoc = await PDFDocument.load(existingPdfBytes);
    const pdfWithPlaceholder = plainAddPlaceholder({
      pdfBuffer: existingPdfBytes,
      reason: "PKCS#11 donanım imzası",
      contactInfo: "basar@example.com",
      name: "Başar Sönmez",
      location: "İzmir",
      signatureLength: 2048, // Daha gerçekçi bir boyut
    });

    fs.writeFileSync(preparedPdfPath, pdfWithPlaceholder);
    console.log(`İmza alanı eklendi: ${preparedPdfPath}`);

    // PDF'nin hash'ini hesapla (node-signpdf bunu kendi içinde yapar)
    const pdfBuffer = fs.readFileSync(preparedPdfPath);

    // Hash'i token ile imzala
    const pdfHash = crypto.createHash("sha256").update(pdfBuffer).digest();
    const rawSignature = createSignature(pdfHash);

    // PKCS#7/CMS imzasını oluştur
    const p7 = forge.pkcs7.createSignedData();
    p7.content = forge.util.createBuffer(pdfHash);
    const cert = forge.pki.certificateFromPem(certPem);
    p7.addCertificate(cert);
    p7.addSigner({
      key: rawSignature, // Bu kısmı token'dan gelen ham imza ile değiştirin
      certificate: cert,
      digestAlgorithm: forge.pki.oids.sha256,
      authenticatedAttributes: [
        {
          type: forge.pki.oids.contentType,
          value: forge.pki.oids.data,
        },
        {
          type: forge.pki.oids.messageDigest,
        },
        {
          type: forge.pki.oids.signingTime,
          value: new Date(),
        },
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
  }
}

sign();