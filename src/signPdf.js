const fs = require("fs");
const signer = require("node-signpdf").default;
const { createCmsSignature } = require("./createCmsSignature");
const crypto = require("crypto");

function getByteRangePositions(pdfBuffer) {
  const byteRangePos = pdfBuffer.indexOf(Buffer.from("/ByteRange ["));
  if (byteRangePos === -1) throw new Error("ByteRange bulunamadı");

  const start = byteRangePos + 11;
  const end = pdfBuffer.indexOf("]", start);
  if (end === -1) throw new Error("ByteRange bitişi bulunamadı");

  const byteRangeStr = pdfBuffer.slice(start, end).toString();
  const parts = byteRangeStr.trim().split(" ").map(Number);
  if (parts.length !== 4) throw new Error("ByteRange formatı yanlış");

  return parts; // [start1, length1, start2, length2]
}

async function sign() {
  const pdfBuffer = fs.readFileSync("C:\\proje\\pkcs11\\src\\a-prepared.pdf");

  const byteRange = getByteRangePositions(pdfBuffer);

  const buffers = [];
  buffers.push(pdfBuffer.slice(byteRange[0], byteRange[0] + byteRange[1]));
  buffers.push(pdfBuffer.slice(byteRange[2], byteRange[2] + byteRange[3]));

  const hash = crypto.createHash("sha256");
  buffers.forEach(buf => hash.update(buf));
  const digest = hash.digest();

  const cmsSignature = await createCmsSignature(digest);

  const signedPdf = signer.sign(pdfBuffer, cmsSignature);

  fs.writeFileSync("C:\\proje\\pkcs11\\src\\a-signed.pdf", signedPdf);

  console.log("PDF başarıyla imzalandı ve kaydedildi: a-signed.pdf");
}

sign().catch(console.error);
