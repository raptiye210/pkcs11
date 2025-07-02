const fs = require('fs');
const { PDFDocument, PDFName, PDFDict, PDFHexString } = require('pdf-lib');

// Gerçek imza verin buraya (C_Sign ile PKCS#11'den alınmış)
const signatureFromToken = fs.readFileSync('signature-from-token.bin'); // Buffer olmalı

const pdfBytes = fs.readFileSync('src/pdf-to-sign.pdf');

(async () => {
  const pdfDoc = await PDFDocument.load(pdfBytes);

  // PDF'e boş bir imza alanı yerleştirmek için bir form alanı oluştur
  const form = pdfDoc.getForm();

  const signatureField = form.createSignature('MySignature');
  const pages = pdfDoc.getPages();
  const firstPage = pages[0];

  signatureField.addToPage(firstPage, {
    x: 50,
    y: 50,
    width: 200,
    height: 50,
  });

  // PDF'i serialize edip ByteRange ile imza boşluğu ayırmak için kaydet
  const pdfWithPlaceholder = await pdfDoc.save({ useObjectStreams: false });

  // ByteRange hesaplama (byte aralıklarını elle yerleştirmek gerekir)
  // PDF’in içinde `/ByteRange [a b c d]` olan yeri bulmamız gerekiyor
  let pdfText = Buffer.from(pdfWithPlaceholder).toString('binary');
  const byteRangePos = pdfText.indexOf('/ByteRange [');
  if (byteRangePos === -1) throw new Error('ByteRange not found.');

  // Tahmini imza alanı büyüklüğü
  const sigPlaceholderLen = 8192; // 8KB
  const byteRangePlaceholder = `[0 ********** ********** **********]`;

  // ByteRange alanını örnek değerlerle yerleştir
  const actualByteRange = `/ByteRange [0 100000 100000 10000]`; // Sadece test için
  pdfText = pdfText.replace(byteRangePlaceholder, actualByteRange);

  // Sahte imza alanı içeriği (C_Sign çıktı)
  const hexSignature = signatureFromToken.toString('hex').toUpperCase();
  const paddedHex = hexSignature.padEnd(sigPlaceholderLen * 2, '0');
  const finalPdf = pdfText.replace(/<<\/Type\/Sig(.|\n)+?\/Contents\s*<([0-9A-F]*)>/, (match) => {
    return match.replace(/<([0-9A-F]*)>/, `<${paddedHex}>`);
  });

  fs.writeFileSync('src/signed.pdf', Buffer.from(finalPdf, 'binary'));
  console.log('PDF imza ile birlikte kaydedildi: src/signed.pdf');
})();
