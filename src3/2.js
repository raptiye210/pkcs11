const fs = require('fs');
const { PDFDocument } = require('pdf-lib');

async function addFakeSignature() {
  const pdfPath = 'C:\\proje\\pkcs11\\src\\a.pdf';
  const pdfBytes = fs.readFileSync(pdfPath);

  const pdfDoc = await PDFDocument.load(pdfBytes);

  const pages = pdfDoc.getPages();
  const firstPage = pages[0];

  // İmza görünümü olarak bir metin kutusu ekle
  firstPage.drawText('imza: Basar Sonmez', {
    x: 50,
    y: 50,
    size: 12,
    // color: rgb(0, 0, 0),
  });

  // Gerçek imza için PDF'in byte'larını kaydet (imzalanacak içerik)
  const modifiedPdfBytes = await pdfDoc.save();

  fs.writeFileSync('C:\\proje\\pkcs11\\src\\a-signed-visible.pdf', modifiedPdfBytes);
  console.log('PDF sahte imza görünümüyle kaydedildi.');
}

addFakeSignature();
