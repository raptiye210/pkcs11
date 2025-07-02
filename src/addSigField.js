const fs = require("fs");
const { PDFDocument, PDFName, PDFNumber, PDFHexString } = require("pdf-lib");

async function addSignatureField(inputPath, outputPath) {
  const existingPdfBytes = fs.readFileSync(inputPath);
  const pdfDoc = await PDFDocument.load(existingPdfBytes);

  const pages = pdfDoc.getPages();
  const firstPage = pages[0];

  const signatureDict = pdfDoc.context.obj({
    Type: PDFName.of('Annot'),
    Subtype: PDFName.of('Widget'),
    FT: PDFName.of('Sig'),
    Rect: [50, 50, 250, 100],
    V: null,
    T: PDFHexString.fromText('Signature1'),
    F: PDFNumber.of(4),
    P: firstPage.ref,
  });

  const signatureRef = pdfDoc.context.register(signatureDict);

  const annots = firstPage.node.Annots() || pdfDoc.context.obj([]);
  annots.push(signatureRef);
  firstPage.node.set(PDFName.of('Annots'), annots);

  const pdfBytes = await pdfDoc.save();
  fs.writeFileSync(outputPath, pdfBytes);

  console.log("İmza alanı eklendi ve dosya kaydedildi:", outputPath);
}

addSignatureField("C:\\proje\\pkcs11\\src\\a.pdf", "C:\\proje\\pkcs11\\src\\a-prepared.pdf");
