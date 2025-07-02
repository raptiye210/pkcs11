const pkcs11 = require('pkcs11js');
const fs = require('fs');
const PDFSign = require('pdf-sign');

// PKCS#11 modülünü başlat
const pkcs11Module = new pkcs11.PKCS11();
pkcs11Module.load('C:/proje/pkcs11/src/pkcs11.dll'); // PKCS#11 DLL/SO dosya yolunu belirtin
pkcs11Module.C_Initialize();

async function signPDF() {
  try {
    // PKCS#11 oturumunu aç
    const slot = pkcs11Module.C_GetSlotList()[0];
    const session = pkcs11Module.C_OpenSession(slot, pkcs11.CKF_SERIAL_SESSION);

    // Kullanıcı PIN ile giriş yap
    pkcs11Module.C_Login(session, pkcs11.CKU_USER, '2945'); // PIN'inizi buraya girin

    // Sertifikayı ve özel anahtarı bul
    pkcs11Module.C_FindObjectsInit(session, [{ type: pkcs11.CKA_CLASS, value: pkcs11.CKO_CERTIFICATE }]);
    const certObj = pkcs11Module.C_FindObjects(session)[0];
    const cert = pkcs11Module.C_GetAttributeValue(session, certObj, [{ type: pkcs11.CKA_VALUE }])[0].value;

    pkcs11Module.C_FindObjectsInit(session, [{ type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PRIVATE_KEY }]);
    const privateKey = pkcs11Module.C_FindObjects(session)[0];

    // PDF dosyasını oku
    const pdfBuffer = fs.readFileSync('C:/proje/pkcs11/src/a.pdf');

    // PDF imzalama işlemi
    const signer = new PDFSign({
      cert: cert,
      privateKey: privateKey,
      pkcs11: pkcs11Module,
      session: session
    });

    const signedPdf = await signer.sign(pdfBuffer);

    // İmzalı PDF'yi kaydet
    fs.writeFileSync('C:/proje/pkcs11/src/a_signed.pdf', signedPdf);

    console.log('PDF başarıyla imzalandı ve kaydedildi: a_signed.pdf');

    // Oturumu kapat
    pkcs11Module.C_Logout(session);
    pkcs11Module.C_CloseSession(session);
  } catch (err) {
    console.error('Hata:', err);
  } finally {
    pkcs11Module.C_Finalize();
  }
}

signPDF();