const pkcs11js = require('pkcs11js');
const forge = require('node-forge');
const fs = require('fs');

class SafeNetTokenManager {
    constructor() {
        this.pkcs11 = new pkcs11js.PKCS11();
        this.session = null;
    }

    async initialize() {
        // SafeNet PKCS#11 kütüphanesini yükle
        // Windows için genellikle: "C:\\Windows\\System32\\eTPKCS11.dll"
        // Linux için: "/usr/lib/libeTPkcs11.so"
        this.pkcs11.load("C:\\Windows\\System32\\eTPKCS11.dll");
        
        this.pkcs11.C_Initialize();
        
        const slots = this.pkcs11.C_GetSlotList(true);
        if (slots.length === 0) {
            throw new Error('Token bulunamadı');
        }

        // İlk slotu kullan
        const slot = slots[0];
        this.session = this.pkcs11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
        
        return this.session;
    }

    async login(pin) {
        this.pkcs11.C_Login(this.session, pkcs11js.CKU_USER, pin);
    }

    async getCertificates() {
        const template = [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_CERTIFICATE },
            { type: pkcs11js.CKA_CERTIFICATE_TYPE, value: pkcs11js.CKC_X_509 }
        ];

        this.pkcs11.C_FindObjectsInit(this.session, template);
        const objects = this.pkcs11.C_FindObjects(this.session, 10);
        this.pkcs11.C_FindObjectsFinal(this.session);

        const certificates = [];
        for (const obj of objects) {
            const certData = this.pkcs11.C_GetAttributeValue(this.session, obj, [
                { type: pkcs11js.CKA_VALUE }
            ])[0].value;
            
            certificates.push(forge.pki.certificateFromAsn1(forge.asn1.fromDer(certData.toString('binary'))));
        }

        return certificates;
    }

    async getPrivateKey() {
        const template = [
            { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
            { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_RSA }
        ];

        this.pkcs11.C_FindObjectsInit(this.session, template);
        const objects = this.pkcs11.C_FindObjects(this.session, 1);
        this.pkcs11.C_FindObjectsFinal(this.session);

        return objects[0];
    }

    async signData(data, privateKeyHandle) {
        const mechanism = { mechanism: pkcs11js.CKM_SHA1_RSA_PKCS };
        this.pkcs11.C_SignInit(this.session, mechanism, privateKeyHandle);
        return this.pkcs11.C_Sign(this.session, data);
    }

    cleanup() {
        if (this.session) {
            this.pkcs11.C_Logout(this.session);
            this.pkcs11.C_CloseSession(this.session);
        }
        this.pkcs11.C_Finalize();
    }
}















const PDFLib = require('pdf-lib');
const crypto = require('crypto');

class PDFSigner {
    async signPDF(pdfPath, certificate, privateKeyHandle, tokenManager) {
        // PDF dosyasını oku
        const pdfBytes = fs.readFileSync(pdfPath);
        const pdfDoc = await PDFLib.PDFDocument.load(pdfBytes);

        // İmza alanı oluştur
        const form = pdfDoc.getForm();
        const pages = pdfDoc.getPages();
        const firstPage = pages[0];
        
        const signatureField = form.createSignature('signature');
        signatureField.addToPage(firstPage, {
            x: 50,
            y: 100,
            width: 200,
            height: 50
        });

        // PDF hash'ini hesapla
        const pdfHash = crypto.createHash('sha1').update(pdfBytes).digest();
        
        // Token ile imzala
        const signature = await tokenManager.signData(pdfHash, privateKeyHandle);

        // İmza bilgilerini ekle
        const signatureDict = {
            Type: 'Sig',
            Filter: 'Adobe.PPKLite',
            SubFilter: 'adbe.pkcs7.detached',
            Name: certificate.subject.getField('CN').value,
            Reason: 'Elektronik İmza',
            Location: 'Türkiye',
            M: new Date().toISOString(),
            Contents: signature
        };

        // İmzalanmış PDF'i kaydet
        const signedPdfBytes = await pdfDoc.save();
        return signedPdfBytes;
    }
}




















async function main() {
    const tokenManager = new SafeNetTokenManager();
    const pdfSigner = new PDFSigner();

    try {
        // Token'ı başlat
        await tokenManager.initialize();
        
        // PIN ile giriş yap
        const pin = '2945'; // PIN'i güvenli şekilde al
        await tokenManager.login(pin);

        // Sertifikaları listele
        const certificates = await tokenManager.getCertificates();
        console.log(`${certificates.length} sertifika bulundu`);

        if (certificates.length > 0) {
            const certificate = certificates[0]; // İlk sertifikayı kullan
            console.log('Sertifika sahibi:', certificate.subject.getField('CN').value);

            // Private key'i al
            const privateKey = await tokenManager.getPrivateKey();

            // PDF'i imzala
            const signedPdfBytes = await pdfSigner.signPDF(
                './a.pdf',
                certificate,
                privateKey,
                tokenManager
            );

            // İmzalanmış PDF'i kaydet
            fs.writeFileSync('./a_signed.pdf', signedPdfBytes);
            console.log('PDF başarıyla imzalandı: a_signed.pdf');
        }

    } catch (error) {
        console.error('Hata:', error.message);
    } finally {
        tokenManager.cleanup();
    }
}

main();