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














const { PDFDocument, PDFName, PDFNumber, PDFHexString } = require('pdf-lib');

class PDFSigner {
    async signPDF(pdfPath, certificate, privateKeyHandle, tokenManager) {
        try {
            // PDF dosyasını oku
            const pdfBytes = fs.readFileSync(pdfPath);
            const pdfDoc = await PDFDocument.load(pdfBytes);

            // PKCS#7 imza oluştur
            const p7 = forge.pkcs7.createSignedData();
            
            // PDF içeriğini hazırla
            const contentToSign = pdfBytes;
            const hash = forge.md.sha1.create();
            hash.update(contentToSign.toString('binary'));
            
            // Token ile imzala
            const signature = await tokenManager.signData(Buffer.from(hash.digest().getBytes(), 'binary'), privateKeyHandle);
            
            // PKCS#7 yapısını oluştur
            p7.content = forge.util.createBuffer(contentToSign.toString('binary'));
            p7.addCertificate(certificate);
            p7.addSigner({
                key: null, // Token'dan gelecek
                certificate: certificate,
                digestAlgorithm: forge.pki.oids.sha1,
                authenticatedAttributes: [{
                    type: forge.pki.oids.contentTypes,
                    value: forge.pki.oids.data
                }, {
                    type: forge.pki.oids.messageDigest,
                    value: hash.digest()
                }]
            });

            // İmzalanmış PDF olarak kaydet (basit yaklaşım)
            const signedPdfPath = pdfPath.replace('.pdf', '_signed.pdf');
            fs.writeFileSync(signedPdfPath, pdfBytes);
            
            // İmza bilgilerini ayrı dosyaya kaydet
            const signatureInfo = {
                signer: certificate.subject.getField('CN').value,
                signDate: new Date().toISOString(),
                signature: signature.toString('base64')
            };
            
            fs.writeFileSync(signedPdfPath.replace('.pdf', '_signature.json'), JSON.stringify(signatureInfo, null, 2));
            
            console.log(`İmzalanmış PDF: ${signedPdfPath}`);
            console.log(`İmza bilgileri: ${signedPdfPath.replace('.pdf', '_signature.json')}`);
            
            return signedPdfPath;

        } catch (error) {
            console.error('PDF imzalama hatası:', error);
            throw error;
        }
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