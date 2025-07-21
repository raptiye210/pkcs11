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









































const hummus = require('muhammara');
//const forge = require('node-forge');

class PDFSigner {
    async signPDF(pdfPath, certificate, privateKeyHandle, tokenManager) {
        try {
            const outputPath = pdfPath.replace('.pdf', '_signed.pdf');
            
            // Önce orijinal dosyayı kopyala
            fs.copyFileSync(pdfPath, outputPath);
            
            // PDF'i modify modunda aç
            const pdfWriter = hummus.createWriterToModify(outputPath);
            
            // PDF bilgilerini al
            const pdfReader = hummus.createReader(pdfPath);
            const pageCount = pdfReader.getPagesCount();
            
            if (pageCount === 0) {
                throw new Error('PDF dosyasında sayfa bulunamadı');
            }

            // İlk sayfayı modify et
            const pageModifier = new hummus.PDFPageModifier(pdfWriter, 0);
            
            // İmza verilerini hazırla
            const pdfBuffer = fs.readFileSync(pdfPath);
            const hash = forge.md.sha1.create();
            hash.update(pdfBuffer.toString('binary'));
            const signature = await tokenManager.signData(Buffer.from(hash.digest().getBytes(), 'binary'), privateKeyHandle);
            
            // İmza annotation'ı ekle
            const objectsContext = pdfWriter.getObjectsContext();
            
            // Annotation dictionary
            const annotationId = objectsContext.getInDirectObjectsRegistry().allocateNewObjectID();
            objectsContext.startNewIndirectObject(annotationId);
            
            const annotationDict = objectsContext.startDictionary();
            annotationDict.writeKey('Type').writeNameValue('Annot');
            annotationDict.writeKey('Subtype').writeNameValue('Widget');
            annotationDict.writeKey('FT').writeNameValue('Sig');
            annotationDict.writeKey('Rect').writeRectangleValue([100, 100, 300, 150]);
            annotationDict.writeKey('F').writeNumberValue(4);
            
            // Signature dictionary
            const sigDictId = objectsContext.getInDirectObjectsRegistry().allocateNewObjectID();
            annotationDict.writeKey('V').writeObjectReferenceValue(sigDictId);
            
            objectsContext.endDictionary(annotationDict);
            objectsContext.endIndirectObject();
            
            // Signature dictionary oluştur
            objectsContext.startNewIndirectObject(sigDictId);
            const signatureDict = objectsContext.startDictionary();
            signatureDict.writeKey('Type').writeNameValue('Sig');
            signatureDict.writeKey('Filter').writeNameValue('Adobe.PPKLite');
            signatureDict.writeKey('SubFilter').writeNameValue('adbe.pkcs7.detached');
            signatureDict.writeKey('Name').writeLiteralStringValue(this.cleanTurkishChars(certificate.subject.getField('CN').value));
            signatureDict.writeKey('Reason').writeLiteralStringValue('Elektronik Imza');
            signatureDict.writeKey('M').writeLiteralStringValue(`D:${new Date().toISOString().replace(/[-:]/g, '').slice(0, -5)}Z`);
            signatureDict.writeKey('Contents').writeHexStringValue(signature.toString('hex').padEnd(2048, '0'));
            
            objectsContext.endDictionary(signatureDict);
            objectsContext.endIndirectObject();
            
            // Sayfaya annotation'ı ekle
            pageModifier.attachURLLinktoCurrentPage(`javascript:void(0)`, [100, 100, 300, 150]);
            pageModifier.endContext().writePage();
            
            // Writer'ı kapat
            pdfWriter.end();
            
            console.log(`PDF başarıyla imzalandı: ${outputPath}`);
            console.log(`Dosya boyutu: ${fs.statSync(outputPath).size} bytes`);
            
            return outputPath;
            
        } catch (error) {
            console.error('PDF imzalama hatası:', error);
            throw error;
        }
    }
    
    cleanTurkishChars(text) {
        if (!text) return 'Bilinmeyen';
        return text
            .replace(/Ã/g, 'İ')
            .replace(/Ä°/g, 'İ')
            .replace(/Ã/g, 'Ç')
            .replace(/Ä/g, 'Ğ')
            .replace(/Å/g, 'Ş')
            .replace(/Ü/g, 'Ü')
            .replace(/Ö/g, 'Ö');
    }
}



















































// test.js - Ana kod dosyanızı güncelleyin
async function main() {
    const tokenManager = new SafeNetTokenManager();
    const pdfSigner = new PDFSigner();

    try {
        await tokenManager.initialize();
        
        const pin = process.env.TOKEN_PIN || '2945'; // Güvenlik için env değişkeni kullanın
        await tokenManager.login(pin);

        const certificates = await tokenManager.getCertificates();
        console.log(`${certificates.length} sertifika bulundu`);

        if (certificates.length > 0) {
            const certificate = certificates[0];
            
            // Türkçe karakter sorunu için
            let commonName = 'Bilinmeyen';
            try {
                const cnField = certificate.subject.getField('CN');
                if (cnField) {
                    commonName = cnField.value;
                }
            } catch (e) {
                console.log('CN alanı okunamadı, varsayılan değer kullanılıyor');
            }
            
            console.log('Sertifika sahibi:', commonName);

            const privateKey = await tokenManager.getPrivateKey();

            // PDF dosyası var mı kontrol et
            const pdfPath = './a.pdf';
            if (!fs.existsSync(pdfPath)) {
                console.error(`PDF dosyası bulunamadı: ${pdfPath}`);
                return;
            }

            const signedPath = await pdfSigner.signPDF(pdfPath, certificate, privateKey, tokenManager);
            console.log('İmzalama işlemi tamamlandı!');
        }

    } catch (error) {
        console.error('Hata:', error.message);
        console.error('Stack:', error.stack);
    } finally {
        tokenManager.cleanup();
    }
}

main();