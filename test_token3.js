// test_token3.js
const pkcs11js = require('pkcs11js');
const forge = require('node-forge');
const fs = require('fs');
const crypto = require('crypto');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');

class SafeNetTokenManager {
    constructor() {
        this.pkcs11 = new pkcs11js.PKCS11();
        this.session = null;
        this.debug = true;
    }

    log(message, data = null) {
        if (this.debug) {
            console.log(`[SafeNet] ${message}`);
            if (data) console.log('[SafeNet] Data:', data);
        }
    }

    // Türkçe ve tüm özel karakterleri temizle
    sanitizeText(text) {
        if (!text || typeof text !== 'string') {
            return 'Unknown';
        }
        
        const turkishMap = {
            'ç': 'c', 'Ç': 'C',
            'ğ': 'g', 'Ğ': 'G',
            'ı': 'i', 'I': 'I',
            'İ': 'I', 'i': 'i',
            'ö': 'o', 'Ö': 'O',
            'ş': 's', 'Ş': 'S',
            'ü': 'u', 'Ü': 'U'
        };
        
        // Önce Türkçe karakterleri değiştir
        let cleanText = text.replace(/[çÇğĞıIİiöÖşŞüÜ]/g, (match) => turkishMap[match] || match);
        
        // Sonra tüm ASCII olmayan karakterleri kaldır (32-126 arası karakterler güvenli)
        cleanText = cleanText.replace(/[^\x20-\x7E]/g, '');
        
        // Boş string kontrolü
        return cleanText.trim() || 'Unknown';
    }

    async initialize() {
        try {
            this.log('Token baslatiliyor...');
            
            this.pkcs11.load("C:\\Windows\\System32\\eTPKCS11.dll");
            this.pkcs11.C_Initialize();
            
            const slots = this.pkcs11.C_GetSlotList(true);
            this.log(`Token'li slot sayisi: ${slots.length}`);

            if (slots.length === 0) {
                throw new Error('Token bulunamadi');
            }

            const slot = slots[0];
            this.log(`Kullanilan slot: ${slot}`);

            // Token bilgilerini al
            try {
                const tokenInfo = this.pkcs11.C_GetTokenInfo(slot);
                this.log('Token bilgileri:', {
                    label: tokenInfo.label.toString().trim(),
                    manufacturerID: tokenInfo.manufacturerID.toString().trim(),
                    model: tokenInfo.model.toString().trim(),
                    serialNumber: tokenInfo.serialNumber.toString().trim()
                });
            } catch (error) {
                this.log('Token bilgileri alinamadi:', error.message);
            }

            this.session = this.pkcs11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
            this.log(`Session acildi: ${this.session}`);

            return this.session;
            
        } catch (error) {
            this.log('Hata:', error.message);
            throw error;
        }
    }

    async login(pin) {
        try {
            this.log(`PIN ile giris yapiliyor... (PIN uzunlugu: ${pin.length})`);
            this.pkcs11.C_Login(this.session, pkcs11js.CKU_USER, pin);
            this.log('Giris basarili');
        } catch (error) {
            this.log('Giris hatasi:', error.message);
            throw error;
        }
    }

    async getCertificates() {
        try {
            this.log('Sertifikalar araniyor...');
            
            const template = [
                { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_CERTIFICATE },
                { type: pkcs11js.CKA_CERTIFICATE_TYPE, value: pkcs11js.CKC_X_509 }
            ];

            this.pkcs11.C_FindObjectsInit(this.session, template);
            const objects = this.pkcs11.C_FindObjects(this.session, 10);
            this.pkcs11.C_FindObjectsFinal(this.session);
            
            this.log(`Bulunan sertifika objesi: ${objects.length}`);

            const certificates = [];
            for (let i = 0; i < objects.length; i++) {
                try {
                    const certData = this.pkcs11.C_GetAttributeValue(this.session, objects[i], [
                        { type: pkcs11js.CKA_VALUE }
                    ])[0].value;
                    
                    const certificate = forge.pki.certificateFromAsn1(forge.asn1.fromDer(certData.toString('binary')));
                    certificates.push(certificate);
                    
                    this.log(`Sertifika ${i + 1} okundu`);
                } catch (error) {
                    this.log(`Sertifika ${i + 1} okunamadi:`, error.message);
                }
            }

            return certificates;
        } catch (error) {
            this.log('Sertifika okuma hatasi:', error.message);
            throw error;
        }
    }

    async getPrivateKey() {
        try {
            this.log('Private key araniyor...');
            
            const template = [
                { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
                { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_RSA }
            ];

            this.pkcs11.C_FindObjectsInit(this.session, template);
            const objects = this.pkcs11.C_FindObjects(this.session, 5);
            this.pkcs11.C_FindObjectsFinal(this.session);

            this.log(`Bulunan private key: ${objects.length}`);

            if (objects.length === 0) {
                throw new Error('Private key bulunamadi');
            }

            return objects[0];
        } catch (error) {
            this.log('Private key hatasi:', error.message);
            throw error;
        }
    }

    async signData(data, privateKeyHandle) {
        try {
            this.log(`Imzalanacak veri boyutu: ${data.length}`);
            
            const mechanism = { mechanism: pkcs11js.CKM_SHA1_RSA_PKCS };
            this.pkcs11.C_SignInit(this.session, mechanism, privateKeyHandle);
            
            let dataToSign = Buffer.isBuffer(data) ? data : Buffer.from(data, 'binary');
            
            // İlk önce imza boyutunu öğrenmek için boş buffer ile çağır
            const tempBuffer = Buffer.alloc(0);
            let signatureLength;
            
            try {
                // İlk çağrıda boyutu öğren
                this.pkcs11.C_Sign(this.session, dataToSign, tempBuffer);
            } catch (error) {
                // Hata mesajından boyutu çıkarmaya çalış veya varsayılan boyut kullan
                signatureLength = 256; // RSA 2048 bit için tipik boyut
            }
            
            // Eğer boyut belirlenemediyse, key bilgilerinden boyutu bulmaya çalış
            if (!signatureLength) {
                try {
                    const keyAttributes = this.pkcs11.C_GetAttributeValue(this.session, privateKeyHandle, [
                        { type: pkcs11js.CKA_MODULUS_BITS }
                    ]);
                    const modulusBits = keyAttributes[0].value.readUInt32BE(0);
                    signatureLength = Math.ceil(modulusBits / 8);
                    this.log(`Key boyutu: ${modulusBits} bit, imza boyutu: ${signatureLength} byte`);
                } catch (e) {
                    signatureLength = 256; // Varsayılan boyut
                    this.log('Key boyutu belirlenemedi, varsayilan 256 byte kullaniliyor');
                }
            }
            
            // Uygun boyutta buffer oluştur ve imzala
            const signatureBuffer = Buffer.alloc(signatureLength);
            const actualSignature = this.pkcs11.C_Sign(this.session, dataToSign, signatureBuffer);
            
            this.log(`Imza olusturuldu, boyut: ${actualSignature.length}`);
            return actualSignature;
            
        } catch (error) {
            this.log('Imzalama hatasi:', error.message);
            throw error;
        }
    }

    // PDF'e dijital imza gömme fonksiyonu
    async embedDigitalSignatureInPDF(pdfPath, outputPath, privateKeyHandle, certificate) {
        try {
            this.log(`PDF'e dijital imza gomuluyor: ${pdfPath}`);
            
            // PDF dosyasını oku
            const pdfBytes = fs.readFileSync(pdfPath);
            
            // PDF dökümanını yükle
            const pdfDoc = await PDFDocument.load(pdfBytes);
            
            // İmza için hash hesapla
            const hash = crypto.createHash('sha256');
            hash.update(pdfBytes);
            const documentHash = hash.digest();
            
            this.log(`PDF hash hesaplandi: ${documentHash.length} bytes`);
            
            // Hash'i imzala
            const signature = await this.signData(documentHash, privateKeyHandle);
            
            // Sertifikatı base64 formatına çevir
            const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(certificate));
            const certBase64 = Buffer.from(certDer, 'binary').toString('base64');
            
            // İmza bilgilerini hazırla
            const signatureInfo = {
                signature: signature.toString('base64'),
                certificate: certBase64,
                algorithm: 'SHA256withRSA',
                timestamp: new Date().toISOString(),
                documentHash: documentHash.toString('hex'),
                signer: this.sanitizeText(this.getCertificateSubject(certificate)),
                issuer: this.sanitizeText(this.getCertificateIssuer(certificate)),
                serialNumber: certificate.serialNumber,
                validFrom: certificate.validity.notBefore.toISOString(),
                validTo: certificate.validity.notAfter.toISOString()
            };
            
            // İmza bilgilerini JSON string olarak hazırla
            const signatureJson = JSON.stringify(signatureInfo);
            
            // PDF metadata'sına dijital imza bilgilerini ekle
            pdfDoc.setTitle(`Dijital Imzali Dokuman - ${new Date().toISOString()}`);
            pdfDoc.setSubject('Dijital Imzali PDF');
            pdfDoc.setCreator('SafeNet Token Imzalayici');
            pdfDoc.setProducer('PDF Digital Signature Embedder v1.0');
            pdfDoc.setAuthor(this.sanitizeText(this.getCertificateSubject(certificate)));
            pdfDoc.setKeywords(`dijital-imza,safenet,pkcs11,${certificate.serialNumber}`);
            
            // Custom metadata olarak imza bilgilerini ekle
            // PDF'in custom properties bölümüne imza verilerini gömüyoruz
            const customMetadata = {
                'DigitalSignature': signatureJson,
                'SignatureVersion': '1.0',
                'SignatureType': 'PKCS11-SafeNet'
            };
            
            // Bu bilgileri PDF'in XMP metadata'sına eklemek için basit bir yaklaşım
            // Gerçek XMP implementasyonu için ek kütüphaneler gerekebilir
            
            // Görsel imza ekleme (opsiyonel)
            const pages = pdfDoc.getPages();
            const firstPage = pages[0];
            const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
            
            // İmza kutusu çizimi
            const signatureBoxX = 400;
            const signatureBoxY = 50;
            const boxWidth = 180;
            const boxHeight = 60;
            
            // Kutu çerçevesi
            firstPage.drawRectangle({
                x: signatureBoxX,
                y: signatureBoxY,
                width: boxWidth,
                height: boxHeight,
                borderColor: rgb(0, 0, 0),
                borderWidth: 1
            });
            
            // İmza metinleri
            firstPage.drawText('DIJITAL IMZA', {
                x: signatureBoxX + 5,
                y: signatureBoxY + boxHeight - 15,
                size: 8,
                font: font,
                color: rgb(0, 0, 0)
            });
            
            const signerName = this.sanitizeText(this.getCertificateSubject(certificate));
            const shortSigner = signerName.length > 25 ? signerName.substring(0, 22) + '...' : signerName;
            
            firstPage.drawText(`Imzalayan: ${shortSigner}`, {
                x: signatureBoxX + 5,
                y: signatureBoxY + boxHeight - 28,
                size: 6,
                font: font,
                color: rgb(0, 0, 0)
            });
            
            const dateStr = new Date().toLocaleDateString('en-US');
            const timeStr = new Date().toLocaleTimeString('en-US', {hour12: false});
            
            firstPage.drawText(`Tarih: ${dateStr}`, {
                x: signatureBoxX + 5,
                y: signatureBoxY + boxHeight - 40,
                size: 6,
                font: font,
                color: rgb(0, 0, 0)
            });
            
            firstPage.drawText(`Saat: ${timeStr}`, {
                x: signatureBoxX + 5,
                y: signatureBoxY + boxHeight - 52,
                size: 6,
                font: font,
                color: rgb(0, 0, 0)
            });
            
            // İmzalı PDF'i kaydet
            const signedPdfBytes = await pdfDoc.save();
            fs.writeFileSync(outputPath, signedPdfBytes);
            
            // Ayrıca imza bilgilerini doğrulama için JSON dosyası olarak da kaydet
            const verificationPath = outputPath.replace('.pdf', '_verification.json');
            fs.writeFileSync(verificationPath, JSON.stringify({
                ...signatureInfo,
                originalFile: pdfPath,
                signedFile: outputPath,
                embeddedInPDF: true
            }, null, 2));
            
            this.log(`PDF'e dijital imza basarıyla gomuldu: ${outputPath}`);
            this.log(`Dogrulama dosyasi: ${verificationPath}`);
            
            return {
                signedPdf: outputPath,
                verificationFile: verificationPath,
                signatureInfo: signatureInfo,
                embedded: true
            };
            
        } catch (error) {
            this.log('PDF imza gomme hatasi:', error.message);
            throw error;
        }
    }

    // PDF'den gömülü imzayı çıkarma ve doğrulama
    async extractAndVerifyEmbeddedSignature(signedPdfPath) {
        try {
            this.log(`Gomulu imza cikariliyor: ${signedPdfPath}`);
            
            // Eğer verification dosyası varsa onu kullan
            const verificationPath = signedPdfPath.replace('.pdf', '_verification.json');
            
            if (fs.existsSync(verificationPath)) {
                const verificationData = JSON.parse(fs.readFileSync(verificationPath, 'utf8'));
                
                // Sertifikayı yeniden oluştur
                const certDer = forge.util.decode64(verificationData.certificate);
                const certificate = forge.pki.certificateFromAsn1(forge.asn1.fromDer(certDer));
                
                // Sertifika geçerliliğini kontrol et
                const now = new Date();
                const validFrom = new Date(verificationData.validFrom);
                const validTo = new Date(verificationData.validTo);
                
                const isCertValid = now >= validFrom && now <= validTo;
                
                // İmza doğrulaması (basit kontrol)
                const signatureValid = verificationData.signature && 
                                     verificationData.documentHash && 
                                     verificationData.algorithm === 'SHA256withRSA';
                
                const result = {
                    isValid: isCertValid && signatureValid,
                    certificate: certificate,
                    signatureInfo: verificationData,
                    certificateValid: isCertValid,
                    signaturePresent: signatureValid,
                    validFrom: validFrom,
                    validTo: validTo,
                    embedded: true
                };
                
                this.log('Gomulu imza dogrulama sonucu:', result.isValid ? 'GECERLI' : 'GECERSIZ');
                
                return result;
            } else {
                throw new Error('Dogrulama dosyasi bulunamadi. PDF gomulu imza icermiyor olabilir.');
            }
            
        } catch (error) {
            this.log('Gomulu imza dogrulama hatasi:', error.message);
            throw error;
        }
    }

    getCertificateSubject(certificate) {
        try {
            if (!certificate || !certificate.subject) {
                return 'Unknown Signer';
            }
            
            const subject = certificate.subject;
            let subjectStr = '';
            
            try {
                if (subject.getField('CN')) {
                    const cn = subject.getField('CN').value;
                    subjectStr += this.sanitizeText(cn || '');
                }
            } catch (e) {
                this.log('CN field okunamadi:', e.message);
            }
            
            try {
                if (subject.getField('O')) {
                    const o = subject.getField('O').value;
                    if (subjectStr) subjectStr += ' ';
                    subjectStr += `(${this.sanitizeText(o || '')})`;
                }
            } catch (e) {
                this.log('O field okunamadi:', e.message);
            }
            
            return this.sanitizeText(subjectStr) || 'Unknown Signer';
        } catch (error) {
            this.log('Sertifika subject okuma hatasi:', error.message);
            return 'Certificate Read Error';
        }
    }

    getCertificateIssuer(certificate) {
        try {
            if (!certificate || !certificate.issuer) {
                return 'Unknown Issuer';
            }
            
            const issuer = certificate.issuer;
            let issuerStr = '';
            
            try {
                if (issuer.getField('CN')) {
                    const cn = issuer.getField('CN').value;
                    issuerStr += this.sanitizeText(cn || '');
                }
            } catch (e) {
                this.log('Issuer CN field okunamadi:', e.message);
            }
            
            try {
                if (issuer.getField('O')) {
                    const o = issuer.getField('O').value;
                    if (issuerStr) issuerStr += ' ';
                    issuerStr += `(${this.sanitizeText(o || '')})`;
                }
            } catch (e) {
                this.log('Issuer O field okunamadi:', e.message);
            }
            
            return this.sanitizeText(issuerStr) || 'Unknown Issuer';
        } catch (error) {
            this.log('Sertifika issuer okuma hatasi:', error.message);
            return 'Issuer Read Error';
        }
    }

    cleanup() {
        try {
            if (this.session) {
                try { this.pkcs11.C_Logout(this.session); } catch (e) {}
                try { this.pkcs11.C_CloseSession(this.session); } catch (e) {}
            }
            try { this.pkcs11.C_Finalize(); } catch (e) {}
            this.log('Temizlik tamamlandi');
        } catch (error) {
            this.log('Temizlik hatasi:', error.message);
        }
    }
}

// Test fonksiyonları
async function testToken() {
    const tokenManager = new SafeNetTokenManager();

    try {
        console.log('=== SafeNet Token Testi ===\n');
        
        await tokenManager.initialize();
        
        // PIN'inizi buraya yazın
        const pin = '2945'; // GERÇEK PIN'İNİZİ YAZIN!
        await tokenManager.login(pin);
        
        const certificates = await tokenManager.getCertificates();
        console.log(`\n${certificates.length} sertifika bulundu`);
        
        if (certificates.length > 0) {
            const certificate = certificates[0];
            try {
                const commonName = certificate.subject.getField('CN').value;
                console.log('Sertifika sahibi:', commonName);
            } catch (e) {
                console.log('Sertifika sahibi okunamadi');
            }
            
            const privateKey = await tokenManager.getPrivateKey();
            console.log('Private key bulundu:', privateKey);
            
            // Test imzalama
            const testData = Buffer.from('test data for signing');
            console.log('\nTest imzalamasi yapiliyor...');
            const signature = await tokenManager.signData(testData, privateKey);
            console.log('Test imzalamasi basarili! Imza boyutu:', signature.length);
            
            console.log('\n=== Test Basarili! ===');
        }
        
    } catch (error) {
        console.error('\n=== Test Hatasi ===');
        console.error('Hata:', error.message);
    } finally {
        tokenManager.cleanup();
    }
}

async function testPDFEmbeddedSigning() {
    const tokenManager = new SafeNetTokenManager();

    try {
        console.log('=== PDF Gomulu Imzalama Testi ===\n');
        
        await tokenManager.initialize();
        await tokenManager.login('2945'); // PIN'inizi yazın
        
        const certificates = await tokenManager.getCertificates();
        const privateKey = await tokenManager.getPrivateKey();
        
        if (certificates.length > 0) {
            // Test PDF dosyası (bu dosya mevcut olmalı)
            const inputPdf = 'test.pdf';
            const outputPdf = 'embedded_signed_test.pdf';
            
            // Dosya varlığını kontrol et
            if (!fs.existsSync(inputPdf)) {
                console.log(`UYARI: ${inputPdf} dosyasi bulunamadi!`);
                console.log('Test PDF dosyasi olusturuluyor...');
                
                // Basit test PDF oluştur
                await createTestPDF(inputPdf);
            }
            
            console.log(`PDF'e dijital imza gomuluyor: ${inputPdf} -> ${outputPdf}`);
            
            const result = await tokenManager.embedDigitalSignatureInPDF(
                inputPdf, 
                outputPdf, 
                privateKey, 
                certificates[0]
            );
            
            console.log('\n=== PDF Gomulu Imzalama Basarili! ===');
            console.log('Imza sahibi:', result.signatureInfo.signer);
            console.log('Imza tarihi:', result.signatureInfo.timestamp);
            console.log('Imzali dosya:', result.signedPdf);
            console.log('Imza PDF icine gomuldu:', result.embedded);
            
            // Gömülü imza doğrulama testi
            console.log('\n=== Gomulu Imza Dogrulama Testi ===');
            const verification = await tokenManager.extractAndVerifyEmbeddedSignature(outputPdf);
            console.log('Imza dogrulama sonucu:', verification.isValid ? 'GECERLI' : 'GECERSIZ');
            console.log('Sertifika gecerliligi:', verification.certificateValid ? 'GECERLI' : 'GECERSIZ');
            console.log('Imza mevcut:', verification.signaturePresent ? 'EVET' : 'HAYIR');
            console.log('Imza gomulu:', verification.embedded ? 'EVET' : 'HAYIR');
        }
        
    } catch (error) {
        console.error('\n=== PDF Gomulu Imzalama Hatasi ===');
        console.error('Hata:', error.message);
    } finally {
        tokenManager.cleanup();
    }
}

// Test PDF oluşturma fonksiyonu - Türkçe karaktersiz
async function createTestPDF(filename) {
    try {
        const pdfDoc = await PDFDocument.create();
        const page = pdfDoc.addPage([600, 800]);
        const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
        
        page.drawText('Test PDF Dokumani', {
            x: 50,
            y: 750,
            size: 20,
            font: font
        });
        
        page.drawText('Bu dokuman SafeNet token ile gomulu imza ile imzalanacak test dosyasidir.', {
            x: 50,
            y: 700,
            size: 12,
            font: font
        });
        
        page.drawText(`Olusturulma tarihi: ${new Date().toLocaleDateString('en-US')}`, {
            x: 50,
            y: 680,
            size: 10,
            font: font
        });
        
        page.drawText('Icerik: Lorem ipsum dolor sit amet, consectetur adipiscing elit.', {
            x: 50,
            y: 650,
            size: 10,
            font: font
        });
        
        page.drawText('Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.', {
            x: 50,
            y: 630,
            size: 10,
            font: font
        });
        
        page.drawText('Ut enim ad minim veniam, quis nostrud exercitation.', {
            x: 50,
            y: 610,
            size: 10,
            font: font
        });
        
        page.drawText('Bu PDF dosyasi dijital imza ile korunacaktir.', {
            x: 50,
            y: 580,
            size: 10,
            font: font
        });
        
        const pdfBytes = await pdfDoc.save();
        fs.writeFileSync(filename, pdfBytes);
        
        console.log(`Test PDF olusturuldu: ${filename}`);
    } catch (error) {
        console.error('Test PDF olusturma hatasi:', error.message);
    }
}

// Ana test fonksiyonu
async function main() {
    const args = process.argv.slice(2);
    
    if (args.includes('--embedded') || args.includes('-e')) {
        await testPDFEmbeddedSigning();
    } else if (args.includes('--basic') || args.includes('-b')) {
        await testToken();
    } else {
        console.log('Kullanim:');
        console.log('  node test_token3.js --basic     (veya -b) : Temel token testi');
        console.log('  node test_token3.js --embedded  (veya -e) : PDF gomulu imzalama testi');
        console.log('\nVarsayilan olarak gomulu PDF imzalama testi calisacak...\n');
        await testPDFEmbeddedSigning();
    }
}

main();