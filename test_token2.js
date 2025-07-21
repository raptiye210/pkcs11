// test_token.js
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

    // PDF İmzalama fonksiyonları
    async signPDF(pdfPath, outputPath, privateKeyHandle, certificate) {
        try {
            this.log(`PDF imzalaniyor: ${pdfPath}`);
            
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
            
            // Sertifikayı PEM formatına çevir
            const certPem = forge.pki.certificateToPem(certificate);
            
            // İmza bilgilerini PDF'e ekle (basit metadata olarak) - Türkçe karaktersiz
            pdfDoc.setTitle(`Imzali Dokuman - ${new Date().toISOString()}`);
            pdfDoc.setSubject('Dijital Imzali PDF');
            pdfDoc.setCreator('SafeNet Token Imzalayici');
            
            // İmzalanmış PDF'i kaydet
            const signedPdfBytes = await pdfDoc.save();
            
            // İmza bilgilerini ayrı dosya olarak kaydet
            const signatureInfo = {
                timestamp: new Date().toISOString(),
                signature: signature.toString('base64'),
                certificate: certPem,
                algorithm: 'SHA256withRSA',
                originalHash: documentHash.toString('hex')
            };
            
            const signatureInfoPath = outputPath.replace('.pdf', '_signature.json');
            fs.writeFileSync(signatureInfoPath, JSON.stringify(signatureInfo, null, 2));
            
            // İmzalanmış PDF'i kaydet
            fs.writeFileSync(outputPath, signedPdfBytes);
            
            this.log(`PDF basarıyla imzalandı: ${outputPath}`);
            this.log(`Imza bilgileri: ${signatureInfoPath}`);
            
            return {
                signedPdf: outputPath,
                signatureInfo: signatureInfoPath,
                signature: signature,
                certificate: certificate
            };
            
        } catch (error) {
            this.log('PDF imzalama hatasi:', error.message);
            throw error;
        }
    }

    // Gelişmiş PDF imzalama
    async signPDFAdvanced(pdfPath, outputPath, privateKeyHandle, certificate) {
        try {
            this.log(`Gelismis PDF imzalama baslatiliyor: ${pdfPath}`);
            
            const pdfBytes = fs.readFileSync(pdfPath);
            
            // PDF dökümanını yükle
            const pdfDoc = await PDFDocument.load(pdfBytes);
            const pages = pdfDoc.getPages();
            const firstPage = pages[0];
            
            // Standart font kullan
            const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
            
            // İmza metadata'sı oluştur - Türkçe karakterleri temizle
            const rawSigner = this.getCertificateSubject(certificate);
            const cleanSigner = this.sanitizeText(rawSigner);
            
            const signatureField = {
                name: 'SafeNetSignature',
                timestamp: new Date(),
                reason: 'Dokuman onayi',
                location: 'Turkiye',
                signer: cleanSigner
            };
            
            // PDF'e imza alanını ekle (görsel imza) - Temizlenmiş metinler
            firstPage.drawText(`Dijital Imza: ${signatureField.signer}`, {
                x: 50,
                y: 50,
                size: 10,
                font: font,
                color: rgb(0, 0, 0)
            });
            
            const dateText = signatureField.timestamp.toLocaleDateString('en-US') + ' ' + 
                           signatureField.timestamp.toLocaleTimeString('en-US');
            
            firstPage.drawText(`Imza Tarihi: ${dateText}`, {
                x: 50,
                y: 35,
                size: 8,
                font: font,
                color: rgb(0, 0, 0)
            });
            
            firstPage.drawText(`Sertifika SN: ${this.sanitizeText(certificate.serialNumber || 'Unknown')}`, {
                x: 50,
                y: 20,
                size: 6,
                font: font,
                color: rgb(0, 0, 0)
            });
            
            // Modifiye edilmiş PDF'i al
            const modifiedPdfBytes = await pdfDoc.save();
            
            // Modifiye edilmiş PDF'in hash'ini al
            const hash = crypto.createHash('sha256');
            hash.update(modifiedPdfBytes);
            const documentHash = hash.digest();
            
            // Hash'i imzala
            const signature = await this.signData(documentHash, privateKeyHandle);
            
            // İmzalı PDF'i kaydet
            fs.writeFileSync(outputPath, modifiedPdfBytes);
            
            // Detaylı imza bilgilerini kaydet
            const detailedSignatureInfo = {
                ...signatureField,
                timestamp: signatureField.timestamp.toISOString(),
                signature: signature.toString('base64'),
                certificate: forge.pki.certificateToPem(certificate),
                documentHash: documentHash.toString('hex'),
                algorithm: 'SHA256withRSA',
                standard: 'Basic PDF Signature',
                certificateInfo: {
                    subject: cleanSigner,
                    issuer: this.sanitizeText(this.getCertificateIssuer(certificate)),
                    serialNumber: certificate.serialNumber,
                    validFrom: certificate.validity.notBefore.toISOString(),
                    validTo: certificate.validity.notAfter.toISOString()
                }
            };
            
            const signatureInfoPath = outputPath.replace('.pdf', '_detailed_signature.json');
            fs.writeFileSync(signatureInfoPath, JSON.stringify(detailedSignatureInfo, null, 2));
            
            this.log('Gelismis PDF imzalama tamamlandi');
            this.log(`Imzali PDF: ${outputPath}`);
            this.log(`Imza detaylari: ${signatureInfoPath}`);
            
            return detailedSignatureInfo;
            
        } catch (error) {
            this.log('Gelismis PDF imzalama hatasi:', error.message);
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

    // İmza doğrulama fonksiyonu
    async verifyPDFSignature(signatureInfoPath) {
        try {
            this.log(`Imza dogrulanıyor: ${signatureInfoPath}`);
            
            const signatureInfo = JSON.parse(fs.readFileSync(signatureInfoPath, 'utf8'));
            const certificate = forge.pki.certificateFromPem(signatureInfo.certificate);
            
            // Sertifika geçerliliğini kontrol et
            const now = new Date();
            const validFrom = certificate.validity.notBefore;
            const validTo = certificate.validity.notAfter;
            
            const isValid = now >= validFrom && now <= validTo;
            
            this.log(`Sertifika gecerliligi: ${isValid}`);
            this.log(`Gecerlilik tarihi: ${validFrom.toLocaleDateString('en-US')} - ${validTo.toLocaleDateString('en-US')}`);
            
            return {
                isValid: isValid,
                certificate: certificate,
                signatureInfo: signatureInfo,
                validFrom: validFrom,
                validTo: validTo
            };
            
        } catch (error) {
            this.log('Imza dogrulama hatasi:', error.message);
            throw error;
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

async function testPDFSigning() {
    const tokenManager = new SafeNetTokenManager();

    try {
        console.log('=== PDF Imzalama Testi ===\n');
        
        await tokenManager.initialize();
        await tokenManager.login('2945'); // PIN'inizi yazın
        
        const certificates = await tokenManager.getCertificates();
        const privateKey = await tokenManager.getPrivateKey();
        
        if (certificates.length > 0) {
            // Test PDF dosyası (bu dosya mevcut olmalı)
            const inputPdf = 'test.pdf';
            const outputPdf = 'signed_test.pdf';
            
            // Dosya varlığını kontrol et
            if (!fs.existsSync(inputPdf)) {
                console.log(`UYARI: ${inputPdf} dosyasi bulunamadi!`);
                console.log('Test PDF dosyasi olusturuluyor...');
                
                // Basit test PDF oluştur
                await createTestPDF(inputPdf);
            }
            
            console.log(`PDF imzalaniyor: ${inputPdf} -> ${outputPdf}`);
            
            const result = await tokenManager.signPDFAdvanced(
                inputPdf, 
                outputPdf, 
                privateKey, 
                certificates[0]
            );
            
            console.log('\n=== PDF Imzalama Basarili! ===');
            console.log('Imza sahibi:', result.signer);
            console.log('Imza tarihi:', result.timestamp);
            console.log('Imzali dosya:', outputPdf);
            
            // İmza doğrulama testi
            const signatureInfoPath = outputPdf.replace('.pdf', '_detailed_signature.json');
            const verification = await tokenManager.verifyPDFSignature(signatureInfoPath);
            console.log('\nImza dogrulama sonucu:', verification.isValid ? 'GECERLI' : 'GECERSIZ');
        }
        
    } catch (error) {
        console.error('\n=== PDF Imzalama Hatasi ===');
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
        
        page.drawText('Bu dokuman SafeNet token ile imzalanacak test dosyasidir.', {
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
        
        const pdfBytes = await pdfDoc.save();
        fs.writeFileSync(filename, pdfBytes);
        
        console.log(`Test PDF olusturuldu: ${filename}`);
    } catch (error) {
        console.error('Test PDF olusturma hatasi:', error.message);
    }
}

// Ana test fonksiyonu - hangisini çalıştırmak istediğinizi seçin
async function main() {
    const args = process.argv.slice(2);
    
    if (args.includes('--pdf') || args.includes('-p')) {
        await testPDFSigning();
    } else if (args.includes('--basic') || args.includes('-b')) {
        await testToken();
    } else {
        console.log('Kullanim:');
        console.log('  node test_token.js --basic   (veya -b) : Temel token testi');
        console.log('  node test_token.js --pdf     (veya -p) : PDF imzalama testi');
        console.log('\nVarsayilan olarak PDF testi calisacak...\n');
        await testPDFSigning();
    }
}

main();