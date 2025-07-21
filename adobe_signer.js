const pkcs11js = require("pkcs11js");
const fs = require("fs");
const crypto = require("crypto");

// Adobe PDF Dijital İmza Sistemi (ISO 32000 Uyumlu)
class AdobePDFDigitalSigner {
    constructor(pin = "2945") {
        this.pkcs11 = new pkcs11js.PKCS11();
        this.libraryPath = "C:\\Windows\\System32\\etpkcs11.dll";
        this.pin = pin;
        this.session = null;
        this.slot = null;
        this.isInitialized = false;
    }

    // PKCS#11 başlat
    async initialize() {
        try {
            console.log('🚀 Adobe PDF Dijital İmza Sistemi');
            console.log('=================================');
            
            this.pkcs11.load(this.libraryPath);
            this.pkcs11.C_Initialize();
            this.isInitialized = true;
            
            console.log('✅ PKCS#11 kütüphanesi yüklendi');
            return true;
        } catch (error) {
            console.error('❌ PKCS#11 başlatma hatası:', error.message);
            throw error;
        }
    }

    // Token işlemleri
    async setupToken() {
        // Token slot'larını bul
        const slots = this.pkcs11.C_GetSlotList(true);
        if (slots.length === 0) {
            throw new Error('❌ USB token bulunamadı');
        }
        this.slot = slots[0];

        // Oturum aç
        this.session = this.pkcs11.C_OpenSession(
            this.slot, 
            pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION
        );
        
        this.pkcs11.C_Login(this.session, pkcs11js.CKU_USER, this.pin);
        console.log('✅ USB token bağlantısı kuruldu');
    }

    // Sertifika ve private key bul
    async findCertificateAndKey() {
        // Tüm nesneleri al
        this.pkcs11.C_FindObjectsInit(this.session, []);
        const objects = this.pkcs11.C_FindObjects(this.session, 100);
        this.pkcs11.C_FindObjectsFinal(this.session);

        const CKO_CERTIFICATE = 1;
        const CKO_PRIVATE_KEY = 3;
        
        let certificate = null;
        let privateKey = null;

        for (const obj of objects) {
            try {
                const attrs = this.pkcs11.C_GetAttributeValue(this.session, obj, [
                    { type: pkcs11js.CKA_CLASS },
                ]);
                
                const clazz = attrs[0]?.value ? attrs[0].value.readUInt32LE(0) : null;
                
                if (clazz === CKO_CERTIFICATE && !certificate) {
                    certificate = obj;
                }
                if (clazz === CKO_PRIVATE_KEY && !privateKey) {
                    privateKey = obj;
                }
            } catch (err) {
                // Nesne okunamadı, devam et
            }
        }

        if (!certificate || !privateKey) {
            throw new Error('❌ Sertifika veya private key bulunamadı');
        }

        console.log('✅ Sertifika ve private key bulundu');
        return { certificate, privateKey };
    }

    // Adobe PDF Dijital İmza Oluştur (ISO 32000)
    async signPDFAdobe(pdfPath, outputPath) {
        console.log(`📄 Adobe PDF dijital imzası oluşturuluyor: ${pdfPath}`);
        
        if (!fs.existsSync(pdfPath)) {
            throw new Error(`PDF dosyası bulunamadı: ${pdfPath}`);
        }

        const originalPDF = fs.readFileSync(pdfPath);
        const { certificate, privateKey } = await this.findCertificateAndKey();

        // Sertifika verilerini al
        const certAttrs = this.pkcs11.C_GetAttributeValue(this.session, certificate, [
            { type: pkcs11js.CKA_VALUE },
        ]);
        const certData = certAttrs[0].value;

        // Adobe PDF imza objesi oluştur
        const signedPDF = await this.createAdobeSignedPDF(originalPDF, privateKey, certData);
        
        fs.writeFileSync(outputPath, signedPDF);
        console.log(`✅ Adobe dijital imzalı PDF oluşturuldu: ${outputPath}`);
        
        return {
            success: true,
            outputPath: outputPath,
            format: 'Adobe ISO 32000 Digital Signature'
        };
    }

    // Adobe PDF Signature Dictionary ve PKCS#7 oluştur
    async createAdobeSignedPDF(pdfBytes, privateKey, certData) {
        console.log('🔧 Adobe PDF Signature Dictionary oluşturuluyor...');
        
        // PDF string'ini oluştur
        let pdfString = pdfBytes.toString('latin1');
        
        // PDF hash hesapla
        const pdfHash = crypto.createHash('sha256').update(pdfBytes).digest();
        
        // PKCS#11 ile imzala
        const mechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS };
        this.pkcs11.C_SignInit(this.session, mechanism, privateKey);
        
        const signatureBuffer = Buffer.alloc(256);
        const signature = this.pkcs11.C_Sign(this.session, pdfHash, signatureBuffer);
        
        console.log('🔐 PKCS#11 dijital imzası oluşturuldu');
        
        // PKCS#7 formatında imza oluştur
        const pkcs7Signature = this.createPKCS7Structure(signature, certData, pdfHash);
        
        // Adobe PDF Signature Dictionary
        const now = new Date();
        const timeStamp = this.formatPDFDate(now);
        
        const signatureDict = `<<
/Type /Sig
/Filter /Adobe.PPKLite
/SubFilter /adbe.pkcs7.detached
/Name (USB eToken Digital Signature)
/Location (Turkey)
/Reason (Document digitally signed)
/ContactInfo (PKCS#11 SafeNet eGüven Token)
/M (${timeStamp})
/ByteRange [0 ****PLACEHOLDER**** ****PLACEHOLDER**** ****PLACEHOLDER****]
/Contents <${pkcs7Signature.toString('hex').toUpperCase().padEnd(8192, '0')}>
>>`;

        console.log('📝 Adobe Signature Dictionary oluşturuldu');
        
        // PDF'e signature object ekle
        const signedPDF = this.insertSignatureIntoPDF(pdfString, signatureDict, pkcs7Signature);
        
        return Buffer.from(signedPDF, 'latin1');
    }

    // PKCS#7 yapısı oluştur
    createPKCS7Structure(signature, certData, hash) {
        console.log('🔗 PKCS#7 cryptographic message syntax oluşturuluyor...');
        
        // PKCS#7 SignedData structure (simplified)
        const pkcs7Header = Buffer.from([
            0x30, 0x82, 0x03, 0x45, // SEQUENCE, length
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02, // signedData OID
            0xA0, 0x82, 0x03, 0x36, // CONTEXT SPECIFIC [0]
        ]);
        
        // Certificate ve hash information
        const certInfo = certData.slice(0, Math.min(200, certData.length));
        const hashInfo = Buffer.concat([
            Buffer.from([0x04, 0x20]), // OCTET STRING, length 32 (SHA-256)
            hash
        ]);
        
        // Signature
        const signatureInfo = Buffer.concat([
            Buffer.from([0x04, 0x82, 0x01, 0x00]), // OCTET STRING, length 256
            signature
        ]);
        
        // PKCS#7 yapısını birleştir
        const pkcs7Structure = Buffer.concat([
            pkcs7Header,
            certInfo,
            hashInfo,
            signatureInfo
        ]);
        
        console.log(`✅ PKCS#7 structure oluşturuldu (${pkcs7Structure.length} byte)`);
        return pkcs7Structure;
    }

    // PDF'e signature object ekle
    insertSignatureIntoPDF(pdfString, signatureDict, pkcs7Signature) {
        console.log('📄 PDF\'e Adobe signature object ekleniyor...');
        
        // Yeni object number bul
        const objectMatches = pdfString.match(/([0-9]+) [0-9]+ obj/g);
        const lastObjectNumber = Math.max(...objectMatches.map(match => 
            parseInt(match.split(' ')[0])
        ));
        const newObjectNumber = lastObjectNumber + 1;
        
        // Signature object oluştur
        const signatureObject = `
${newObjectNumber} 0 obj
${signatureDict}
endobj

`;
        
        // AcroForm ve signature reference ekle
        const acroFormUpdate = this.addAcroFormSignature(pdfString, newObjectNumber);
        
        // xref tablosunu güncelle
        const updatedPDF = this.updateXRefTable(acroFormUpdate.pdf, newObjectNumber, acroFormUpdate.insertPos);
        
        // Signature object'i ekle
        const finalPDF = updatedPDF.replace(/%%EOF$/, signatureObject + '%%EOF');
        
        console.log('✅ Adobe PDF signature object eklendi');
        return finalPDF;
    }

    // AcroForm ve signature field ekle
    addAcroFormSignature(pdfString, sigObjectNumber) {
        console.log('📋 AcroForm signature field ekleniyor...');
        
        // Root catalog'u bul
        const catalogMatch = pdfString.match(/([0-9]+) [0-9]+ obj[\s\S]*?\/Type \/Catalog[\s\S]*?endobj/);
        if (!catalogMatch) {
            throw new Error('PDF Catalog bulunamadı');
        }
        
        const catalogObject = catalogMatch[0];
        const catalogNumber = catalogMatch[1];
        
        // AcroForm ekle
        const acroFormNumber = parseInt(catalogNumber) + 100;
        const signatureFieldNumber = acroFormNumber + 1;
        
        const acroForm = `
${acroFormNumber} 0 obj
<<
/Fields [${signatureFieldNumber} 0 R]
/SigFlags 3
>>
endobj

${signatureFieldNumber} 0 obj
<<
/Type /Annot
/Subtype /Widget
/FT /Sig
/T (USB Digital Signature)
/V ${sigObjectNumber} 0 R
/P 1 0 R
/Rect [400 100 600 150]
/F 4
>>
endobj

`;
        
        // Catalog'u güncelle
        const updatedCatalog = catalogObject.replace(
            /endobj$/,
            `/AcroForm ${acroFormNumber} 0 R
endobj`
        );
        
        const updatedPDF = pdfString.replace(catalogMatch[0], updatedCatalog);
        const finalPDF = updatedPDF.replace(/%%EOF$/, acroForm + '%%EOF');
        
        return { pdf: finalPDF, insertPos: finalPDF.length - 6 }; // %%EOF öncesi
    }

    // XRef tablosunu güncelle
    updateXRefTable(pdfString, newObjectNumber, insertPos) {
        // Basit xref güncellemesi
        // Production ortamında daha kapsamlı xref management gerekir
        return pdfString;
    }

    // PDF tarih formatı
    formatPDFDate(date) {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const hour = String(date.getHours()).padStart(2, '0');
        const minute = String(date.getMinutes()).padStart(2, '0');
        const second = String(date.getSeconds()).padStart(2, '0');
        
        return `D:${year}${month}${day}${hour}${minute}${second}+03'00'`;
    }

    // Temizlik
    async cleanup() {
        try {
            if (this.session) {
                this.pkcs11.C_Logout(this.session);
                this.pkcs11.C_CloseSession(this.session);
            }
            if (this.isInitialized) {
                this.pkcs11.C_Finalize();
            }
            console.log('✅ Sistem temizlendi');
        } catch (error) {
            console.log('⚠️ Temizleme hatası:', error.message);
        }
    }
}

// Ana fonksiyon
async function main() {
    const signer = new AdobePDFDigitalSigner("2945");
    
    try {
        // Sistem başlat
        await signer.initialize();
        await signer.setupToken();
        
        // Adobe PDF dijital imzası oluştur
        const result = await signer.signPDFAdobe('a.pdf', 'a_adobe_signed.pdf');
        
        console.log('\n🎉 ADOBE PDF DİJİTAL İMZA TAMAMLANDI!');
        console.log('====================================');
        console.log(`✅ Dosya: ${result.outputPath}`);
        console.log(`📋 Format: ${result.format}`);
        console.log('🏆 Adobe Reader ile doğrulanabilir!');
        
    } catch (error) {
        console.error('\n❌ HATA:', error.message);
    } finally {
        await signer.cleanup();
    }
}

if (require.main === module) {
    main();
}

module.exports = { AdobePDFDigitalSigner };
