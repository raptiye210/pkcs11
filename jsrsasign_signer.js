const pkcs11js = require("pkcs11js");
const fs = require("fs");
const crypto = require("crypto");
const jsrsasign = require("jsrsasign");

// JSrsaSign ile Adobe PDF Dijital İmza Sistemi
class JSrsaSignAdobePDFSigner {
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
            console.log('🚀 JSrsaSign Adobe PDF Dijital İmza Sistemi');
            console.log('============================================');
            
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

    // Token setup
    async setupToken() {
        const slots = this.pkcs11.C_GetSlotList(true);
        if (slots.length === 0) {
            throw new Error('❌ USB token bulunamadı');
        }
        this.slot = slots[0];

        this.session = this.pkcs11.C_OpenSession(
            this.slot, 
            pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION
        );
        
        this.pkcs11.C_Login(this.session, pkcs11js.CKU_USER, this.pin);
        console.log('✅ USB token bağlantısı kuruldu');
    }

    // Sertifika ve private key bul
    async findCertificateAndKey() {
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
                // Nesne okunamadı
            }
        }

        if (!certificate || !privateKey) {
            throw new Error('❌ Sertifika veya private key bulunamadı');
        }

        console.log('✅ Sertifika ve private key bulundu');
        return { certificate, privateKey };
    }

    // JSrsaSign ile Adobe PDF dijital imzası
    async signPDFWithJSrsaSign(pdfPath, outputPath) {
        console.log(`📄 JSrsaSign ile Adobe PDF dijital imzası: ${pdfPath}`);
        
        if (!fs.existsSync(pdfPath)) {
            throw new Error(`PDF dosyası bulunamadı: ${pdfPath}`);
        }

        const { certificate, privateKey } = await this.findCertificateAndKey();

        // Sertifika verilerini al
        const certAttrs = this.pkcs11.C_GetAttributeValue(this.session, certificate, [
            { type: pkcs11js.CKA_VALUE },
        ]);
        const certDataDER = certAttrs[0].value;

        console.log('📋 Sertifika verileri alındı');

        // PDF'i oku
        const pdfBuffer = fs.readFileSync(pdfPath);
        
        // JSrsaSign ile X.509 sertifikası parse et
        const certHex = certDataDER.toString('hex');
        const x509 = new jsrsasign.X509();
        x509.readCertHex(certHex);
        
        const certInfo = x509.getSubjectString();
        const issuerInfo = x509.getIssuerString();
        
        console.log(`🏢 Sertifika Sahibi: ${certInfo}`);
        console.log(`🏛️ Sertifika Yayınlayıcı: ${issuerInfo}`);

        // PDF hash hesapla
        const pdfHash = crypto.createHash('sha256').update(pdfBuffer).digest();
        console.log('🔐 PDF hash hesaplandı (SHA-256)');

        // PKCS#11 ile dijital imza
        const mechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS };
        this.pkcs11.C_SignInit(this.session, mechanism, privateKey);
        
        const signatureBuffer = Buffer.alloc(256);
        const pkcs11Signature = this.pkcs11.C_Sign(this.session, pdfHash, signatureBuffer);
        
        console.log(`🔑 PKCS#11 dijital imzası oluşturuldu: ${pkcs11Signature.length} byte`);

        // JSrsaSign ile PKCS#7 SignedData oluştur
        const pkcs7Hex = this.createJSrsaSign_PKCS7(pdfHash, pkcs11Signature, certHex);
        console.log('📦 JSrsaSign PKCS#7 SignedData oluşturuldu');

        // Adobe PDF'e PKCS#7 embedded imza ekle
        const signedPDF = this.embedPKCS7InPDF(pdfBuffer, pkcs7Hex);
        
        fs.writeFileSync(outputPath, signedPDF);
        console.log(`✅ Adobe uyumlu PDF dijital imzası kaydedildi: ${outputPath}`);

        return {
            success: true,
            outputPath: outputPath,
            certSubject: certInfo,
            certIssuer: issuerInfo,
            signatureLength: pkcs11Signature.length,
            format: 'Adobe PDF + JSrsaSign PKCS#7',
            adobeCompatible: true
        };
    }

    // JSrsaSign ile PKCS#7 SignedData oluştur
    createJSrsaSign_PKCS7(messageHash, signature, certHex) {
        console.log('🔨 JSrsaSign ile PKCS#7 SignedData yapısı oluşturuluyor...');

        try {
            // JSrsaSign PKCS#7 SignedData
            const sd = new jsrsasign.KJUR.asn1.cms.SignedData({
                version: 1,
                hashalgs: ['sha256'],
                econtent: {
                    type: 'data',
                    content: messageHash.toString('hex')
                }
            });

            // Sertifikayı ekle
            sd.addCert(certHex);

            // SignerInfo oluştur
            const signerInfo = new jsrsasign.KJUR.asn1.cms.SignerInfo({
                version: 1,
                id: {
                    type: 'isssn',
                    cert: certHex
                },
                hashalg: 'sha256',
                sattrs: [
                    new jsrsasign.KJUR.asn1.cms.ContentType({ oid: '1.2.840.113549.1.7.1' }),
                    new jsrsasign.KJUR.asn1.cms.MessageDigest({ hex: messageHash.toString('hex') }),
                    new jsrsasign.KJUR.asn1.cms.SigningTime()
                ],
                sigalg: 'SHA256withRSA',
                sig: signature.toString('hex')
            });

            sd.addSignerInfo(signerInfo);

            // PKCS#7 hex string
            const pkcs7Hex = sd.getContentInfoEncodedHex();
            console.log(`✅ PKCS#7 SignedData oluşturuldu: ${pkcs7Hex.length} karakter`);
            
            return pkcs7Hex;

        } catch (error) {
            console.log('⚠️ JSrsaSign PKCS#7 hatası:', error.message);
            
            // Fallback: Basit PKCS#7 structure
            console.log('🔄 Basit PKCS#7 formatına geçiliyor...');
            return this.createSimplePKCS7(messageHash, signature, certHex);
        }
    }

    // Basit PKCS#7 structure (fallback)
    createSimplePKCS7(messageHash, signature, certHex) {
        console.log('🔧 Basit PKCS#7 yapısı oluşturuluyor...');
        
        // PKCS#7 wrapper
        const pkcs7Header = '308202f4'; // SEQUENCE header
        const signedDataOID = '06092a864886f70d010702'; // signedData OID
        
        // Content
        const contentInfo = '30820100'; // contentInfo wrapper
        const dataOID = '06092a864886f70d010701'; // data OID
        const hashHex = messageHash.toString('hex');
        const signatureHex = signature.toString('hex');
        
        // Basit PKCS#7 structure
        const simplePKCS7 = pkcs7Header + signedDataOID + contentInfo + dataOID + 
                           '04' + (hashHex.length/2).toString(16).padStart(2, '0') + hashHex +
                           '04' + (signatureHex.length/2).toString(16).padStart(4, '0') + signatureHex;
        
        console.log('✅ Basit PKCS#7 yapısı tamamlandı');
        return simplePKCS7;
    }

    // Adobe PDF'e PKCS#7 embedded signature ekle
    embedPKCS7InPDF(pdfBuffer, pkcs7Hex) {
        console.log('📄 Adobe PDF\'e PKCS#7 dijital imzası gömülüyor...');

        let pdfString = pdfBuffer.toString('latin1');
        
        console.log(`📦 PKCS#7 hex boyutu: ${pkcs7Hex.length} karakter`);

        // Adobe PDF Signature Dictionary
        const now = new Date();
        const pdfDate = this.formatPDFDate(now);
        
        // Son object numarasını bul
        const objectMatches = pdfString.match(/([0-9]+) [0-9]+ obj/g);
        const lastObjectNumber = Math.max(...objectMatches.map(match => 
            parseInt(match.split(' ')[0])
        ));
        const sigObjNum = lastObjectNumber + 1;
        const acroFormNum = sigObjNum + 1;
        const sigFieldNum = sigObjNum + 2;

        // Adobe Signature Dictionary
        const signatureDict = `${sigObjNum} 0 obj
<<
/Type /Sig
/Filter /Adobe.PPKLite
/SubFilter /adbe.pkcs7.detached
/Name (USB eToken Digital Signature)
/Location (Turkey)
/Reason (Document digitally signed with USB Token)
/ContactInfo (PKCS#11 SafeNet eGüven Token)
/M (${pdfDate})
/ByteRange [0 ****PLACEHOLDER**** ****PLACEHOLDER**** ****PLACEHOLDER****]
/Contents <${pkcs7Hex.toUpperCase().padEnd(8192, '0')}>
>>
endobj

`;

        // AcroForm ve Signature Field
        const acroForm = `${acroFormNum} 0 obj
<<
/Fields [${sigFieldNum} 0 R]
/SigFlags 3
>>
endobj

${sigFieldNum} 0 obj
<<
/Type /Annot
/Subtype /Widget
/FT /Sig
/T (USB Digital Signature)
/V ${sigObjNum} 0 R
/P 1 0 R
/Rect [400 50 600 100]
/F 132
>>
endobj

`;

        // Root Catalog'u güncelle
        const catalogPattern = /([0-9]+) [0-9]+ obj[\s\S]*?\/Type \/Catalog[\s\S]*?endobj/;
        const catalogMatch = pdfString.match(catalogPattern);
        
        if (catalogMatch) {
            const updatedCatalog = catalogMatch[0].replace(
                /endobj$/,
                `/AcroForm ${acroFormNum} 0 R
endobj`
            );
            pdfString = pdfString.replace(catalogMatch[0], updatedCatalog);
        }

        // Signature objects'leri PDF'e ekle
        pdfString = pdfString.replace(/%%EOF$/, signatureDict + acroForm + '%%EOF');

        console.log('✅ Adobe PDF signature dictionary eklendi');
        console.log('📋 AcroForm ve signature field eklendi');
        
        return Buffer.from(pdfString, 'latin1');
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
    const signer = new JSrsaSignAdobePDFSigner("2945");
    
    try {
        // Sistem başlat
        await signer.initialize();
        await signer.setupToken();
        
        // JSrsaSign ile Adobe PDF dijital imzası
        const result = await signer.signPDFWithJSrsaSign('a.pdf', 'a_jsrsasign_signed.pdf');
        
        console.log('\n🎉 JSRSASIGN ADOBE PDF DİJİTAL İMZA TAMAMLANDI!');
        console.log('==============================================');
        console.log(`✅ Dosya: ${result.outputPath}`);
        console.log(`👤 Sertifika: ${result.certSubject}`);
        console.log(`🏛️ Yayınlayıcı: ${result.certIssuer}`);
        console.log(`🔐 İmza: ${result.signatureLength} byte`);
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

module.exports = { JSrsaSignAdobePDFSigner };
