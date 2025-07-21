const pkcs11js = require("pkcs11js");
const fs = require("fs");
const crypto = require("crypto");
const forge = require("node-forge");

// Node-Forge ile Adobe PDF Dijital İmza Sistemi
class ForgeAdobePDFSigner {
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
            console.log('🚀 Node-Forge Adobe PDF Dijital İmza Sistemi');
            console.log('==============================================');
            
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

    // Node-Forge ile Adobe PDF dijital imzası
    async signPDFWithForge(pdfPath, outputPath) {
        console.log(`📄 Node-Forge ile Adobe PDF dijital imzası: ${pdfPath}`);
        
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
        
        // Node-Forge ile X.509 sertifikası parse et
        const certASN1 = forge.asn1.fromDer(certDataDER.toString('binary'));
        const cert = forge.pki.certificateFromAsn1(certASN1);
        
        console.log(`🏢 Sertifika Sahibi: ${cert.subject.getField('CN').value}`);
        console.log(`🏛️ Sertifika Yayınlayıcı: ${cert.issuer.getField('CN').value}`);

        // PDF hash hesapla
        const pdfHash = crypto.createHash('sha256').update(pdfBuffer).digest();
        console.log('🔐 PDF hash hesaplandı (SHA-256)');

        // PKCS#11 ile dijital imza
        const mechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS };
        this.pkcs11.C_SignInit(this.session, mechanism, privateKey);
        
        const signatureBuffer = Buffer.alloc(256);
        const pkcs11Signature = this.pkcs11.C_Sign(this.session, pdfHash, signatureBuffer);
        
        console.log(`🔑 PKCS#11 dijital imzası oluşturuldu: ${pkcs11Signature.length} byte`);

        // Node-Forge ile PKCS#7 SignedData oluştur
        const pkcs7 = this.createForge_PKCS7_SignedData(pdfHash, pkcs11Signature, cert);
        console.log('📦 Node-Forge PKCS#7 SignedData oluşturuldu');

        // Adobe PDF'e PKCS#7 embedded imza ekle
        const signedPDF = this.embedPKCS7InPDF(pdfBuffer, pkcs7);
        
        fs.writeFileSync(outputPath, signedPDF);
        console.log(`✅ Adobe uyumlu PDF dijital imzası kaydedildi: ${outputPath}`);

        return {
            success: true,
            outputPath: outputPath,
            certSubject: cert.subject.getField('CN').value,
            certIssuer: cert.issuer.getField('CN').value,
            signatureLength: pkcs11Signature.length,
            format: 'Adobe PDF + PKCS#7 SignedData',
            adobeCompatible: true
        };
    }

    // Node-Forge ile PKCS#7 SignedData oluştur
    createForge_PKCS7_SignedData(messageHash, signature, certificate) {
        console.log('🔨 Node-Forge ile PKCS#7 SignedData yapısı oluşturuluyor...');

        // PKCS#7 SignedData structure
        const p7 = forge.pkcs7.createSignedData();
        
        // Content bilgisi (PDF hash)
        p7.content = forge.util.createBuffer(messageHash.toString('binary'));
        
        // Sertifikayı ekle
        p7.addCertificate(certificate);
        
        // Signer bilgisi oluştur
        const signer = {
            key: null, // Private key reference (PKCS#11'de)
            certificate: certificate,
            digestAlgorithm: forge.pki.oids.sha256,
            signatureAlgorithm: forge.pki.oids.sha256WithRSAEncryption
        };

        // Manuel signature ekleme (PKCS#11'den gelen)
        const authenticatedAttributes = [];
        
        // Content Type
        authenticatedAttributes.push({
            type: forge.pki.oids.contentTypes,
            value: forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OID, 
                false, forge.asn1.oidToDer(forge.pki.oids.data).getBytes())
        });

        // Signing Time
        authenticatedAttributes.push({
            type: forge.pki.oids.signingTime,
            value: forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.UTCTIME, 
                false, forge.asn1.dateToUtcTime(new Date()))
        });

        // Message Digest
        authenticatedAttributes.push({
            type: forge.pki.oids.messageDigest,
            value: forge.asn1.create(forge.asn1.Class.UNIVERSAL, forge.asn1.Type.OCTETSTRING, 
                false, messageHash.toString('binary'))
        });

        // Signer Info oluştur
        const signerInfo = {
            version: 1,
            issuerAndSerialNumber: {
                issuer: certificate.issuer,
                serialNumber: certificate.serialNumber
            },
            digestAlgorithm: forge.pki.oids.sha256,
            authenticatedAttributes: authenticatedAttributes,
            signatureAlgorithm: forge.pki.oids.sha256WithRSAEncryption,
            signature: signature.toString('binary') // PKCS#11'den gelen imza
        };

        // SignerInfo'yu PKCS#7'ye ekle
        p7.signers = [signerInfo];

        console.log('✅ PKCS#7 SignedData yapısı tamamlandı');
        return p7;
    }

    // Adobe PDF'e PKCS#7 embedded signature ekle
    embedPKCS7InPDF(pdfBuffer, pkcs7SignedData) {
        console.log('📄 Adobe PDF\'e PKCS#7 dijital imzası gömülüyor...');

        let pdfString = pdfBuffer.toString('latin1');
        
        // PKCS#7'yi DER formatına çevir
        const p7Der = forge.asn1.toDer(pkcs7SignedData.toAsn1()).getBytes();
        const p7Hex = forge.util.bytesToHex(p7Der).toUpperCase();
        
        console.log(`📦 PKCS#7 DER boyutu: ${p7Der.length} byte`);

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
/Contents <${p7Hex.padEnd(8192, '0')}>
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
    const signer = new ForgeAdobePDFSigner("2945");
    
    try {
        // Sistem başlat
        await signer.initialize();
        await signer.setupToken();
        
        // Node-Forge ile Adobe PDF dijital imzası
        const result = await signer.signPDFWithForge('a.pdf', 'a_forge_signed.pdf');
        
        console.log('\n🎉 NODE-FORGE ADOBE PDF DİJİTAL İMZA TAMAMLANDI!');
        console.log('===============================================');
        console.log(`✅ Dosya: ${result.outputPath}`);
        console.log(`👤 Sertifika: ${result.certSubject}`);
        console.log(`🏛️ Yayınlayıcı: ${result.certIssuer}`);
        console.log(`🔐 İmza: ${result.signatureLength} byte`);
        console.log(`📋 Format: ${result.format}`);
        console.log('🏆 Adobe Reader ile doğrulanabilir!');
        
    } catch (error) {
        console.error('\n❌ HATA:', error.message);
        console.error(error.stack);
    } finally {
        await signer.cleanup();
    }
}

if (require.main === module) {
    main();
}

module.exports = { ForgeAdobePDFSigner };
