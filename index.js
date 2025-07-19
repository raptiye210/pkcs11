const pkcs11js = require("pkcs11js");
const fs = require("fs");
const crypto = require("crypto");

// PKCS#11 SafeNet eGüven Token Reader
class SafeNetTokenReader {
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
            console.log('🚀 SafeNet eGüven PKCS#11 Token Reader');
            console.log('=====================================');
            
            this.pkcs11.load(this.libraryPath);
            this.pkcs11.C_Initialize();
            this.isInitialized = true;
            
            console.log('✅ PKCS#11 kütüphanesi yüklendi ve başlatıldı');
            return true;
        } catch (error) {
            console.error('❌ PKCS#11 başlatma hatası:', error.message);
            throw error;
        }
    }

    // Token slot'larını bul
    async findTokenSlots() {
        if (!this.isInitialized) {
            throw new Error('PKCS#11 başlatılmamış');
        }

        console.log('🔍 USB token slot\'ları aranıyor...');
        
        const slots = this.pkcs11.C_GetSlotList(true);
        if (slots.length === 0) {
            throw new Error('❌ Hiçbir USB token bulunamadı');
        }

        console.log(`📱 Bulunan slot sayısı: ${slots.length}`);
        this.slot = slots[0];
        return slots;
    }

    // Token oturum aç
    async openSession() {
        if (!this.slot) {
            throw new Error('Token slot seçilmemiş');
        }

        console.log('🔐 Token oturumu açılıyor...');
        
        this.session = this.pkcs11.C_OpenSession(
            this.slot, 
            pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION
        );
        
        this.pkcs11.C_Login(this.session, pkcs11js.CKU_USER, this.pin);
        console.log('✅ Oturum açıldı ve PIN ile giriş yapıldı');
        
        return this.session;
    }

    // Token'daki sertifika ve anahtarları listele
    async listTokenObjects() {
        if (!this.session) {
            throw new Error('Oturum açılmamış');
        }

        console.log('📜 Token nesneleri taranıyor...');
        
        // Tüm nesneleri al
        this.pkcs11.C_FindObjectsInit(this.session, []);
        const objects = this.pkcs11.C_FindObjects(this.session, 100);
        this.pkcs11.C_FindObjectsFinal(this.session);

        console.log('🔍 Sertifika ve private key\'ler filtreleniyor...');

        const CKO_CERTIFICATE = 1;
        const CKO_PRIVATE_KEY = 3;
        const filteredObjects = [];

        for (const obj of objects) {
            try {
                const attrs = this.pkcs11.C_GetAttributeValue(this.session, obj, [
                    { type: pkcs11js.CKA_LABEL },
                    { type: pkcs11js.CKA_CLASS },
                ]);
                
                const clazz = attrs[1]?.value ? attrs[1].value.readUInt32LE(0) : null;
                
                if (clazz === CKO_CERTIFICATE || clazz === CKO_PRIVATE_KEY) {
                    const label = attrs[0]?.value ? attrs[0].value.toString() : "<Etiket yok>";
                    
                    filteredObjects.push({
                        handle: obj,
                        class: clazz,
                        label: label,
                        type: clazz === CKO_CERTIFICATE ? "Sertifika" : "Private Key"
                    });
                }
            } catch (err) {
                console.log('⚠️ Nesne okunamadı:', err.message);
            }
        }

        console.log(`📋 Toplam sertifika ve anahtar sayısı: ${filteredObjects.length}`);
        
        for (const obj of filteredObjects) {
            console.log(`   ${obj.type}: "${obj.label}"`);
        }

        return filteredObjects;
    }

    // Token'daki sertifika ve private key'ini bul
    async findCertificate() {
        const objects = await this.listTokenObjects();
        
        console.log('🔍 Sertifika ve private key aranıyor...');

        const certificate = objects.find(obj => obj.class === 1);
        const privateKey = objects.find(obj => obj.class === 3);

        if (!certificate) {
            throw new Error('❌ Sertifika bulunamadı');
        }

        if (!privateKey) {
            throw new Error('❌ Private key bulunamadı');
        }

        console.log('✅ Sertifika bulundu');
        console.log('✅ Private key bulundu');

        return {
            certificate: certificate,
            privateKey: privateKey
        };
    }

    // Sertifika verilerini al ve kaydet
    async extractCertificate(certHandle) {
        console.log('📄 Sertifika verileri çıkarılıyor...');
        
        const certAttrs = this.pkcs11.C_GetAttributeValue(this.session, certHandle, [
            { type: pkcs11js.CKA_VALUE },
        ]);
        
        const certificate = certAttrs[0].value;
        
        // DER formatında kaydet
        fs.writeFileSync("certificate.der", certificate);
        console.log('💾 Sertifika DER formatında kaydedildi: certificate.der');

        // PEM formatına çevir ve kaydet
        const certificatePem = `-----BEGIN CERTIFICATE-----\n${certificate.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;
        fs.writeFileSync("certificate.pem", certificatePem);
        console.log('💾 Sertifika PEM formatında kaydedildi: certificate.pem');

        return {
            der: certificate,
            pem: certificatePem
        };
    }

    // Test imzalama işlemi
    async testSigning(privateKeyHandle, testData = "Test verisi") {
        console.log('🔐 Test imzalama işlemi başlatılıyor...');
        
        // Test verisinin hash'ini al
        const hash = crypto.createHash("sha256").update(testData).digest();
        console.log('📋 Test verisi hash\'i hesaplandı');
        
        // İmza işlemini başlat
        const mechanism = { mechanism: pkcs11js.CKM_SHA256_RSA_PKCS };
        this.pkcs11.C_SignInit(this.session, mechanism, privateKeyHandle);
        console.log('✅ İmza işlemi başlatıldı');

        // İmzala
        const MAX_SIGNATURE_LENGTH = 256;
        const signatureBuffer = Buffer.alloc(MAX_SIGNATURE_LENGTH);
        const signature = this.pkcs11.C_Sign(this.session, hash, signatureBuffer);
        
        console.log(`📋 İmza uzunluğu: ${signature.length} byte`);
        console.log(`🔐 İmza (Base64): ${signature.toString("base64").substring(0, 64)}...`);
        
        return signature;
    }

    // Temizlik
    async cleanup() {
        try {
            if (this.session) {
                this.pkcs11.C_Logout(this.session);
                this.pkcs11.C_CloseSession(this.session);
                console.log('✅ Oturum kapatıldı');
            }
            
            if (this.isInitialized) {
                this.pkcs11.C_Finalize();
                console.log('✅ PKCS#11 kütüphanesi kapatıldı');
            }
        } catch (error) {
            console.log('⚠️ Temizleme hatası:', error.message);
        }
    }
}

// Ana fonksiyon
async function main() {
    const tokenReader = new SafeNetTokenReader("2945");
    
    try {
        // 1. PKCS#11 başlat
        await tokenReader.initialize();
        
        // 2. Token slot'larını bul
        await tokenReader.findTokenSlots();
        
        // 3. Oturum aç
        await tokenReader.openSession();
        
        // 4. Token nesnelerini listele
        await tokenReader.listTokenObjects();
        
        // 5. Sertifika ve private key'ini bul
        const certs = await tokenReader.findCertificate();
        
        // 6. Sertifika verilerini çıkar
        const certData = await tokenReader.extractCertificate(certs.certificate.handle);
        
        // 7. Test imzalama
        const signature = await tokenReader.testSigning(certs.privateKey.handle);
        
        console.log('\n🎉 İŞLEMLER BAŞARIYLA TAMAMLANDI!');
        console.log('===============================');
        console.log('✅ SafeNet eGüven token okundu');
        console.log('✅ Sertifika bulundu');
        console.log('✅ Sertifika DER/PEM formatında kaydedildi');
        console.log('✅ Test imzalama başarılı');
        console.log('\n📋 Sonuç:');
        console.log(`   Sertifika: ${certs.certificate.label}`);
        console.log(`   Private Key: ${certs.privateKey.label}`);
        console.log(`   İmza boyutu: ${signature.length} byte`);
        console.log('\n🔐 Token hazır - PDF imzalama için kullanılabilir!');

    } catch (error) {
        console.error('\n❌ HATA:', error.message);
        console.log('\n🛠️ Sorun Giderme:');
        console.log('1. SafeNet eGüven USB token takılı olduğundan emin olun');
        console.log('2. PIN kodunun doğru olduğundan emin olun (2945)');
        console.log('3. Token sürücülerinin yüklü olduğunu kontrol edin');
        console.log('4. Uygulamayı yönetici olarak çalıştırın');
    } finally {
        await tokenReader.cleanup();
    }
}

// Çalıştır
if (require.main === module) {
    main();
}

module.exports = { SafeNetTokenReader };