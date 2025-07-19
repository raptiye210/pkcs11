const pkcs11 = require('pkcs11js');

// SafeNet eGüven token için PKCS#11 modülü yolları
const PKCS11_MODULES = [
    'C:\\Windows\\System32\\eTPKCS11.dll',
    'C:\\Windows\\SysWOW64\\eTPKCS11.dll',
    'C:\\Program Files\\SafeNet\\eToken\\libs\\eToken.dll',
    'C:\\Program Files (x86)\\SafeNet\\eToken\\libs\\eToken.dll'
];

class RealPKCS11TokenReader {
    constructor() {
        this.pkcs11Module = null;
        this.session = null;
        this.slot = null;
    }

    // PKCS#11 modülünü yükle
    async loadPKCS11Module() {
        console.log('🔍 PKCS#11 modülü aranıyor...');
        
        for (const modulePath of PKCS11_MODULES) {
            try {
                const fs = require('fs');
                if (fs.existsSync(modulePath)) {
                    console.log(`📁 PKCS#11 modülü bulundu: ${modulePath}`);
                    
                    // PKCS#11 modülünü yükle
                    const mod = new pkcs11.PKCS11();
                    mod.load(modulePath);
                    
                    // Başlat
                    mod.C_Initialize();
                    
                    this.pkcs11Module = mod;
                    console.log('✅ PKCS#11 modülü başarıyla yüklendi!');
                    return true;
                }
            } catch (error) {
                console.log(`⚠️ ${modulePath} yüklenemedi: ${error.message}`);
            }
        }
        
        throw new Error('❌ Hiçbir PKCS#11 modülü bulunamadı veya yüklenemedi');
    }

    // USB token slot'larını bul
    async findTokenSlots() {
        if (!this.pkcs11Module) {
            throw new Error('PKCS#11 modülü yüklenmemiş');
        }

        console.log('🔍 USB token slot\'ları aranıyor...');
        
        // Tüm slot'ları al (token var olan)
        const slots = this.pkcs11Module.C_GetSlotList(true);
        
        if (slots.length === 0) {
            throw new Error('❌ Hiçbir USB token bulunamadı');
        }

        console.log(`📱 ${slots.length} adet USB token slot bulundu:`);
        
        // Her slot için bilgi al
        for (let i = 0; i < slots.length; i++) {
            const slotInfo = this.pkcs11Module.C_GetSlotInfo(slots[i]);
            const tokenInfo = this.pkcs11Module.C_GetTokenInfo(slots[i]);
            
            console.log(`\n  Slot ${i + 1}:`);
            console.log(`    Slot ID: ${slots[i]}`);
            console.log(`    Açıklama: ${slotInfo.slotDescription.trim()}`);
            console.log(`    Üretici: ${slotInfo.manufacturerID.trim()}`);
            console.log(`    Token Etiketi: ${tokenInfo.label.trim()}`);
            console.log(`    Token Üreticisi: ${tokenInfo.manufacturerID.trim()}`);
            console.log(`    Token Modeli: ${tokenInfo.model.trim()}`);
            console.log(`    Seri No: ${tokenInfo.serialNumber.trim()}`);
            
            // İlk token'ı kullan
            if (i === 0) {
                this.slot = slots[i];
            }
        }

        return slots;
    }

    // USB token ile oturum aç
    async openSession(pin = '2945') {
        if (!this.pkcs11Module || this.slot === null) {
            throw new Error('Token slot seçilmemiş');
        }

        console.log(`\n🔐 Token oturumu açılıyor (Slot ${this.slot})...`);
        
        // Oturum aç
        this.session = this.pkcs11Module.C_OpenSession(this.slot, pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION);
        console.log(`✅ Oturum açıldı: ${this.session}`);
        
        // PIN ile giriş yap
        console.log('🔑 PIN ile giriş yapılıyor...');
        this.pkcs11Module.C_Login(this.session, pkcs11.CKU_USER, pin);
        console.log('✅ PIN doğrulandı, oturum hazır!');
        
        return this.session;
    }

    // Token'daki tüm sertifikaları listele
    async listCertificates() {
        if (!this.session) {
            throw new Error('Oturum açılmamış');
        }

        console.log('\n📜 USB token\'daki sertifikalar aranıyor...');
        
        // Sertifika nesnelerini ara
        this.pkcs11Module.C_FindObjectsInit(this.session, [{
            type: pkcs11.CKA_CLASS,
            value: pkcs11.CKO_CERTIFICATE
        }]);

        const certificateHandles = this.pkcs11Module.C_FindObjects(this.session);
        this.pkcs11Module.C_FindObjectsFinal(this.session);

        if (certificateHandles.length === 0) {
            console.log('❌ Token\'da hiç sertifika bulunamadı');
            return [];
        }

        console.log(`✅ ${certificateHandles.length} adet sertifika bulundu:\n`);

        const certificates = [];

        for (let i = 0; i < certificateHandles.length; i++) {
            const handle = certificateHandles[i];
            
            try {
                console.log(`📋 Sertifika ${i + 1}:`);
                console.log(`   Handle: ${handle}`);
                
                // Her özniteliği ayrı ayrı al
                try {
                    const labelAttr = this.pkcs11Module.C_GetAttributeValue(this.session, handle, [{ type: pkcs11.CKA_LABEL }]);
                    const label = labelAttr[0].value ? labelAttr[0].value.toString().trim() : 'No Label';
                    console.log(`   Etiket: ${label}`);
                } catch (e) {
                    console.log(`   Etiket: okunamadı (${e.message})`);
                }
                
                try {
                    const subjectAttr = this.pkcs11Module.C_GetAttributeValue(this.session, handle, [{ type: pkcs11.CKA_SUBJECT }]);
                    const subject = subjectAttr[0].value ? this.parseDN(subjectAttr[0].value) : 'Unknown Subject';
                    console.log(`   Konu: ${subject}`);
                } catch (e) {
                    console.log(`   Konu: okunamadı (${e.message})`);
                }
                
                try {
                    const issuerAttr = this.pkcs11Module.C_GetAttributeValue(this.session, handle, [{ type: pkcs11.CKA_ISSUER }]);
                    const issuer = issuerAttr[0].value ? this.parseDN(issuerAttr[0].value) : 'Unknown Issuer';
                    console.log(`   Veren: ${issuer}`);
                } catch (e) {
                    console.log(`   Veren: okunamadı (${e.message})`);
                }
                
                try {
                    const serialAttr = this.pkcs11Module.C_GetAttributeValue(this.session, handle, [{ type: pkcs11.CKA_SERIAL_NUMBER }]);
                    const serialNumber = serialAttr[0].value ? serialAttr[0].value.toString('hex').toUpperCase() : 'Unknown';
                    console.log(`   Seri No: ${serialNumber}`);
                } catch (e) {
                    console.log(`   Seri No: okunamadı (${e.message})`);
                }

                // Basit sertifika verisi
                const certData = {
                    handle: handle,
                    label: 'Token Certificate ' + (i + 1),
                    available: true
                };

                certificates.push(certData);
                console.log('   ✅ Sertifika erişilebilir\n');

            } catch (error) {
                console.error(`⚠️ Sertifika ${i + 1} okunamadı:`, error.message);
            }
        }

        return certificates;
    }

    // DN (Distinguished Name) parse et
    parseDN(dnBuffer) {
        try {
            // Basit DN parsing - gerçek ASN.1 parsing yerine
            const dnStr = Buffer.from(dnBuffer).toString('utf8');
            return dnStr.replace(/[\\x00-\\x1F\\x7F-\\xFF]/g, '').trim() || 'Parse Error';
        } catch (error) {
            return 'Parse Error';
        }
    }

    // Private key'leri listele
    async listPrivateKeys() {
        if (!this.session) {
            throw new Error('Oturum açılmamış');
        }

        console.log('\n🔑 USB token\'daki private key\'ler aranıyor...');
        
        // Private key nesnelerini ara
        this.pkcs11Module.C_FindObjectsInit(this.session, [{
            type: pkcs11.CKA_CLASS,
            value: pkcs11.CKO_PRIVATE_KEY
        }]);

        const keyHandles = this.pkcs11Module.C_FindObjects(this.session);
        this.pkcs11Module.C_FindObjectsFinal(this.session);

        console.log(`🔐 ${keyHandles.length} adet private key bulundu:\n`);

        for (let i = 0; i < keyHandles.length; i++) {
            const handle = keyHandles[i];
            
            try {
                console.log(`🔑 Private Key ${i + 1}:`);
                console.log(`   Handle: ${handle}`);
                
                // Her özniteliği ayrı ayrı al
                try {
                    const labelAttr = this.pkcs11Module.C_GetAttributeValue(this.session, handle, [{ type: pkcs11.CKA_LABEL }]);
                    const label = labelAttr[0].value ? labelAttr[0].value.toString().trim() : 'No Label';
                    console.log(`   Etiket: ${label}`);
                } catch (e) {
                    console.log(`   Etiket: okunamadı (${e.message})`);
                }
                
                try {
                    const keyTypeAttr = this.pkcs11Module.C_GetAttributeValue(this.session, handle, [{ type: pkcs11.CKA_KEY_TYPE }]);
                    const keyType = keyTypeAttr[0].value ? keyTypeAttr[0].value.readUInt32LE(0) : 'Unknown';
                    console.log(`   Key Type: ${keyType === pkcs11.CKK_RSA ? 'RSA' : 'Other (' + keyType + ')'}`);
                } catch (e) {
                    console.log(`   Key Type: okunamadı (${e.message})`);
                }
                
                console.log(`   ✅ Private Key erişilebilir\n`);

            } catch (error) {
                console.error(`⚠️ Private Key ${i + 1} okunamadı:`, error.message);
            }
        }

        return keyHandles;
    }

    // Temizlik
    async cleanup() {
        try {
            if (this.session) {
                this.pkcs11Module.C_Logout(this.session);
                this.pkcs11Module.C_CloseSession(this.session);
            }
            if (this.pkcs11Module) {
                this.pkcs11Module.C_Finalize();
            }
            console.log('✅ PKCS#11 temizlendi');
        } catch (error) {
            console.log('⚠️ Temizleme hatası:', error.message);
        }
    }
}

// Ana fonksiyon
async function main() {
    const tokenReader = new RealPKCS11TokenReader();
    
    try {
        console.log('🚀 GERÇEK PKCS#11 USB TOKEN OKUYUCU');
        console.log('=====================================');
        console.log('SafeNet eGüven USB token\'ından sertifika okuma\n');

        // 1. PKCS#11 modülünü yükle
        await tokenReader.loadPKCS11Module();

        // 2. Token slot'larını bul
        await tokenReader.findTokenSlots();

        // 3. Token ile oturum aç
        await tokenReader.openSession('2945'); // PIN

        // 4. Sertifikaları listele
        const certificates = await tokenReader.listCertificates();

        // 5. Private key'leri listele
        await tokenReader.listPrivateKeys();

        console.log('\n🎉 İŞLEM TAMAMLANDI!');
        console.log(`📋 Toplam ${certificates.length} sertifika bulundu`);
        console.log('🔐 Token hazır, PDF imzalama için kullanılabilir');

    } catch (error) {
        console.error('\n❌ HATA:', error.message);
        console.log('\n🛠️ Sorun Giderme:');
        console.log('1. SafeNet eGüven USB token takılı olduğundan emin olun');
        console.log('2. Token sürücülerinin yüklü olduğunu kontrol edin');
        console.log('3. PIN kodunun doğru olduğundan emin olun (2945)');
        console.log('4. Uygulamayı yönetici olarak çalıştırın');
    } finally {
        // Temizlik
        await tokenReader.cleanup();
    }
}

// Çalıştır
if (require.main === module) {
    main();
}

module.exports = { RealPKCS11TokenReader };
