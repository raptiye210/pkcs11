// test_token.js
const pkcs11js = require('pkcs11js');
const forge = require('node-forge');
const fs = require('fs');

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

    async initialize() {
        try {
            this.log('Token başlatılıyor...');
            
            this.pkcs11.load("C:\\Windows\\System32\\eTPKCS11.dll");
            this.pkcs11.C_Initialize();
            
            const slots = this.pkcs11.C_GetSlotList(true);
            this.log(`Token\'lı slot sayısı: ${slots.length}`);

            if (slots.length === 0) {
                throw new Error('Token bulunamadı');
            }

            const slot = slots[0];
            this.log(`Kullanılan slot: ${slot}`);

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
                this.log('Token bilgileri alınamadı:', error.message);
            }

            this.session = this.pkcs11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
            this.log(`Session açıldı: ${this.session}`);

            return this.session;
            
        } catch (error) {
            this.log('Hata:', error.message);
            throw error;
        }
    }

    async login(pin) {
        try {
            this.log(`PIN ile giriş yapılıyor... (PIN uzunluğu: ${pin.length})`);
            this.pkcs11.C_Login(this.session, pkcs11js.CKU_USER, pin);
            this.log('Giriş başarılı');
        } catch (error) {
            this.log('Giriş hatası:', error.message);
            throw error;
        }
    }

    async getCertificates() {
        try {
            this.log('Sertifikalar aranıyor...');
            
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
                    this.log(`Sertifika ${i + 1} okunamadı:`, error.message);
                }
            }

            return certificates;
        } catch (error) {
            this.log('Sertifika okuma hatası:', error.message);
            throw error;
        }
    }

    async getPrivateKey() {
        try {
            this.log('Private key aranıyor...');
            
            const template = [
                { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
                { type: pkcs11js.CKA_KEY_TYPE, value: pkcs11js.CKK_RSA }
            ];

            this.pkcs11.C_FindObjectsInit(this.session, template);
            const objects = this.pkcs11.C_FindObjects(this.session, 5);
            this.pkcs11.C_FindObjectsFinal(this.session);

            this.log(`Bulunan private key: ${objects.length}`);

            if (objects.length === 0) {
                throw new Error('Private key bulunamadı');
            }

            return objects[0];
        } catch (error) {
            this.log('Private key hatası:', error.message);
            throw error;
        }
    }


















async signData(data, privateKeyHandle) {
    try {
        this.log(`İmzalanacak veri boyutu: ${data.length}`);
        
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
                this.log('Key boyutu belirlenemedi, varsayılan 256 byte kullanılıyor');
            }
        }
        
        // Uygun boyutta buffer oluştur ve imzala
        const signatureBuffer = Buffer.alloc(signatureLength);
        const actualSignature = this.pkcs11.C_Sign(this.session, dataToSign, signatureBuffer);
        
        this.log(`İmza oluşturuldu, boyut: ${actualSignature.length}`);
        return actualSignature;
        
    } catch (error) {
        this.log('İmzalama hatası:', error.message);
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
            this.log('Temizlik tamamlandı');
        } catch (error) {
            this.log('Temizlik hatası:', error.message);
        }
    }
}

// Test fonksiyonu
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
                console.log('Sertifika sahibi okunamadı');
            }
            
            const privateKey = await tokenManager.getPrivateKey();
            console.log('Private key bulundu:', privateKey);
            
            // Test imzalama
            const testData = Buffer.from('test data for signing');
            console.log('\nTest imzalaması yapılıyor...');
            const signature = await tokenManager.signData(testData, privateKey);
            console.log('Test imzalaması başarılı! İmza boyutu:', signature.length);
            
            console.log('\n=== Test Başarılı! ===');
        }
        
    } catch (error) {
        console.error('\n=== Test Hatası ===');
        console.error('Hata:', error.message);
    } finally {
        tokenManager.cleanup();
    }
}

testToken();