const pkcs11js = require('pkcs11js');
const forge = require('node-forge');
const fs = require('fs');

class SafeNetTokenManager {
    constructor() {
        this.pkcs11 = new pkcs11js.PKCS11();
        this.session = null;
        this.debug = true; // Debug modu açık
    }

    log(message, data = null) {
        if (this.debug) {
            console.log(`[SafeNet Debug] ${message}`);
            if (data) console.log('[SafeNet Debug] Data:', data);
        }
    }

    async initialize() {
        try {
            this.log('Token başlatılıyor...');
            
            // Farklı olası PKCS#11 kütüphane yolları
            const possiblePaths = [
                "C:\\Windows\\System32\\eTPKCS11.dll",
                "C:\\Windows\\SysWOW64\\eTPKCS11.dll",
                "C:\\Program Files\\SafeNet\\Authentication\\SAC\\x64\\eTPKCS11.dll",
                "C:\\Program Files (x86)\\SafeNet\\Authentication\\SAC\\x32\\eTPKCS11.dll",
                "C:\\Windows\\System32\\dkck201.dll",
                "C:\\Windows\\System32\\dkck232.dll"
            ];

            let loadedPath = null;
            
            for (const path of possiblePaths) {
                try {
                    this.log(`Kütüphane yolu deneniyor: ${path}`);
                    if (fs.existsSync(path)) {
                        this.log(`Dosya mevcut: ${path}`);
                        this.pkcs11.load(path);
                        loadedPath = path;
                        this.log(`Kütüphane başarıyla yüklendi: ${path}`);
                        break;
                    } else {
                        this.log(`Dosya mevcut değil: ${path}`);
                    }
                } catch (error) {
                    this.log(`Kütüphane yüklenemedi: ${path}`, error.message);
                    continue;
                }
            }

            if (!loadedPath) {
                throw new Error('Hiçbir PKCS#11 kütüphanesi yüklenemedi. SafeNet driver\'ları yüklü mü?');
            }

            this.log('C_Initialize çağrılıyor...');
            this.pkcs11.C_Initialize();
            this.log('C_Initialize başarılı');

            this.log('Slotlar kontrol ediliyor...');
            const slots = this.pkcs11.C_GetSlotList(true);
            this.log(`Bulunan slot sayısı: ${slots.length}`, slots);

            if (slots.length === 0) {
                // Tüm slotları kontrol et (token olmasa bile)
                const allSlots = this.pkcs11.C_GetSlotList(false);
                this.log(`Toplam slot sayısı (token olmadan): ${allSlots.length}`, allSlots);
                
                if (allSlots.length > 0) {
                    // Her slot için bilgi al
                    for (let i = 0; i < allSlots.length; i++) {
                        try {
                            const slotInfo = this.pkcs11.C_GetSlotInfo(allSlots[i]);
                            this.log(`Slot ${i} bilgisi:`, {
                                slotDescription: slotInfo.slotDescription,
                                manufacturerID: slotInfo.manufacturerID,
                                flags: slotInfo.flags
                            });
                        } catch (error) {
                            this.log(`Slot ${i} bilgisi alınamadı:`, error.message);
                        }
                    }
                }
                
                throw new Error('Token takılı değil veya algılanamıyor. Token\'ı çıkarıp tekrar takın.');
            }

            // İlk slotu kullan
            const slot = slots[0];
            this.log(`Kullanılan slot: ${slot}`);

            // Slot bilgilerini al
            try {
                const slotInfo = this.pkcs11.C_GetSlotInfo(slot);
                this.log('Slot bilgileri:', {
                    slotDescription: slotInfo.slotDescription,
                    manufacturerID: slotInfo.manufacturerID,
                    hardwareVersion: slotInfo.hardwareVersion,
                    firmwareVersion: slotInfo.firmwareVersion
                });
            } catch (error) {
                this.log('Slot bilgileri alınamadı:', error.message);
            }

            // Token bilgilerini al
            try {
                const tokenInfo = this.pkcs11.C_GetTokenInfo(slot);
                this.log('Token bilgileri:', {
                    label: tokenInfo.label,
                    manufacturerID: tokenInfo.manufacturerID,
                    model: tokenInfo.model,
                    serialNumber: tokenInfo.serialNumber
                });
            } catch (error) {
                this.log('Token bilgileri alınamadı:', error.message);
            }

            this.log('Session açılıyor...');
            this.session = this.pkcs11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
            this.log(`Session açıldı: ${this.session}`);

            return this.session;
            
        } catch (error) {
            this.log('Token başlatma hatası:', error.message);
            console.error('Detaylı hata:', error);
            throw error;
        }
    }

    async login(pin) {
        try {
            this.log('Token girişi yapılıyor...');
            this.log(`PIN uzunluğu: ${pin ? pin.length : 'PIN yok'}`);
            
            this.pkcs11.C_Login(this.session, pkcs11js.CKU_USER, pin);
            this.log('Token girişi başarılı');
            
            // Session bilgilerini kontrol et
            try {
                const sessionInfo = this.pkcs11.C_GetSessionInfo(this.session);
                this.log('Session bilgileri:', {
                    state: sessionInfo.state,
                    flags: sessionInfo.flags,
                    slotID: sessionInfo.slotID
                });
            } catch (error) {
                this.log('Session bilgileri alınamadı:', error.message);
            }
            
        } catch (error) {
            this.log('Token giriş hatası:', error.message);
            
            // Yaygın hataları kontrol et
            if (error.message.includes('CKR_PIN_INCORRECT')) {
                throw new Error('PIN yanlış');
            } else if (error.message.includes('CKR_PIN_LOCKED')) {
                throw new Error('PIN kilitli - token\'ı resetleyin');
            } else if (error.message.includes('CKR_USER_ALREADY_LOGGED_IN')) {
                this.log('Kullanıcı zaten giriş yapmış');
                return;
            }
            
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
            
            this.log(`Bulunan sertifika objesi sayısı: ${objects.length}`, objects);

            const certificates = [];
            for (let i = 0; i < objects.length; i++) {
                try {
                    this.log(`Sertifika ${i} okunuyor...`);
                    
                    const certData = this.pkcs11.C_GetAttributeValue(this.session, objects[i], [
                        { type: pkcs11js.CKA_VALUE }
                    ])[0].value;
                    
                    this.log(`Sertifika ${i} veri boyutu: ${certData.length}`);
                    
                    const certificate = forge.pki.certificateFromAsn1(forge.asn1.fromDer(certData.toString('binary')));
                    certificates.push(certificate);
                    
                    this.log(`Sertifika ${i} başarıyla okundu`);
                    
                } catch (error) {
                    this.log(`Sertifika ${i} okunamadı:`, error.message);
                }
            }

            this.log(`Toplam okunan sertifika sayısı: ${certificates.length}`);
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

            this.log(`Bulunan private key sayısı: ${objects.length}`, objects);

            if (objects.length === 0) {
                throw new Error('Private key bulunamadı');
            }

            // İlk private key'i kullan
            const privateKey = objects[0];
            this.log(`Private key handle: ${privateKey}`);

            // Private key bilgilerini kontrol et
            try {
                const keyAttrs = this.pkcs11.C_GetAttributeValue(this.session, privateKey, [
                    { type: pkcs11js.CKA_MODULUS_BITS },
                    { type: pkcs11js.CKA_KEY_TYPE }
                ]);
                
                this.log('Private key bilgileri:', {
                    modulusBits: keyAttrs[0].value ? keyAttrs[0].value.readUInt32BE() : 'Bilinmeyen',
                    keyType: keyAttrs[1].value ? keyAttrs[1].value.readUInt32BE() : 'Bilinmeyen'
                });
            } catch (error) {
                this.log('Private key bilgileri alınamadı:', error.message);
            }

            return privateKey;
            
        } catch (error) {
            this.log('Private key okuma hatası:', error.message);
            throw error;
        }
    }

    cleanup() {
        try {
            this.log('Temizlik yapılıyor...');
            
            if (this.session) {
                try {
                    this.pkcs11.C_Logout(this.session);
                    this.log('Logout başarılı');
                } catch (error) {
                    this.log('Logout hatası:', error.message);
                }
                
                try {
                    this.pkcs11.C_CloseSession(this.session);
                    this.log('Session kapatıldı');
                } catch (error) {
                    this.log('Session kapatma hatası:', error.message);
                }
            }
            
            try {
                this.pkcs11.C_Finalize();
                this.log('C_Finalize başarılı');
            } catch (error) {
                this.log('C_Finalize hatası:', error.message);
            }
            
            this.log('Token bağlantısı temizlendi');
            
        } catch (error) {
            this.log('Temizleme hatası:', error.message);
        }
    }
}