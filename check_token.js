// check_token.js
const pkcs11js = require('pkcs11js');

function checkToken() {
    const pkcs11 = new pkcs11js.PKCS11();
    
    try {
        console.log('1. PKCS#11 kütüphanesi yükleniyor...');
        pkcs11.load("C:\\Windows\\System32\\eTPKCS11.dll");
        
        console.log('2. C_Initialize...');
        pkcs11.C_Initialize();
        
        console.log('3. Slotlar kontrol ediliyor...');
        const allSlots = pkcs11.C_GetSlotList(false);
        console.log(`Toplam slot: ${allSlots.length}`);
        
        const tokenSlots = pkcs11.C_GetSlotList(true);
        console.log(`Token\'lı slot: ${tokenSlots.length}`);
        
        if (allSlots.length === 0) {
            console.log('Hiç slot bulunamadı - Driver problemi olabilir');
        }
        
        pkcs11.C_Finalize();
        
    } catch (error) {
        console.error('Kontrol hatası:', error);
    }
}

checkToken();