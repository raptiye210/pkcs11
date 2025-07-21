// test_simple.js
const SafeNetTokenManager = require('./test4.js'); // veya aynı dosyada tanımladıysanız

async function simpleTest() {
    const tokenManager = new SafeNetTokenManager();

    try {
        console.log('=== SafeNet Token Test Başlıyor ===');
        
        console.log('\n1. Token başlatılıyor...');
        await tokenManager.initialize();
        
        console.log('\n2. PIN ile giriş yapılıyor...');
        const pin = '2945'; // Gerçek PIN'inizi yazın
        await tokenManager.login(pin);
        
        console.log('\n3. Sertifikalar okunuyor...');
        const certificates = await tokenManager.getCertificates();
        
        if (certificates.length > 0) {
            console.log('\n4. Sertifika bilgileri:');
            certificates.forEach((cert, index) => {
                console.log(`Sertifika ${index + 1}:`);
                console.log(`  Sahibi: ${cert.subject.getField('CN').value}`);
                console.log(`  Geçerlilik: ${cert.validity.notBefore} - ${cert.validity.notAfter}`);
            });
            
            console.log('\n5. Private key aranıyor...');
            const privateKey = await tokenManager.getPrivateKey();
            console.log(`Private key bulundu: ${privateKey}`);
            
            console.log('\n=== Test Başarılı! ===');
        }
        
    } catch (error) {
        console.error('\n=== Test Hatası ===');
        console.error('Hata:', error.message);
        console.error('Stack:', error.stack);
    } finally {
        tokenManager.cleanup();
    }
}

simpleTest();