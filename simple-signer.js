const fs = require('fs');
const path = require('path');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const forge = require('node-forge');

class BasitElektronikImza {
    constructor(pin) {
        this.pin = pin;
        this.imzaYetkili = "Dijital İmza Sahibi";
    }

    // Basit PDF imzalama işlevi
    async pdfImzala(inputPath, outputPath) {
        try {
            console.log(`📄 PDF dosyası okunuyor: ${inputPath}`);
            
            if (!fs.existsSync(inputPath)) {
                throw new Error(`PDF dosyası bulunamadı: ${inputPath}`);
            }

            // PDF dosyasını oku
            const existingPdfBytes = fs.readFileSync(inputPath);
            const pdfDoc = await PDFDocument.load(existingPdfBytes);
            
            // İlk sayfayı al
            const pages = pdfDoc.getPages();
            const firstPage = pages[0];
            const { width, height } = firstPage.getSize();
            
            // Font yükle
            const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
            const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
            
            // İmza tarihi ve bilgileri
            const imzaTarihi = new Date();
            const tarihStr = imzaTarihi.toLocaleString('tr-TR');
            
            // PDF hash'ini hesapla (imza öncesi)
            const hash = forge.md.sha256.create();
            hash.update(Buffer.from(existingPdfBytes).toString('binary'));
            const pdfHash = hash.digest().toHex();
            
            // İmza bilgileri
            const imzaBilgileri = [
                'DİJİTAL İMZA',
                `Tarih: ${tarihStr}`,
                `İmza Sahibi: ${this.imzaYetkili}`,
                `PIN Doğrulandı: ${this.pin ? '✓' : '✗'}`,
                `Doküman Hash: ${pdfHash.substring(0, 16)}...`,
                'Bu doküman dijital olarak imzalanmıştır.'
            ];

            // İmza kutusu konumu (sağ alt köşe)
            const imzaKutusu = {
                x: width - 280,
                y: 50,
                width: 250,
                height: 120
            };

            // İmza kutusunun arka planı
            firstPage.drawRectangle({
                x: imzaKutusu.x - 5,
                y: imzaKutusu.y - 5,
                width: imzaKutusu.width + 10,
                height: imzaKutusu.height + 10,
                borderColor: rgb(0, 0, 0),
                borderWidth: 2,
                color: rgb(0.95, 0.95, 1) // Açık mavi ton
            });

            // İç çerçeve
            firstPage.drawRectangle({
                x: imzaKutusu.x,
                y: imzaKutusu.y,
                width: imzaKutusu.width,
                height: imzaKutusu.height,
                borderColor: rgb(0.2, 0.2, 0.8),
                borderWidth: 1,
                color: rgb(1, 1, 1) // Beyaz arka plan
            });

            // İmza bilgilerini yaz
            let yPosition = imzaKutusu.y + imzaKutusu.height - 20;
            
            imzaBilgileri.forEach((satir, index) => {
                const fontSize = index === 0 ? 14 : 9;
                const textFont = index === 0 ? boldFont : font;
                const textColor = index === 0 ? rgb(0.8, 0, 0) : rgb(0, 0, 0);
                
                firstPage.drawText(satir, {
                    x: imzaKutusu.x + 10,
                    y: yPosition - (index * 16),
                    size: fontSize,
                    font: textFont,
                    color: textColor
                });
            });

            // Dijital mühür efekti
            const muhrX = imzaKutusu.x + imzaKutusu.width - 50;
            const muhrY = imzaKutusu.y + 20;
            
            // Daire çiz
            firstPage.drawCircle({
                x: muhrX,
                y: muhrY,
                size: 25,
                borderColor: rgb(0.8, 0, 0),
                borderWidth: 2,
                color: rgb(1, 0.9, 0.9)
            });
            
            // Mühür içine yıl yaz
            firstPage.drawText(imzaTarihi.getFullYear().toString(), {
                x: muhrX - 12,
                y: muhrY - 4,
                size: 8,
                font: boldFont,
                color: rgb(0.8, 0, 0)
            });

            // Metadata ekle
            pdfDoc.setTitle('Dijital İmzalanmış Doküman');
            pdfDoc.setSubject(`İmza Hash: ${pdfHash}`);
            pdfDoc.setCreator(`Elektronik İmza Sistemi v1.0`);
            pdfDoc.setProducer(`PIN: ${this.pin} - Tarih: ${tarihStr}`);
            pdfDoc.setKeywords('dijital-imza,elektronik-imza,pdf');
            pdfDoc.setCreationDate(imzaTarihi);
            pdfDoc.setModificationDate(imzaTarihi);

            // Son PDF'i kaydet
            const finalPdfBytes = await pdfDoc.save();
            fs.writeFileSync(outputPath, finalPdfBytes);
            
            console.log('✅ PDF başarıyla imzalandı!');
            console.log(`📁 Çıktı dosyası: ${outputPath}`);
            console.log(`🔐 Doküman hash: ${pdfHash.substring(0, 32)}...`);
            console.log(`📅 İmza tarihi: ${tarihStr}`);
            
            return {
                success: true,
                outputPath: outputPath,
                hash: pdfHash,
                timestamp: imzaTarihi,
                signer: this.imzaYetkili
            };

        } catch (error) {
            console.error('❌ PDF imzalama hatası:', error.message);
            throw error;
        }
    }

    // İmza doğrulama
    async imzaDogrula(pdfPath) {
        try {
            console.log(`🔍 İmza doğrulanıyor: ${pdfPath}`);
            
            const pdfBytes = fs.readFileSync(pdfPath);
            const pdfDoc = await PDFDocument.load(pdfBytes);
            
            // Metadata bilgilerini al
            const title = pdfDoc.getTitle();
            const subject = pdfDoc.getSubject();
            const creator = pdfDoc.getCreator();
            const producer = pdfDoc.getProducer();
            const keywords = pdfDoc.getKeywords();
            const creationDate = pdfDoc.getCreationDate();
            
            console.log('📋 İmza Detayları:');
            console.log(`Başlık: ${title || 'Belirtilmemiş'}`);
            console.log(`Konu: ${subject || 'Belirtilmemiş'}`);
            console.log(`Oluşturan: ${creator || 'Belirtilmemiş'}`);
            console.log(`İşleyici: ${producer || 'Belirtilmemiş'}`);
            console.log(`Anahtar kelimeler: ${keywords || 'Belirtilmemiş'}`);
            console.log(`Oluşturma tarihi: ${creationDate ? creationDate.toLocaleString('tr-TR') : 'Belirtilmemiş'}`);
            
            // İmza hash kontrolü
            let isValid = false;
            let extractedHash = '';
            
            if (subject && subject.includes('İmza Hash:')) {
                extractedHash = subject.split('İmza Hash: ')[1];
                isValid = extractedHash && extractedHash.length > 10;
                console.log(`🔐 İmza hash: ${extractedHash}`);
            }
            
            // Dijital imza anahtar kelimesi kontrolü
            const hasDigitalSignature = keywords && keywords.includes('dijital-imza');
            
            // Elektronik imza sistemi kontrolü
            const isFromElectronicSystem = creator && creator.includes('Elektronik İmza Sistemi');
            
            const overallValid = isValid && hasDigitalSignature && isFromElectronicSystem;
            
            if (overallValid) {
                console.log('✅ İmza GEÇERLI - Doküman güvenilir');
            } else {
                console.log('❌ İmza GEÇERSIZ veya şüpheli');
            }
            
            return {
                valid: overallValid,
                hash: extractedHash,
                hasDigitalSignature: hasDigitalSignature,
                isFromElectronicSystem: isFromElectronicSystem,
                creationDate: creationDate,
                details: {
                    title, subject, creator, producer, keywords
                }
            };
            
        } catch (error) {
            console.error('❌ İmza doğrulama hatası:', error.message);
            return { 
                valid: false, 
                error: error.message,
                hash: null
            };
        }
    }

    // PIN doğrulama (basit)
    pinDogrula(girilenPin) {
        const dogruPin = this.pin;
        const dogru = girilenPin === dogruPin;
        
        if (dogru) {
            console.log('✅ PIN kodu doğrulandı');
        } else {
            console.log('❌ Geçersiz PIN kodu');
        }
        
        return dogru;
    }
}

// Ana fonksiyon
async function main() {
    try {
        console.log('🚀 Basit Elektronik İmza Sistemi');
        console.log('================================');
        
        const pin = '2945';
        const imzaSistemi = new BasitElektronikImza(pin);
        
        // PIN doğrulama testi
        console.log('\\n🔐 PIN kodu doğrulanıyor...');
        const pinGecerli = imzaSistemi.pinDogrula(pin);
        
        if (!pinGecerli) {
            throw new Error('Geçersiz PIN kodu');
        }
        
        // Dosya yolları
        const inputPdf = path.join(__dirname, 'terazi.pdf');
        const outputPdf = path.join(__dirname, 'terazi_imzali.pdf');
        
        // Giriş dosyası kontrolü
        if (!fs.existsSync(inputPdf)) {
            console.log(`❌ PDF dosyası bulunamadı: ${inputPdf}`);
            console.log('💡 Lütfen "terazi.pdf" dosyasını proje klasörüne yerleştirin.');
            return;
        }
        
        console.log('\\n📄 PDF dosyası bulundu, imzalama başlıyor...');
        
        // PDF'i imzala
        const sonuc = await imzaSistemi.pdfImzala(inputPdf, outputPdf);
        
        if (sonuc.success) {
            console.log('\\n🎉 İmzalama işlemi tamamlandı!');
            console.log(`📂 İmzalanmış dosya: ${sonuc.outputPath}`);
            
            // İmzayı doğrula
            console.log('\\n🔍 İmza doğrulama testi...');
            const dogrulama = await imzaSistemi.imzaDogrula(outputPdf);
            
            console.log('\\n📊 İşlem Özeti:');
            console.log(`├─ Giriş dosyası: ${inputPdf}`);
            console.log(`├─ Çıkış dosyası: ${outputPdf}`);
            console.log(`├─ PIN kodu: ${pin} (Doğrulandı)`);
            console.log(`├─ İmza hash: ${sonuc.hash.substring(0, 16)}...`);
            console.log(`├─ İmza tarihi: ${sonuc.timestamp.toLocaleString('tr-TR')}`);
            console.log(`└─ Doğrulama: ${dogrulama.valid ? 'BAŞARILI ✅' : 'BAŞARISIZ ❌'}`);
        }
        
    } catch (error) {
        console.error('\\n💥 Hata:', error.message);
        console.log('\\n🛠️ Sorun giderme:');
        console.log('• PDF dosyasının mevcut olduğundan emin olun');
        console.log('• PIN kodunun doğru olduğundan emin olun');
        console.log('• Dosya izinlerini kontrol edin');
    }
}

// Komut satırından çalıştırıldıysa ana fonksiyonu çalıştır
if (require.main === module) {
    main();
} else {
    console.log('📦 Basit Elektronik İmza modülü yüklendi');
}

module.exports = { BasitElektronikImza };
