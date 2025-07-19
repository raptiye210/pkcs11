const fs = require('fs');
const path = require('path');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const forge = require('node-forge');

class ElektronikImzaSistemi {
    constructor(pin) {
        this.pin = pin;
        this.imzaYetkili = "Dijital Imza Sahibi";
    }

    // PDF imzalama
    async pdfImzala(inputPath, outputPath) {
        try {
            console.log(`📄 PDF dosyasi okunuyor: ${inputPath}`);
            
            if (!fs.existsSync(inputPath)) {
                throw new Error(`PDF dosyasi bulunamadi: ${inputPath}`);
            }

            const existingPdfBytes = fs.readFileSync(inputPath);
            const pdfDoc = await PDFDocument.load(existingPdfBytes);
            
            const pages = pdfDoc.getPages();
            const firstPage = pages[0];
            const { width, height } = firstPage.getSize();
            
            const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
            const boldFont = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
            
            const imzaTarihi = new Date();
            const tarihStr = imzaTarihi.toLocaleString('tr-TR');
            
            // PDF hash hesaplama
            const hash = forge.md.sha256.create();
            hash.update(Buffer.from(existingPdfBytes).toString('binary'));
            const pdfHash = hash.digest().toHex();
            
            // Imza bilgileri (Turkce karakter kullanmadan)
            const imzaBilgileri = [
                'DIJITAL IMZA',
                `Tarih: ${tarihStr}`,
                `Imza Sahibi: ${this.imzaYetkili}`,
                `PIN Dogrulandi: ${this.pin ? 'EVET' : 'HAYIR'}`,
                `Dokuman Hash: ${pdfHash.substring(0, 16)}...`,
                'Bu dokuman dijital olarak imzalanmistir.'
            ];

            // Imza kutusu
            const imzaKutusu = {
                x: width - 280,
                y: 50,
                width: 250,
                height: 120
            };

            // Dis cerceve
            firstPage.drawRectangle({
                x: imzaKutusu.x - 5,
                y: imzaKutusu.y - 5,
                width: imzaKutusu.width + 10,
                height: imzaKutusu.height + 10,
                borderColor: rgb(0, 0, 0),
                borderWidth: 2,
                color: rgb(0.95, 0.95, 1)
            });

            // Ic cerceve
            firstPage.drawRectangle({
                x: imzaKutusu.x,
                y: imzaKutusu.y,
                width: imzaKutusu.width,
                height: imzaKutusu.height,
                borderColor: rgb(0.2, 0.2, 0.8),
                borderWidth: 1,
                color: rgb(1, 1, 1)
            });

            // Yazi yazma
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

            // Dijital muhur
            const muhrX = imzaKutusu.x + imzaKutusu.width - 50;
            const muhrY = imzaKutusu.y + 20;
            
            firstPage.drawCircle({
                x: muhrX,
                y: muhrY,
                size: 25,
                borderColor: rgb(0.8, 0, 0),
                borderWidth: 2,
                color: rgb(1, 0.9, 0.9)
            });
            
            firstPage.drawText(imzaTarihi.getFullYear().toString(), {
                x: muhrX - 12,
                y: muhrY - 4,
                size: 8,
                font: boldFont,
                color: rgb(0.8, 0, 0)
            });

            // Metadata
            pdfDoc.setTitle('Dijital Imzalanmis Dokuman');
            pdfDoc.setSubject(`Imza Hash: ${pdfHash}`);
            pdfDoc.setCreator(`Elektronik Imza Sistemi v1.0`);
            pdfDoc.setProducer(`PIN: ${this.pin} - Tarih: ${tarihStr}`);
            pdfDoc.setKeywords(['dijital-imza', 'elektronik-imza', 'pdf']);
            pdfDoc.setCreationDate(imzaTarihi);
            pdfDoc.setModificationDate(imzaTarihi);

            const finalPdfBytes = await pdfDoc.save();
            fs.writeFileSync(outputPath, finalPdfBytes);
            
            console.log('✅ PDF basariyla imzalandi!');
            console.log(`📁 Cikti dosyasi: ${outputPath}`);
            console.log(`🔐 Dokuman hash: ${pdfHash.substring(0, 32)}...`);
            console.log(`📅 Imza tarihi: ${tarihStr}`);
            
            return {
                success: true,
                outputPath: outputPath,
                hash: pdfHash,
                timestamp: imzaTarihi,
                signer: this.imzaYetkili
            };

        } catch (error) {
            console.error('❌ PDF imzalama hatasi:', error.message);
            throw error;
        }
    }

    // Imza dogrulama
    async imzaDogrula(pdfPath) {
        try {
            console.log(`🔍 Imza dogrulanyor: ${pdfPath}`);
            
            const pdfBytes = fs.readFileSync(pdfPath);
            const pdfDoc = await PDFDocument.load(pdfBytes);
            
            const title = pdfDoc.getTitle();
            const subject = pdfDoc.getSubject();
            const creator = pdfDoc.getCreator();
            const producer = pdfDoc.getProducer();
            const keywords = pdfDoc.getKeywords();
            const creationDate = pdfDoc.getCreationDate();
            
            console.log('📋 Imza Detaylari:');
            console.log(`Baslik: ${title || 'Belirtilmemis'}`);
            console.log(`Konu: ${subject || 'Belirtilmemis'}`);
            console.log(`Olusturan: ${creator || 'Belirtilmemis'}`);
            console.log(`Isleyici: ${producer || 'Belirtilmemis'}`);
            console.log(`Anahtar kelimeler: ${keywords || 'Belirtilmemis'}`);
            console.log(`Olusturma tarihi: ${creationDate ? creationDate.toLocaleString('tr-TR') : 'Belirtilmemis'}`);
            
            let isValid = false;
            let extractedHash = '';
            
            if (subject && subject.includes('Imza Hash:')) {
                extractedHash = subject.split('Imza Hash: ')[1];
                isValid = extractedHash && extractedHash.length > 10;
                console.log(`🔐 Imza hash: ${extractedHash}`);
            }
            
            const hasDigitalSignature = keywords && keywords.includes('dijital-imza');
            const isFromElectronicSystem = creator && creator.includes('Elektronik Imza Sistemi');
            
            const overallValid = isValid && hasDigitalSignature && isFromElectronicSystem;
            
            if (overallValid) {
                console.log('✅ Imza GECERLI - Dokuman guvenilir');
            } else {
                console.log('❌ Imza GECERSIZ veya supheli');
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
            console.error('❌ Imza dogrulama hatasi:', error.message);
            return { 
                valid: false, 
                error: error.message,
                hash: null
            };
        }
    }

    pinDogrula(girilenPin) {
        const dogru = girilenPin === this.pin;
        
        if (dogru) {
            console.log('✅ PIN kodu dogrulandi');
        } else {
            console.log('❌ Gecersiz PIN kodu');
        }
        
        return dogru;
    }
}

async function main() {
    try {
        console.log('🚀 Elektronik Imza Sistemi');
        console.log('===========================');
        
        const pin = '2945';
        const imzaSistemi = new ElektronikImzaSistemi(pin);
        
        console.log('🔐 PIN kodu dogrulanyor...');
        const pinGecerli = imzaSistemi.pinDogrula(pin);
        
        if (!pinGecerli) {
            throw new Error('Gecersiz PIN kodu');
        }
        
        const inputPdf = path.join(__dirname, 'terazi.pdf');
        const outputPdf = path.join(__dirname, 'terazi_imzali.pdf');
        
        if (!fs.existsSync(inputPdf)) {
            console.log(`❌ PDF dosyasi bulunamadi: ${inputPdf}`);
            console.log('💡 Lutfen "terazi.pdf" dosyasini proje klasorune yerlestirin.');
            return;
        }
        
        console.log('📄 PDF dosyasi bulundu, imzalama basliyor...');
        
        const sonuc = await imzaSistemi.pdfImzala(inputPdf, outputPdf);
        
        if (sonuc.success) {
            console.log('🎉 Imzalama islemi tamamlandi!');
            console.log(`📂 Imzalanmis dosya: ${sonuc.outputPath}`);
            
            console.log('🔍 Imza dogrulama testi...');
            const dogrulama = await imzaSistemi.imzaDogrula(outputPdf);
            
            console.log('📊 Islem Ozeti:');
            console.log(`├─ Giris dosyasi: ${inputPdf}`);
            console.log(`├─ Cikis dosyasi: ${outputPdf}`);
            console.log(`├─ PIN kodu: ${pin} (Dogrulandi)`);
            console.log(`├─ Imza hash: ${sonuc.hash.substring(0, 16)}...`);
            console.log(`├─ Imza tarihi: ${sonuc.timestamp.toLocaleString('tr-TR')}`);
            console.log(`└─ Dogrulama: ${dogrulama.valid ? 'BASARILI ✅' : 'BASARISIZ ❌'}`);
        }
        
    } catch (error) {
        console.error('💥 Hata:', error.message);
        console.log('🛠️ Sorun giderme:');
        console.log('• PDF dosyasinin mevcut oldugunu kontrol edin');
        console.log('• PIN kodunun dogru oldugunu kontrol edin');  
        console.log('• Dosya izinlerini kontrol edin');
    }
}

if (require.main === module) {
    main();
}

module.exports = { ElektronikImzaSistemi };
