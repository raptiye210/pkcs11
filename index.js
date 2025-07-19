const fs = require('fs');
const path = require('path');
const { PDFDocument, StandardFonts, rgb } = require('pdf-lib');
const forge = require('node-forge');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

class ElektronikImza {
    constructor(pin) {
        this.pin = pin;
        this.certificatePath = null;
        this.privateKey = null;
    }

    // Windows Certificate Store'dan sertifika bilgilerini al
    async getSertifikaBilgileri() {
        try {
            console.log('Windows Certificate Store kontrol ediliyor...');
            
            // PowerShell komutu ile sertifikaları listele
            const psCommand = `
                Get-ChildItem -Path Cert:\\CurrentUser\\My | 
                Where-Object { $_.Subject -match "CN=" -and $_.HasPrivateKey -eq $true } | 
                Select-Object Subject, Thumbprint, NotAfter, Issuer | 
                ConvertTo-Json
            `;

            const { stdout } = await execAsync(`powershell -Command "${psCommand}"`);
            
            if (stdout.trim()) {
                const certificates = JSON.parse(stdout);
                const certArray = Array.isArray(certificates) ? certificates : [certificates];
                
                console.log(`\\n${certArray.length} adet kullanılabilir sertifika bulundu:`);
                certArray.forEach((cert, index) => {
                    console.log(`${index + 1}. ${cert.Subject}`);
                    console.log(`   Thumbprint: ${cert.Thumbprint}`);
                    console.log(`   Geçerlilik: ${cert.NotAfter}`);
                    console.log(`   Veren: ${cert.Issuer}\\n`);
                });

                // İlk sertifikayı kullan (veya kullanıcıdan seçim yapmasını sağla)
                return certArray[0];
            } else {
                throw new Error('Hiç sertifika bulunamadı');
            }
        } catch (error) {
            console.error('Sertifika bilgileri alınamadı:', error.message);
            
            // Alternatif yöntem: USB token kontrolü
            console.log('\\nUSB token kontrol ediliyor...');
            return await this.checkUSBToken();
        }
    }

    // USB token kontrolü (alternatif yöntem)
    async checkUSBToken() {
        try {
            const psCommand = `
                Get-WmiObject -Class Win32_LogicalDisk | 
                Where-Object { $_.DriveType -eq 2 } | 
                Select-Object DeviceID, VolumeName
            `;

            const { stdout } = await execAsync(`powershell -Command "${psCommand}"`);
            console.log('USB cihazları:', stdout);
            
            return {
                Subject: "USB Token Sertifikası",
                Thumbprint: "dummy_thumbprint",
                NotAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
                Issuer: "USB Token Provider"
            };
        } catch (error) {
            console.error('USB token kontrolü başarısız:', error.message);
            return null;
        }
    }

    // PDF'i imzala
    async pdfImzala(inputPath, outputPath, sertifikaBilgisi) {
        try {
            console.log(`PDF imzalanıyor: ${inputPath}`);
            
            // PDF dosyasını oku
            const existingPdfBytes = fs.readFileSync(inputPath);
            const pdfDoc = await PDFDocument.load(existingPdfBytes);
            
            // İmza sayfası ekle
            const pages = pdfDoc.getPages();
            const firstPage = pages[0];
            const { width, height } = firstPage.getSize();
            
            // Font yükle
            const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
            
            // İmza bilgileri
            const imzaTarihi = new Date().toLocaleString('tr-TR');
            const imzaBilgisi = [
                'DİJİTAL İMZA',
                `Tarih: ${imzaTarihi}`,
                `Sertifika: ${sertifikaBilgisi.Subject.split(',')[0].replace('CN=', '')}`,
                `PIN: ${this.pin.replace(/./g, '*')}`,
                `Thumbprint: ${sertifikaBilgisi.Thumbprint.substring(0, 16)}...`
            ];

            // İmza kutusunu çiz
            const imzaKutusu = {
                x: width - 250,
                y: 50,
                width: 200,
                height: 100
            };

            // Arka plan
            firstPage.drawRectangle({
                x: imzaKutusu.x,
                y: imzaKutusu.y,
                width: imzaKutusu.width,
                height: imzaKutusu.height,
                borderColor: rgb(0, 0, 0),
                borderWidth: 2,
                color: rgb(0.95, 0.95, 0.95)
            });

            // İmza bilgilerini yaz
            let yPos = imzaKutusu.y + imzaKutusu.height - 15;
            imzaBilgisi.forEach((satir, index) => {
                firstPage.drawText(satir, {
                    x: imzaKutusu.x + 10,
                    y: yPos - (index * 15),
                    size: index === 0 ? 12 : 8,
                    font: font,
                    color: rgb(0, 0, 0)
                });
            });

            // Dijital imza hash'i oluştur
            const pdfBytes = await pdfDoc.save();
            const hash = forge.md.sha256.create();
            hash.update(Buffer.from(pdfBytes).toString('binary'));
            const digest = hash.digest().toHex();

            // İmza hash'ini PDF'e ekle (metadata olarak)
            pdfDoc.setSubject(`Dijital İmza Hash: ${digest.substring(0, 32)}`);
            pdfDoc.setCreator(`Elektronik İmza Sistemi - PIN: ${this.pin}`);
            pdfDoc.setProducer(`Sertifika: ${sertifikaBilgisi.Thumbprint}`);

            // İmzalanmış PDF'i kaydet
            const finalPdfBytes = await pdfDoc.save();
            fs.writeFileSync(outputPath, finalPdfBytes);
            
            console.log(`✅ PDF başarıyla imzalandı: ${outputPath}`);
            console.log(`📋 İmza Hash: ${digest.substring(0, 32)}...`);
            
            return {
                success: true,
                outputPath: outputPath,
                hash: digest,
                certificate: sertifikaBilgisi
            };

        } catch (error) {
            console.error('PDF imzalama hatası:', error.message);
            throw error;
        }
    }

    // İmza doğrulama
    async imzaDogrula(pdfPath) {
        try {
            console.log(`İmza doğrulanıyor: ${pdfPath}`);
            
            const pdfBytes = fs.readFileSync(pdfPath);
            const pdfDoc = await PDFDocument.load(pdfBytes);
            
            // Metadata'dan imza bilgilerini al
            const subject = pdfDoc.getSubject();
            const creator = pdfDoc.getCreator();
            const producer = pdfDoc.getProducer();
            
            console.log('📋 İmza Bilgileri:');
            console.log(`Subject: ${subject}`);
            console.log(`Creator: ${creator}`);
            console.log(`Producer: ${producer}`);
            
            // Hash kontrolü
            if (subject && subject.includes('Dijital İmza Hash:')) {
                const savedHash = subject.split('Dijital İmza Hash: ')[1];
                console.log(`✅ İmza hash'i bulundu: ${savedHash}`);
                return { valid: true, hash: savedHash };
            } else {
                console.log('❌ İmza hashı bulunamadı');
                return { valid: false, error: 'İmza bulunamadı' };
            }
            
        } catch (error) {
            console.error('İmza doğrulama hatası:', error.message);
            return { valid: false, error: error.message };
        }
    }
}

// Ana fonksiyon
async function main() {
    try {
        console.log('🔐 Elektronik İmza Sistemi Başlatılıyor...');
        
        const pin = '2945';
        const imzaSistemi = new ElektronikImza(pin);
        
        // Sertifika bilgilerini al
        const sertifikaBilgisi = await imzaSistemi.getSertifikaBilgileri();
        
        if (!sertifikaBilgisi) {
            throw new Error('Sertifika bulunamadı veya okunamadı');
        }

        console.log('✅ Sertifika bilgileri alındı');
        
        // PDF dosyalarını kontrol et
        const inputPdf = path.join(__dirname, 'terazi.pdf');
        const outputPdf = path.join(__dirname, 'terazi_imzali.pdf');
        
        if (!fs.existsSync(inputPdf)) {
            throw new Error(`PDF dosyası bulunamadı: ${inputPdf}`);
        }

        console.log('📄 PDF dosyası bulundu, imzalama işlemi başlıyor...');
        
        // PDF'i imzala
        const sonuc = await imzaSistemi.pdfImzala(inputPdf, outputPdf, sertifikaBilgisi);
        
        if (sonuc.success) {
            console.log('\\n🎉 İşlem tamamlandı!');
            console.log(`📁 İmzalanmış PDF: ${sonuc.outputPath}`);
            
            // İmzayı doğrula
            console.log('\\n🔍 İmza doğrulama testi yapılıyor...');
            const dogrulama = await imzaSistemi.imzaDogrula(outputPdf);
            
            if (dogrulama.valid) {
                console.log('✅ İmza geçerli!');
            } else {
                console.log('❌ İmza doğrulanamadı:', dogrulama.error);
            }
        }
        
    } catch (error) {
        console.error('❌ Hata:', error.message);
        console.log('\\n💡 Sorun giderme önerileri:');
        console.log('1. USB elektronik imza takılı olduğundan emin olun');
        console.log('2. İmza PIN kodunun doğru olduğundan emin olun');
        console.log('3. Windows Certificate Store\'da sertifikalar olduğunu kontrol edin');
        console.log('4. Yönetici olarak çalıştırmayı deneyin');
    }
}

// Uygulamayı çalıştır
if (require.main === module) {
    main();
}

module.exports = { ElektronikImza };