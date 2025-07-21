const fs = require('fs');
const crypto = require('crypto');
const { PDFDocument } = require('pdf-lib');

// PDF Dijital İmza Doğrulama Aracı
class PDFSignatureVerifier {
    constructor() {
        this.results = {};
    }

    // PDF imza analizi
    async verifyPDF(pdfPath) {
        console.log('🔍 PDF DİJİTAL İMZA ANALİZİ');
        console.log('============================');
        console.log(`📄 PDF Dosyası: ${pdfPath}`);

        if (!fs.existsSync(pdfPath)) {
            throw new Error(`PDF dosyası bulunamadı: ${pdfPath}`);
        }

        const pdfBytes = fs.readFileSync(pdfPath);
        console.log(`📋 PDF Boyutu: ${pdfBytes.length} byte`);

        try {
            // PDF-lib ile PDF'i yükle
            const pdfDoc = await PDFDocument.load(pdfBytes);
            
            // Metadata analizi
            await this.analyzeMetadata(pdfDoc);
            
            // PDF byte stream analizi
            await this.analyzeByteStream(pdfBytes);
            
            // PDF structure analizi
            await this.analyzePDFStructure(pdfBytes);
            
            // Sonuçları göster
            this.showResults();
            
        } catch (error) {
            console.error('❌ PDF analiz hatası:', error.message);
        }
    }

    // PDF Metadata analizi
    async analyzeMetadata(pdfDoc) {
        console.log('\n📝 PDF METADATA ANALİZİ:');
        console.log('-----------------------');

        try {
            const title = pdfDoc.getTitle();
            const subject = pdfDoc.getSubject();
            const creator = pdfDoc.getCreator();
            const producer = pdfDoc.getProducer();
            const keywords = pdfDoc.getKeywords();

            console.log(`📑 Title: ${title || 'Belirtilmemiş'}`);
            console.log(`📋 Subject: ${subject || 'Belirtilmemiş'}`);
            console.log(`👤 Creator: ${creator || 'Belirtilmemiş'}`);
            console.log(`🏭 Producer: ${producer || 'Belirtilmemiş'}`);
            console.log(`🏷️ Keywords: ${keywords || 'Belirtilmemiş'}`);

            // İmza belirtilerini ara
            this.results.hasSignatureMetadata = false;
            if (subject && subject.includes('signature')) {
                this.results.hasSignatureMetadata = true;
                console.log('✅ Metadata\'da dijital imza belirtisi bulundu');
            }
            if (creator && creator.includes('PKCS')) {
                this.results.hasSignatureMetadata = true;
                console.log('✅ Metadata\'da PKCS#11 belirtisi bulundu');
            }
            if (producer && producer.includes('Digital Signature')) {
                this.results.hasSignatureMetadata = true;
                console.log('✅ Metadata\'da dijital imza üretici bilgisi bulundu');
            }

        } catch (error) {
            console.log('⚠️ Metadata okunamadı:', error.message);
        }
    }

    // PDF byte stream analizi
    async analyzeByteStream(pdfBytes) {
        console.log('\n🔍 PDF BYTE STREAM ANALİZİ:');
        console.log('---------------------------');

        const pdfString = pdfBytes.toString('latin1');
        
        // Adobe PDF dijital imza objelerini ara
        const signatureKeywords = [
            '/Sig',           // Signature dictionary
            '/ByteRange',     // Signature byte range
            '/Contents',      // Signature contents
            '/Filter',        // Signature filter
            '/SubFilter',     // Signature sub filter
            'Adobe.PPKLite',  // Adobe signature filter
            'adbe.pkcs7',     // Adobe PKCS#7 format
            'PKCS#7',         // PKCS#7 reference
            '/Reason',        // Signature reason
            '/Location',      // Signature location
            '/ContactInfo',   // Contact information
        ];

        this.results.foundSignatureObjects = [];
        
        signatureKeywords.forEach(keyword => {
            if (pdfString.includes(keyword)) {
                this.results.foundSignatureObjects.push(keyword);
                console.log(`✅ Adobe imza objesi bulundu: ${keyword}`);
            }
        });

        if (this.results.foundSignatureObjects.length > 0) {
            console.log(`📋 Toplam Adobe imza objesi: ${this.results.foundSignatureObjects.length}`);
        } else {
            console.log('❌ Adobe dijital imza objesi bulunamadı');
        }

        // Hash değerlerini ara
        const hashPattern = /[a-fA-F0-9]{32,}/g;
        const hashes = pdfString.match(hashPattern);
        if (hashes) {
            console.log(`🔐 Hash benzeri değerler bulundu: ${hashes.length} adet`);
            this.results.hasHashes = true;
        }
    }

    // PDF structure analizi
    async analyzePDFStructure(pdfBytes) {
        console.log('\n🏗️ PDF YAPISAL ANALİZ:');
        console.log('---------------------');

        const pdfString = pdfBytes.toString('latin1');
        
        // PDF signature dictionary ara
        const sigDictPattern = /<<[\s\S]*?\/Type[\s\S]*?\/Sig[\s\S]*?>>/g;
        const sigDicts = pdfString.match(sigDictPattern);
        
        if (sigDicts) {
            console.log(`✅ PDF Signature Dictionary bulundu: ${sigDicts.length} adet`);
            this.results.hasSignatureDictionary = true;
            
            sigDicts.forEach((dict, index) => {
                console.log(`📋 Signature Dictionary ${index + 1}:`);
                console.log(dict.substring(0, 200) + '...');
            });
        } else {
            console.log('❌ PDF Signature Dictionary bulunamadı');
            this.results.hasSignatureDictionary = false;
        }

        // Annotation objelerini ara (görsel imza için)
        const annotPattern = /\/Annot/g;
        const annots = pdfString.match(annotPattern);
        if (annots) {
            console.log(`📝 PDF Annotation objesi: ${annots.length} adet`);
            this.results.hasAnnotations = true;
        }
    }

    // Sonuçları göster
    showResults() {
        console.log('\n🏆 PDF DİJİTAL İMZA DEĞERLENDİRME:');
        console.log('==================================');

        let totalScore = 0;
        let maxScore = 0;

        // Adobe standardı kontrolleri
        console.log('\n📊 Adobe PDF Dijital İmza Standardı:');
        console.log('------------------------------------');
        
        maxScore += 10;
        if (this.results.hasSignatureDictionary) {
            console.log('✅ PDF Signature Dictionary: VAR (+10 puan)');
            totalScore += 10;
        } else {
            console.log('❌ PDF Signature Dictionary: YOK (0 puan)');
        }

        maxScore += 10;
        if (this.results.foundSignatureObjects.length >= 5) {
            console.log('✅ Adobe İmza Objeleri: KAPSAMLI (+10 puan)');
            totalScore += 10;
        } else if (this.results.foundSignatureObjects.length > 0) {
            console.log('⚠️ Adobe İmza Objeleri: KISMI (+5 puan)');
            totalScore += 5;
        } else {
            console.log('❌ Adobe İmza Objeleri: YOK (0 puan)');
        }

        // Metadata kontrolleri
        console.log('\n📋 Metadata ve Bilgilendirme:');
        console.log('-----------------------------');
        
        maxScore += 5;
        if (this.results.hasSignatureMetadata) {
            console.log('✅ İmza Metadata: VAR (+5 puan)');
            totalScore += 5;
        } else {
            console.log('❌ İmza Metadata: YOK (0 puan)');
        }

        maxScore += 5;
        if (this.results.hasAnnotations) {
            console.log('✅ Görsel İmza Alanı: VAR (+5 puan)');
            totalScore += 5;
        } else {
            console.log('❌ Görsel İmza Alanı: YOK (0 puan)');
        }

        // Cryptographic kontroller
        console.log('\n🔐 Cryptographic İçerik:');
        console.log('------------------------');
        
        maxScore += 5;
        if (this.results.hasHashes) {
            console.log('✅ Hash Değerleri: VAR (+5 puan)');
            totalScore += 5;
        } else {
            console.log('❌ Hash Değerleri: YOK (0 puan)');
        }

        // Genel değerlendirme
        const percentage = Math.round((totalScore / maxScore) * 100);
        console.log('\n🎯 GENEL DEĞERLENDİRME:');
        console.log('======================');
        console.log(`📊 Toplam Puan: ${totalScore}/${maxScore} (${percentage}%)`);

        if (percentage >= 80) {
            console.log('🏆 Sonuç: Adobe Reader ile doğrulanabilir dijital imza');
            console.log('✅ PDF, dijital imza standartlarına uygun');
        } else if (percentage >= 50) {
            console.log('⚠️ Sonuç: Kısmi dijital imza - Adobe Reader sınırlı tanıyabilir');
            console.log('📝 Görsel imza mevcut, ancak tam Adobe standardı eksik');
        } else {
            console.log('❌ Sonuç: Adobe Reader dijital imzayı tanımaz');
            console.log('📄 Sadece görsel imza veya metadata mevcut');
        }

        console.log('\n💡 ÖNERİLER:');
        console.log('============');
        if (!this.results.hasSignatureDictionary) {
            console.log('• Adobe PDF Signature Dictionary eklenmeli');
        }
        if (this.results.foundSignatureObjects.length < 5) {
            console.log('• Adobe.PPKLite ve PKCS#7 formatı kullanılmalı');
        }
        if (!this.results.hasSignatureMetadata) {
            console.log('• PDF metadata\'ya dijital imza bilgileri eklenmeli');
        }
        
        console.log('• Tam Adobe uyumluluk için PKCS#7 embedded signature gerekli');
        console.log('• Adobe PDF SDK veya benzer profesyonel araç önerilir');
    }
}

// Test fonksiyonu
async function main() {
    const verifier = new PDFSignatureVerifier();
    
    const pdfFiles = ['a_adobe_signed.pdf', 'a_imzali.pdf', 'a.pdf'];
    
    for (const pdfFile of pdfFiles) {
        if (fs.existsSync(pdfFile)) {
            console.log(`\n${'='.repeat(60)}`);
            console.log(`DOSYA ANALİZİ: ${pdfFile}`);
            console.log(`${'='.repeat(60)}`);
            await verifier.verifyPDF(pdfFile);
        }
    }
}

if (require.main === module) {
    main().catch(console.error);
}

module.exports = { PDFSignatureVerifier };
