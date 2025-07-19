# Elektronik İmza ile PDF İmzalama Sistemi

Bu Node.js uygulaması, USB'de takılı elektronik imza kullanarak PDF dokümanlarını dijital olarak imzalamanızı sağlar.

## Özellikler

- 🔐 USB elektronik imza desteği
- 📄 PDF doküman imzalama
- ✅ İmza doğrulama
- 🖥️ Windows Certificate Store entegrasyonu
- 📋 Dijital hash imzası

## Kurulum

```bash
# Projeyi klonlayın
git clone https://github.com/raptiye210/pkcs11.git
cd pkcs11

# Bağımlılıkları yükleyin
npm install
```

## Kullanım

1. USB elektronik imzanızı bilgisayara takın
2. PIN kodunuzu `index.js` dosyasında güncelleyin (varsayılan: 2945)
3. İmzalamak istediğiniz PDF dosyasını proje klasörüne yerleştirin
4. Uygulamayı çalıştırın:

```bash
npm start
```

## Örnek Kullanım

```javascript
const { ElektronikImza } = require('./index.js');

async function pdfImzala() {
    const imza = new ElektronikImza('2945'); // PIN kodunuz
    
    // Sertifika bilgilerini al
    const sertifika = await imza.getSertifikaBilgileri();
    
    // PDF'i imzala
    const sonuc = await imza.pdfImzala(
        './terazi.pdf',        // Giriş PDF
        './terazi_imzali.pdf', // Çıkış PDF
        sertifika
    );
    
    console.log('İmzalama tamamlandı:', sonuc.success);
}
```

## Desteklenen Formatlar

- **Giriş**: PDF dosyaları
- **Çıkış**: Dijital imzalı PDF dosyaları
- **Sertifika**: Windows Certificate Store
- **İmza**: SHA-256 hash tabanlı dijital imza

## Sistem Gereksinimleri

- Node.js 14.x veya üzeri
- Windows 10/11
- USB elektronik imza cihazı
- Geçerli dijital sertifika

## Sorun Giderme

### Sık Karşılaşılan Sorunlar

1. **Sertifika bulunamıyor**
   - USB imza cihazının takılı olduğundan emin olun
   - Windows Certificate Store'da sertifikaları kontrol edin
   - Uygulamayı yönetici olarak çalıştırın

2. **PIN kodu hatası**
   - PIN kodunun doğru olduğundan emin olun
   - İmza cihazının kilitli olmadığını kontrol edin

3. **PDF işleme hatası**
   - PDF dosyasının bozuk olmadığından emin olun
   - Dosya izinlerini kontrol edin

### Hata Kodları

- `CERT_NOT_FOUND`: Sertifika bulunamadı
- `INVALID_PIN`: Geçersiz PIN kodu
- `PDF_CORRUPT`: PDF dosyası bozuk
- `SIGN_FAILED`: İmzalama işlemi başarısız

## API Referansı

### ElektronikImza Sınıfı

#### Constructor
```javascript
new ElektronikImza(pin)
```

#### Metodlar

- `getSertifikaBilgileri()`: Sertifika bilgilerini getirir
- `pdfImzala(inputPath, outputPath, certificate)`: PDF dosyasını imzalar  
- `imzaDogrula(pdfPath)`: İmza geçerliliğini kontrol eder

## Güvenlik

- PIN kodları asla kaynak kodda sabit olarak tutulmamalıdır
- İmzalanmış PDF'ler hash tabanlı doğrulama içerir
- Tüm işlemler yerel makinede gerçekleştirilir

## Katkıda Bulunma

1. Fork edin
2. Feature branch oluşturun (`git checkout -b feature/yeni-ozellik`)
3. Commit yapın (`git commit -am 'Yeni özellik eklendi'`)
4. Branch'i push edin (`git push origin feature/yeni-ozellik`)
5. Pull Request oluşturun

## Lisans

Bu proje ISC lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.

## İletişim

- GitHub: [@raptiye210](https://github.com/raptiye210)
- Email: basar@example.com

---

⚠️ **Önemli Uyarı**: Bu uygulama eğitim amaçlı hazırlanmıştır. Üretim ortamında kullanmadan önce güvenlik denetimi yapınız.