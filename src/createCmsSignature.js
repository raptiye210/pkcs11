const forge = require("node-forge");

// PKCS#11’den aldığın raw imza (Buffer)
const rawSignature = /* PKCS#11 imzan */ Buffer.alloc(256); // Örnek boş buffer, sen gerçek imzayı koy

// Sertifika (PEM formatında)
// PKCS#11 sertifikandan alman lazım, veya dosyadan oku
const certPem = `-----BEGIN CERTIFICATE-----
...sertifikan burada...
-----END CERTIFICATE-----`;

const cert = forge.pki.certificateFromPem(certPem);

// İmzalanan verinin hash’i (örneğin sha256 digest)
const digest = /* PKCS#11 hash’ini al veya hesapla */ Buffer.alloc(32); // Örnek boş digest

// CMS yapılandırması oluştur
const p7 = forge.pkcs7.createSignedData();
p7.content = forge.util.createBuffer(digest.toString("binary"));
p7.addCertificate(cert);
p7.addSigner({
  key: null,            // Çünkü imzayı biz dışarıdan veriyoruz
  certificate: cert,
  digestAlgorithm: forge.pki.oids.sha256,
  authenticatedAttributes: [
    {
      type: forge.pki.oids.contentType,
      value: forge.pki.oids.data,
    },
    {
      type: forge.pki.oids.messageDigest,
      value: digest.toString("binary"),
    },
    {
      type: forge.pki.oids.signingTime,
      value: new Date(),
    },
  ],
  // rawSignature dışarıdan verilecek, key boş bırakılıyor
});

// raw imzayı, p7 içindeki imza alanına elle koyacağız:
p7.signers[0].signature = forge.util.createBuffer(rawSignature.toString("binary"));

// Son olarak DER formatında CMS oluştur
const cmsDer = forge.asn1.toDer(p7.toAsn1()).getBytes();

// Buffer olarak PDF’ye gömebilirsin:
const cmsBuffer = Buffer.from(cmsDer, "binary");

// cmsBuffer’ı node-signpdf.sign(pdfBuffer, cmsBuffer) ile kullanabilirsin.
