const pkcs11js = require("pkcs11js");
const pkcs11 = new pkcs11js.PKCS11();

const libraryPath = "C:\\Windows\\System32\\etpkcs11.dll"; // DLL yolu
const PIN = "2945"; // PIN kodun



const fs = require("fs");
const crypto = require("crypto");

const pdfPath = "C:\\proje\\pkcs11\\src\\a.pdf";
const pdfData = fs.readFileSync(pdfPath);

// SHA-256 hash hesapla
const hash = crypto.createHash("sha256").update(pdfData).digest();




try {
  pkcs11.load(libraryPath);
  pkcs11.C_Initialize();

  const slots = pkcs11.C_GetSlotList(true);
  if (slots.length === 0) {
    console.log("Cihaza bağlı slot bulunamadı.");
    process.exit(1);
  }

  const slot = slots[0];
  const session = pkcs11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);

  pkcs11.C_Login(session, pkcs11js.CKU_USER, PIN);

  // Nesne aramaya başla, filtreyi belirt (CKA_CLASS = CKO_CERTIFICATE veya CKO_PRIVATE_KEY)
  // Fakat filtre parametresi array olarak veriliyor, bu yüzden OR yapmak için
  // birden fazla kez arama yapmak gerekiyor veya filtre boş bırakılıp sonra filtrelenebilir.
  
  // Örnek: filtre boş bırak, sonra kendi içinde filtrele:
  pkcs11.C_FindObjectsInit(session, []);

  const objects = pkcs11.C_FindObjects(session, 100);
  pkcs11.C_FindObjectsFinal(session);

  // Sertifika ve private keyleri filtrele
  const CKO_CERTIFICATE = 1;
  const CKO_PRIVATE_KEY = 3;

  const filteredObjects = [];

  for (const obj of objects) {
    try {
      const attrs = pkcs11.C_GetAttributeValue(session, obj, [
        { type: pkcs11js.CKA_LABEL },
        { type: pkcs11js.CKA_CLASS }
      ]);

      const clazz = attrs[1]?.value ? attrs[1].value.readUInt32LE(0) : null;

      if (clazz === CKO_CERTIFICATE || clazz === CKO_PRIVATE_KEY) {
        filteredObjects.push({ obj, clazz, label: attrs[0]?.value ? attrs[0].value.toString() : "<Etiket yok>" });
      }
    } catch (err) {
      console.log("Nesne okunamadı:", err.message);
    }
  }

  console.log(`Toplam Sertifika ve Anahtar sayısı: ${filteredObjects.length}`);

  for (const { obj, clazz, label } of filteredObjects) {
    const className = clazz === CKO_CERTIFICATE ? "Sertifika" : "Özel Anahtar";
    console.log(`Nesne: label="${label}", class=${clazz} (${className})`);
  }

  pkcs11.C_Logout(session);
  pkcs11.C_CloseSession(session);
} catch (e) {
  console.error("Hata:", e);
} finally {
  try {
    pkcs11.C_Finalize();
  } catch {}
}
