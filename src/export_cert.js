const pkcs11js = require("pkcs11js");
const pkcs11 = new pkcs11js.PKCS11();
const fs = require("fs");

const libraryPath = "C:\\Windows\\System32\\etpkcs11.dll";
const PIN = "2945";
const outputCertPath = "C:\\proje\\pkcs11\\src\\cert.der";

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

  const CKO_CERTIFICATE = 1;
  pkcs11.C_FindObjectsInit(session, [{ type: pkcs11js.CKA_CLASS, value: Buffer.from([CKO_CERTIFICATE]) }]);
  const certObjects = pkcs11.C_FindObjects(session, 100);
  pkcs11.C_FindObjectsFinal(session);

  let index = 1;
  for (const obj of certObjects) {
    try {
      // Sadece CKA_VALUE'yu sorgula
      const valueAttrs = pkcs11.C_GetAttributeValue(session, obj, [
        { type: pkcs11js.CKA_VALUE },
      ]);
      const certData = valueAttrs[0]?.value;
      if (certData) {
        const certFilePath = `C:\\proje\\pkcs11\\src\\cert_${index}.der`;
        fs.writeFileSync(certFilePath, certData);
        console.log(`Sertifika kaydedildi: ${certFilePath}`);
        index++;
      }
    } catch (err) {
      console.log(`Sertifika ${index} okunamadı:`, err.message);
      continue;
    }
  }

  if (index === 1) {
    throw new Error("Hiçbir sertifika bulunamadı!");
  }

  pkcs11.C_Logout(session);
  pkcs11.C_CloseSession(session);
} catch (e) {
  console.error("Hata:", e.message);
} finally {
  try {
    pkcs11.C_Finalize();
  } catch {}
}