const pkcs11js = require("pkcs11js");
const pkcs11 = new pkcs11js.PKCS11(); // <-- DÜZGÜN ŞEKİLDE NESNE OLUŞTUR

pkcs11.load("C:\\Windows\\System32\\etpkcs11.dll");
pkcs11.C_Initialize();

try {
    const slots = pkcs11.C_GetSlotList(true);
    if (slots.length === 0) {
        throw new Error("Takılı bir token bulunamadı.");
    }

    const session = pkcs11.C_OpenSession(slots[0], pkcs11js.CKF_SERIAL_SESSION);
    pkcs11.C_Login(session, pkcs11js.CKU_USER, "2945");

    pkcs11.C_FindObjectsInit(session, []);
    const objects = pkcs11.C_FindObjects(session, 10);
    pkcs11.C_FindObjectsFinal(session);

    console.log("Nesne sayısı:", objects.length);

for (const obj of objects) {
    try {
        const attrs = pkcs11.C_GetAttributeValue(session, obj, [
            { type: pkcs11js.CKA_LABEL },
            { type: pkcs11js.CKA_CLASS }
        ]);

        let label = attrs[0]?.value?.toString() || "<etiket yok>";
        let cls = attrs[1]?.value?.readUInt32LE?.() || "<sınıf yok>";

        console.log(`Nesne: label=${label}, class=${cls}`);
    } catch (e) {
        console.error("Nesne okunamadı:", e.message || e);
    }
}


    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
} catch (err) {
    console.error("Hata:", err.message || err);
} finally {
    pkcs11.C_Finalize();
}
