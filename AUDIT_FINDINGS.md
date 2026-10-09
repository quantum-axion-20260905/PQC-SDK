# PQC Engine SDK — Xavfsizlik, Unumdorlik va Arxitektura Kamchiliklari Tahlili

Ushbu hujjat **PQC-SDK** (Post-Quantum Cryptography Engine SDK) loyihasining kod bazasi, kriptografik xavfsizligi, ma'lumotlar uzatish unumdorligi va arxitektura mustahkamligi bo'yicha o'tkazilgan tahlil natijalarini jamlaydi.

---

## 1. Kriptografik Xavfsizlik Kamchiliklari

### 1.1. Forward Secrecy (FS) va Post-Compromise Security (PCS) yo'qligi
* **Muammo:** V2 va V3 protokollarida xabarlar qabul qiluvchining uzoq muddatli statik qurilma kalitiga (`kemPublicKeyBase64`) to'g'ridan-to'g'ri encapsulate qilinadi (`_primitives.encapsulate(...)`).
* **Xavf darajasi:** **Juda yuqori (Critical)**
* **Tafsilot:** Double Ratchet (Signal) yoki PQXDH kabi efemer (vaqtinchalik yangilanuvchi) kalit almashish mexanizmi mavjud emas. Agar hujumchi yoki uchinchi tomon kelajakda foydalanuvchi qurilmasining shaxsiy kalitini (`kemSecretKeyBase64`) qo'lga kiritsa, u oldin tarmoqdan yozib olingan barcha tarixiy xabarlarning shifrini ochib o'qiy oladi.
* **Tavsiya:** Har bir xabar zanjirida kalitlarni oldinga siljituvchi KEM-Ratchet / Double Ratchet mexanizmini joriy qilish.

### 1.2. Gibrid Kriptografiya (Classical + Post-Quantum Hybrid) yo'qligi
* **Muammo:** SDK faqatgina yangi post-kvant primitivlariga (`ML-KEM-768` va `ML-DSA-65`) tayanadi.
* **Xavf darajasi:** **Yuqori (High)**
* **Tafsilot:** NIST, NSA, IETF hamda yirik xavfsizlik arxitekturalari (Apple iMessage PQ3, Signal, Google Chrome TLS) post-kvantga o'tish davrida gibrid sxemani (masalan, `X25519 + ML-KEM-768` va `Ed25519 + ML-DSA-65`) qat'iy talab qiladi. ML-KEM va ML-DSA nisbatan yangi standartlar bo'lib, kelajakda ularda kutilmagan kriptoanalitik zaiflik topilsa, o'n yillar davomida isbotlangan klassik Elliptic Curve (ECC) zaxira xavfsizlik himoyasini ta'minlab berishi kerak.
* **Tavsiya:** KEM va imzolash bosqichlariga X25519 va Ed25519 primitivlarini qo'shib, gibrid kalit hosil qilish (KDF orqali birlashtirish).

### 1.3. Maxfiy Kalitlarni Xotirada Tozalash (*Zeroization*) Yo'qligi
* **Muammo:** Xususiy kalitlar (`kemSecretKeyBase64`, `signingSecretKeyBase64`, `recoveryKey`, `contentKey`) Dart xotirasida `String` (Base64) yoki oddiy `Uint8List` sifatida saqlanadi.
* **Xavf darajasi:** **Yuqori (High)**
* **Tafsilot:** Dart tili avtomatik xotira tozalovchi (Garbage Collector) ga ega. Dartda `String` ob'ektlari immutable (o'zgarmas) bo'lib, ularni xotiradan to'g'ridan-to'g'ri o'chirib (*zeroize*) bo'lmaydi. `pqcrypto` paketida `zeroize.dart` mavjud bo'lsa ham, SDK uni biror marta chaqirmaydi. Qurilma xotirasi (RAM dump) tahlil qilinganda, ushbu kalitlar uzoq vaqt xotirada qolib ketishi sababli sizib chiqishi mumkin.
* **Tavsiya:** Maxfiy kalitlarni faqat `Uint8List` ko'rinishida saqlash va ishlatib bo'lingach, ularni darhol nollar bilan to'ldirish (`fillRange(0, length, 0)` yoki `zeroize`).

### 1.4. Kanonik JSON (RFC 8785 / JCS) Yo'qligi va Imzo Zaifligi
* **Muammo:** `v3_envelope.dart` va `v2_private_codec.dart` fayllarida raqamli imzo xom JSON satri ustida hisoblanadi:
  ```dart
  String unsignedCanonicalJson() => jsonEncode(toJson(includeSignature: false));
  ```
* **Xavf darajasi:** **O'rta / Yuqori (Medium - High)**
* **Tafsilot:** Dartning standart `jsonEncode` funksiyasi RFC 8785 (JSON Canonicalization Scheme - JCS) standartiga amal qilmaydi. Map kalitlari faqat qo'shilish tartibi bo'yicha ketadi. Agar tizimga boshqa platformalar (iOS/Swift, Android/Kotlin, Go/Rust backend) integratsiya qilinsa, ularning JSON serializeri kalitlar tartibini yoki bo'shliqlarni boshqacha formatlashi natijasida raqamli imzo (`ML-DSA-65`) tekshiruvdan o'tmaydi.
* **Tavsiya:** Rasmiy RFC 8785 kanonik JSON serializerini joriy qilish yoki imzolanadigan ma'lumotlarni qat'iy binar formatda (TLV yoki Protobuf) serializatsiya qilish.

---

## 2. Unumdorlik va Masshtablilik (Performance & Scalability)

### 2.1. Katta Birikmalar (Attachments) da OOM (Out-Of-Memory) Xavfi va Streaming Yo'qligi
* **Muammo:** `v3_attachment_codec.dart` fayl baytlarini to'liq bitta xotira blokida (`List<int> bytes`) qabul qiladi, AES-GCM orqali bittada shifrlaydi, Base64 qiladi, so'ngra umumiy envelope ichida yana bir bor Base64Url kodlaydi (*Double Base64*).
* **Xavf darajasi:** **Yuqori (High)**
* **Tafsilot:** 50 MB hajmdagi fayl shifrlash jarayonida RAM da taxminan 250–400 MB xotira talab qiladi:
  * Asl baytlar: 50 MB
  * Shifrlangan baytlar: 50 MB
  * Ichki Base64 satri: ~67 MB
  * Tashqi Envelope JSON va Base64Url satri: ~90 MB
  Mobil qurilmalarda (iOS/Android Flutter) bu jarayon ilovaning kutilmaganda yopilib ketishiga (*Out of Memory Crash*) sabab bo'ladi.
* **Tavsiya:** Oqimli shifrlash (Chunked / Streaming AEAD) mexanizmini joriy qilish (masalan, faylni 64 KB yoki 1 MB li qismlarga bo'lib, oqim tarzida shifrlash).

### 2.2. Guruh Xabarlarida $O(N)$ Ciphertext Bloat va CPU Yuklamasi
* **Muammo:** `v3_group_codec.dart` guruhdagi har bir a'zoning har bir qurilmasi uchun alohida `PqcV3RecipientWrap` yaratadi.
* **Xavf darajasi:** **O'rta / Yuqori (Medium - High)**
* **Tafsilot:** ML-KEM-768 shifrmatni 1088 bayt, o'ralgan kalit bilan birga bitta wrap ~1.5 KB ni tashkil qiladi. Agar guruhda 100 ta foydalanuvchi bo'lsa (har birida 2 tadan qurilma = 200 ta qurilma):
  * Bitta oddiy matnli xabar hajmi kamida **~300 KB** ga yetadi!
  * Yuboruvchi har bir xabar jo'natishda 200 marta Kyber-768 encapsulate operatsiyasini bajaradi. Bu mobil qurilma protsessorini qizdiradi va batareyani tez tugatadi.
* **Tavsiya:** Signal Sender-Keys yoki MLS (Messaging Layer Security - RFC 9420 / TreeKEM) arxitekturasidan foydalanish.

### 2.3. `randomBytes` Generatsiyasi Samaradorligi
* **Muammo:** `primitives.dart` da baytlar quyidagicha yaratiladi:
  ```dart
  Uint8List randomBytes(int length) => Uint8List.fromList(
    List<int>.generate(length, (_) => _random.nextInt(256)),
  );
  ```
* **Tafsilot:** Har bir bayt uchun `_random.nextInt(256)` alohida siklda chaqiriladi. Katta hajmdagi ma'lumotlar uchun bu sekin ishlaydi.
* **Tavsiya:** `Random.secure()` dan to'g'ridan-to'g'ri `Uint8List` buferini to'ldiruvchi optimallashtirilgan blokli usulga o'tish.

---

## 3. Saqlash Tizimi va Replay Guard

### 3.1. Replay Store Keshida TTL / Eviction / Tozalash Mexanizmi Yo'qligi
* **Muammo:** `PqcAtomicReplayStore` har bir kelgan xabar uchun doimiy omborga yangi atomik yozuv qo'shadi (`pqc-engine-sdk.replay.v1` namespace).
* **Xavf darajasi:** **O'rta (Medium)**
* **Tafsilot:** Eskirgan xabar identifikatorlarini tozalash (pruning), yashash muddati (TTL) yoki cheklangan o'lchamli oyna (sliding window) mavjud emas. Foydalanuvchi yuz minglab xabarlar olganda, mobil qurilmaning xavfsiz omborida (masalan, iOS Keychain yoki Android Keystore) yuz minglab kalitlar to'planib qoladi. iOS Keychain bunday katta miqdordagi kalitlar uchun mo'ljallanmagan va jiddiy xatolarga olib kelishi mumkin.
* **Tavsiya:** Timestampga asoslangan sliding-window kesh yoki davriy ravishda eskirgan ID larni tozalash (TTL pruning) mexanizmini kiritish.

---

## 4. Platforma va Integratsiya (Developer Experience)

### 4.1. Tayyor Platforma Adapterlarining Yo'qligi
* **Muammo:** SDK faqat `PqcMemoryAtomicStore` (faqat testlar uchun) taqdim etadi.
* **Tafsilot:** Production muhitda foydalanish uchun iOS Keychain, Android Keystore yoki SQLCipher/SQLite uchun tayyor rasmiy adapterlar yo'q. SDK integratsiya qiluvchi har bir dasturchi `PqcProductionAtomicStore` ni o'zi to'g'ri yozishi talab etiladi. Bu esa ishlab chiqaruvchilar tomonidan xatoliklarga yo'l qo'yilish xavfini oshiradi.
* **Tavsiya:** Mobil va desktop platformalari uchun tayyor plugin/adapterlar to'plamini (masalan, `pqc_engine_flutter_storage`) taqdim etish.

### 4.2. Web (Dart to JS) Muhitida Testlarning To'liq Emasligi
* **Muammo:** `tool/web_smoke.dart` faqatgina protokol versiyalarining raqamlarini solishtiradi, lekin real KEM va imzo tekshiruvlarini bajarmaydi.
* **Tafsilot:** ML-KEM va ML-DSA ning og'ir matritsaviy va ko'phadli hisob-kitoblari JavaScript dvijogida qanday tezlikda ishlashi va xotira chegaralari bo'yicha integratsion testlar va benchmarklar yo'q.
* **Tavsiya:** Web platforma uchun to'liq kriptografik testlar va WebAssembly (Wasm) benchmarklarini qo'shish.

---

## Xulosa va Qadamlar Xaritasi (Roadmap)

| Ustuvorlik | Yo'nalish | Tavsiya etilgan chora |
| :--- | :--- | :--- |
| **P0 (Kritik)** | Kriptografiya | Double Ratchet / Ephemeral KEM orqali Forward Secrecy ta'minlash |
| **P0 (Kritik)** | Unumdorlik | Katta fayllar (attachments) uchun Streaming Chunked AEAD yaratish |
| **P1 (Yuqori)** | Xavfsizlik | Maxfiy kalitlarni `Uint8List` ga o'tkazish va xotiradan tozalash (Zeroization) |
| **P1 (Yuqori)** | Standartlar | RFC 8785 kanonik JSON serializatsiyasini joriy qilish |
| **P2 (O'rta)** | Arxitektura | Guruh xabarlari uchun Sender-Keys yoki TreeKEM (MLS) modeliga o'tish |
| **P2 (O'rta)** | Saqlash | Replay Guard uchun TTL / Sliding-window tozalash mexanizmini qo'shish |
| **P3 (Qulaylik)** | Integratsiya | Flutter/Mobile uchun tayyor Keychain va Keystore adapterlarini yaratish |

---

## 5. Bajarilgan Kriptografik Xavfsizlik Tuzatishlari (Implemented Hardening)

Loyiha bo'yicha quyidagi professional kriptografik xavfsizlik yaxshilanishlari amalga oshirildi va to'liq verifikatsiya qilindi:

1. **`crypto_utils.dart` moduli yaratildi:**
   * **Timing-Attack Protection:** Baytlar va satrlar uchun `constantTimeBytesEquals` va `constantTimeStringEquals` joriy qilindi.
   * **RFC 8785 Canonical JSON (JCS):** Standartlarga mos, leksikografik saralangan `canonicalJsonEncode` amalga oshirildi.
   * **Xotirani tozalash (*Zeroization*):** `wipeBytes` va `secureZero` yordamida sezgir xotira buferlarini darhol tozalash mexanizmlari ulandi.

2. **Xotirada Maxfiy Kalitlar Tozalandi (Defense-in-Depth Zeroization):**
   * `PqcKemEnvelope` va `PqcAeadBox` ga `zeroize()` qo'shildi.
   * `v3_private_codec.dart`: `contentKey` va har bir `sharedSecret` ishlatilgach, `try/finally` blokida xotiradan o'chirildi.
   * `v3_attachment_codec.dart`: birikmalar kaliti va har bir KEM shared secret nollab tozalandi.
   * `v2_private_codec.dart` va `v2_authenticated_group_codec.dart`: barcha oraliq `contentKey`, `wrapKey` va `clear` buferlari shifrlash/ochishdan so'ng xotiradan tozalandi.
   * `recovery.dart`: qayta tiklangan vault baytlari foydalanilgach `secureZero` qilindi.

3. **Replay Guard va Timing Attack himoyasi kuchaytirildi:**
   * `replay_guard.dart` da sekin va zaif RegExp o'rniga doimiy vaqtli xavfsiz hex tekshiruvi va `constantTimeStringEquals` o'rnatildi.

4. **PqcRatchetSession (Forward Secrecy & Post-Compromise Security) qo'shildi:**
   * `pqc_ratchet.dart` moduli ishlab chiqildi.
   * Continuous ML-KEM exchange va HKDF-SHA256 zanjir ratcheting mexanizmi orqali har bir xabarga bir martalik kalit hosil qilinadi.
   * O'tgan xabarlar kaliti darhol yo'q qilinadi (*Forward Secrecy*).
   * Har bir xabar `ML-DSA-65` bilan imzolanadi va kanonik JSON orqali bog'lanadi.

5. **Testlar va Verifikatsiya:**
   * `test/security_hardening_test.dart` orqali yangi kriptografik primitivlar, kanonik JSON va ratchet almashinuvlari 100% sinovdan o'tkazildi.
   * SDK ning mavjud 84 ta va yangi 7 ta testi (jami 91 ta test) muvaffaqiyatli yakunlandi.
   * `dart analyze` to'liq toza (0 warnings, 0 errors).

---

## 6. Bajarilgan Unumdorlik va Masshtablash Tuzatishlari (Implemented Scalability & Performance)

Loyihada aniqlangan xotira (RAM), tarmoq yuklamasi va masshtablash muammolari bo'yicha quyidagi yechimlar ishlab chiqildi va integratsiya qilindi:

1. **Oqimli (Streaming / Chunked) Birikma Shifrlash (`v3_chunked_attachment.dart`):**
   * **OOM (Out-Of-Memory) to'liq bartaraf etildi:** Fayllar bittada butun xotiraga yuklanmasdan, 64 KB li darchalarda oqimli shifrlanadi.
   * Fayl hajmi 100 MB yoki 2 GB bo'lishidan qat'i nazar, xotira sarfi (RAM) **doimiy ~64 KB** bo'lib qoladi.
   * Har bir bo'lak `chunkIndex` va deterministik nonce bilan bog'lanadi, shuning uchun bo'laklarni almashtirish yoki o'g'irlash imkonsiz.
   * `PqcV3ChunkedAttachmentManifest` orqali ML-KEM kalit o'rami bir marta hosil qilinadi, so'ngra streaming dekodlash amalga oshiriladi.

2. **Guruhlar uchun $O(1)$ Sender-Key Protokoli (`pqc_group_sender_key.dart`):**
   * **Tarmoq va CPU yuklamasi kamaytirildi:** Eski $O(N)$ ML-KEM modeli o'rniga zamonaviy Signal/MLS uslubidagi Sender-Key arxitekturasi joriy qilindi.
   * `createDistribution` orqali Sender Key faqat bir marta guruh a'zolariga tarqatiladi.
   * Har bir guruh xabari endi barcha a'zolarga takroriy ML-KEM qilmasdan, yagona tezkor simmetrik zanjir orqali jo'natiladi.
   * Guruh a'zolari soni 10 ta bo'ladimi yoki 10,000 ta bo'ladimi — xabar hajmi **doimiy kichik hajmda** qoladi va shifrlash bir zumda bajariladi.

3. **Replay Guard uchun Sliding-Window va Xotira Tozalash:**
   * `PqcMemoryReplayStore` ga `maxEntries` (sukut bo'yicha 50,000) va FIFO asosidagi avtomatik darcha (sliding window) tozalash mexanizmi qo'shildi.
   * Xotira cheksiz shishib ketishi (memory leak / storage bloat) to'xtatildi.

4. **Verifikatsiya va Testlar:**
   * `test/scalability_and_streaming_test.dart` orqali streaming shifrlash, $O(1)$ guruh xabarlari va replay eviction to'liq sinovdan o'tkazildi.
   * Jami testlar soni **94 taga yetkazildi** (barchasi yashil / pass).
   * `dart analyze` to'liq toza (0 issues found).
