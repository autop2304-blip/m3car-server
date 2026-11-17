# Audit Keamanan Firebase Rules & Mekanisme Biaya Tol M3CAR

> **Status:** Rancangan Audit & Draft Rules (BELUM di-deploy ke produksi Firebase).  
> **File Rancangan:** `DRAFT_firestore.rules` & `DRAFT_storage.rules`

---

## 1. Temuan Audit Rules Saat Ini (`firestore.rules` & `storage.rules`)

1. **Catch-all Terbuka Total (`allow read, write: if true`)**  
   - `firestore.rules` baris 4–55 dan `storage.rules` baris 4–12 membuka akses baca, tulis, ubah, dan hapus untuk **seluruh koleksi Firestore** dan **seluruh file Storage** tanpa autentikasi.
   - Risiko kritis: siapa pun di internet dapat membaca foto KTP/SIM A driver, `passwordHash` / `recoveryCodeHash` driver, `adminAccessCode` pada `setting_admin/config`, data pelanggan, serta mengubah tarif, saldo driver, atau catatan keuangan `keuangan_admin` & `laporan_keuangan`.
2. **Ketidaksinkronan Daftar Koleksi**  
   - Koleksi aktif di aplikasi seperti `tarif_config`, `tarif_history`, `order_idempotency`, `customers`, `penumpang`, `users`, dan `_connection_test` sebelumnya belum terdaftar secara eksplisit di `firestore.rules` sehingga jatuh ke wildcard terbuka `/{document=**}`.
3. **Kesenjangan Autentikasi Aplikasi vs `request.auth` (Sangat Penting!)**  
   - **Pelanggan** saat ini login memakai Nama + No. HP (`localStorage`), bukan Firebase Auth wajib (`customerUid` hanya opsional).
   - **Driver** saat ini login memakai verifikasi `/api/driver/verify-password` (cookie HMAC aplikasi), bukan Firebase Auth custom token / UID.
   - **Admin** saat ini login via `/api/admin/login` (cookie HMAC aplikasi) atau cek lokal terhadap `setting_admin/config.adminAccessCode`, belum memakai Custom Claims `admin: true` atau koleksi `/admins/{uid}` secara konsisten.
   - **Listener Global `onSnapshot` di `firestoreService.ts`** langsung berlangganan hampir seluruh koleksi (termasuk `drivers`, `customers`, `keuangan_admin`, `laporan_keuangan`, `saldo_history`, `topup_requests`, `setting_admin/config`) saat aplikasi dibuka sebelum login.
   - **Mutasi Saldo & Keuangan dari Klien**: transaksi `acceptOrderWithTransaction`, `completeOrderWithTransaction`, `cancelOrReleaseOrderWithTransaction`, `approveTopUpRequest`, dan pencatatan `keuangan_admin` / `laporan_keuangan` masih berjalan langsung melalui Firestore Web SDK dari browser.

---

## 2. Matriks Akses Berbasis Peran (RBAC) pada Rancangan Baru

| Koleksi / Path | Pelanggan (`customer`) | Driver (`driver`) | Admin (`admin`) | Catatan Keamanan |
| :--- | :--- | :--- | :--- | :--- |
| `tarif_config`, `settings_jarak_dekat`, `settings_jarak_jauh` | `get`, `list` | `get`, `list` | **CRUD Penuh** | Pelanggan & driver hanya membaca tarif resmi; ubah/hapus khusus Admin. |
| `tarif_history` | Ditolak | Ditolak | **CRUD Penuh** | Audit trail perubahan tarif hanya untuk Admin. |
| `setting_admin/config` | **Ditolak** | **Ditolak** | **CRUD Penuh** | Memuat pengaturan sensitif & kode admin; dilarang diakses non-admin. |
| `setting_admin/{theme\|ad\|app\|payment}_config` | `get` saja | `get` saja | **CRUD Penuh** | Hanya dokumen konfigurasi UI non-rahasia yang bisa di-`get`. |
| `orders_jarak_dekat`, `orders_jarak_jauh`, `orders` | `get`/`list`/`create` milik sendiri; `update` hanya batal (`DIBATALKAN`) sebelum selesai | `get`/`list` milik sendiri + antrean `MENCARI_DRIVER` (jika aktif); `update` terima order & status perjalanan saja (tanpa ubah harga/komisi) | **CRUD Penuh** | Terminal state `SELESAI` & `DIBATALKAN` dikunci bagi non-admin. |
| `order_idempotency` | `get`/`create` milik sendiri | Ditolak | **CRUD Penuh** | Mencegah duplikasi/replay idempotency milik user lain. |
| `drivers`, `users_driver` | **Ditolak** | `get`/`list` profil sendiri; `create` (`MENUNGGU`, saldo 0); `update` lokasi/online/foto saja | **CRUD Penuh** | Driver **dilarang** mengubah `saldo`, `balance`, `status`, `isDeleted`, `totalTrips`. |
| `customers`, `users_customer`, `penumpang`, `users` | `get`/`list`/`create`/`update` profil sendiri (role `customer`) | **Ditolak** | **CRUD Penuh** | Isolasi PII nomor HP & data penumpang. |
| `topup_requests` | Ditolak | `get`/`list`/`create` (`MENUNGGU`, nominal > 0) milik sendiri | **CRUD Penuh** (Setujui / Tolak / Hapus) | Hanya Admin yang dapat mengubah status menjadi `BERHASIL` atau `DITOLAK`. |
| `saldo_history` | Ditolak | `get`/`list` mutasi milik sendiri | **CRUD Penuh** | Penulisan mutasi saldo dilarang dari klien non-admin. |
| `keuangan_admin`, `laporan_keuangan`, `wa_notifications`, `wa_logs` | **Ditolak** | **Ditolak** | **CRUD Penuh** | Data buku kas, rekap omset tahunan, & log WA eksklusif Admin. |
| `admins/{uid}` | `get` hanya UID sendiri | `get` hanya UID sendiri | `get` | `list/create/update/delete: if false` (anti eskalasi hak akses). |
| Storage `/drivers/ktp/*`, `/drivers/sim/*` | **Ditolak** | `read`/`create`/`update` file milik sendiri (maks 5 MB, image) | **Read & Delete** | Mencegah kebocoran foto KTP & SIM A publik. |

---

## 3. Simulasi Uji Serangan ("Dirty Dozen" Payload Checks)

1. **Anonim membaca semua driver (`getDocs(collection(db, 'drivers'))`)** -> **DITOLAK** (`list` wajib `isAdmin()` atau `resource.data.uid == request.auth.uid`).
2. **Anonim membaca `setting_admin/config` untuk mencuri `adminAccessCode`** -> **DITOLAK** (`setting_admin/config` khusus `isAdmin()`).
3. **Pelanggan/Driver mengubah tarif di `tarif_config/active` atau `settings_jarak_dekat/config`** -> **DITOLAK** (write wajib `isAdmin()`).
4. **Driver menaikkan saldo sendiri (`updateDoc(driverRef, { saldo: 99999999 })`)** -> **DITOLAK** (`saldo` & `balance` masuk daftar terlarang pada `isDriverSelfAllowedUpdate`).
5. **Driver menyetujui pendaftaran / top-up sendiri (`status: 'AKTIF'` atau `'BERHASIL'`)** -> **DITOLAK** (`create` dikunci `MENUNGGU`, `update` status/top-up khusus `isAdmin()`).
6. **Pelanggan A membaca atau membatalkan order Pelanggan B** -> **DITOLAK** (`isOrderCustomer` mengecek `customerUid == request.auth.uid`).
7. **Driver memanipulasi `totalPrice`, `commissionAmount`, atau `driverEarnings` saat menyelesaikan order** -> **DITOLAK** (`affectedKeys().hasOnly(...)` memblokir seluruh field harga & komisi).
8. **Pengguna biasa menulis `admins/{uid}` untuk mengangkat dirinya menjadi Admin** -> **DITOLAK** (`allow write: if false`).
9. **Pengguna mengubah order yang sudah `SELESAI` atau `DIBATALKAN`** -> **DITOLAK** (terminal state guard untuk non-admin).
10. **Anonim atau user lain mengunduh KTP/SIM Driver di Storage** -> **DITOLAK** (`DRAFT_storage.rules` hanya mengizinkan pemilik UID atau Admin).
11. **Driver/Pelanggan membaca atau menghapus buku kas `keuangan_admin` / `laporan_keuangan`** -> **DITOLAK** (`if isAdmin()`).
12. **Akses ke koleksi liar/tidak dikenal (`/unknown_collection/x`)** -> **DITOLAK** (catch-all `allow read, write: if false`).

---

## 4. Dampak Penerapan Rules Terhadap Aplikasi Saat Ini (Breaking Changes)

Jika `DRAFT_firestore.rules` dan `DRAFT_storage.rules` langsung di-deploy **sebelum** penyesuaian jalur autentikasi & backend, bagian berikut akan terkena `PERMISSION_DENIED`:
1. **Login Non-Firebase-Auth (Pelanggan, Driver, Admin)**: Karena saat ini login menggunakan `localStorage` + session cookie server `/api/*` tanpa token `request.auth` Firebase, seluruh operasi Firestore dari browser akan ditolak jika user belum terautentikasi Firebase (`Anonymous` + `Custom Token` atau `Google Sign-In` untuk Admin).
2. **`startFirestoreRealtimeSync()` di `src/services/firestoreService.ts`**: Pemanggilan listener `onSnapshot` global pada seluruh koleksi saat startup (sebelum login & tanpa filter `where('customerUid', '==', uid)` / `where('driverUid', '==', uid)`) akan gagal di Firestore.
3. **Transaksi Klien yang Menyentuh Saldo & Keuangan**:
   - `acceptOrderWithTransaction` & `completeOrderWithTransaction` saat driver menerima/menyelesaikan order langsung memperbarui `drivers.saldo` dan menulis `saldo_history`, `keuangan_admin`, dan `laporan_keuangan` dari browser.
   - Pada arsitektur Zero-Trust, pemotongan/pengembalian saldo komisi dan pencatatan `keuangan_admin`/`laporan_keuangan` harus dipindahkan ke backend tepercaya (Express/Netlify Functions atau Cloud Functions dengan **Firebase Admin SDK** yang melewati rules klien), atau dieksekusi dengan kredensial Admin terverifikasi.
4. **Query Pencarian Driver by Phone (`fetchDriverByPhoneFromFirestore`)**: Saat ini melakukan `getDocs(collection(db, 'drivers'))` di browser; setelah rules aktif, login driver harus tetap lewat backend (`/api/driver/verify-password`) yang mengembalikan **Firebase Custom Token** ber-claim `{ role: 'driver', driverActive: true }` atau data terfilter aman.
5. **Upload KTP/SIM sebelum login**: Saat mendaftar driver baru, klien harus memiliki Firebase Auth session terlebih dahulu (mis. `signInAnonymously` atau akun Firebase Auth) dan menamai path/metadata sesuai `request.auth.uid`.

---

## 5. Audit Mekanisme Biaya Tol (`Biaya Tol`)

- **Hasil Pemeriksaan Kode**:
  - **Belum ada integrasi atau kalkulasi biaya tol otomatis** (Google Routes API hanya dipakai untuk menghitung jarak & durasi rute jalan, bukan tarif gerbang tol; `Order.tollRoute` hanya berupa teks deskriptif statis seperti `"Tol Jakarta-Merak + Tol Serang-Panimbang 83,6 km"` atau `"Layanan Jarak Dekat (X km)"`).
  - **Belum ada kolom input nominal tol terpisah** di form pemesanan penumpang (`CustomerView.tsx`) maupun penyelesaian order driver (`DriverView.tsx`).
  - Pada tampilan penumpang (`CustomerView.tsx`) dan driver (`DriverView.tsx`), aplikasi sudah menampilkan keterangan eksplisit: `"Biaya Tol: Terpisah (Ditanggung Penumpang)"` dan `"Biaya tol dibebankan terpisah kepada penumpang (di luar tarif & komisi)"`.
  - **Temuan Penting pada `biayaTambahanDefault`**:
    - Di `AdminPricingSection.tsx` & `autoTariffCalculator.ts`, field `biayaTambahanDefault` memiliki label default `"Biaya Tambahan / Tol"` (Indonesia) dan `"Tol / Caj Tambahan"` (Malaysia), dan nilainya secara default adalah **`0`** (`Rp 0` / `RM 0`).
    - Namun secara matematis di `calculateAutoFare()`, jika Admin mengisi `biayaTambahanDefault > 0`, nilai tersebut **ikut masuk ke `totalPrice` dan ikut terkena potongan komisi driver (`komisiPersen`)**.
    - **Kebijakan Operasional yang Direkomendasikan**: Jangan mengklaim biaya tol dihitung otomatis; biarkan `biayaTambahanDefault = 0` untuk komponen tol, dan apabila di tahap berikutnya ingin menambah fitur input nominal tol aktual (mis. struk tol yang dibayarkan penumpang), gunakan field terpisah (mis. `biayaTolTerpisah`) yang **tidak masuk ke `totalPrice` tarif perjalanan maupun dasar perhitungan `commissionAmount`**.
