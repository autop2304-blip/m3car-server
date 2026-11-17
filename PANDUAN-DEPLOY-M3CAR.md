# M3CAR — paket GitHub dan Netlify

## Cara memasang
1. Ekstrak ZIP ini dan unggah seluruh isi folder ke repository GitHub privat (jangan unggah kata sandi atau file `.env` asli).
2. Netlify → Add new project → Import from GitHub → pilih repository.
3. Build command `npm run build`, publish directory `dist`. Netlify Functions berada di `netlify/functions` sesuai `netlify.toml`.
4. Netlify → Project configuration → Environment variables: atur `ADMIN_ACCESS_CODE` (kode admin baru yang kuat dan rahasia), `ADMIN_SESSION_SECRET` (acak, minimal 32 karakter), dan `QUOTE_SIGNING_SECRET` (acak). Jangan menaruh nilai rahasia pada variabel `VITE_*`.
5. Deploy ulang. Periksa `https://DOMAIN-ANDA/api/admin/health` dan `/api/driver/health` — keduanya harus menampilkan JSON `ok: true`.
6. Jalankan `node scripts/check-deployment.mjs https://DOMAIN-ANDA` di komputer dengan Node 20+.
7. Konfirmasi konfigurasi Firebase di `src/firebase.ts` cocok dengan proyek Firebase milik Anda; atur Firebase Authentication authorized domains bila digunakan, Firestore dan Storage rules sebelum dipakai publik.
8. Uji manual: pendaftaran driver → terlihat pada admin → admin menyetujui → driver login → penumpang pesan → order muncul pada driver dan admin. Uji juga driver pending/ditolak, sandi salah, dan jaringan putus.

## PENTING: BELUM AMAN UNTUK PRODUKSI
File `firestore.rules` bawaan proyek mengizinkan pembacaan/penulisan publik (`if true`) untuk data sensitif termasuk driver, admin, order. **JANGAN terbitkan aturan tersebut.** Arsitektur autentikasi masih membutuhkan perubahan server-side: endpoint verifikasi driver menerima hash sandi dan status dari browser, sehingga tidak boleh dipercaya sebagai otorisasi. Seluruh penulisan data sensitif harus memakai identitas yang diverifikasi server dan Firestore Security Rules ketat. Paket ini tidak menjamin login selalu berhasil, tidak membuktikan koneksi Firebase langsung, dan tidak dinyatakan siap melayani pengguna publik.

## Jika muncul 'server terputus'
Periksa Netlify → Logs → Functions → `driver-api`, URL health di atas, redirect `/api/driver/*` pada `netlify.toml`, dan error browser Network. Jika health sukses tetapi login gagal, cek data driver di Firestore, status persetujuan, dan kebijakan keamanan. Jangan mematikan verifikasi sandi sebagai solusi.
