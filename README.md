# Muntazam Control

Muntazam cihaz yonetim paneli Express, Vite ve PostgreSQL ile calisir. Production'da frontend `dist` klasorunden Express tarafindan servis edilir.

## Calistirma

```bash
npm install
npm run dev
```

## Railway

1. Railway'de bir PostgreSQL servisi ekleyin.
2. Bu klasoru GitHub repository olarak deploy edin veya Railway CLI ile baglayin.
3. Uygulama servisinde `DATABASE_URL` degiskenini PostgreSQL servisinden reference olarak ekleyin.
4. `SESSION_SECRET` icin uzun, rastgele bir deger ekleyin.
5. `NODE_ENV=production` ayarlayin.

Railway `npm start` komutunu ve `railway.toml` icindeki `/api/health` healthcheck'ini kullanir. Veritabani tablolari ilk acilista otomatik olusturulur. Ilk yonetici sifresi `123123`'tur; deploy sonrasi Ayarlar ekranindan degistirilmelidir.

Panel rotalari hash tabanlidir: `#overview`, `#devices`, `#device/:id`, `#activity`, `#schedule`, `#settings`.

Yonetici sifresi ve cihazlar PostgreSQL'de tutulur. Oturumlar HttpOnly cookie ile korunur. Uzaktan komutlar bu prototipte audit kaydi ve kuyruk cevabi olarak calisir; gercek cihaz uygulamasi, kullanici onayi ve sifreli cihaz kanali sonraki asamada eklenmelidir.
