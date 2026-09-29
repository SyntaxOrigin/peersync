# PeerSync (30 EşDosya)

Sunucusuz P2P dosya senkronizasyonu: UDP yayın eş keşfi, içerik tanımlayıcılı
parçalama (CDC) ve uçtan uca şifreli delta aktarımı.

Tek bir çalıştırılabilir dosya, iki komut, sıfır yapılandırma dosyası. İki eş aynı
klasörü karşılıklı paylaşır; hangisinin yeni olduğu bilinmezse **son yazan kazanır**
kuralı devreye girer ve kaybeden tarafın sürümü asla silinmez.

## Özellikler

- **Sunucusuz P2P** — merkezi sunucu, hesap veya bulut yok. Eşler UDP yayın ilanıyla
  (`PSYN` paketi, 47474/udp) birbirini bulur, el sıkışmayla karşılıklı kimlik
  değişimi yapar.
- **Parça tabanlı delta** — kayan pencere (64 bayt) + 13-bit eşik (`0x1FFF`) ile
  içerik tanımlayıcılı parçalama. Ortak parçalar hiç taşınmaz; hedefte zaten
  bulunan parça için **tek bayt** gitmez.
- **Uçtan uca şifreli** — parola → Argon2id → HKDF-SHA256 → ChaCha20-Poly1305.
  Parola diske yazılmaz, log'a girmez, ağda dolaşmaz. Anahtar tek yönlü
  türetilir; karşı taraf parolayı bilmeden oturumu açamaz.
- **Kayıpsız taşıma** — büyük çerçeveler `PSSG` segmentlerine bölünür, 48 segmentlik
  pencereyle akış denetimi yapılır, kayıp segmentler yeniden gönderilir.
- **Çakışma güvenliği** — revizyon numarası sonra, eşitlikte sahip kimliği karar
  verir. Kaybeden tarafın sürümü `dosya.conflict-<kimlik>-<revizyon>.conflict`
  adıyla yan yana korunur.
- **Atomik yazım** — gelen dosya geçici dosyada kurulur, karması doğrulanır,
  sonra hedefe taşınır. Yarım kalan dosya hedefte asla görünmez.
- **Tek yönlü tekrarsız nonce** — oturum başına sayaç tabanlı nonce üretimi; aynı
  anahtarla aynı nonce iki kez üretilemez.
- **Bant genişliği sınırı** — `--sn` ile bayt/saniye cinsinden akış hızı
  sınırlanabilir.

## Kurulum

Gereksinim: **Rust 1.98+** (aşağıdaki MSRV notuna bakınız) ve Windows'ta
`link.exe` için MinGW-w64 (POSIX/UCRT paketi).

> **MSRV beyanı doğrulanmamıştır.** `Cargo.toml` içindeki `rust-version = "1.98"`
> **geliştirme ve doğrulama** için kullanılan toolchain'i yansıtır: `cargo build
> --release`, `cargo test` ve kalite kapısı koşumlarının tamamı `rustc 1.98.1`
> üzerinde yapılmıştır. Kodun 1.98'den **daha eski** bir toolchain'de derlenip
> derlenmediği **test edilmemiştir** ve bu depoda iddia edilmemektedir. Daha eski
> bir toolchain'de derleme gerekirse `rust-version` değerini düşürüp
> `cargo +<sürüm> build --release && cargo +<sürüm> test` ile **kendi
> ortamınızda** doğrulayın.

```powershell
# MinGW araç zincirini PATH'e ekleyin (yoksa)
$env:PATH = "%USERPROFILE%\AppData\Local\Microsoft\WinGet\Packages\BrechtSanders.WinLibs.POSIX.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\mingw64\bin;" + $env:PATH
$env:PATH = "%USERPROFILE%\.cargo\bin;" + $env:PATH

# Derle
cd %USERPROFILE%\Desktop\Projeler\projects\30-peersync
cargo build --release
```

Çıktı: `target\release\peersync.exe`

## Kullanım

Üç komut vardır: `serve` (paylaşılan klasörü yayınlar), `sync` (tek eşe bağlanır),
`join` (yalnızca eş arar), artı `status` ve `pair`.

### İki eş arasında senkronizasyon

Terminal 1 — paylaşılacak klasörü aç:

```powershell
$env:PEERSYNC_PAROLA = "ortak-parola"
.\target\release\peersync.exe serve --root .\kaynak --password-env PEERSYNC_PAROLA
```

Terminal 2 — hedef klasörü eşle:

```powershell
$env:PEERSYNC_PAROLA = "ortak-parola"
.\target\release\peersync.exe sync --root .\hedef --password-env PEERSYNC_PAROLA --peer 127.0.0.1:47474
```

Gerçek çalıştırmadan alınan çıktı (kaynak: `buyuk.bin` 300 000 B, `orta.bin`
60 000 B, `rapor.txt`; hedefte yalnızca farklı `rapor.txt` vardı):

```
peersync 0.1.0 sync: 2bb4729a090b7abf0d79ca1a317b98f6 es, 1 dosya taranildi, oturum 7825488845bd9ac2
sonuc: 2 cekildi, 0 gonderildi, 1 catisma, 6 parca, 360000 bayt, 0 gecici silindi
aktarilan 1040 bayt, hiz siniri 0 bayt/sn
```

Sunucu tarafı:

```
peersync 0.1.0 serve: 3 dosya taranildi, port 47474 dinleniyor (yayin: acik)
el sikisma tamam: 7825488845bd9ac2
senkronizasyon: 0 gonderildi, 360000 bayt
```

Sonuç: `buyuk.bin` ve `orta.bin` hedefe SHA-256 olarak birebir geldi; `rapor.txt`
çakıştı, hedefteki sürüm korundu, kaybeden kaynağın sürümü
`rapor.conflict-2bb4729a090b7abf0d79ca1a317b98f6-1.conflict` olarak yedeklendi.

### Alt komutlar

| Komut | Ne yapar |
| --- | --- |
| `serve` | Yayın ilanı gönderir, el sıkışma kabul eder, gelen talepleri yanıtlar. |
| `join` | Verilen süre boyunca yayın dinler ve bulunan eşleri listeler. |
| `sync` | Verilen `IP:PORT` eşine bağlanır ve senkronizasyon yapar. |
| `status` | Depo durumunu raporlar (dosya/parça/bayt sayıları, kimlik). |
| `pair` | Grup etiketi ve yerel kimliği gösterir; iki eşi eşleştirmek için kullanılır. |

Parola üç yolla verilebilir. `--password-env` önerilir; `--password` işlem
listesinde görünür ve tercih edilmemelidir.

```powershell
--password-env PEERSYNC_PAROLA   # ortam değişkeninden (önerilen)
--password-file .\parola.txt     # dosyadan
--password "parola"              # doğrudan (önerilmez)
```

## Test

```powershell
cargo test                      # 202 test (195 birim + 7 uçtan uca)
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo build --release
```

Son doğrulanan sonuç:

```
running 195 tests
test result: ok. 195 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
running 7 tests
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Uçtan uca testler (`tests/e2e_senkron.rs`) gerçek UDP soketleri ve gerçek
şifreli oturum kullanır; hiçbiri taklit (mock) değildir:

- `gercek_iki_es_arasinda_dosya_cekilir_ve_dogrulanir` — iki depo, iki soket,
  tam el sıkışma; içerik ve karmalar karşılaştırılır, aktarılan bayt sayısı
  dosyaların toplamından küçük çıkar (delta gerçekten çalışır).
- `gercek_iki_es_arasinda_kaynaktan_hedefe_gonderim_yapilir` — sunucu rolündeki
  eşten istemciye gönderim.
- `catisma_durumunda_kaybeden_surum_yedeklenir` — kaybeden tarafın sürümü
  `.conflict` dosyası olarak korunur.
- `bant_genisligi_siniri_uygulanir` — `--sn` sınırı ölçülür.
- `bozuk_parca_aktarimi_hedefe_yazmaz` — bozuk segment hedefe yazılmaz.
- `manifest_icerigi_ozetlerle_karsilastirilir` — manifest özeti tutarlılığı.
- `yanlis_parola_ile_el_sikisma_kurulamaz` — yanlış parola oturumu açamaz.

## Proje Yapısı

`src/` altında 15 dosya, toplam ~9 700 satır (testler dahil).

| Dosya | Satır | Sorumluluk |
| --- | ---: | --- |
| `protok.rs` | 1 415 | Çerçeve kodu/okuma, serileştirme, segment başlığı, `PSSG` |
| `senkron.rs` | 1 201 | Delta kararı, çakışma çözümü, iki fazlı senkronizasyon akışı |
| `depo.rs` | 1 002 | Tarama, parça deposu, atomik birleştirme, çakışma yedeği |
| `tasma.rs` | 772 | UDP taşıma, segmentasyon, akış denetimi, yeniden gönderim |
| `parca.rs` | 731 | CDC parçalayıcı, parça doğrulama |
| `kesif.rs` | 731 | Yayın ilanı, eş tablosu, bayat düşürme |
| `sifre.rs` | 695 | Argon2id, HKDF, ChaCha20-Poly1305, nonce, parola kanıtı |
| `el_sikisma.rs` | 692 | Karşılıklı kimlik doğrulama durum makinesi |
| `kuyruk.rs` | 530 | Öncelik kuyruğu, duraklatma, hız sınırlayıcı |
| `main.rs` | 462 | `clap` CLI |
| `kimlik.rs` | 399 | Kimlik üretimi/yüklenmesi, kaynak sınırları |
| `karma.rs` | 322 | SHA-256, karmalayıcı, liste özeti |
| `gunluk.rs` | 314 | JSONL olay günlüğü |
| `hata.rs` | 258 | Hata türleri ve `Display` |
| `lib.rs` | 169 | Modül dışa aktarımları, `kimlik_yukle_veya_uret` |

Ayrıca `tests/e2e_senkron.rs` ve `tests/yardimci/mod.rs` (geçici dizin ve
deterministik veri üreteçleri; `tempfile` bağımlılığı kullanılmaz).

## Yapılandırma

Her şey komut satırı bayraklarıyla verilir; yapılandırma dosyası yoktur.

| Bayrak | Varsayılan | Açıklama |
| --- | --- | --- |
| `--root <KLASOR>` | zorunlu | Paylaşılan klasörün kökü |
| `--peer <IP:PORT>` | — | `sync` için karşı eş adresi |
| `--port <PORT>` | `47474` | Yayın portu (keşiften sonra bağlanılacak port) |
| `--password-env <DEG>` | — | Parolanın okunacağı ortam değişkeni |
| `--password-file <DOSYA>` | — | Parolanın okunacağı dosya |
| `--password <PAROLA>` | — | Doğrudan parola (önerilmez) |
| `--sn <BAYT_SN>` | `0` | Bant genişliği sınırı; `0` = sınırsız |
| `--timeout-ms <MS>` | `5000` | El sıkışma ve çerçeve zaman aşımı |
| `--announce-ms <MS>` | `2000` | Yayın ilanı aralığı |
| `--broadcast <IP>` | `255.255.255.255` + alt ağ | Yayın hedefi |

Depo, paylaşılan klasörün içinde `.peersync/` altında tutulur: `indeks.json`
(dosya kayıtları), `parcalar/` (içerik adresli parçalar) ve `gecmis.jsonl`
(olay günlüğü).

Derleme sabitleri:

| Sabit | Değer | Nerede |
| --- | --- | --- |
| Yayın portu | `47474` | `kesif::VARSAYILAN_PORT` |
| Maksimum eş | `16` | `kesif::AZAMI_ES` |
| Segment başlığı | `12` bayt | `protok::SEGMENT_BASLIK` |
| Pencere | `48` segment | `tasma` |
| Maksimum istek yığını | `256` parça | `protok::AZAMI_ISTEK` |
| CDC penceresi | `64` bayt | `parca::PENCERE` |
| CDC eşiği | `0x1FFF` (13 bit) | `parca::VARSAYILAN_ESIK` |
| Minimum parça | `2 KiB` | `parca::ParcaAyari` |
| Maksimum parça | `64 KiB` (sert üst sınır `1 MiB`) | `parca` / `senkron::AZAMI_PARCA` |
| Dizin derinliği | `32` | `depo::AZAMI_DERINLIK` |

## Bilinen Sınırlamalar

- **Çakışma çözümü son yazan kazanır.** İki eş aynı dosyayı eşzamanlı ve
  çevrimdışıyken değiştirirse, yüksek revizyonlu (eşitlikte kimlik büyük olan)
  taraf kazanır. Kaybedenin verisi yedeğe alınır ama birleştirilmez; üç yönlü
  birleştirme (three-way merge) kapsam dışıdır.
- **Tam eş yönlendirme yok.** Oturum tek bir karşı eşle kurulur; çok eşli ağ
  (transit aktarım, dedupe tabanlı P2P) yoktur. Her oturumda veri eşler arasında
  yalnızca iki nokta arasında akar.
- **Eş keşfi yayına bağlı.** Ağ yayınını engelliyorsa `join` eş bulamaz; `sync`
  `--peer` ile elle adres verilerek çalışır. NAT arkasındaki eşlere dışarıdan
  bağlanılamaz (STUN/rendezvous yok).
- **Depo taraması tam taramadır.** Her `serve`/`sync` başlangıcında klasör
  yeniden taranır; dosya sistemi izleyicisi (watcher) yoktur.
- **Güvenlik kanalı yok.** Trafik gizli değildir; yayın ilanı paketleri düz
  metindir. Ağ üzerinden gizlilik için VPN önerilir.
- **Parola gücüne bağlı.** Argon2id parametreleri makul bir denge; parola
  sözlüğü saldırısına karşı garanti verilmez.
- **Sıra sayacının üst sınırı `u64`, oturum yenilemesi zorunlu.** Gönderen taraf
  `NonceSayaci::sonraki_nonce` ile `u64::MAX`'te sarmalamayı **reddeder** ve
  alıcı taraf aynı sözleşmeyi uygular: sayaç taşarsa `Hata::SiraTasmasi` döner,
  bağlantı kapatılmalıdır. Taşma pratikte `2^64` pakete yaklaşmayı gerektirir;
  bu yüzden koruma bir **sözleşme tutarlılığı** garantisidir, bir olasılık
  azaltması değil. Doğrulama penceresi (replay window) `beklenen` sayacıdır ve
  sarmalama bir kez olsa **tüm eski paketler yeniden kabul edilir**; bu yüzden
  sarmalama yerine hata dönmesi bilinçli bir seçimdir
  (`sifre::tests::tasma_deneden_sonra_eski_paket_hala_oynatma_reddedilir`).
- **MSRV beyanı ölçülmüş değildir.** Bkz. [Kurulum](#kurulum) bölümündeki not:
  `rust-version = "1.98"` yalnızca doğrulamanın yapıldığı toolchain'i yansıtır,
  daha eski sürümler test edilmemiştir.

## Gelecek Geliştirmeler

- Üç yönlü birleştirme ve çakışma çözümleme arayüzü.
- Çok eşli ağ: dedupe tabanlı yönlendirme ve geçici aktarım zinciri.
- STUN/rendezvous ile NAT geçişi.
- Dosya sistemi izleyici ile kademeli tarama.
- Sıkıştırma (zstd) ve bant genişliği uyarlaması.
- Anahtar rotasyonu ve oturum devamlılığı.
- Platform paketleri ( MSI / Scoop ).

## Troubleshooting

**`el sikisma merhaba yaniti` zaman aşımı hatası**
Sunucu ayakta mı? `serve` çalışan terminalde `--port` değerini `--peer` ile
aynı kullanın. Ağ yayınını engelliyorsa `--peer 127.0.0.1:47474` gibi elle adres
verin.

**`es bulunamadi: ag yayinini engelliyor olabilir`**
`join` komutu yayın ilanı duymuyor. Güvenlik duvarı veya yönlendirici UDP
broadcast'u engelliyor olabilir. `--peer` ile elle bağlanın; `serve --broadcast`
ile hedefi değiştirin.

**Yanlış parola hatası**
İki tarafın parolası birebir aynı olmalı. Tıraflı boşluk/tab farkı bile farklı
grup etiketi üretir. `pair` komutunu iki tarafta çalıştırıp etiketleri
karşılaştırın.

**`sistem belirtilen dosyayı bulamıyor` (Hata::Io)**
Hedef dosya adı geçersiz veya silinmiş. `status` çalıştırıp depo indeksini
kontrol edin; gerekirse hedef klasördeki `.peersync/` dizinini silip yeniden
tarayın.

**Sinyal zayıf / port meşgul**
`--port` ile farklı bir port seçin. `serve` portu yayın portuyla aynıdır; iki
PeerSync örneğini aynı makinede çalıştırıyorsanız ikisine farklı port verin.

**Çakışma yedeklerini temizlemek**
Yedekler `*.conflict` uzantısıyla durur ve normal taramaya girmez. Yedeklemeden
emin olduktan sonra elle silebilirsiniz.

## Lisans

MIT. Ayrıntı için `LICENSE.txt`.

## Atıflar

- Chris Ancliff ve ark., *Rolling Hash* — CDC'de kayan pencere fikri.
- Larry Peterson ve Bruce Davie, *Computer Networks: A Systems Approach*, 5. baskı,
  bölüm 4 (ağ katmanı, güvenilirlik) — UDP üzerinde akış denetimi.
- RustCrypto, *chacha20poly1305* ve *argon2* crate'leri (RustCrypto projesi).
- D. B. Wilson, *The Assignation Address Codes* — STUN/RTCIceCandidate kaynak
  çalışması.
- Yerel şartname: `%USERPROFILE%\Desktop\Fikirler\30-es-dosya-senkron-p2p.html`
  ve `%USERPROFILE%\Desktop\Projeler\WORKER_CONTRACT.md`.
