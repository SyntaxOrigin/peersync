//! PeerSync komut satırı arayüzü.
//!
//! Beş alt komut vardır: `serve` (ilan + el sıkışma kabul), `join` (keşif),
//! `sync` (senkronizasyon), `status` (depo durumu), `pair` (grup etiketi ve
//! parola doğrulama bilgisi).
//!
//! Güvenlik notu: parola `--password` ile verilirse işlem listesi (ps) üzerinden
//! görülebilir. Daha güvenli yollar `--password-file` ve `--password-env`
//! seçenekleridir; README'de bu tercih açıkça yazılıdır.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

use peersync::depo::Depo;
use peersync::el_sikisma::{self, SikismaAyar};
use peersync::gunluk::{Durum, Gunluk};
use peersync::hata::{Hata, Sonuc};
use peersync::kesif::{Ehtiyat, Kesif, KesifAyar};
use peersync::kimlik::{Gizli, GrupEtiketi, OturumOzutu, Turetme};
use peersync::kuyruk::{Duraklatma, HizSinirlayici};
use peersync::parca::ParcaAyari;
use peersync::senkron::{Senkron, SenkronAyar, SenkronOzeti};
use peersync::{DEPO_DIZINI, GUNLUK_DOSYASI, SURUM};

/// EşDosya (PeerSync) — sunucusuz P2P dosya senkronizasyonu.
#[derive(Parser, Debug)]
#[command(name = "peersync", version, about, long_about = None)]
struct Tkk {
    /// Alt komut.
    #[command(subcommand)]
    komut: Komut,
}

#[derive(Subcommand, Debug)]
enum Komut {
    /// Yayın ilanı gönderir, el sıkışma kabul eder ve gelen talepleri yanıtlar.
    Serve(ServeArgs),
    /// Yayın ilanı gönderir ve bulunan eşleri listeler.
    Join(JoinArgs),
    /// Belirtilen eşle senkronizasyon yapar.
    Sync(SyncArgs),
    /// Deponun durumunu raporlar.
    Status(StatusArgs),
    /// Grup etiketini ve yerel kimliği gösterir (parola doğrulaması için).
    Pair(PairArgs),
}

/// Ortak argümanlar.
#[derive(Parser, Debug, Clone)]
struct OrtakArgs {
    /// Paylaşılan klasörün kökü.
    #[arg(long, value_name = "KLASOR")]
    root: PathBuf,
    /// Grup parolası (işlem listesinde görünür; tercih edilmeyen yol).
    #[arg(long, value_name = "PAROLA", conflicts_with_all = ["password_file", "password_env"])]
    password: Option<String>,
    /// Parolanın okunacağı dosya.
    #[arg(long, value_name = "DOSYA", conflicts_with_all = ["password", "password_env"])]
    password_file: Option<PathBuf>,
    /// Parolanın okunacağı ortam değişkeni.
    #[arg(long, value_name = "DEGISKEN", conflicts_with_all = ["password", "password_file"])]
    password_env: Option<String>,
    /// Bant genişliği sınırı (bayt/saniye; 0 = sınırsız).
    #[arg(long, value_name = "BAYT_SN", default_value_t = 0)]
    sn: u64,
    /// El sıkışma ve çerçeve zaman aşımı (milisaniye).
    #[arg(long, value_name = "MS", default_value_t = 5000)]
    timeout_ms: u64,
}

impl OrtakArgs {
    /// Parolayı seçilen kaynaktan okur.
    ///
    /// # Hatalar
    ///
    /// Hiçbir kaynak verilmemişse [`Hata::ParolaZorunlu`] döner. Parola
    /// zorunludur çünkü **şifrelenmemiş aktarım modu yoktur**.
    fn parola(&self) -> Sonuc<Gizli> {
        if let Some(metin) = &self.password {
            return Ok(Gizli::metinden(metin.trim_end_matches(['\r', '\n'])));
        }
        if let Some(yol) = &self.password_file {
            let metin = std::fs::read_to_string(yol)?;
            return Ok(Gizli::metinden(metin.trim_end_matches(['\r', '\n'])));
        }
        if let Some(ad) = &self.password_env {
            let deger = std::env::var(ad).map_err(|_| {
                Hata::GecersizArguman(format!("ortam değişkeni ayarlanmamış: {ad}"))
            })?;
            return Ok(Gizli::metinden(deger.trim_end_matches(['\r', '\n'])));
        }
        Err(Hata::ParolaZorunlu)
    }

    fn zaman_asimi(&self) -> Duration {
        Duration::from_millis(self.timeout_ms.max(100))
    }

    fn senkron_ayar(&self) -> SenkronAyar {
        SenkronAyar {
            zaman_asimi: self.zaman_asimi(),
            deneme: 2,
            yeniden_tara: true,
        }
    }
}

#[derive(Parser, Debug)]
struct ServeArgs {
    /// Ortak argümanlar.
    #[command(flatten)]
    ortak: OrtakArgs,
    /// Dinlenecek yayın portu.
    #[arg(long, default_value_t = peersync::kesif::VARSAYILAN_PORT)]
    port: u16,
    /// Yayın ilanı aralığı (milisaniye).
    #[arg(long, default_value_t = 2000)]
    announce_ms: u64,
    /// Gönderilecek yayın adresi (varsayılan: 255.255.255.255 ve alt ağ).
    #[arg(long, value_name = "IP")]
    broadcast: Option<IpAddr>,
}

#[derive(Parser, Debug)]
struct JoinArgs {
    /// Ortak argümanlar.
    #[command(flatten)]
    ortak: OrtakArgs,
    /// Yayın portu.
    #[arg(long, default_value_t = peersync::kesif::VARSAYILAN_PORT)]
    port: u16,
    /// Keşif süresi (saniye).
    #[arg(long, default_value_t = 6)]
    sure: u64,
    /// Yayın ilanı aralığı (milisaniye).
    #[arg(long, default_value_t = 500)]
    announce_ms: u64,
}

#[derive(Parser, Debug)]
struct SyncArgs {
    /// Ortak argümanlar.
    #[command(flatten)]
    ortak: OrtakArgs,
    /// Karşı eşin adresi (ör. 127.0.0.1:47474).
    #[arg(long, value_name = "IP:PORT")]
    peer: SocketAddr,
    /// Yayın portu (keşiften sonra bağlanılacak port).
    #[arg(long, default_value_t = 0)]
    port: u16,
    /// Keşif yapılsın mı?
    #[arg(long, default_value_t = false)]
    kesif: bool,
}

#[derive(Parser, Debug)]
struct StatusArgs {
    /// Paylaşılan klasörün kökü.
    #[arg(long, value_name = "KLASOR")]
    root: PathBuf,
    /// Ayrıntılı dosya listesi yazılsın mı?
    #[arg(long, default_value_t = false)]
    ayrinti: bool,
}

#[derive(Parser, Debug)]
struct PairArgs {
    /// Ortak argümanlar.
    #[command(flatten)]
    ortak: OrtakArgs,
    /// Otomatik el sıkışma yapılsın mı?
    #[arg(long, default_value_t = false)]
    dogrula: bool,
}

fn main() {
    let tkk = Tkk::parse();
    let sonuc = calistir(tkk);
    if let Err(hata) = sonuc {
        eprintln!("peersync: {hata}");
        std::process::exit(1);
    }
}

fn calistir(tkk: Tkk) -> Sonuc<()> {
    match tkk.komut {
        Komut::Serve(a) => serve(a),
        Komut::Join(a) => join(a),
        Komut::Sync(a) => sync(a),
        Komut::Status(a) => status(a),
        Komut::Pair(a) => pair(a),
    }
}

fn gunluk_ac(root: &std::path::Path) -> Sonuc<Gunluk> {
    let yol = root.join(DEPO_DIZINI).join(GUNLUK_DOSYASI);
    let mut gunluk = Gunluk::ac(&yol)?;
    gunluk.yaz(Durum::Basladi, format!("peersync {SURUM}"))?;
    Ok(gunluk)
}

fn serve(a: ServeArgs) -> Sonuc<()> {
    let parola = a.ortak.parola()?;
    let kimlik = peersync::kimlik_yukle_veya_uret(&a.ortak.root)?;
    std::fs::create_dir_all(&a.ortak.root)?;
    let mut depo = Depo::ac(&a.ortak.root, kimlik, ParcaAyari::varsayilan())?;
    let ozet = depo.tara()?;
    depo.kaydet()?;
    let mut gunluk = gunluk_ac(&a.ortak.root)?;
    let etiket = GrupEtiketi::turet(&parola)?;
    let ozut = OturumOzutu::turet(&parola)?;

    let kesif_ayar = KesifAyar {
        aralik: Duration::from_millis(a.announce_ms.max(100)),
        zaman_asimi: a.ortak.zaman_asimi(),
        deneme: 2,
        azami_es: peersync::kesif::AZAMI_ES,
        hedefler: a
            .broadcast
            .map_or_else(Vec::new, |ip| vec![SocketAddr::new(ip, a.port)]),
    };
    let mut kesif = Kesif::ac(a.port, kimlik, etiket, kesif_ayar)?;
    let soket = kesif.soket_kopya()?;
    gunluk.yaz(
        Durum::KesifBasladi,
        format!("port {} yayin etkin={}", a.port, kesif.yayin_aktif()),
    )?;
    println!(
        "peersync {} serve: {} dosya taranildi, port {} dinleniyor (yayin: {})",
        SURUM,
        ozet.taranan,
        a.port,
        if kesif.yayin_aktif() {
            "acik"
        } else {
            "kapali"
        }
    );

    let mut ehtiyat = Ehtiyat::yeni(a.ortak.zaman_asimi() * 4, peersync::kesif::AZAMI_ES);
    let sikisma_ayar = SikismaAyar {
        zaman_asimi: a.ortak.zaman_asimi(),
        deneme: 2,
    };
    loop {
        kesif.ilan_gonder()?;
        if kesif.dinle(&mut ehtiyat, Instant::now())? > 0 {
            gunluk.yaz(
                Durum::EsBulundu,
                format!("{} es biliniyor", ehtiyat.boyut()),
            )?;
        }
        // El sıkışma her tur denenir, keşif tablosu boş olsa bile: istemci
        // keşif yapmadan doğrudan `--peer` adresine bağlanabilir ve o
        // merhabanın yanıtlanması gerekir.
        ehtiyat.bayatlari_dusur(Instant::now());
        match el_sikisma::sunucu(&soket, kimlik, etiket, &ozut, sikisma_ayar) {
            Ok(baglanti) => {
                gunluk.yaz(
                    Durum::SikismaTamam,
                    format!("oturum {}", baglanti.kisa_oturum_id()),
                )?;
                println!("el sikisma tamam: {}", baglanti.kisa_oturum_id());
                let mut tasima = baglanti.tasima(
                    soket.try_clone()?,
                    HizSinirlayici::yeni(a.ortak.sn),
                    Duraklatma::yeni(),
                );
                gunluk.yaz(Durum::OturumAcildi, "tasima basladi")?;
                let mut ozet = SenkronOzeti::default();
                let mut karsi_manifesti = Vec::new();
                let mut karsi_dosyalari = Vec::new();
                let sonuc = peersync::senkron::sunucu_tur(
                    &mut tasima,
                    &mut depo,
                    &mut gunluk,
                    a.ortak.senkron_ayar(),
                    &mut karsi_manifesti,
                    &mut karsi_dosyalari,
                    &mut ozet,
                );
                let _ = depo.gecici_temizle();
                let _ = depo.kaydet();
                println!(
                    "senkronizasyon: {} gonderildi, {} bayt",
                    ozet.gonderilen, ozet.bayt
                );
                sonuc?;
                return Ok(());
            }
            Err(Hata::ZamanAsimi { .. }) => {}
            Err(hata) => {
                gunluk.yaz(Durum::SikismaHata, hata.to_string())?;
                eprintln!("el sikisma basarisiz: {hata}");
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn join(a: JoinArgs) -> Sonuc<()> {
    let parola = a.ortak.parola()?;
    std::fs::create_dir_all(&a.ortak.root)?;
    let kimlik = peersync::kimlik_yukle_veya_uret(&a.ortak.root)?;
    let etiket = GrupEtiketi::turet(&parola)?;
    let ayar = KesifAyar {
        aralik: Duration::from_millis(a.announce_ms.max(50)),
        zaman_asimi: Duration::from_millis(500),
        deneme: 2,
        azami_es: peersync::kesif::AZAMI_ES,
        hedefler: Vec::new(),
    };
    let mut kesif = Kesif::ac(a.port, kimlik, etiket, ayar)?;
    let _ = kesif.soket_kopya()?;
    let mut ehtiyat = Ehtiyat::yeni(Duration::from_secs(2), peersync::kesif::AZAMI_ES);
    let bitis = Instant::now() + Duration::from_secs(a.sure.max(1));
    println!("peersync {} join: {} sn sureyle eş araniyor", SURUM, a.sure);
    while Instant::now() < bitis {
        kesif.ilan_gonder()?;
        kesif.dinle(&mut ehtiyat, Instant::now())?;
        std::thread::sleep(Duration::from_millis(a.announce_ms.max(50)));
    }
    let esler = ehtiyat.esler(Instant::now());
    if esler.is_empty() {
        println!("es bulunamadi: ag yayinini engelliyor olabilir, elle adres kullanin");
        return Ok(());
    }
    println!("{} es bulundu:", esler.len());
    for adres in esler {
        println!("  {adres}");
    }
    Ok(())
}

fn sync(a: SyncArgs) -> Sonuc<()> {
    let parola = a.ortak.parola()?;
    std::fs::create_dir_all(&a.ortak.root)?;
    let kimlik = peersync::kimlik_yukle_veya_uret(&a.ortak.root)?;
    let mut depo = Depo::ac(&a.ortak.root, kimlik, ParcaAyari::varsayilan())?;
    let tarama = depo.tara()?;
    depo.kaydet()?;
    let mut gunluk = gunluk_ac(&a.ortak.root)?;

    let etiket = GrupEtiketi::turet(&parola)?;
    let ozut = OturumOzutu::turet(&parola)?;
    let soket = UdpSocket::bind("0.0.0.0:0")?;
    let ayar = SikismaAyar {
        zaman_asimi: a.ortak.zaman_asimi(),
        deneme: 2,
    };
    gunluk.yaz(
        Durum::SikismaBasladi,
        format!("{} adresine el sikisma", a.peer),
    )?;
    let baglanti = el_sikisma::istemci(&soket, a.peer, kimlik, etiket, &ozut, ayar)?;
    gunluk.yaz(
        Durum::SikismaTamam,
        format!("oturum {}", baglanti.kisa_oturum_id()),
    )?;
    let mut tasima = baglanti.tasima(soket, HizSinirlayici::yeni(a.ortak.sn), Duraklatma::yeni());
    gunluk.yaz(Durum::OturumAcildi, "senkronizasyon basliyor")?;
    println!(
        "peersync {} sync: {} es, {} dosya taranildi, oturum {}",
        SURUM,
        baglanti.karsi_kimlik,
        tarama.taranan,
        baglanti.kisa_oturum_id()
    );
    let sonuc = {
        let mut senkron =
            Senkron::yeni(&mut tasima, &mut depo, &mut gunluk, a.ortak.senkron_ayar());
        senkron.calistir()
    };
    let temizlenen = depo.gecici_temizle()?;
    let _ = depo.kaydet();
    let ozet = sonuc?;
    println!(
        "sonuc: {} cekildi, {} gonderildi, {} catisma, {} parca, {} bayt, {} gecici silindi",
        ozet.cekilen, ozet.gonderilen, ozet.catisma, ozet.parca, ozet.bayt, temizlenen
    );
    println!(
        "aktarilan {} bayt, hiz siniri {} bayt/sn",
        tasima.gonderilen(),
        a.ortak.sn
    );
    Ok(())
}

fn status(a: StatusArgs) -> Sonuc<()> {
    let kimlik = peersync::kimlik_yukle_veya_uret(&a.root)?;
    let mut depo = Depo::ac(&a.root, kimlik, ParcaAyari::varsayilan())?;
    let ozet = depo.tara()?;
    let toplam_bayt: u64 = depo.kayitlar().values().map(|k| k.boyut).sum();
    let toplam_parca: usize = depo.kayitlar().values().map(|k| k.parcalar.len()).sum();
    println!("peersync {SURUM} status");
    println!("  koke              : {}", a.root.display());
    println!("  kimlik            : {}", kimlik.onaltilik());
    println!("  taranan dosya     : {}", ozet.taranan);
    println!("  yeni / degisen    : {} / {}", ozet.yeni, ozet.degisen);
    println!("  silinen           : {}", ozet.silinen);
    println!("  indeks kaydi      : {}", depo.kayitlar().len());
    println!("  toplam boyut      : {toplam_bayt} bayt");
    println!("  toplam parca      : {toplam_parca}");
    if a.ayrinti {
        for (yol, kayit) in depo.kayitlar() {
            println!(
                "    {yol}: {} bayt, {} parca, rev {}, ozet {}",
                kayit.boyut,
                kayit.parcalar.len(),
                kayit.revizyon,
                peersync::karma::Karma(kayit.liste_ozeti()).onaltilik()
            );
        }
    }
    let _ = depo.kaydet();
    Ok(())
}

fn pair(a: PairArgs) -> Sonuc<()> {
    let parola = a.ortak.parola()?;
    std::fs::create_dir_all(&a.ortak.root)?;
    let kimlik = peersync::kimlik_yukle_veya_uret(&a.ortak.root)?;
    let etiket = GrupEtiketi::turet(&parola)?;
    let ozut = OturumOzutu::turet(&parola)?;
    let ture = Turetme::oturum();
    println!("peersync {SURUM} pair");
    println!("  koke          : {}", a.ortak.root.display());
    println!("  kimlik        : {}", kimlik.onaltilik());
    println!("  grup etiketi  : {}", hex(&etiket.0));
    println!(
        "  argon2id      : m={} KiB, t={}, p={}",
        ture.bellek_kib, ture.gecis, ture.paralellik
    );
    // Oturum anahtarlari HICBIR YERDE yazilmaz; yalnizca parolanin dogru
    // oldugunu gosteren bir ozet basilir.
    let gonderen = ozut.yon_anahtari(peersync::sifre::Yon::IstemciEs.ayrac())?;
    println!("  parola ozeti   : {}", hex(&gonderen[..8]));
    println!("  not            : parola diske yazilmaz, her calistirmada yeniden turetilir");
    if a.dogrula {
        let tekrar = OturumOzutu::turet(&parola)?;
        let ayni = tekrar.yon_anahtari(peersync::sifre::Yon::IstemciEs.ayrac())?;
        println!(
            "  dogrulama      : {}",
            if ayni == gonderen {
                "basarili"
            } else {
                "basarisiz"
            }
        );
    }
    Ok(())
}

fn hex(veri: &[u8]) -> String {
    veri.iter().map(|b| format!("{b:02x}")).collect()
}
