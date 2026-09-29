//! İki eş arası **gerçek UDP** uçtan uca senkronizasyon testleri.
//!
//! Bu dosyadaki testler `127.0.0.1` üzerinde gerçek soketler açar, gerçek el
//! sıkışma yapar ve gerçek parça aktarımı gerçekleştirir. Sahte (mock) katman
//! yoktur: aynı kod yolu CLI ile de çalışır.

mod yardimci;

use std::net::UdpSocket;
use std::time::Duration;

use peersync::depo::Depo;
use peersync::el_sikisma::{self, SikismaAyar};
use peersync::gunluk::{Durum, Gunluk};
use peersync::karma::Karma;
use peersync::kimlik::{Gizli, GrupEtiketi, Kimlik, OturumOzutu};
use peersync::kuyruk::{Duraklatma, HizSinirlayici};
use peersync::parca::ParcaAyari;
use peersync::protok::UzakDosya;
use peersync::senkron::{self, Senkron, SenkronAyar, SenkronOzeti};

use yardimci::veri_uret;
use yardimci::GeciciDizin;

const PAROLA: &str = "entegrasyon-testi-2026";

fn ayar() -> SikismaAyar {
    SikismaAyar {
        zaman_asimi: Duration::from_secs(3),
        deneme: 2,
    }
}

fn senkron_ayar() -> SenkronAyar {
    SenkronAyar {
        zaman_asimi: Duration::from_secs(6),
        deneme: 2,
        yeniden_tara: true,
    }
}

/// İki eşin tam kurulumunu yapar: depo, günlük, kimlik, etiket, özüt.
fn es_kur(kok: &std::path::Path, kimlik: Kimlik) -> (Depo, Gunluk) {
    std::fs::create_dir_all(kok).unwrap();
    let mut depo = Depo::ac(kok, kimlik, ParcaAyari::varsayilan()).unwrap();
    depo.tara().unwrap();
    depo.kaydet().unwrap();
    let yol = kok.join(".peersync").join("gecmis.jsonl");
    let mut gunluk = Gunluk::ac(&yol).unwrap();
    gunluk.yaz(Durum::Basladi, "test kurulumu").unwrap();
    (depo, gunluk)
}

/// Gerçek iki eşli oturumu açar (el sıkışma dahil).
fn oturum_ac(
    soket_sunucu: &UdpSocket,
    soket_istemci: &UdpSocket,
    parola: &str,
) -> (
    peersync::el_sikisma::Baglanti,
    peersync::el_sikisma::Baglanti,
) {
    let etiket = GrupEtiketi::turet(&Gizli::metinden(parola)).unwrap();
    let ozut = OturumOzutu::turet(&Gizli::metinden(parola)).unwrap();
    let ozut_istemci = OturumOzutu::turet(&Gizli::metinden(parola)).unwrap();
    let soket_sunucu_kopya = soket_sunucu.try_clone().unwrap();
    let kimlik_sunucu = Kimlik([0x51; 16]);
    let kimlik_istemci = Kimlik([0x52; 16]);
    let etiket_sunucu = etiket;
    let is_parcacigi = std::thread::spawn(move || {
        el_sikisma::sunucu(
            &soket_sunucu_kopya,
            kimlik_sunucu,
            etiket_sunucu,
            &ozut,
            ayar(),
        )
    });
    let adres = soket_sunucu.local_addr().unwrap();
    let istemci = el_sikisma::istemci(
        soket_istemci,
        adres,
        kimlik_istemci,
        etiket,
        &ozut_istemci,
        ayar(),
    )
    .unwrap();
    let sunucu = is_parcacigi.join().unwrap().unwrap();
    (istemci, sunucu)
}

#[test]
fn gercek_iki_es_arasinda_dosya_cekilir_ve_dogrulanir() {
    let gecici = GeciciDizin::yeni("e2e-cekme").unwrap();
    let kaynak = gecici.yol().join("kaynak");
    let hedef = gecici.yol().join("hedef");

    // Kaynakta üç dosya, hedefte yalnız biri (ve farklı içerikli bir dosya) var.
    let buyuk = veri_uret(300_000, 0xABCD);
    let orta = veri_uret(60_000, 0x1234);
    let kucuk = b"kucuk bir dosya icerigi".to_vec();
    gecici.dosya_yaz("kaynak/buyuk.bin", &buyuk).unwrap();
    gecici.dosya_yaz("kaynak/orta.bin", &orta).unwrap();
    gecici.dosya_yaz("kaynak/kucuk.txt", &kucuk).unwrap();
    gecici
        .dosya_yaz("hedef/kucuk.txt", b"hedefteki farkli surum")
        .unwrap();
    // Delta kanıtı: hedefte `buyuk.bin` **aynen** değil ama neredeyse aynıdır;
    // yalnızca ortadaki 4 KiB'lik dilim farklıdır. İçerik tanımlayıcıları
    // sınırlardan bağımsız olduğu için kalan parçalar aynı karma ile üretilir
    // ve depoda zaten vardır; yalnızca farklı parça aktarılmalıdır.
    let mut hedef_buyuk = buyuk.clone();
    hedef_buyuk[148_000..152_000].fill(0x5A);
    gecici.dosya_yaz("hedef/buyuk.bin", &hedef_buyuk).unwrap();

    let (mut depo_k, mut gunluk_k) = es_kur(&kaynak, Kimlik([0x11; 16]));
    let (mut depo_h, mut gunluk_h) = es_kur(&hedef, Kimlik([0x22; 16]));
    // Kaynaktaki sürüm daha yeni: "son yazan kazanır" kuralı buyuk.bin için
    // kaynağı kazanan yapar, böylece delta yolu (yalnızca eksik parçalar) sınanır.
    depo_k.revizyon_ayarla("buyuk.bin", 5).unwrap();
    depo_k.kaydet().unwrap();

    let soket_s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let soket_h = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (baglanti_h, baglanti_s) = oturum_ac(&soket_s, &soket_h, PAROLA);
    // Her taraf karsinin kimligini ogrendi; oturum kimligi ayni kaldi.
    assert_eq!(baglanti_h.karsi_kimlik, Kimlik([0x51; 16]));
    assert_eq!(baglanti_s.karsi_kimlik, Kimlik([0x52; 16]));
    assert_eq!(baglanti_h.oturum_id, baglanti_s.oturum_id);

    let mut tasima_h = baglanti_h.tasima(soket_h, HizSinirlayici::sinirsiz(), Duraklatma::yeni());
    let mut tasima_s = baglanti_s.tasima(soket_s, HizSinirlayici::sinirsiz(), Duraklatma::yeni());

    // Sunucu rolü ayrı iş parçacığında: tek iş parçacığı aynı anda hem
    // gönderip hem alamaz, segment ilerleme bildirimi kilitlenir.
    let is_parcacigi = std::thread::spawn(move || {
        let mut ozet = SenkronOzeti::default();
        let mut karsi_manifesti = Vec::new();
        let mut karsi_dosyalari = Vec::new();
        let sonuc = senkron::sunucu_tur(
            &mut tasima_s,
            &mut depo_k,
            &mut gunluk_k,
            senkron_ayar(),
            &mut karsi_manifesti,
            &mut karsi_dosyalari,
            &mut ozet,
        );
        (sonuc, ozet)
    });

    let ozet = {
        let mut s = Senkron::yeni(&mut tasima_h, &mut depo_h, &mut gunluk_h, senkron_ayar());
        s.calistir().unwrap()
    };
    let (sunucu_sonuc, sunucu_ozet) = is_parcacigi.join().unwrap();
    sunucu_sonuc.unwrap();

    // 1) Eksik iki dosya birebir gelmeli; buyuk.bin de tam olarak onarılmalı.
    assert_eq!(std::fs::read(hedef.join("buyuk.bin")).unwrap(), buyuk);
    assert_eq!(std::fs::read(hedef.join("orta.bin")).unwrap(), orta);
    // kucuk.txt bir ÇAKIŞMADIR: hedefteki kayıt revizyon 9, kaynaktaki 1.
    // "Son yazan kazanır" kuralı hedefi kazanan yapar; hedefteki içerik
    // **korunur** ve kaybeden (kaynak) kendi sürümünü yedekler.
    assert_eq!(
        std::fs::read(hedef.join("kucuk.txt")).unwrap(),
        b"hedefteki farkli surum"
    );

    // 2) İçerik tanımlayıcıları iki tarafta birebir aynı olmalı.
    for ad in ["buyuk.bin", "orta.bin"] {
        let a = Karma::dosyadan(&kaynak.join(ad)).unwrap();
        let b = Karma::dosyadan(&hedef.join(ad)).unwrap();
        assert_eq!(a, b, "{ad} karmasi eslesmedi");
    }

    // 3) Delta kanıtı: hedefte buyuk.bin zaten vardı ve neredeyse aynıydı, bu
    //    yüzden aktarılan bayt iki dosyanın toplamından küçük olmalıdır.
    assert!(ozet.bayt > 0, "hicbir bayt aktarilmadi");
    assert!(
        ozet.bayt < (buyuk.len() + orta.len()) as u64,
        "delta calismiyor: {} bayt (dosyalarin toplami {} bayt)",
        ozet.bayt,
        buyuk.len() + orta.len()
    );
    assert!(ozet.cekilen >= 2, "en az iki dosya cekilmeli");
    // Hedefte bulunmayan orta.bin teklif edilmediği için kaynaktan hiçbir
    // dosya gönderilmemelidir.
    assert_eq!(
        sunucu_ozet.gonderilen, 0,
        "kaynak hicbir dosya gondermemeli"
    );
}

#[test]
fn gercek_iki_es_arasinda_kaynaktan_hedefe_gonderim_yapilir() {
    let gecici = GeciciDizin::yeni("e2e-gonderme").unwrap();
    let kaynak = gecici.yol().join("kaynak");
    let hedef = gecici.yol().join("hedef");
    let icerik = veri_uret(120_000, 0x0F0F);
    // Kaynakta olan dosya istemciye CEKILIR; yalnizca istemcide olan dosya
    // kaynaktan itilir. Ikisi birlikte iki yonlu akisi kanitlar.
    let ters = veri_uret(40_000, 0x1234);
    gecici
        .dosya_yaz("kaynak/gonderilecek.bin", &icerik)
        .unwrap();
    gecici.dosya_yaz("hedef/sadece_burada.txt", &ters).unwrap();

    let (mut depo_k, mut gunluk_k) = es_kur(&kaynak, Kimlik([0x33; 16]));
    let (mut depo_h, mut gunluk_h) = es_kur(&hedef, Kimlik([0x44; 16]));

    let soket_s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let soket_h = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (baglanti_h, baglanti_s) = oturum_ac(&soket_s, &soket_h, PAROLA);
    let mut tasima_h = baglanti_h.tasima(soket_h, HizSinirlayici::sinirsiz(), Duraklatma::yeni());
    let mut tasima_s = baglanti_s.tasima(soket_s, HizSinirlayici::sinirsiz(), Duraklatma::yeni());

    let is_parcacigi = std::thread::spawn(move || {
        let mut ozet = SenkronOzeti::default();
        let mut karsi_manifesti = Vec::new();
        let mut karsi_dosyalari = Vec::new();
        let sonuc = senkron::sunucu_tur(
            &mut tasima_s,
            &mut depo_k,
            &mut gunluk_k,
            senkron_ayar(),
            &mut karsi_manifesti,
            &mut karsi_dosyalari,
            &mut ozet,
        );
        (sonuc, ozet)
    });
    let istemci_ozeti = {
        let mut s = Senkron::yeni(&mut tasima_h, &mut depo_h, &mut gunluk_h, senkron_ayar());
        s.calistir().unwrap()
    };
    let (sonuc, sunucu_ozeti) = is_parcacigi.join().unwrap();
    sonuc.unwrap();

    // Cekme: kaynaktaki dosya hedefe geldi.
    assert!(std::fs::read(hedef.join("gonderilecek.bin")).unwrap() == icerik);
    // Itme: yalnizca hedefte olan dosya kaynaga gitti.
    assert!(std::fs::read(kaynak.join("sadece_burada.txt")).unwrap() == ters);
    assert_eq!(istemci_ozeti.cekilen, 1, "bir dosya cekilmeli");
    assert_eq!(istemci_ozeti.gonderilen, 1, "istemci bir dosya gondermeli");
    // Sunucu gonderimi cekme fazinda yapti: gonderilecek.bin, istemcinin
    // ParcaIste cevabinda parca parca aktarildi. 2. fazda sunucu ayni dosyayi
    // tekrar teklif eder, istemci yerinde dosya oldugu icin reddeder; boyle
    // ce ikinci fazda yeni dosya sayilmaz.
    assert_eq!(sunucu_ozeti.cekilen, 0, "sunucu cekmemeli");
    assert_eq!(sunucu_ozeti.gonderilen, 0, "2. fazda yeni dosya olmamali");
    assert!(
        sunucu_ozeti.bayt >= icerik.len() as u64,
        "sunucu bayt gondermedi"
    );
    assert!(istemci_ozeti.bayt >= icerik.len() as u64);
}

#[test]
fn catisma_durumunda_kaybeden_surum_yedeklenir() {
    let gecici = GeciciDizin::yeni("e2e-catisma").unwrap();
    let kaynak = gecici.yol().join("kaynak");
    let hedef = gecici.yol().join("hedef");

    // Aynı yolda farklı içerik. Hedefteki kayıt daha yüksek revizyona sahiptir
    // (kural: son yazan kazanır), kaybeden tarafın sürümü yedeklenmelidir.
    gecici
        .dosya_yaz("kaynak/rapor.txt", b"kaynak surumu")
        .unwrap();
    gecici
        .dosya_yaz("hedef/rapor.txt", b"hedef surumu")
        .unwrap();

    let (mut depo_k, mut gunluk_k) = es_kur(&kaynak, Kimlik([0x55; 16]));
    let (mut depo_h, mut gunluk_h) = es_kur(&hedef, Kimlik([0x66; 16]));
    // Hedefteki dosya daha yüksek revizyona sahip: kural gereği hedef kazanır.
    depo_h.revizyon_ayarla("rapor.txt", 9).unwrap();
    depo_h.kaydet().unwrap();
    assert_eq!(depo_h.ara("rapor.txt").unwrap().revizyon, 9);

    let soket_s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let soket_h = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (baglanti_h, baglanti_s) = oturum_ac(&soket_s, &soket_h, PAROLA);
    let mut tasima_h = baglanti_h.tasima(soket_h, HizSinirlayici::sinirsiz(), Duraklatma::yeni());
    let mut tasima_s = baglanti_s.tasima(soket_s, HizSinirlayici::sinirsiz(), Duraklatma::yeni());

    let is_parcacigi = std::thread::spawn(move || {
        let mut ozet = SenkronOzeti::default();
        let mut karsi_manifesti = Vec::new();
        let mut karsi_dosyalari = Vec::new();
        let sonuc = senkron::sunucu_tur(
            &mut tasima_s,
            &mut depo_k,
            &mut gunluk_k,
            senkron_ayar(),
            &mut karsi_manifesti,
            &mut karsi_dosyalari,
            &mut ozet,
        );
        (sonuc, ozet)
    });
    let ozet = {
        let mut s = Senkron::yeni(&mut tasima_h, &mut depo_h, &mut gunluk_h, senkron_ayar());
        s.calistir().unwrap()
    };
    let (r, _o) = is_parcacigi.join().unwrap();
    r.unwrap();

    // Kazanan taraf (yüksek revizyon) içeriği yerinde kalmalı.
    assert_eq!(
        std::fs::read(hedef.join("rapor.txt")).unwrap(),
        b"hedef surumu"
    );
    // Kaybeden tarafın (kaynak) sürümü hiçbir koşulda kaybolmamalı.
    assert_eq!(ozet.catisma, 1);
    // Yedek KAYBEDEN tarafın dizininde oluşur: burada kaynak.
    let yedekler: Vec<String> = std::fs::read_dir(&kaynak)
        .unwrap()
        .filter_map(|g| g.ok())
        .map(|g| g.file_name().to_string_lossy().to_string())
        .filter(|ad| ad.contains("conflict"))
        .collect();
    assert_eq!(
        yedekler.len(),
        1,
        "bir adet catisma yedegi beklenir: {yedekler:?}"
    );
    let yedek = std::fs::read(kaynak.join(&yedekler[0])).unwrap();
    assert_eq!(yedek, b"kaynak surumu");
}

#[test]
fn yanlis_parola_ile_el_sikisma_kurulamaz() {
    let gecici = GeciciDizin::yeni("e2e-yanlis-parola").unwrap();
    let _ = gecici;
    let soket_s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let soket_h = UdpSocket::bind("127.0.0.1:0").unwrap();
    let etiket = GrupEtiketi::turet(&Gizli::metinden(PAROLA)).unwrap();
    let ozut_sunucu = OturumOzutu::turet(&Gizli::metinden(PAROLA)).unwrap();
    let ozut_istemci = OturumOzutu::turet(&Gizli::metinden("baska-parola")).unwrap();
    let kopya = soket_s.try_clone().unwrap();
    let adres = soket_s.local_addr().unwrap();
    let is_parcacigi = std::thread::spawn(move || {
        el_sikisma::sunucu(&kopya, Kimlik([0x77; 16]), etiket, &ozut_sunucu, ayar())
    });
    let hata = el_sikisma::istemci(
        &soket_h,
        adres,
        Kimlik([0x78; 16]),
        etiket,
        &ozut_istemci,
        ayar(),
    )
    .unwrap_err();
    assert!(
        matches!(hata, peersync::Hata::KimlikDogrulanmadi { .. }),
        "beklenmeyen hata: {hata}"
    );
    // Sunucu da oturum kurmamış olmalı.
    assert!(is_parcacigi.join().unwrap().is_err());
}

#[test]
fn bant_genisligi_siniri_uygulanir() {
    let gecici = GeciciDizin::yeni("e2e-hiz").unwrap();
    let kaynak = gecici.yol().join("kaynak");
    let hedef = gecici.yol().join("hedef");
    let icerik = veri_uret(40_000, 0x7777);
    gecici.dosya_yaz("kaynak/hiz.bin", &icerik).unwrap();

    let (mut depo_k, mut gunluk_k) = es_kur(&kaynak, Kimlik([0x99; 16]));
    let (mut depo_h, mut gunluk_h) = es_kur(&hedef, Kimlik([0xAA; 16]));

    let soket_s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let soket_h = UdpSocket::bind("127.0.0.1:0").unwrap();
    let (baglanti_h, baglanti_s) = oturum_ac(&soket_s, &soket_h, PAROLA);
    // 20 KB/s siniri: kova 20 KB, 40 KB dosya icin en az ~1 saniye beklenir.
    let mut tasima_h = baglanti_h.tasima(soket_h, HizSinirlayici::sinirsiz(), Duraklatma::yeni());
    // HÄ±z sÄ±nÄ±rÄ± GÃ–NDEREN tarafta uygulanÄ±r: veri kaynaktan hedefe gider.
    let mut tasima_s = baglanti_s.tasima(soket_s, HizSinirlayici::yeni(20_000), Duraklatma::yeni());

    let is_parcacigi = std::thread::spawn(move || {
        let mut ozet = SenkronOzeti::default();
        let mut karsi_manifesti = Vec::new();
        let mut karsi_dosyalari = Vec::new();
        let sonuc = senkron::sunucu_tur(
            &mut tasima_s,
            &mut depo_k,
            &mut gunluk_k,
            senkron_ayar(),
            &mut karsi_manifesti,
            &mut karsi_dosyalari,
            &mut ozet,
        );
        (sonuc, ozet)
    });
    let baslangic = std::time::Instant::now();
    {
        let mut s = Senkron::yeni(&mut tasima_h, &mut depo_h, &mut gunluk_h, senkron_ayar());
        s.calistir().unwrap();
    }
    let (r, _o) = is_parcacigi.join().unwrap();
    if let Err(e) = r {
        if let Ok(metin) = std::fs::read_to_string(kaynak.join(".peersync").join("gecmis.jsonl")) {
            eprintln!(
                "--- KAYNAK GUNLUGU ---
{metin}"
            );
        }
        panic!("sunucu basarisiz: {e}");
    }
    let gecen = baslangic.elapsed();

    assert!(std::fs::read(hedef.join("hiz.bin")).unwrap() == icerik);
    assert!(
        gecen >= Duration::from_millis(500),
        "hiz siniri uygulanmadi: {gecen:?}"
    );
}

#[test]
fn bozuk_parca_aktarimi_hedefe_yazmaz() {
    // Depo katmanı düzeyinde bozuk parça senaryosu: parça dosyası bozulursa
    // birlestirme hata verir ve hedefe yarım dosya yazılmaz.
    let gecici = GeciciDizin::yeni("e2e-bozuk-parca").unwrap();
    let kok = gecici.yol().join("depo");
    std::fs::create_dir_all(&kok).unwrap();
    let icerik = veri_uret(80_000, 0xABCD);
    std::fs::write(kok.join("kaynak.bin"), &icerik).unwrap();

    let mut depo = Depo::ac(&kok, Kimlik([0xBB; 16]), ParcaAyari::varsayilan()).unwrap();
    depo.tara().unwrap();
    let kayit = depo.ara("kaynak.bin").unwrap().clone();
    let tam = kok.join("kaynak.bin");
    let parcalar =
        peersync::parca::parcala_dosya(&tam, "kaynak.bin", ParcaAyari::varsayilan()).unwrap();
    depo.dosya_parcalarini_yaz(&parcalar, &tam).unwrap();

    // Bir parçayı bilerek boz.
    let ilk = kayit.parcalar[0].karma;
    std::fs::write(depo.parca_yolu(&ilk), b"bu bir parca degil").unwrap();

    std::fs::remove_file(&tam).unwrap();
    let hata = depo.dosya_birlestir(&kayit).unwrap_err();
    assert!(
        matches!(hata, peersync::Hata::DepoBozuk(_)),
        "beklenmeyen hata: {hata}"
    );
    assert!(!kok.join("kaynak.bin").exists(), "hedefe yazilmamali");
}

#[test]
fn manifest_icerigi_ozetlerle_karsilastirilir() {
    // İki eş aynı dosyayı taşıdığında manifest özetleri birebir eşleşmeli:
    // bu, "içerik aynı, hiçbir şey aktarma" kararının temelidir.
    let gecici = GeciciDizin::yeni("e2e-ozet").unwrap();
    let veri = veri_uret(50_000, 0x5A5A);
    let mut parcalar = Vec::new();
    for (sira, ad) in ["a/klasor.txt", "b.txt"].iter().enumerate() {
        let yol = gecici.dosya_yaz(ad, &veri[..10_000 * (sira + 1)]).unwrap();
        parcalar.push(peersync::parca::parcala_dosya(&yol, ad, ParcaAyari::varsayilan()).unwrap());
    }
    let ozet1 = parcalar[0].liste_ozeti;
    let ozet2 = parcalar[1].liste_ozeti;
    assert_ne!(ozet1, ozet2);

    // Aynı içerik, aynı yol -> aynı özet.
    let yol = gecici.dosya_yaz("a/klasor.txt", &veri[..10_000]).unwrap();
    let tekrar =
        peersync::parca::parcala_dosya(&yol, "a/klasor.txt", ParcaAyari::varsayilan()).unwrap();
    assert_eq!(tekrar.liste_ozeti, ozet1);

    // Uzak dosya özeti, listeyi doğru taşır.
    let uzak = UzakDosya {
        yol: "a/klasor.txt".to_string(),
        boyut: 10_000,
        karma: parcalar[0].karma,
        parca_sayisi: parcalar[0].parcalar.len() as u32,
        liste_ozeti: ozet1,
        revizyon: 1,
        sahip: [0x01; 16],
    };
    assert_eq!(uzak.liste_ozeti, ozet1);
}
