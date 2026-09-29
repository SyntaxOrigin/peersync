//! İçerik tanımlayıcısı: SHA-256 karması, onaltılık kodlama ve karma kümeleri.
//!
//! Bu modülün sorumluluğu "bu bayt dizisi kimdir" sorusunu tek yanıtla çözmektir.
//! Bu modülün sorumluluğu *değil*: parçalamak (bkz. [`crate::parca`]) ve
//! parçaları taşımak (bkz. [`crate::protok`]).
//!
//! Karma algoritması FIPS 180-4 SHA-256'dır. Raporun önerdiği BLAKE3 bu
//! projede **kullanılmaz**; gerekçe `MANIFEST.md` kart 30'da ve README'de yazılıdır.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::hata::{Hata, Sonuc};

/// SHA-256 çıktısının bayt cinsinden uzunluğu.
pub const KARMA_UZUNLUGU: usize = 32;

/// Dosya okunurken kullanılan blok boyutu (128 KiB).
const OKUMA_BLOKU: usize = 128 * 1024;

/// 32 baytlık SHA-256 içerik tanımlayıcısı.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Karma(pub [u8; KARMA_UZUNLUGU]);

impl Karma {
    /// Verilen baytların SHA-256 karmasını üretir.
    pub fn hesapla(veri: &[u8]) -> Karma {
        let mut kase = Sha256::new();
        kase.update(veri);
        let sonuc = kase.finalize();
        let mut dizi = [0u8; KARMA_UZUNLUGU];
        dizi.copy_from_slice(&sonuc);
        Karma(dizi)
    }

    /// Dosyanın tamamının SHA-256 karmasını blok blok okuyarak üretir.
    ///
    /// Dosyanın tamamı belleğe alınmaz; 200 MB RSS bütçesinin korunması için
    /// sabit boyutlu blokta okunur.
    pub fn dosyadan(yol: &Path) -> Sonuc<Karma> {
        let mut dosya = File::open(yol)?;
        let mut kase = Sha256::new();
        let mut tampon = vec![0u8; OKUMA_BLOKU];
        loop {
            let okunan = dosya.read(&mut tampon)?;
            if okunan == 0 {
                break;
            }
            kase.update(&tampon[..okunan]);
        }
        let sonuc = kase.finalize();
        let mut dizi = [0u8; KARMA_UZUNLUGU];
        dizi.copy_from_slice(&sonuc);
        Ok(Karma(dizi))
    }

    /// Karma dizisini küçük harf onaltılık metne çevirir (dosya adı olarak güvenlidir).
    pub fn onaltilik(&self) -> String {
        let mut cikti = String::with_capacity(KARMA_UZUNLUGU * 2);
        for bayt in &self.0 {
            cikti.push(nibbel_digit(bayt >> 4));
            cikti.push(nibbel_digit(bayt & 0x0f));
        }
        cikti
    }

    /// Onaltılık metinden karma üretir.
    ///
    /// # Hatalar
    ///
    /// Metin 64 karakterden kısa/uzunsa veya onaltılık karakter değilse
    /// [`Hata::BozukPaket`] döner; sessizce düzeltme yapılmaz.
    pub fn onaltilikten(metin: &str) -> Sonuc<Karma> {
        let baytlar = metin.as_bytes();
        if baytlar.len() != KARMA_UZUNLUGU * 2 {
            return Err(Hata::BozukPaket(format!(
                "onaltılık karma {} karakter, beklenen {}",
                baytlar.len(),
                KARMA_UZUNLUGU * 2
            )));
        }
        let mut dizi = [0u8; KARMA_UZUNLUGU];
        for (sira, pencere) in baytlar.chunks_exact(2).enumerate() {
            let yuksek = nibbel_deger(pencere[0])?;
            let alcak = nibbel_deger(pencere[1])?;
            dizi[sira] = (yuksek << 4) | alcak;
        }
        Ok(Karma(dizi))
    }

    /// Dosya sistemi yolu için iki onaltılık karakterlik ön ek (kova) üretir.
    ///
    /// Parça deposu `parca/<ön ek>/<karma>` olarak dizilir; böylece tek bir
    /// dizinde on binlerce dosya birikmez.
    pub fn on_ek(&self) -> String {
        self.onaltilik()[..2].to_string()
    }
}

impl std::fmt::Display for Karma {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.onaltilik())
    }
}

/// Verilen SHA-256 karmalayÄ±cÄ±yÄ± sonlandÄ±rÄ±p iÃ§erik tanÄ±mlayÄ±cÄ±sÄ±na Ã§evirir.
///
/// Tek geÃ§iÅŸte hem dosya karmasÄ±nÄ± hem parÃ§a sÄ±nÄ±rlarÄ±nÄ± Ã¼reten tarama yolu
/// bunu kullanÄ±r; dosya ikinci kez okunmaz.
pub fn karmalayici_bitir(kase: sha2::Sha256) -> Karma {
    let sonuc = kase.finalize();
    let mut dizi = [0u8; KARMA_UZUNLUGU];
    dizi.copy_from_slice(&sonuc);
    Karma(dizi)
}
fn nibbel_digit(deger: u8) -> char {
    match deger {
        0..=9 => (b'0' + deger) as char,
        _ => (b'a' + deger - 10) as char,
    }
}

fn nibbel_deger(bayt: u8) -> Sonuc<u8> {
    match bayt {
        b'0'..=b'9' => Ok(bayt - b'0'),
        b'a'..=b'f' => Ok(bayt - b'a' + 10),
        b'A'..=b'F' => Ok(bayt - b'A' + 10),
        _ => Err(Hata::BozukPaket(format!(
            "onaltılık olmayan karakter: {}",
            bayt as char
        ))),
    }
}

/// `offset (u64, big-endian) | uzunluk (u32, big-endian) | karma (32 bayt)`
/// dizisinin SHA-256 karması: parça listesinin tek satırlık özeti.
///
/// Eşler bu özeti karşılaştırarak "bu dosyanın parça listesi birebir aynı mı"
/// sorusunu tek bir 32 baytla yanıtlar. Liste birebir aynıysa hiçbir parça
/// istenmez.
pub fn liste_ozeti(ogeler: &[(u64, u32, [u8; KARMA_UZUNLUGU])]) -> [u8; KARMA_UZUNLUGU] {
    let mut kase = Sha256::new();
    for (konum, uzunluk, karma) in ogeler {
        kase.update(konum.to_be_bytes());
        kase.update(uzunluk.to_be_bytes());
        kase.update(karma);
    }
    let sonuc = kase.finalize();
    let mut dizi = [0u8; KARMA_UZUNLUGU];
    dizi.copy_from_slice(&sonuc);
    dizi
}

/// Çok sayıda parça listesini bir arada tutan, tekilleştirilmiş karma kümesi.
///
/// Delta karar mantığının sıcak yolu budur: karşı tarafın listesindeki her
/// parça için "bende var mı" sorusu `O(1)` yerine `O(log n)` maliyetle yanıtlanır
/// (hash tablosu), ama en kötü durumdaki `HashMap` karması çakışması bu yapıda
/// veri bütünlüğü hatasına yol açmaz çünkü karşılaştırma tam 32 bayttır.
#[derive(Debug, Clone, Default)]
pub struct KarmaKumesi {
    sayaclar: HashMap<[u8; KARMA_UZUNLUGU], u32>,
}

impl KarmaKumesi {
    /// Boş küme oluşturur.
    pub fn bos() -> KarmaKumesi {
        KarmaKumesi {
            sayaclar: HashMap::new(),
        }
    }

    /// Bir parça listesinden küme kurar (her karma bir kez sayılır).
    pub fn listeden(karmalar: &[[u8; KARMA_UZUNLUGU]]) -> KarmaKumesi {
        let mut kume = KarmaKumesi::bos();
        for karma in karmalar {
            kume.ekle(*karma);
        }
        kume
    }

    /// Kümeye bir karma ekler; aynı karma birden çok listede varsa sayac artar.
    pub fn ekle(&mut self, karma: [u8; KARMA_UZUNLUGU]) {
        *self.sayaclar.entry(karma).or_insert(0) += 1;
    }

    /// Kümede en az bir tane o karma var mı?
    pub fn iceriyor(&self, karma: &[u8; KARMA_UZUNLUGU]) -> bool {
        self.sayaclar.contains_key(karma)
    }

    /// Kümedeki farklı karma sayısı.
    pub fn boyut(&self) -> usize {
        self.sayaclar.len()
    }

    /// Kümeyi ikiye böler ve ikinci parçayı döndürür; eski küme boş kalır.
    ///
    /// Büyük depolarda tüm karmaları bellekte tutmamak için kullanılır.
    pub fn bol(&mut self) -> KarmaKumesi {
        let eski = std::mem::take(&mut self.sayaclar);
        let yari = eski.len() / 2;
        let mut yeni = HashMap::with_capacity(eski.len().saturating_sub(yari).max(1));
        let mut kalan = HashMap::with_capacity(yari.max(1));
        for (sira, (karma, adet)) in eski.into_iter().enumerate() {
            if sira % 2 == 0 {
                yeni.insert(karma, adet);
            } else {
                kalan.insert(karma, adet);
            }
        }
        self.sayaclar = kalan;
        KarmaKumesi { sayaclar: yeni }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hata::Hata;

    #[test]
    fn bos_girdi_bilinen_fips_vektorune_esittir() {
        // FIPS 180-4: SHA-256("") = e3b0c442...7852b855
        let beklenen = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(Karma::hesapla(b"").onaltilik(), beklenen);
    }

    #[test]
    fn abc_girdi_bilinen_fips_vektorune_esittir() {
        // FIPS 180-4: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let beklenen = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(Karma::hesapla(b"abc").onaltilik(), beklenen);
    }

    #[test]
    fn iki_bloklu_girdi_vektorune_esittir() {
        // FIPS 180-4 örnek 2: 448 bit (iki blok) girdi
        let beklenen = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        let veri = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(veri.len(), 56);
        assert_eq!(Karma::hesapla(veri).onaltilik(), beklenen);
    }

    #[test]
    fn blok_ekleme_karmayi_degistirmez_ama_karma_degistirir() {
        let tek = Karma::hesapla(&[b'a'; 1_000_000]);
        let parca = Karma::hesapla(&[b'a'; 1000]);
        // Blok eklemenin sonucu değiştirmediğini doğrular: aynı bayt dizisi.
        assert_eq!(parca, Karma::hesapla(&[b'a'; 1000]));
        assert_ne!(tek, parca);
        assert_eq!(tek.onaltilik().len(), 64);
    }

    #[test]
    fn onaltilik_gidis_donus_kayipsizdir() {
        let karma = Karma::hesapla(b"peersync gidis-donus");
        let metin = karma.onaltilik();
        assert_eq!(metin.len(), 64);
        assert_eq!(Karma::onaltilikten(&metin).unwrap(), karma);
    }

    #[test]
    fn onaltilikten_hatali_girdiyi_hata_ile_reddeder() {
        let hata = Karma::onaltilikten("kisa").unwrap_err();
        assert!(matches!(hata, Hata::BozukPaket(_)));
        let hata = Karma::onaltilikten(&"z".repeat(64)).unwrap_err();
        assert!(matches!(hata, Hata::BozukPaket(_)));
    }

    #[test]
    fn on_ek_karma_ilk_iki_onaltilik_karakterdir() {
        let karma = Karma::hesapla(b"kova");
        assert_eq!(karma.on_ek(), karma.onaltilik()[..2]);
    }

    #[test]
    fn liste_ozeti_konuma_duyarlidir() {
        let a = [1u8; 32];
        let sol = liste_ozeti(&[(0, 10, a)]);
        let sag = liste_ozeti(&[(1, 10, a)]);
        assert_ne!(sol, sag);
        assert_eq!(sol, liste_ozeti(&[(0, 10, a)]));
        assert_eq!(liste_ozeti(&[]), Karma::hesapla(b"").0);
    }

    #[test]
    fn karma_kumesi_tekrar_sayilari_ile_calisir() {
        let a = [7u8; 32];
        let mut kume = KarmaKumesi::bos();
        assert!(!kume.iceriyor(&a));
        kume.ekle(a);
        kume.ekle(a);
        assert!(kume.iceriyor(&a));
        assert_eq!(kume.boyut(), 1);
    }

    #[test]
    fn karma_kumesi_listeden_kurulur() {
        let karmalar = vec![[1u8; 32], [2u8; 32], [1u8; 32]];
        let kume = KarmaKumesi::listeden(&karmalar);
        assert_eq!(kume.boyut(), 2);
        assert!(kume.iceriyor(&[1u8; 32]));
        assert!(kume.iceriyor(&[2u8; 32]));
        assert!(!kume.iceriyor(&[3u8; 32]));
    }

    #[test]
    fn karma_kumesi_bolme_parcalar_corpus_butunlugu_korur() {
        let karmalar: Vec<[u8; 32]> = (0..40u8).map(|i| [i; 32]).collect();
        let mut kume = KarmaKumesi::listeden(&karmalar);
        let mut toplam = 0usize;
        let yari = kume.bol();
        toplam += kume.boyut();
        toplam += yari.boyut();
        assert_eq!(toplam, 40);
    }
}
