//! İçerik tanımlayıcılı parçalama: kayan pencere + geçiş (CDC) kuralı.
//!
//! Bu modülün sorumluluğu bir bayt dizisini **içeriğe bağlı** sınırlarla parçalara
//! bölmek ve her parçanın bağımsız SHA-256 kimliğini üretmektir.
//! Bu modülün sorumluluğu *değil*: parçaları taşımak, saklamak veya karşılaştırmak.
//!
//! # Neden sabit parça değil
//!
//! Sabit boyutlu bloklarda dosyanın başına bir bayt eklenmesi **bütün** sınırları
//! bir bayt kaydırır ve dosyanın tamamı yeniden üretilir. Buradaki kayan pencere
//! karması (`Buys-Bolli` döngüsel polinomu) yalnızca son [`PENCERE`] bayta bağlıdır;
//! sınır kuralı `hash & ESIK == 0` olduğunda tetiklenir. Ekleme noktasından sonraki
//! sınırlar içerik tarafından yeniden belirlenir, öncekiler yerinde kalır.
//!
//! # Kayan pencere karması
//!
//! `h(i) = rol(h(i-1), 1) ^ OUT[b_i] ^ rol(OUT[b_{i-PENCERE}], PENCERE)`
//!
//! `rol(.,1)` terimi girdiyi bir bayt kaydırır, geç kalan `rol(OUT[.], PENCERE)`
//! terimi ise pencereden çıkan baytın katkısını tam olarak geri alır. Böylece
//! `h(i)` yalnızca `b_{i-PENCERE+1} .. b_i` aralığına bağlıdır — kayan pencere
//! tanımı bu eşitlikle kanıtlanır (`pencere_kayan_ozelligi` testi).
//!
//! # Sınırlar (bilinçli sadeleştirme)
//!
//! - Maske **13 bit** (`VARSAYILAN_ESIK`), ortalama parça 8 KiB'dir.
//! - `en_kucuk` alt sınırı içerikten bağımsızdır; sıfır baytta sonsuz sınır
//!   oluşmasını (ve dolayısıyla parça başına 32 bayt karmanın yalnızca başlık
//!   verisi için harcanmasını) engeller.
//! - `en_buyuk` üst sınırı gereksiz uzun parçaları engeller.
//! - Bu gerçek bir CDC'dir ama **rsync/BLAKE3 düzeyinde bir delta yamalaması
//!   değildir**: parça *içi* kayan pencere farkı üretilmez (MANIFEST kart 30'da
//!   "delta sıkıştırma" ertelenmiştir). Delta, parça *seviyesindedir.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::hata::{Hata, Sonuc};
use crate::karma::{liste_ozeti, Karma, KARMA_UZUNLUGU};

/// Karma penceresinin bayt cinsinden uzunluğu.
pub const PENCERE: usize = 64;

/// Varsayılan üst sınır: bir parça 1 MiB'den büyük olamaz.
pub const AZAMI_PARCA: u32 = 1024 * 1024;

/// Dosya okunurken kullanılan blok boyutu (128 KiB).
const OKUMA_BLOGU: usize = 128 * 1024;

/// Bir parçanın tanımı: mutlak konum, uzunluk ve içerik karması.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TamParca {
    /// Parçanın dosya içindeki mutlak başlangıç baytı.
    pub konum: u64,
    /// Parçanın bayt cinsinden uzunluğu.
    pub uzunluk: u32,
    /// Parça içeriğinin SHA-256 karması.
    pub karma: [u8; KARMA_UZUNLUGU],
}

impl TamParca {
    /// Mutlak konumdan parçanın bittiği ilk dış konum.
    pub fn son_konum(&self) -> u64 {
        self.konum + u64::from(self.uzunluk)
    }
}

/// Bir dosyanın parçalanmış hâli: kimlik, parça listesi ve liste özeti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DosyaParcalari {
    /// Dosyanın göreli yolu (`/` ile normalleştirilmiş).
    pub yol: String,
    /// Dosyanın bayt cinsinden boyutu.
    pub boyut: u64,
    /// Dosyanın tamamının SHA-256 karması (içerik tanımlayıcısı).
    pub karma: [u8; KARMA_UZUNLUGU],
    /// Sırayla parçalar.
    pub parcalar: Vec<TamParca>,
    /// Parça listesinin tek satırlık özeti (delta kararı için).
    pub liste_ozeti: [u8; KARMA_UZUNLUGU],
}

impl DosyaParcalari {
    /// Parça listesindeki yalnızca karmaları verir.
    pub fn karmalar(&self) -> Vec<[u8; KARMA_UZUNLUGU]> {
        self.parcalar.iter().map(|p| p.karma).collect()
    }
}

/// Parçalanırken üretilen ve **içeriğiyle** birlikte döndürülen parça.
///
/// Tarama katmanı bu tipi kullanır: parça içeriği zaten bellekte olduğu için
/// dosya ikinci kez okunmadan depoya yazılabilir. `parca()` yalnız sınırları ve
/// karmayı içeren [`TamParca`]'ya indirger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YeniParca {
    /// Dosya içindeki mutlak başlangıç baytı.
    pub konum: u64,
    /// Parçanın bayt uzunluğu.
    pub uzunluk: u32,
    /// Parça içeriğinin karması.
    pub karma: [u8; KARMA_UZUNLUGU],
    /// Parçanın baytları.
    pub veri: Vec<u8>,
}

impl YeniParca {
    /// Yalnız sınırları ve karmayı içeren kayda dönüştürür.
    pub fn parca(&self) -> TamParca {
        TamParca {
            konum: self.konum,
            uzunluk: self.uzunluk,
            karma: self.karma,
        }
    }
}

/// Parçalama ayarları.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParcaAyari {
    /// Parçanın küçülebileceği en küçük bayt sayısı.
    pub en_kucuk: u32,
    /// Parçanın büyüyebileceği en büyük bayt sayısı.
    pub en_buyuk: u32,
    /// Geçiş maskesi: `hash & esik == 0` olduğunda sınır oluşur.
    pub esik: u64,
    /// Karma penceresi (bayt).
    pub pencere: usize,
}

impl Default for ParcaAyari {
    fn default() -> Self {
        ParcaAyari::varsayilan()
    }
}

impl ParcaAyari {
    /// Rapor b05'in önerdiği varsayılan: 13 bit eşik, 2 KiB en küçük, 64 KiB en büyük.
    pub fn varsayilan() -> ParcaAyari {
        ParcaAyari {
            en_kucuk: 2 * 1024,
            en_buyuk: 64 * 1024,
            esik: VARSAYILAN_ESIK,
            pencere: PENCERE,
        }
    }

    /// Ayarın kendi içinde tutarlı olduğunu doğrular.
    ///
    /// # Hatalar
    ///
    /// Pencere sabit kodludur ve [`PENCERE`]'e eşit olmalıdır; en küçük sınır
    /// pencereden küçükse kayan karmanın anlamı kalmaz; eşik sıfırsa ya da
    /// `2^n - 1` biçiminde değilse belirsiz sınır kuralı oluşur; aralık boşsa
    /// veya üst sınır [`AZAMI_PARCA`]'yı aşarsa hata döner.
    pub fn dogrula(&self) -> Sonuc<()> {
        if self.pencere != PENCERE {
            return Err(Hata::AyarGecersiz {
                ad: "parca_ayari.pencere",
                deger: format!("{} (sabit {PENCERE} olmalı)", self.pencere),
            });
        }
        if self.en_kucuk == 0 || self.en_kucuk >= self.en_buyuk {
            return Err(Hata::AyarGecersiz {
                ad: "parca_ayari.en_kucuk",
                deger: format!("{}/{}", self.en_kucuk, self.en_buyuk),
            });
        }
        if self.en_buyuk > AZAMI_PARCA {
            return Err(Hata::AyarGecersiz {
                ad: "parca_ayari.en_buyuk",
                deger: format!("{} (azami {AZAMI_PARCA})", self.en_buyuk),
            });
        }
        if u64::from(self.en_kucuk) < self.pencere as u64 {
            return Err(Hata::AyarGecersiz {
                ad: "parca_ayari.en_kucuk",
                deger: format!(
                    "{} (pencereden küçük olamaz: {})",
                    self.en_kucuk, self.pencere
                ),
            });
        }
        if self.esik == 0 || self.esik & self.esik.wrapping_add(1) != 0 {
            return Err(Hata::AyarGecersiz {
                ad: "parca_ayari.esik",
                deger: format!("{:#x} (sıfır veya 2^n-1 biçiminde olmalı)", self.esik),
            });
        }
        Ok(())
    }

    /// Eşiğin kaç bit olduğunu döndürür (loglanabilir karakteristik).
    ///
    /// `esik = 0` için `0` döner. Geçerli bir eşik `2^n - 1` biçimindedir, bu
    /// yüzden nokta `esik & (esik + 1) == 0` kontrolünden sonra `esik`'in en
    /// yüksek set biti konumuyla bulunur.
    pub fn esik_bit(&self) -> u32 {
        if self.esik == 0 {
            return 0;
        }
        64 - self.esik.leading_zeros()
    }
}

/// 13 bitlik geçiş eşiği: ortalama parça boyutu 8192 bayt.
pub const VARSAYILAN_ESIK: u64 = 0x1FFF;

/// Sabit, derleme zamanında üretilen `OUT` tablosu.
///
/// Tablo sabit bir tohumlu xorshift* ile üretilir; derleyiciden ve çalıştırma
/// ortamından bağımsız, her makinede **aynı** sonucu verir. Testlerin
/// belirlenimliliği bu tabloya dayanır.
const fn out_tablo() -> [u64; 256] {
    let mut tablo = [0u64; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut x = (i as u64)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            .wrapping_add(0x0123_4567_89AB_CDEF)
            | 1;
        x ^= x >> 12;
        x = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        x ^= x >> 25;
        x = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
        x ^= x >> 27;
        tablo[i] = x;
        i += 1;
    }
    tablo
}

static OUT: [u64; 256] = out_tablo();

/// Kayan pencere parçalayıcısı.
///
/// Baytlar `besle` ile **akış** hâlinde yutturulur; her sınırda tamamlanan parça
/// `Vec<TamParca>` olarak döner. Böylece dosya belleğe alınmaz, yalnızca içinde
/// bulunulan parça (azami `en_buyuk` bayt) tutulur.
#[derive(Debug, Clone)]
pub struct Parcalayici {
    ayar: ParcaAyari,
    karma: u64,
    halka: [u8; PENCERE],
    dolu: usize,
    sonraki: usize,
    parca_uzunlugu: u32,
    parca_baslangic: u64,
    toplam: u64,
    tampon: Vec<u8>,
}

impl Parcalayici {
    /// Verilen ayarla yeni parçalayıcı oluşturur.
    ///
    /// # Hatalar
    ///
    /// Ayar tutarsızsa [`ParcaAyari::dogrula`] hatası döner.
    pub fn yeni(ayar: ParcaAyari) -> Sonuc<Parcalayici> {
        ayar.dogrula()?;
        Ok(Parcalayici {
            ayar,
            karma: 0,
            halka: [0u8; PENCERE],
            dolu: 0,
            sonraki: 0,
            parca_uzunlugu: 0,
            parca_baslangic: 0,
            toplam: 0,
            tampon: Vec::with_capacity(ayar.en_buyuk as usize),
        })
    }

    /// Ayarların kopyasını döndürür.
    pub fn ayar(&self) -> ParcaAyari {
        self.ayar
    }

    /// Şu ana kadar yutturulan toplam bayt sayısı.
    pub fn yutulen_bayt(&self) -> u64 {
        self.toplam
    }

    /// Bayt dizisini yutturur ve bu aralıkta tamamlanan parçaları
    /// **içerikleriyle** döndürür.
    ///
    /// Parça sınırları blok sınırlarıyla çakışmayabilir: bir parça bir blokta
    /// başlayıp sonraki blokta tamamlanabilir. Bu yüzden yalnız mutlak konum
    /// vermek yeterli değildir; tarama katmanı parçayı depoya yazabilmek için
    /// baytları da almalıdır.
    pub fn besle_veri(&mut self, veri: &[u8]) -> Sonuc<Vec<YeniParca>> {
        let mut tamamlanan = Vec::new();
        for bayt in veri {
            // Yeni parça başlıyorsa pencere sıfırlanır; kayan karmanın parça
            // sınırlarından bağımsız olması bu resetle sağlanır.
            if self.parca_uzunlugu == 0 {
                self.karma = 0;
                self.dolu = 0;
                self.sonraki = 0;
                self.parca_baslangic = self.toplam;
            }
            self.karma = self.rol_ekle(*bayt);
            self.tampon.push(*bayt);
            self.parca_uzunlugu += 1;
            self.toplam += 1;

            let sinir_kurali = self.karma & self.ayar.esik == 0;
            if self.parca_uzunlugu >= self.ayar.en_buyuk
                || (self.parca_uzunlugu >= self.ayar.en_kucuk && sinir_kurali)
            {
                let veri_kopya = self.tampon.clone();
                let parca = self.parcayi_kapat();
                tamamlanan.push(YeniParca {
                    konum: parca.konum,
                    uzunluk: parca.uzunluk,
                    karma: parca.karma,
                    veri: veri_kopya,
                });
            }
        }
        Ok(tamamlanan)
    }

    /// Dosya sonunda bekleyen parçayı içeriğiyle birlikte kapatır.
    pub fn bitir_veri(&mut self) -> Sonuc<Option<YeniParca>> {
        if self.parca_uzunlugu == 0 {
            return Ok(None);
        }
        let veri = self.tampon.clone();
        let parca = self.parcayi_kapat();
        Ok(Some(YeniParca {
            konum: parca.konum,
            uzunluk: parca.uzunluk,
            karma: parca.karma,
            veri,
        }))
    }

    /// Bayt dizisini yutturur, bu aralıkta tamamlanan parçaları döndürür.
    ///
    /// Dönen parçaların `konum` alanı, bu çağrıdan önce yutturulan toplam
    /// baytın üzerine kurulmuş **mutlak** dosya konumudur; çağıran taraf akış
    /// hâlinde besleyebilir.
    pub fn besle(&mut self, veri: &[u8]) -> Sonuc<Vec<TamParca>> {
        let mut tamamlanan = Vec::new();
        for bayt in veri {
            // Yeni parça başlıyorsa pencere sıfırlanır; kayan karmanın
            // parça sınırlarından bağımsız olması bu resetle sağlanır.
            if self.parca_uzunlugu == 0 {
                self.karma = 0;
                self.dolu = 0;
                self.sonraki = 0;
                self.parca_baslangic = self.toplam;
            }
            self.karma = self.rol_ekle(*bayt);
            self.tampon.push(*bayt);
            self.parca_uzunlugu += 1;
            self.toplam += 1;

            let sinir_kurali = self.karma & self.ayar.esik == 0;
            if self.parca_uzunlugu >= self.ayar.en_buyuk
                || (self.parca_uzunlugu >= self.ayar.en_kucuk && sinir_kurali)
            {
                tamamlanan.push(self.parcayi_kapat());
            }
        }
        Ok(tamamlanan)
    }

    /// Akış sonunda kalan (varsa) son parçayı kapatır.
    pub fn bitir(&mut self) -> Sonuc<Option<TamParca>> {
        if self.parca_uzunlugu == 0 {
            return Ok(None);
        }
        Ok(Some(self.parcayi_kapat()))
    }

    /// Dosya sonunda bekleyen parça olup olmadığını söyler.
    pub fn bekleyen_var(&self) -> bool {
        self.parca_uzunlugu > 0
    }

    fn parcayi_kapat(&mut self) -> TamParca {
        let parca = TamParca {
            konum: self.parca_baslangic,
            uzunluk: self.parca_uzunlugu,
            karma: Karma::hesapla(&self.tampon).0,
        };
        self.tampon.clear();
        self.parca_uzunlugu = 0;
        parca
    }

    /// Bir baytı kayan pencere karmasına ekler.
    ///
    /// `h' = rol(h,1) ^ OUT[b] ^ rol(OUT[çıkan], PENCERE)`; pencere dolmadan
    /// çıkan bayt yoktur, bu yüzden geçmiş terim atlanır.
    fn rol_ekle(&mut self, bayt: u8) -> u64 {
        let mut karma = self.karma.rotate_left(1) ^ OUT[usize::from(bayt)];
        if self.dolu == PENCERE {
            let cikan = self.halka[self.sonraki];
            karma ^= OUT[usize::from(cikan)].rotate_left(PENCERE as u32);
        } else {
            self.dolu += 1;
        }
        self.halka[self.sonraki] = bayt;
        self.sonraki = (self.sonraki + 1) % PENCERE;
        karma
    }
}

/// Bayt dizisini parçalara böler (tüm girdi bellekte).
pub fn parcala(veri: &[u8], ayar: ParcaAyari) -> Sonuc<Vec<TamParca>> {
    let mut parcalayici = Parcalayici::yeni(ayar)?;
    let mut parcalar = parcalayici.besle(veri)?;
    if let Some(son) = parcalayici.bitir()? {
        parcalar.push(son);
    }
    Ok(parcalar)
}

/// Dosyayı blok blok okuyup parçalar ve içerik karmasını üretir.
///
/// Dosyanın tamamı belleğe alınmaz. Göreli yol, depo tarafından verilir ve
/// `\` işaretçisi `/` yerine normalleştirilir; böylece iki farklı işletim
/// sisteminde aynı dosya aynı anahtarla eşleşir.
pub fn parcala_dosya(yol: &Path, goreli: &str, ayar: ParcaAyari) -> Sonuc<DosyaParcalari> {
    let dosya_karma = Karma::dosyadan(yol)?;
    let mut dosya = File::open(yol)?;
    let mut parcalayici = Parcalayici::yeni(ayar)?;
    let mut parcalar: Vec<TamParca> = Vec::new();
    let mut toplam = 0u64;
    let mut tampon = vec![0u8; OKUMA_BLOGU];
    loop {
        let okunan = dosya.read(&mut tampon)?;
        if okunan == 0 {
            break;
        }
        parcalar.extend(parcalayici.besle(&tampon[..okunan])?);
        toplam += okunan as u64;
    }
    if let Some(son) = parcalayici.bitir()? {
        parcalar.push(son);
    }
    let ozet = liste_ozeti(
        &parcalar
            .iter()
            .map(|p| (p.konum, p.uzunluk, p.karma))
            .collect::<Vec<_>>(),
    );
    Ok(DosyaParcalari {
        yol: goreli.to_string(),
        boyut: toplam,
        karma: dosya_karma.0,
        parcalar,
        liste_ozeti: ozet,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Test verisi üreticisi: sabit tohumlu xorshift (belirlenimli).
    fn uret(bayt_sayisi: usize, tohum: u64) -> Vec<u8> {
        let mut x = tohum | 1;
        let mut veri = Vec::with_capacity(bayt_sayisi);
        for _ in 0..bayt_sayisi {
            x ^= x >> 12;
            x = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
            x ^= x >> 25;
            x = x.wrapping_mul(0x2545_F491_4F6C_DD1D);
            x ^= x >> 27;
            veri.push((x & 0xff) as u8);
        }
        veri
    }

    fn butunluk(parcalar: &[TamParca], veri: &[u8]) {
        let toplam: u64 = parcalar.iter().map(|p| u64::from(p.uzunluk)).sum();
        assert_eq!(
            toplam,
            veri.len() as u64,
            "parça boyutları toplamı dosya boyutuna eşit olmalı"
        );
        for (sira, parca) in parcalar.iter().enumerate() {
            let bas = parca.konum as usize;
            let son = parca.son_konum() as usize;
            assert_eq!(
                Karma::hesapla(&veri[bas..son]).0,
                parca.karma,
                "parça {sira} karması"
            );
            if sira > 0 {
                let onceki = &parcalar[sira - 1];
                assert_eq!(
                    onceki.son_konum(),
                    parca.konum,
                    "parçalar aralıksız bitmeli"
                );
            }
        }
    }

    #[test]
    fn ayar_dogrulama_hatali_araligi_reddeder() {
        let mut ayar = ParcaAyari::varsayilan();
        assert!(ayar.dogrula().is_ok());
        ayar.en_kucuk = 0;
        assert!(ayar.dogrula().is_err());
        ayar = ParcaAyari::varsayilan();
        ayar.en_kucuk = 100_000;
        ayar.en_buyuk = 50_000;
        assert!(ayar.dogrula().is_err());
        ayar = ParcaAyari::varsayilan();
        ayar.en_buyuk = AZAMI_PARCA + 1;
        assert!(ayar.dogrula().is_err());
        ayar = ParcaAyari::varsayilan();
        ayar.esik = 0;
        assert!(ayar.dogrula().is_err());
        ayar = ParcaAyari::varsayilan();
        ayar.esik = 0b1010;
        assert!(ayar.dogrula().is_err(), "eşik tek bir güç olmalı");
    }

    #[test]
    fn esik_bit_karakteristigi_dogru_hesaplanir() {
        assert_eq!(ParcaAyari::varsayilan().esik_bit(), 13);
    }

    #[test]
    fn bos_girdi_parca_uretmez() {
        let parcalar = parcala(b"", ParcaAyari::varsayilan()).unwrap();
        assert!(parcalar.is_empty());
    }

    #[test]
    fn kisa_girdi_tek_parca_olarak_kapanir() {
        let veri = b"kucuk bir dosya";
        let parcalar = parcala(veri, ParcaAyari::varsayilan()).unwrap();
        assert_eq!(parcalar.len(), 1);
        assert_eq!(parcalar[0].uzunluk as usize, veri.len());
        butunluk(&parcalar, veri);
    }

    #[test]
    fn orta_boyda_cok_parca_ve_buyuk_girdide_daha_cok_parca() {
        // 13 bit esik ortalama 8 KiB parca uretir: 64 KiB girdi zaten birkac
        // parcaya bolunur, 1 MiB girdi daha cok parca verir.
        let ayar = ParcaAyari::varsayilan();
        let orta = uret(64 * 1024, 0x1234);
        let orta_parcalar = parcala(&orta, ayar).unwrap();
        butunluk(&orta_parcalar, &orta);
        assert!(
            orta_parcalar.len() > 1,
            "64 KiB girdi tek parcaya bolunmemeli"
        );
        let buyuk = uret(1024 * 1024, 0xabcd);
        let parcalar = parcala(&buyuk, ayar).unwrap();
        butunluk(&parcalar, &buyuk);
        assert!(
            parcalar.len() > 16,
            "1 MiB girdide cok sayida parca beklenir"
        );
        assert!(parcalar.len() > orta_parcalar.len());
    }

    #[test]
    fn parcalar_asla_en_kucuk_ve_en_buyuk_siniri_asmaz() {
        let veri = uret(700 * 1024, 7);
        let parcalar = parcala(&veri, ParcaAyari::varsayilan()).unwrap();
        for parca in &parcalar[..parcalar.len() - 1] {
            assert!(parca.uzunluk >= ParcaAyari::varsayilan().en_kucuk);
            assert!(parca.uzunluk <= ParcaAyari::varsayilan().en_buyuk);
        }
    }

    #[test]
    fn tekrarli_veri_parca_sinirlarini_kaydirmaz() {
        // Aynı verinin iki kopyası bitişik konduğunda ikinci kopyanın sınırları
        // kendi içeriğinden çıkar; sabit bloklamada olduğu gibi kaymaz.
        let veri = uret(300 * 1024, 99);
        let mut cift = veri.clone();
        cift.extend_from_slice(&veri);
        let parcalar = parcala(&cift, ParcaAyari::varsayilan()).unwrap();
        butunluk(&parcalar, &cift);
        let karmalar: HashSet<[u8; 32]> = parcalar.iter().map(|p| p.karma).collect();
        assert!(
            karmalar.len() < parcalar.len(),
            "tekrarli içerik aynı parçayı verir"
        );
    }

    #[test]
    fn basa_bayt_ekleme_dosyanin_cogununu_yeniden_uretmez() {
        // Rapor b05 kabul kriteri: başa eklenen bayt dosyanın %99+'unu
        // yeniden ürettirmemeli.
        let veri = uret(2 * 1024 * 1024, 0x5150);
        let ayar = ParcaAyari::varsayilan();
        let degistirilmis = {
            let mut yeni = Vec::with_capacity(veri.len() + 1);
            yeni.push(0xAA);
            yeni.extend_from_slice(&veri);
            yeni
        };
        let eski_karmalar: HashSet<[u8; 32]> = parcala(&veri, ayar)
            .unwrap()
            .iter()
            .map(|p| p.karma)
            .collect();
        let yeni_parcalar = parcala(&degistirilmis, ayar).unwrap();
        let korunan = yeni_parcalar
            .iter()
            .filter(|p| eski_karmalar.contains(&p.karma))
            .count();
        let oran = korunan as f64 / yeni_parcalar.len() as f64;
        assert!(
            oran > 0.90,
            "korunan parça oranı {oran:.3} beklenenden düşük (eşik {:#x})",
            ayar.esik
        );
    }

    #[test]
    fn orta_bayt_ekleme_dosyanin_cogununu_yeniden_uretmez() {
        let veri = uret(2 * 1024 * 1024, 0x2024);
        let ayar = ParcaAyari::varsayilan();
        let mut degistirilmis = veri.clone();
        degistirilmis.insert(1024 * 1024, 0xBB);
        let eski_karmalar: HashSet<[u8; 32]> = parcala(&veri, ayar)
            .unwrap()
            .iter()
            .map(|p| p.karma)
            .collect();
        let yeni_parcalar = parcala(&degistirilmis, ayar).unwrap();
        let korunan = yeni_parcalar
            .iter()
            .filter(|p| eski_karmalar.contains(&p.karma))
            .count();
        let oran = korunan as f64 / yeni_parcalar.len() as f64;
        assert!(oran > 0.45, "orta eklemede korunan parça oranı {oran:.3}");
    }

    #[test]
    fn sona_bayt_ekleme_yalnizca_son_parcayi_degistirir() {
        let veri = uret(512 * 1024, 0x3131);
        let ayar = ParcaAyari::varsayilan();
        let mut degistirilmis = veri.clone();
        degistirilmis.push(0xCC);
        let eski = parcala(&veri, ayar).unwrap();
        let yeni = parcala(&degistirilmis, ayar).unwrap();
        let farkli = yeni
            .iter()
            .zip(eski.iter())
            .filter(|(a, b)| a.karma != b.karma)
            .count();
        assert!(
            farkli <= 2,
            "sona bayt eklemede değişen parça sayısı {farkli}, en fazla 2 olmalı"
        );
    }

    #[test]
    fn pencere_kayan_ozelligi_karma_yalnizca_son_baytlara_bagli() {
        // Ayni son PENCERE baytla biten ama ondeki icerigi farkli olan iki dizi
        // ayni karmayi vermelidir: kayan karmanin gecmisi pencereden tasmaz.
        let ayar = ParcaAyari {
            en_kucuk: 4096,
            en_buyuk: 8192,
            esik: VARSAYILAN_ESIK,
            pencere: PENCERE,
        };
        let kuyruk = uret(2048 + PENCERE, 0xFEED);
        let mut a = Parcalayici::yeni(ayar).unwrap();
        a.besle(&[0x11u8; 2048]).unwrap();
        a.besle(&kuyruk[2048..]).unwrap();
        let mut b = Parcalayici::yeni(ayar).unwrap();
        b.besle(&[0x22u8; 2048]).unwrap();
        b.besle(&kuyruk[2048..]).unwrap();
        assert_eq!(
            a.karma, b.karma,
            "kayan pencere son PENCERE bayta bagli olmali"
        );
        // Onden bir bayt daha fazla beslemek karmayi degistirir.
        let mut c = Parcalayici::yeni(ayar).unwrap();
        c.besle(&[0x22u8; 2048]).unwrap();
        c.besle(&kuyruk[2048..2048 + PENCERE - 1]).unwrap();
        assert_ne!(
            a.karma, c.karma,
            "pencere tam dolmadan kayanlik gecerli olmamali"
        );
    }

    #[test]
    fn akis_besleme_ve_tek_seferde_besleme_ayni_sonucu_verir() {
        let veri = uret(300 * 1024, 0x77);
        let ayar = ParcaAyari::varsayilan();
        let tek = parcala(&veri, ayar).unwrap();
        let mut akis = Parcalayici::yeni(ayar).unwrap();
        let mut parcalar = Vec::new();
        for dilim in veri.chunks(4093) {
            parcalar.extend(akis.besle(dilim).unwrap());
        }
        if let Some(son) = akis.bitir().unwrap() {
            parcalar.push(son);
        }
        assert_eq!(
            tek, parcalar,
            "blok boyutundan bağımsız sınırlar üretilmelidir"
        );
    }

    #[test]
    fn bos_dosyada_bitir_none_doner() {
        let mut parcalayici = Parcalayici::yeni(ParcaAyari::varsayilan()).unwrap();
        assert!(!parcalayici.bekleyen_var());
        assert!(parcalayici.bitir().unwrap().is_none());
    }

    #[test]
    fn son_konum_hesabi_dogru() {
        let parca = TamParca {
            konum: 100,
            uzunluk: 50,
            karma: [0; 32],
        };
        assert_eq!(parca.son_konum(), 150);
    }
}
