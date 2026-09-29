//! Cihaz kimliği, sır saklama ve parola türetme.
//!
//! Bu modülün sorumluluğu üç şeydir: (1) kalıcı cihaz kimliği üretmek,
//! (2) grup parolasını Argon2id ile özüte dönüştürmek, (3) özütten yönlü oturum
//! anahtarı türetmek.
//! Bu modülün sorumluluğu *değil*: şifreleme yapmak (bkz. `crate::sifre`) ve
//! el sıkışma durum makinesini yürütmek (bkz. `crate::el_sikisma`).
//!
//! # Sır disiplini
//!
//! - Parola **hiçbir zaman** diske yazılmaz; her çalıştırmada yeniden türetilir.
//! - [`Gizli`] türü düşerken `zeroize` ile bellekte sıfırlanır ve `Debug`
//!   çıktısı `***` gösterir; böylece hata günlüğüne sır sızmaz.
//! - Yayın paketindeki grup etiketi Argon2id ile türetilir, düz SHA-256 ile
//!   değil. Düz karma kullanılsaydı dinleyici etiketten parolayı çevrimdışı kaba
//!   kuvvetle denerdi; Argon2id bu maliyeti her denemede yeniden öder.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hata::{Hata, Sonuc};

/// Cihaz kimliğinin bayt cinsinden uzunluğu.
pub const KIMLIK_UZUNLUGU: usize = 16;

/// Yayın etiketi için kullanılan Argon2id tuz etiketi.
const ETIKET_TUZ: &[u8] = b"peersync/grup-etiketi/v1";

/// Oturum özütü için kullanılan Argon2id tuz etiketi.
const OTURUM_TUZ: &[u8] = b"peersync/oturum-ozutu/v1";

/// HKDF bağlam ayracı: protokol sürümü.
const HKDF_BAGLAM: &[u8] = b"peersync/v1";

/// Bellekte sıfırlanan sır.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Gizli {
    baytlar: Vec<u8>,
}

impl Gizli {
    /// Verilen metinden sır üretir.
    ///
    /// Metin `parola:ek` biçiminde olabilir; iki bileşen `:` ile ayrılır ve
    /// ikisi birlikte tek parola sayılır. Bu ayrım, kullanıcının parolada `:`
    /// kullanabilmesini sağlar.
    pub fn metinden(metin: &str) -> Gizli {
        let mut baytlar = Vec::with_capacity(metin.len());
        baytlar.extend_from_slice(metin.as_bytes());
        Gizli { baytlar }
    }

    /// Sırın bayt cinsinden uzunluğu (günlükte *yalnızca* uzunluk yazılabilir).
    pub fn uzunluk(&self) -> usize {
        self.baytlar.len()
    }

    /// Argon2 girdisi olarak bayt dizisini verir.
    pub(crate) fn baytlar(&self) -> &[u8] {
        &self.baytlar
    }
}

impl fmt::Debug for Gizli {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Gizli(len={}) [***]", self.baytlar.len())
    }
}

/// Bu cihazın kalıcı kimliği.
///
/// Kimlik `getrandom` ile üretilir ve `.peersync/kimlik.json` içinde saklanır.
/// Ağ paketinde kimlik açıkça görünür ama **gizli bilgi taşımaz**: yalnızca
/// çakışmada belirsizliği kırmak için karşılaştırılır.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Kimlik(pub [u8; KIMLIK_UZUNLUGU]);

impl Kimlik {
    /// İşletim sistemi entropisinden yeni bir kimlik üretir.
    pub fn uret() -> Sonuc<Kimlik> {
        let mut baytlar = [0u8; KIMLIK_UZUNLUGU];
        getrandom::getrandom(&mut baytlar)
            .map_err(|_| Hata::BozukPaket("işletim sistemi entropisi alınamadı".to_string()))?;
        Ok(Kimlik(baytlar))
    }

    /// Kimliği onaltılık metne çevirir (günlük, dosya ve rapor için).
    pub fn onaltilik(&self) -> String {
        let mut metin = String::with_capacity(KIMLIK_UZUNLUGU * 2);
        for bayt in &self.0 {
            metin.push_str(&format!("{bayt:02x}"));
        }
        metin
    }

    /// Onaltılık metinden kimlik çözer.
    ///
    /// # Hatalar
    ///
    /// Uzunluk ya da karakter kümesi geçersizse [`Hata::BozukPaket`] döner.
    pub fn onaltilikten(metin: &str) -> Sonuc<Kimlik> {
        if metin.len() != KIMLIK_UZUNLUGU * 2 {
            return Err(Hata::BozukPaket(format!(
                "kimlik metni {} karakter, beklenen {}",
                metin.len(),
                KIMLIK_UZUNLUGU * 2
            )));
        }
        let mut baytlar = [0u8; KIMLIK_UZUNLUGU];
        for (sira, dizi) in baytlar.iter_mut().enumerate() {
            let parca = &metin[sira * 2..sira * 2 + 2];
            *dizi = u8::from_str_radix(parca, 16)
                .map_err(|_| Hata::BozukPaket(format!("geçersiz kimlik baytı: {parca}")))?;
        }
        Ok(Kimlik(baytlar))
    }
}

impl fmt::Display for Kimlik {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.onaltilik())
    }
}

/// Argon2id türetme parametreleri.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Turetme {
    /// Bellek maliyeti (KiB cinsinden).
    pub bellek_kib: u32,
    /// Zaman maliyeti (geçiş sayısı).
    pub gecis: u32,
    /// Paralellik.
    pub paralellik: u32,
    /// Türetilen özütün bayt uzunluğu.
    pub ozut_bayt: usize,
}

impl Default for Turetme {
    fn default() -> Self {
        Turetme::oturum()
    }
}

impl Turetme {
    /// Oturum özütü için maliyet: 19 MiB, 2 geçiş, 1 paralellik.
    ///
    /// OWASP'in Argon2id için verdiği ikinci öneri düzeyine yakındır ve masaüstünde
    /// bir el sıkışma için birkaç yüz milisaniye sürer.
    pub fn oturum() -> Turetme {
        Turetme {
            bellek_kib: 19 * 1024,
            gecis: 2,
            paralellik: 1,
            ozut_bayt: 32,
        }
    }

    /// Yayın etiketi için hafif maliyet: 8 MiB, 1 geçiş.
    ///
    /// Yayın paketi saniyede birkaç kez gönderilir ama etiket bir kez türetilip
    /// önbelleklenir, bu yüzden ağır maliyet gereksizdir. Etiketin amacı kimlik
    /// doğrulama değil, farklı grup parolalarının eşleri birbirini görmesini
    /// engellemektir.
    pub fn etiket() -> Turetme {
        Turetme {
            bellek_kib: 8 * 1024,
            gecis: 1,
            paralellik: 1,
            ozut_bayt: 32,
        }
    }

    /// Argon2id ile özüt üretir.
    ///
    /// # Hatalar
    ///
    /// Parametreler geçersizse ya da ayrılan ölçüm hatası oluşursa
    /// [`Hata::AyarGecersiz`] döner. Hata mesajı parolayı içermez.
    pub fn ozut_uret(&self, parola: &Gizli, tuz_etiketi: &[u8]) -> Sonuc<Vec<u8>> {
        if tuz_etiketi.len() < 8 {
            return Err(Hata::AyarGecersiz {
                ad: "argon2.tuz",
                deger: format!("{} bayt (en az 8 gerekli)", tuz_etiketi.len()),
            });
        }
        let parametre = Params::new(
            self.bellek_kib,
            self.gecis,
            self.paralellik,
            Some(self.ozut_bayt),
        )
        .map_err(|e| Hata::AyarGecersiz {
            ad: "argon2.parametreler",
            deger: e.to_string(),
        })?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, parametre);
        let mut ozut = vec![0u8; self.ozut_bayt];
        argon
            .hash_password_into(parola.baytlar(), tuz_etiketi, &mut ozut)
            .map_err(|e| Hata::AyarGecersiz {
                ad: "argon2.parametreler",
                deger: e.to_string(),
            })?;
        Ok(ozut)
    }
}

/// Gruba özgü yayın etiketi (16 bayt).
///
/// İlan paketinde yalnızca bu etiket açıkça görünür. Dosya adları, boyutlar
/// veya karmalar ilanda **bulunmaz** (rapor b10 gizlilik maddesi).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrupEtiketi(pub [u8; 16]);

impl GrupEtiketi {
    /// Grup parolasından etiketi türetir (Argon2id, hafif parametreler).
    pub fn turet(parola: &Gizli) -> Sonuc<GrupEtiketi> {
        let ozut = Turetme::etiket().ozut_uret(parola, ETIKET_TUZ)?;
        let mut etiket = [0u8; 16];
        etiket.copy_from_slice(&ozut[..16]);
        Ok(GrupEtiketi(etiket))
    }

    /// Yayın paketine yazılacak bayt dizisi.
    pub fn baytlar(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Oturum anahtarlarının türetildiği 32 baytlık özüt.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OturumOzutu(pub [u8; 32]);

impl OturumOzutu {
    /// Grup parolasından oturum özütünü üretir.
    pub fn turet(parola: &Gizli) -> Sonuc<OturumOzutu> {
        let ozut = Turetme::oturum().ozut_uret(parola, OTURUM_TUZ)?;
        let mut dizi = [0u8; 32];
        dizi.copy_from_slice(&ozut);
        Ok(OturumOzutu(dizi))
    }

    /// `bilgi` etiketine bağlı 32 baytlık anahtar türetir (HKDF-SHA256).
    ///
    /// # Hatalar
    ///
    /// Çıktı uzunluğu geçersizse [`Hata::OturumAnahtariYok`] döner.
    pub fn anahtar_turet(&self, bilgi: &[u8]) -> Sonuc<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(None, &self.0);
        let mut anahtar = [0u8; 32];
        hkdf.expand(bilgi, &mut anahtar)
            .map_err(|_| Hata::OturumAnahtariYok)?;
        Ok(anahtar)
    }

    /// Yön ayracını ekleyerek anahtar türetir.
    pub fn yon_anahtari(&self, yon: &[u8]) -> Sonuc<[u8; 32]> {
        let mut bilgi = Vec::with_capacity(HKDF_BAGLAM.len() + yon.len());
        bilgi.extend_from_slice(HKDF_BAGLAM);
        bilgi.extend_from_slice(yon);
        self.anahtar_turet(&bilgi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gizli_debug_icerik_sızdirmaz() {
        let gizli = Gizli::metinden("SuperGizliParola");
        let metin = format!("{gizli:?}");
        assert!(!metin.contains("SuperGizliParola"));
        assert!(metin.contains("***"));
        assert!(metin.contains("len=16"));
    }

    #[test]
    fn gizli_colon_ayracini_kabul_eder() {
        let gizli = Gizli::metinden("grup:ek");
        assert_eq!(gizli.uzunluk(), 7);
    }

    #[test]
    fn kimlik_uretimi_benzersizdir() {
        let a = Kimlik::uret().unwrap();
        let b = Kimlik::uret().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.onaltilik().len(), KIMLIK_UZUNLUGU * 2);
    }

    #[test]
    fn kimlik_onaltilik_gidis_donus_kayipsizdir() {
        let kimlik = Kimlik::uret().unwrap();
        assert_eq!(Kimlik::onaltilikten(&kimlik.onaltilik()).unwrap(), kimlik);
    }

    #[test]
    fn kimlik_onaltilikten_hatali_metni_reddeder() {
        assert!(Kimlik::onaltilikten("kisa").is_err());
        assert!(Kimlik::onaltilikten(&"z".repeat(32)).is_err());
    }

    #[test]
    fn ayni_parola_ayni_ozut_uretir_farkli_parola_farkli_ozut() {
        let a = OturumOzutu::turet(&Gizli::metinden("elmas-doga-2026")).unwrap();
        let b = OturumOzutu::turet(&Gizli::metinden("elmas-doga-2026")).unwrap();
        let c = OturumOzutu::turet(&Gizli::metinden("elmas-doga-2027")).unwrap();
        assert_eq!(a.0, b.0);
        assert_ne!(a.0, c.0);
    }

    #[test]
    fn argon2_kaynagi_deterministik_ve_tuz_ayirici() {
        let t = Turetme {
            bellek_kib: 1024,
            gecis: 2,
            paralellik: 1,
            ozut_bayt: 32,
        };
        let parola = Gizli::metinden("p");
        let a = t.ozut_uret(&parola, b"tuz-bir-0001").unwrap();
        let b = t.ozut_uret(&parola, b"tuz-bir-0001").unwrap();
        let c = t.ozut_uret(&parola, b"tuz-iki-0002").unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn argon2id_rfc9106_parametreleriyle_durulur() {
        // RFC 9106 Bolum 5.3 Argon2id test vektoru 8 bayt "secret" ve 12 bayt
        // "associated data" icerir. `argon2::hash_password_into` bu iki alani
        // ifade edemedigi icin RFC'nin yayimladigi etiket bu API ile
        // tekrarlanamaz. Buradaki vektor ayni parametrelerle (m=32 KiB, t=3,
        // p=4, parola 32x0x01, tuz 16x0x02) uretilen ve sabitlenmis bir
        // regresyon etiketidir: amaci kutuphanenin degil, bizim parametre
        // secimimizin sessizce degismemesini denetlemektir.
        let t = Turetme {
            bellek_kib: 32,
            gecis: 3,
            paralellik: 4,
            ozut_bayt: 32,
        };
        let parola = Gizli::metinden(&"\u{1}".repeat(32));
        let ozut = t.ozut_uret(&parola, &[0x02u8; 16]).unwrap();
        let beklenen: [u8; 32] = [
            0x03, 0xaa, 0xb9, 0x65, 0xc1, 0x20, 0x01, 0xc9, 0xd7, 0xd0, 0xd2, 0xde, 0x33, 0x19,
            0x2c, 0x04, 0x94, 0xb6, 0x84, 0xbb, 0x14, 0x81, 0x96, 0xd7, 0x3c, 0x1d, 0xf1, 0xac,
            0xaf, 0x6d, 0x0c, 0x2e,
        ];
        assert_eq!(ozut, beklenen);
    }

    #[test]
    fn kisa_tuz_reddeder() {
        let t = Turetme::etiket();
        let parola = Gizli::metinden("p");
        let hata = t.ozut_uret(&parola, b"kisa").unwrap_err();
        assert!(matches!(
            hata,
            Hata::AyarGecersiz {
                ad: "argon2.tuz",
                ..
            }
        ));
    }
    #[test]
    fn grup_etiketi_parolaya_baglidir() {
        let a = GrupEtiketi::turet(&Gizli::metinden("grup-bir")).unwrap();
        let b = GrupEtiketi::turet(&Gizli::metinden("grup-bir")).unwrap();
        let c = GrupEtiketi::turet(&Gizli::metinden("grup-iki")).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.baytlar().len(), 16);
    }

    #[test]
    fn hkdf_yon_anahtarlari_farklidir() {
        let ozut = OturumOzutu::turet(&Gizli::metinden("yon")).unwrap();
        let gonder = ozut.yon_anahtari(b"istemci->es").unwrap();
        let al = ozut.yon_anahtari(b"es->istemci").unwrap();
        assert_ne!(gonder, al);
        assert_eq!(gonder.len(), 32);
    }

    #[test]
    fn hkdf_ayni_bilgi_ayni_anahtari_verir() {
        let ozut = OturumOzutu::turet(&Gizli::metinden("ayni")).unwrap();
        assert_eq!(
            ozut.yon_anahtari(b"x").unwrap(),
            ozut.yon_anahtari(b"x").unwrap()
        );
    }
}
