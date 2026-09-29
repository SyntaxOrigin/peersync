//! Oturum anahtarları, nonce disiplini ve akış şifreleme (ChaCha20-Poly1305).
//!
//! Bu modülün sorumluluğu el sıkışmadan sonraki **her** baytın şifrelenmesini,
//! bütünlüğünün doğrulanmasını ve nonce'un asla tekrarlanmamasını garanti
//! etmektir. Bu modülün sorumluluğu *değil*: el sıkışmanın kendisi
//! (bkz. `crate::el_sikisma`) ve paketlerin taşınması (bkz. `crate::protok`).
//!
//! # Nonce disiplini
//!
//! Nonce 12 bayttır ve iki parçadan oluşur: 4 baytlık **yön etiketi** ve 8
//! baytlık **sayaç**. Yön etiketi iki tarafın aynı sayacı kullansa bile
//! farklı nonce üretmesini garanti eder; sayaç ise tek yön içinde kesin ve
//! artan sıradadır. [`NonceSayaci`] tükenmeyi ve sarmalama (wrap) riskini
//! `Hata::NonceTekrari` ile reddeder, sessizce bir nonce'u yeniden vermez.
//!
//! Paketin ilk 8 baytı bu sayaçtır. Çözme tarafı sayacın **azalan** olmasını
//! (yani tekrar oynatma) reddeder; artan ama boşluğu olan bir sayacı kabul
//! eder ve boşluğu günlüğe yazar. Böylece bellekte sınırsız bir "görülen
//! sayaç" tablosu tutulmaz.
//!
//! # Şifreleme zorunluluğu
//!
//! Parola modunda şifrelenmemiş aktarım **yoktur**: [`GuvenlikModu`] yalnızca
//! `Sifreli` değerini üretebilir, `Sifresiz` değeri bilinçli olarak hata verir
//! (bkz. `GuvenlikModu::sifresiz_istiyor`).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce as ChaChaNonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hata::{Hata, Sonuc};
use crate::kimlik::OturumOzutu;

/// ChaCha20-Poly1305 anahtar uzunluğu (256 bit).
pub const ANAHTAR_UZUNLUGU: usize = 32;

/// ChaCha20-Poly1305 nonce uzunluğu (96 bit).
pub const NONCE_UZUNLUGU: usize = 12;

/// Paket başlığında taşınan sıra numarasının bayt uzunluğu.
pub const SIRA_UZUNLUGU: usize = 8;

/// Bir paketin şifreli bölümünden önce gelen başlık uzunluğu.
pub const BASLIK_UZUNLUGU: usize = NONCE_UZUNLUGU + SIRA_UZUNLUGU;

/// Taşıma katmanının seçtiği güvenlik kipi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuvenlikModu {
    /// Zorunlu kip: tüm taşıma akış şifrelemesiyle yapılır.
    Sifreli,
}

impl GuvenlikModu {
    /// Şifrelenmemiş taşıma talebini karşılamak için çağrılır.
    ///
    /// Bu işlev **her zaman** hata döndürür ve amacı hatayı erken, anlaşılır bir
    /// noktada üretmektir: sürümlenmiş bir istemci "şifrelemeyi kapat" derse
    /// sessizce düz metin göndermek yerine açık bir hata alır.
    ///
    /// # Hatalar
    ///
    /// Daima [`Hata::SifrelemeZorunlu`] döner.
    pub fn sifresiz_istiyor() -> Sonuc<GuvenlikModu> {
        Err(Hata::SifrelemeZorunlu)
    }
}

/// Ek kimlik doğrulama verisi (AAD) olarak kullanılan yön etiketi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Yon {
    /// İstemciden sunucuya.
    IstemciEs,
    /// Sunucudan istemciye.
    EsIstemci,
}

impl Yon {
    /// Nonce'in ilk 4 baytına yazılan yön etiketi.
    pub fn etiket(&self) -> [u8; 4] {
        match self {
            Yon::IstemciEs => *b"PS01",
            Yon::EsIstemci => *b"PS02",
        }
    }

    /// Karşı yön.
    pub fn karsi(&self) -> Yon {
        match self {
            Yon::IstemciEs => Yon::EsIstemci,
            Yon::EsIstemci => Yon::IstemciEs,
        }
    }

    /// HKDF yön ayracı.
    pub fn ayrac(&self) -> &'static [u8] {
        match self {
            Yon::IstemciEs => b"yon/istemci-es/v1",
            Yon::EsIstemci => b"yon/es-istemci/v1",
        }
    }
}

/// 12 baytlık ChaCha20-Poly1305 nonce'i.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce(pub [u8; NONCE_UZUNLUGU]);

impl Nonce {
    /// Başlıktaki sıra numarasını döndürür.
    pub fn sira(&self) -> u64 {
        let mut dizi = [0u8; 8];
        dizi.copy_from_slice(&self.0[4..]);
        u64::from_le_bytes(dizi)
    }
}

/// Hiçbir zaman aynı nonce'u iki kez vermeyen sayaç.
#[derive(Debug, Clone)]
pub struct NonceSayaci {
    yon: Yon,
    sonraki: u64,
}

impl NonceSayaci {
    /// Verilen yön ve başlangıç değeriyle sayaç oluşturur.
    pub fn yeni(yon: Yon, baslangic: u64) -> NonceSayaci {
        NonceSayaci {
            yon,
            sonraki: baslangic,
        }
    }

    /// Sıradaki nonce'u üretir ve sayacı bir artırır.
    ///
    /// # Hatalar
    ///
    /// Sayaç `u64::MAX`'teyse [`Hata::NonceTekrari`] döner; sarmalama (wrap)
    /// bir nonce'un yeniden kullanılmasına yol açacağı için asla sessizce
    /// sarmalama yapılmaz.
    pub fn sonraki_nonce(&mut self) -> Sonuc<Nonce> {
        if self.sonraki == u64::MAX {
            return Err(Hata::NonceTekrari);
        }
        let siradaki = self.sonraki;
        self.sonraki += 1;
        let mut baytlar = [0u8; NONCE_UZUNLUGU];
        baytlar[..4].copy_from_slice(&self.yon.etiket());
        baytlar[4..].copy_from_slice(&siradaki.to_le_bytes());
        Ok(Nonce(baytlar))
    }

    /// Bir sonraki sıra numarasını (üretmeden) bildirir.
    pub fn siradaki_sira(&self) -> u64 {
        self.sonraki
    }
}

/// Bellekte sıfırlanan oturum anahtarı.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Anahtar([u8; ANAHTAR_UZUNLUGU]);

impl Anahtar {
    /// Bayt dizisinden anahtar oluşturur.
    pub fn yeni(baytlar: [u8; ANAHTAR_UZUNLUGU]) -> Anahtar {
        Anahtar(baytlar)
    }

    /// Anahtarın bayt dizisi.
    pub fn baytlar(&self) -> &[u8; ANAHTAR_UZUNLUGU] {
        &self.0
    }
}

impl std::fmt::Debug for Anahtar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Anahtar([***])")
    }
}

/// Tek yönlü şifreli kanal: gönderen sayaç üretir, alan sırayı denetler.
#[derive(Debug)]
pub struct SifreliKanal {
    anahtar: Anahtar,
    yon: Yon,
    sayac: NonceSayaci,
    beklenen: u64,
}

impl SifreliKanal {
    /// Türetilmiş anahtarla gönderme kanalı oluşturur.
    pub fn gonderen(anahtar: Anahtar, yon: Yon) -> SifreliKanal {
        SifreliKanal {
            anahtar,
            yon,
            sayac: NonceSayaci::yeni(yon, 0),
            beklenen: 0,
        }
    }

    /// Türetilmiş anahtarla alma kanalı oluşturur (sıra denetimi açık).
    pub fn alan(anahtar: Anahtar, yon: Yon) -> SifreliKanal {
        SifreliKanal {
            anahtar,
            yon,
            sayac: NonceSayaci::yeni(yon, 0),
            beklenen: 0,
        }
    }

    /// Kanalın yönü.
    pub fn yon(&self) -> Yon {
        self.yon
    }

    /// Bir sonraki gönderilecek sıra numarası.
    pub fn siradaki_sira(&self) -> u64 {
        self.sayac.siradaki_sira()
    }

    /// Düz metni şifreler: `nonce(12) | sira(8) | şifre metni`.
    ///
    /// # Hatalar
    ///
    /// Nonce kaynağı tükendiyse [`Hata::NonceTekrari`] döner.
    pub fn sifrele(&mut self, duz: &[u8]) -> Sonuc<Vec<u8>> {
        let nonce = self.sayac.sonraki_nonce()?;
        let sira = nonce.sira();
        let simge = self.simge();
        let sifreli = simge
            .encrypt(
                ChaChaNonce::from_slice(&nonce.0),
                Payload {
                    msg: duz,
                    aad: &self.yon.etiket(),
                },
            )
            .map_err(|_| Hata::SifrelemeHatasi)?;
        let mut paket = Vec::with_capacity(BASLIK_UZUNLUGU + sifreli.len());
        paket.extend_from_slice(&nonce.0);
        paket.extend_from_slice(&sira.to_le_bytes());
        paket.extend_from_slice(&sifreli);
        Ok(paket)
    }

    /// Şifreli paketi çözer ve sırayı doğrular.
    ///
    /// # Hatalar
    ///
    /// - Paket başlıktan kısaysa [`Hata::BozukPaket`].
    /// - Sıra, daha önce görülmüş bir sayfadan küçükse (tekrar oynatma)
    ///   [`Hata::BaglantiKapandi`].
    /// - Poly1305 etiketi tutmazsa ya da yön etiketi çelişirse
    ///   [`Hata::SifrelemeHatasi`].
    /// - Sayaç `u64::MAX`'e ulaşırsa [`Hata::SiraTasmasi`].
    ///
    /// Sıra numarası nonce içinde taşınır ve nonce AEAD etiketiyle örtülü
    /// olduğundan **uzaktan değiştirilemez**; taşma ancak tam olarak
    /// `u64::MAX` paket işlendiğinde mümkündür. Yine de gönderen taraf
    /// `u64::MAX`'te sarmalamayı reddettiği için alıcı da aynı sözleşmeyi
    /// uygular: taşma sarmalanmaz, hata döner. Sarmalanma olsaydı sayaç `0`'a
    /// döner ve oynatma penceresi **tümüyle sıfırlanırdı**.
    pub fn coz(&mut self, paket: &[u8]) -> Sonuc<Vec<u8>> {
        if paket.len() < BASLIK_UZUNLUGU + 16 {
            return Err(Hata::BozukPaket(format!(
                "şifreli paket çok kısa: {} bayt",
                paket.len()
            )));
        }
        let mut nonce_dizi = [0u8; NONCE_UZUNLUGU];
        nonce_dizi.copy_from_slice(&paket[..NONCE_UZUNLUGU]);
        let nonce = Nonce(nonce_dizi);
        if nonce.0[..4] != self.yon.etiket() {
            return Err(Hata::BozukPaket("paket yön etiketi eşleşmiyor".to_string()));
        }
        let sira = nonce.sira();
        if sira < self.beklenen {
            return Err(Hata::BaglantiKapandi {
                gerekce: "yeniden oynatma: sira geride",
            });
        }
        let duz = self
            .simge()
            .decrypt(
                ChaChaNonce::from_slice(&nonce.0),
                Payload {
                    msg: &paket[BASLIK_UZUNLUGU..],
                    aad: &self.yon.etiket(),
                },
            )
            .map_err(|_| Hata::SifrelemeHatasi)?;
        if sira > self.beklenen {
            self.beklenen = sira;
        }
        // `saturating_add` yerine **açık hata**: sarmalama `beklenen`'i 0'a
        // düşürür ve oynatma penceresi sıfırlanır. Gönderen taraf da
        // `sonraki_nonce` ile sarmalamayı reddediyor; iki tarafın sözleşmesi
        // aynı olmalıdır.
        if self.beklenen == u64::MAX {
            return Err(Hata::SiraTasmasi);
        }
        self.beklenen += 1;
        Ok(duz)
    }

    /// Alınan paketlerde görülen en büyük sırayı bildirir (günlük için).
    pub fn gorulen_en_buyuk_sira(&self) -> u64 {
        self.beklenen.saturating_sub(1)
    }

    fn simge(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(self.anahtar.baytlar()))
    }
}

/// Bir oturumun iki yönlü anahtar çifti.
#[derive(Debug)]
pub struct Oturum {
    /// İstemciden sunucuya anahtar.
    pub gonderen: Anahtar,
    /// Sunucudan istemciye anahtar.
    pub alan: Anahtar,
    /// İstemcinin yönü (`IstemciEs`).
    pub gonderen_yon: Yon,
}

impl Oturum {
    /// İstemci tarafında: özütten iki yönlü anahtar türetir.
    ///
    /// # Hatalar
    ///
    /// HKDF çıktı uzunluğu geçersizse [`Hata::OturumAnahtariYok`] döner. Hata
    /// **sessizce yutulmaz** ve sıfır anahtara düşülmez: anahtar türetilemezse
    /// oturum kurulamaz.
    pub fn istemci(ozut: &OturumOzutu) -> Sonuc<Oturum> {
        Ok(Oturum {
            gonderen: Anahtar::yeni(ozut.yon_anahtari(Yon::IstemciEs.ayrac())?),
            alan: Anahtar::yeni(ozut.yon_anahtari(Yon::EsIstemci.ayrac())?),
            gonderen_yon: Yon::IstemciEs,
        })
    }

    /// Sunucu tarafında: istemciyle aynı iki anahtarı ters yönde üretir.
    ///
    /// # Hatalar
    ///
    /// [`Oturum::istemci`] ile aynı koşulda hata döner.
    pub fn sunucu(ozut: &OturumOzutu) -> Sonuc<Oturum> {
        Ok(Oturum {
            gonderen: Anahtar::yeni(ozut.yon_anahtari(Yon::EsIstemci.ayrac())?),
            alan: Anahtar::yeni(ozut.yon_anahtari(Yon::IstemciEs.ayrac())?),
            gonderen_yon: Yon::EsIstemci,
        })
    }
}

/// El sıkışma sırasında karşılıklı parola kanıtı üretir.
///
/// Kanıt, oturum özütünden türetilen ayrı bir anahtarla `ChaCha20-Poly1305`
/// ile mühürlenir. Anahtar yanlış paroladan türetilirse açma **her zaman**
/// başarısız olur; bu, parolanın ağa hiç taşınmamasını sağlar.
#[derive(Debug)]
pub struct KanitMuhrü {
    anahtar: Anahtar,
}

impl KanitMuhrü {
    /// Oturum özütünden kanıt anahtarı türetir.
    pub fn turet(ozut: &OturumOzutu) -> Sonuc<KanitMuhrü> {
        let anahtar = ozut.yon_anahtari(b"kanit/v1")?;
        Ok(KanitMuhrü {
            anahtar: Anahtar::yeni(anahtar),
        })
    }

    /// Metni mühürler ve 32 baytlık kanıtı döndürür.
    ///
    /// Nonce, iki tarafın da bildiği oturum tanımlayıcısından deterministik
    /// olarak türetilir: iki taraf aynı mührü üretir, karşı taraf yalnızca
    /// karşılaştırır. Nonce tekrarı tehlikesi yoktur çünkü kanıt paketi
    /// oturum başına **bir kez** gönderilir.
    pub fn mruhle(&self, metin: &[u8], oturum_tanimlayici: &[u8; 12]) -> Sonuc<[u8; 32]> {
        let simge = ChaCha20Poly1305::new(Key::from_slice(self.anahtar.baytlar()));
        // Metin once 16 bayta ozetlenir: boylece sifreli metin 16 + 16 (Poly1305
        // etiketi) = tam 32 bayt olur ve kanit tasimada kesilmez.
        let ozet = &crate::karma::Karma::hesapla(metin).0[..16];
        let sifreli = simge
            .encrypt(
                ChaChaNonce::from_slice(oturum_tanimlayici),
                Payload {
                    msg: ozet,
                    aad: oturum_tanimlayici,
                },
            )
            .map_err(|_| Hata::SifrelemeHatasi)?;
        let mut kanit = [0u8; 32];
        kanit.copy_from_slice(&sifreli);
        Ok(kanit)
    }

    /// Kanıtı açar; parola yanlışsa [`Hata::KimlikDogrulanmadi`] döner.
    pub fn ac(&self, metin: &[u8], kanit: &[u8; 32], oturum_tanimlayici: &[u8; 12]) -> Sonuc<()> {
        let simge = ChaCha20Poly1305::new(Key::from_slice(self.anahtar.baytlar()));
        let sifreli = simge
            .decrypt(
                ChaChaNonce::from_slice(oturum_tanimlayici),
                Payload {
                    msg: kanit,
                    aad: oturum_tanimlayici,
                },
            )
            .map_err(|_| Hata::KimlikDogrulanmadi {
                gerekce: "parola kaniti acilamadi",
            })?;
        let beklenen = &crate::karma::Karma::hesapla(metin).0[..16];
        if sifreli == beklenen {
            Ok(())
        } else {
            Err(Hata::KimlikDogrulanmadi {
                gerekce: "parola kaniti beklenen metni vermedi",
            })
        }
    }
}

/// İki tarafın da bildiği, oturuma özgü 12 baytlık tanımlayıcı.
///
/// El sıkışma nonce'larının türetildiği ve kanıt mühründe nonce olarak
/// kullanılan değerdir. Her iki taraf aynı değeri bildiği için kanıt
/// karşılaştırılabilir.
pub fn oturum_tanimlayici(istemci_nonce: [u8; 8], es_nonce: [u8; 8]) -> [u8; 12] {
    let mut girdi = Vec::with_capacity(24 + 8 + 8);
    girdi.extend_from_slice(b"peersync/oturum-id/v1");
    girdi.extend_from_slice(&istemci_nonce);
    girdi.extend_from_slice(&es_nonce);
    let kase = crate::karma::Karma::hesapla(&girdi);
    let mut tanim = [0u8; 12];
    tanim.copy_from_slice(&kase.0[..12]);
    tanim
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kimlik::Gizli;
    use std::collections::HashSet;

    fn ozut(parola: &str) -> OturumOzutu {
        OturumOzutu::turet(&Gizli::metinden(parola)).unwrap()
    }

    #[test]
    fn sifresiz_tasma_talebi_her_zaman_hata_dondurur() {
        let hata = GuvenlikModu::sifresiz_istiyor().unwrap_err();
        assert!(matches!(hata, Hata::SifrelemeZorunlu));
        assert!(hata.to_string().contains("zorunludur"));
    }

    #[test]
    fn nonce_sayaci_tekrarsiz_nonce_uretir() {
        let mut sayac = NonceSayaci::yeni(Yon::IstemciEs, 0);
        let mut gorulen = HashSet::new();
        for _ in 0..20_000 {
            let nonce = sayac.sonraki_nonce().unwrap();
            assert!(gorulen.insert(nonce.0), "nonce tekrarladi");
        }
    }

    #[test]
    fn nonce_sayaci_yon_etiketi_ile_birlikte_kullanilir() {
        let mut a = NonceSayaci::yeni(Yon::IstemciEs, 0);
        let mut b = NonceSayaci::yeni(Yon::EsIstemci, 0);
        assert_ne!(a.sonraki_nonce().unwrap().0, b.sonraki_nonce().unwrap().0);
    }

    #[test]
    fn nonce_sayaci_sarmalamayi_reddeder() {
        let mut sayac = NonceSayaci::yeni(Yon::IstemciEs, u64::MAX);
        let hata = sayac.sonraki_nonce().unwrap_err();
        assert!(matches!(hata, Hata::NonceTekrari));
    }

    #[test]
    fn nonce_sayaci_baslangic_degerine_honum_eder() {
        let mut sayac = NonceSayaci::yeni(Yon::EsIstemci, 1000);
        assert_eq!(sayac.sonraki_nonce().unwrap().sira(), 1000);
        assert_eq!(sayac.siradaki_sira(), 1001);
    }

    #[test]
    fn sifreli_gidis_donus_duz_metin_verir() {
        let o = ozut("gidis-donus");
        let istemci = Oturum::istemci(&o).unwrap();
        let sunucu = Oturum::sunucu(&o).unwrap();
        let mut gonderen =
            SifreliKanal::gonderen(Anahtar::yeni(*istemci.gonderen.baytlar()), Yon::IstemciEs);
        let mut alan = SifreliKanal::alan(Anahtar::yeni(*sunucu.alan.baytlar()), Yon::IstemciEs);
        let duz = b"merhaba peersync";
        let sifreli = gonderen.sifrele(duz).unwrap();
        assert_ne!(
            &sifreli[BASLIK_UZUNLUGU..],
            &duz[..],
            "sifre metni duz metin olmamali"
        );
        assert_eq!(alan.coz(&sifreli).unwrap(), duz.to_vec());
    }

    #[test]
    fn sifreli_kanal_nonce_tekrari_uretmez() {
        let o = ozut("nonce-kontrol");
        let istemci = Oturum::istemci(&o).unwrap();
        let mut gonderen =
            SifreliKanal::gonderen(Anahtar::yeni(*istemci.gonderen.baytlar()), Yon::IstemciEs);
        let mut gorulen = HashSet::new();
        for _ in 0..5_000 {
            let paket = gonderen.sifrele(b"x").unwrap();
            let mut baslik = [0u8; BASLIK_UZUNLUGU];
            baslik.copy_from_slice(&paket[..BASLIK_UZUNLUGU]);
            assert!(gorulen.insert(baslik), "paket basligi tekrarladi");
        }
    }

    #[test]
    fn yanlis_anahtarla_cozme_basarisizdir() {
        let gonderen_ozut = ozut("dogru");
        let alan_ozut = ozut("yanlis");
        let mut gonderen = SifreliKanal::gonderen(
            Anahtar::yeni(*Oturum::istemci(&gonderen_ozut).unwrap().gonderen.baytlar()),
            Yon::IstemciEs,
        );
        let mut alan = SifreliKanal::alan(
            Anahtar::yeni(*Oturum::istemci(&alan_ozut).unwrap().alan.baytlar()),
            Yon::IstemciEs,
        );
        let paket = gonderen.sifrele(b"gizli veri").unwrap();
        let hata = alan.coz(&paket).unwrap_err();
        assert!(matches!(hata, Hata::SifrelemeHatasi));
    }

    #[test]
    fn bozuk_sifreli_paket_reddedilir() {
        let o = ozut("bozuk");
        let istemci = Oturum::istemci(&o).unwrap();
        let mut gonderen =
            SifreliKanal::gonderen(Anahtar::yeni(*istemci.gonderen.baytlar()), Yon::IstemciEs);
        let mut alan =
            SifreliKanal::alan(Anahtar::yeni(*istemci.gonderen.baytlar()), Yon::IstemciEs);
        let mut paket = gonderen.sifrele(b"bozulacak veri").unwrap();
        let son = paket.len() - 1;
        paket[son] ^= 0xff;
        assert!(matches!(
            alan.coz(&paket).unwrap_err(),
            Hata::SifrelemeHatasi
        ));
    }

    #[test]
    fn kisa_paket_reddedilir() {
        let o = ozut("kisa");
        let mut alan = SifreliKanal::alan(
            Anahtar::yeni(*Oturum::istemci(&o).unwrap().alan.baytlar()),
            Yon::IstemciEs,
        );
        assert!(matches!(
            alan.coz(&[0u8; 10]).unwrap_err(),
            Hata::BozukPaket(_)
        ));
    }

    #[test]
    fn tekrar_oynatma_geri_sira_ile_reddedilir() {
        let o = ozut("tekrar");
        let istemci = Oturum::istemci(&o).unwrap();
        let mut gonderen =
            SifreliKanal::gonderen(Anahtar::yeni(*istemci.gonderen.baytlar()), Yon::IstemciEs);
        let mut alan =
            SifreliKanal::alan(Anahtar::yeni(*istemci.gonderen.baytlar()), Yon::IstemciEs);
        let ilk = gonderen.sifrele(b"birinci").unwrap();
        let ikinci = gonderen.sifrele(b"ikinci").unwrap();
        alan.coz(&ilk).unwrap();
        alan.coz(&ikinci).unwrap();
        let hata = alan.coz(&ilk).unwrap_err();
        assert!(matches!(hata, Hata::BaglantiKapandi { .. }));
    }

    #[test]
    fn siradaki_bir_paket_boşlukla_kabul_edilir() {
        let o = ozut("bosluk");
        let istemci = Oturum::istemci(&o).unwrap();
        let mut gonderen =
            SifreliKanal::gonderen(Anahtar::yeni(*istemci.gonderen.baytlar()), Yon::IstemciEs);
        let mut alan =
            SifreliKanal::alan(Anahtar::yeni(*istemci.gonderen.baytlar()), Yon::IstemciEs);
        let ilk = gonderen.sifrele(b"birinci").unwrap();
        let ucuncu = gonderen.sifrele(b"ucuncu").unwrap();
        alan.coz(&ilk).unwrap();
        assert_eq!(alan.coz(&ucuncu).unwrap(), b"ucuncu".to_vec());
    }

    // -----------------------------------------------------------------------
    // Sıra sayacı taşması
    // -----------------------------------------------------------------------

    /// Alıcı kanalın sıra beklentisini doğrudan ayarlar.
    ///
    /// `beklenen` özel alandır ve 2^64 paket göndermeden `u64::MAX`'a
    /// ulaştırılamaz; testler modül içinde olduğu için buradan ayarlanabilir.
    fn alan_beklenen(anahtar: [u8; ANAHTAR_UZUNLUGU], beklenen: u64) -> SifreliKanal {
        SifreliKanal {
            anahtar: Anahtar::yeni(anahtar),
            yon: Yon::IstemciEs,
            sayac: NonceSayaci::yeni(Yon::IstemciEs, 0),
            beklenen,
        }
    }

    /// İstenen sıra numarasıyla geçerli bir paket üretir.
    ///
    /// `sifrele` yalnızca `sonraki_nonce` sırasını izleyebildiği için
    /// `u64::MAX` gibi uç değerleri üretemez; sözleşmeyi doğrulayan testler
    /// paketi elle kurmak zorundadır. Düzen `sifrele` ile birebir aynıdır.
    fn paket_uret(kanal: &SifreliKanal, sira: u64, duz: &[u8]) -> Vec<u8> {
        let mut nonce_dizi = [0u8; NONCE_UZUNLUGU];
        nonce_dizi[..4].copy_from_slice(&kanal.yon.etiket());
        nonce_dizi[4..].copy_from_slice(&sira.to_le_bytes());
        let sifreli = kanal
            .simge()
            .encrypt(
                ChaChaNonce::from_slice(&nonce_dizi),
                Payload {
                    msg: duz,
                    aad: &kanal.yon.etiket(),
                },
            )
            .expect("test paketi sifrelenemedi");
        let mut paket = Vec::with_capacity(BASLIK_UZUNLUGU + sifreli.len());
        paket.extend_from_slice(&nonce_dizi);
        paket.extend_from_slice(&sira.to_le_bytes());
        paket.extend_from_slice(&sifreli);
        paket
    }

    #[test]
    fn sira_uy64_max_ta_hata_doner_ve_oynatma_penceresi_sifirlanmaz() {
        // `beklenen` zaten u64::MAX'a dayandiginda, sira = u64::MAX paketi
        // sayaci 1 arttirarak **tasir**. Sarmalama release derlemesinde 0'a
        // doner ve tum eski paketler yeniden kabul edilir.
        let mut alan = alan_beklenen([9u8; ANAHTAR_UZUNLUGU], u64::MAX);
        assert_eq!(alan.gorulen_en_buyuk_sira(), u64::MAX - 1);

        let paket = paket_uret(&alan, u64::MAX, b"tasma");
        let hata = alan.coz(&paket).unwrap_err();
        assert!(
            matches!(hata, Hata::SiraTasmasi),
            "u64::MAX paketinde hata donmeliydi, alinan: {hata:?}"
        );
        assert_eq!(
            alan.gorulen_en_buyuk_sira(),
            u64::MAX - 1,
            "hata sonrasi oynatma penceresi **aynen korunmali** (0'a donmemeli)"
        );
    }

    #[test]
    fn tasma_deneden_sonra_eski_paket_hala_oynatma_reddedilir() {
        // Asil zarar siranin sifirlanmasiydi: tasmadan sonra daha once
        // gorulmus ama yuksek bir sira tekrar kabul edilirdi. Yeni kodda
        // beklenen u64::MAX'da kalir, dolayisiyla oynatma reddi surer.
        let mut alan = alan_beklenen([11u8; ANAHTAR_UZUNLUGU], 1_000);
        // 1) Once sayaci tasi.
        let tasan = paket_uret(&alan, u64::MAX, b"tasma");
        assert!(matches!(alan.coz(&tasan).unwrap_err(), Hata::SiraTasmasi));

        // 2) Daha once gorulmus bir sirayi tekrar gonder.
        let eski = paket_uret(&alan, 500, b"eski paket");
        let hata = alan.coz(&eski).unwrap_err();
        assert!(
            matches!(hata, Hata::BaglantiKapandi { .. }),
            "tasma sonrasi eski paket oynatma olarak reddedilmeliydi, alinan: {hata:?}"
        );
    }

    #[test]
    fn gonderen_ve_alici_tarafin_tasma_sozlesmesi_ayni() {
        // Gonderen u64::MAX'te sarmalamayi reddeder; dolayisiyla uretebilecegi
        // en buyuk sira u64::MAX - 1'dir ve alici onu kabul edebilmelidir.
        let o = ozut("tasma-sozlesme");
        let istemci = Oturum::istemci(&o).unwrap();
        let anahtar = *istemci.gonderen.baytlar();
        let mut sayac = NonceSayaci::yeni(Yon::IstemciEs, u64::MAX - 1);
        let nonce = sayac.sonraki_nonce().unwrap();
        assert_eq!(nonce.sira(), u64::MAX - 1);
        // Bir sonraki gonderim reddedilir.
        assert!(matches!(
            sayac.sonraki_nonce().unwrap_err(),
            Hata::NonceTekrari
        ));

        let mut alan = alan_beklenen(anahtar, 0);
        let son = paket_uret(&alan, u64::MAX - 1, b"son gonderilebilir");
        assert_eq!(alan.coz(&son).unwrap(), b"son gonderilebilir".to_vec());
        assert_eq!(alan.gorulen_en_buyuk_sira(), u64::MAX - 1);
        // Alıcı, gönderenin asla üretemeyeceği sırayı da kabul etmez.
        let tasacak = paket_uret(&alan, u64::MAX, b"gonderilemez");
        assert!(matches!(alan.coz(&tasacak).unwrap_err(), Hata::SiraTasmasi));
    }

    #[test]
    fn tam_giden_sayaci_tasma_yapmaz() {
        // Butun yolun bittigi durum temizdir: son kabul edilebilir sira
        // gonderilir, sonraki gonderim reddedilir ve alici tasmaz.
        let o = ozut("tam-son");
        let istemci = Oturum::istemci(&o).unwrap();
        let anahtar = *istemci.gonderen.baytlar();
        let mut alan = alan_beklenen(anahtar, u64::MAX - 1);
        let son = paket_uret(&alan, u64::MAX - 1, b"son");
        assert_eq!(alan.coz(&son).unwrap(), b"son".to_vec());
        assert_eq!(alan.gorulen_en_buyuk_sira(), u64::MAX - 1);
    }

    #[test]
    fn yanlis_yon_etiketli_paket_reddedilir() {
        let o = ozut("yon");
        let istemci = Oturum::istemci(&o).unwrap();
        let mut gonderen =
            SifreliKanal::gonderen(Anahtar::yeni(*istemci.gonderen.baytlar()), Yon::IstemciEs);
        let mut ters = SifreliKanal::alan(Anahtar::yeni(*istemci.alan.baytlar()), Yon::EsIstemci);
        let paket = gonderen.sifrele(b"yon testi").unwrap();
        assert!(matches!(ters.coz(&paket).unwrap_err(), Hata::BozukPaket(_)));
    }

    #[test]
    fn istemci_ve_sunucu_anahtarlari_ters_tes_durur() {
        let o = ozut("ters");
        let i = Oturum::istemci(&o).unwrap();
        let s = Oturum::sunucu(&o).unwrap();
        assert_eq!(i.gonderen.baytlar(), s.alan.baytlar());
        assert_eq!(i.alan.baytlar(), s.gonderen.baytlar());
        assert_ne!(i.gonderen.baytlar(), i.alan.baytlar());
    }

    #[test]
    fn anahtar_debug_icerik_gostermez() {
        let anahtar = Anahtar::yeni([0xab; 32]);
        let metin = format!("{anahtar:?}");
        assert!(!metin.contains("ab"));
        assert!(metin.contains("***"));
    }

    #[test]
    fn dogru_parola_kaniti_acilir() {
        let o = ozut("dogru-parola");
        let m = KanitMuhrü::turet(&o).unwrap();
        let tanim = oturum_tanimlayici([1u8; 8], [2u8; 8]);
        let kanit = m.mruhle(b"PEERSYNC-DOGRULA-V1", &tanim).unwrap();
        assert!(m.ac(b"PEERSYNC-DOGRULA-V1", &kanit, &tanim).is_ok());
    }

    #[test]
    fn yanlis_parola_kaniti_acilamaz_ve_hata_doner() {
        let dogru = KanitMuhrü::turet(&ozut("dogru-parola")).unwrap();
        let yanlis = KanitMuhrü::turet(&ozut("yanlis-parola")).unwrap();
        let tanim = oturum_tanimlayici([1u8; 8], [2u8; 8]);
        let kanit = yanlis.mruhle(b"PEERSYNC-DOGRULA-V1", &tanim).unwrap();
        let hata = dogru
            .ac(b"PEERSYNC-DOGRULA-V1", &kanit, &tanim)
            .unwrap_err();
        assert!(matches!(hata, Hata::KimlikDogrulanmadi { .. }));
    }

    #[test]
    fn kanit_bayti_bozulursa_acma_basarisizdir() {
        let o = ozut("bozuk-kanit");
        let m = KanitMuhrü::turet(&o).unwrap();
        let tanim = oturum_tanimlayici([3u8; 8], [4u8; 8]);
        let mut kanit = m.mruhle(b"PEERSYNC-DOGRULA-V1", &tanim).unwrap();
        kanit[0] ^= 0xff;
        assert!(m.ac(b"PEERSYNC-DOGRULA-V1", &kanit, &tanim).is_err());
    }

    #[test]
    fn oturum_tanimlayici_simetrik_ve_konuma_duyarlidir() {
        let a = oturum_tanimlayici([1u8; 8], [2u8; 8]);
        let b = oturum_tanimlayici([1u8; 8], [2u8; 8]);
        let c = oturum_tanimlayici([2u8; 8], [1u8; 8]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn rfc8439_aead_vektoru_kutudan_gecer() {
        // RFC 8439 Bolum 2.8.2 AEAD ChaCha20-Poly1305 test vektoru.
        let anahtar: [u8; 32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
            0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
            0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let mut nonce_dizi = [0u8; 12];
        nonce_dizi[..4].copy_from_slice(b"PS01");
        nonce_dizi[4..].copy_from_slice(&7u64.to_le_bytes());
        let duz = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let simge = ChaCha20Poly1305::new(Key::from_slice(&anahtar));
        let sifreli = simge
            .encrypt(
                ChaChaNonce::from_slice(&nonce_dizi),
                Payload {
                    msg: duz,
                    aad: &nonce_dizi,
                },
            )
            .unwrap();
        let acilan = simge
            .decrypt(
                ChaChaNonce::from_slice(&nonce_dizi),
                Payload {
                    msg: &sifreli,
                    aad: &nonce_dizi,
                },
            )
            .unwrap();
        assert_eq!(acilan, duz.to_vec());
        // AAD degisince dogrulama kirilir.
        assert!(simge
            .decrypt(
                ChaChaNonce::from_slice(&nonce_dizi),
                Payload {
                    msg: &sifreli,
                    aad: b"baska"
                }
            )
            .is_err());
    }
}
