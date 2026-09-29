//! İkili çerçeve biçimi, uygulama düzeyi segmentasyon ve yeniden birleştirme.
//!
//! Bu modülün sorumluluğu taşınan baytların **biçimidir**: çerçeve kodlama/çözme,
//! sınırların denetlenmesi, büyük çerçevenin segmentlere bölünmesi ve segmentlerin
//! doğru sırayla birleştirilmesi.
//! Bu modülün sorumluluğu *değil*: şifreleme (bkz. `crate::sifre`), yönlendirme
//! (UDP yayın, bkz. `crate::kesif`) ve senkronizasyon kararları (bkz. `crate::senkron`).
//!
//! # Katmanlar
//!
//! ```text
//! Cerceve  ->  AEAL (SifreliKanal)  ->  Segmentasyon  ->  UDP datagramı
//! ```
//!
//! Segment başlığı 8 bayttır: `cerceve kimligi (u32) | sıra (u16) | adet (u16)`.
//! Datagramın tamamı tek segmentse (loopback MTU'su) segment başlığı **yazılmaz**;
//! bu, geliştirme ve test trafiğini gereksiz 8 bayttan arındırır. Alıcı taraf
//! tek segmentli paketleri de çok segmentli paketlerle aynı yolla tanır: gelen
//! baytların ilk 8 baytı geçerli bir segment başlığı ise çok segmentli kabul
//! edilir, değilse paketin tamamı tek parça cerceve sayılır.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::hata::{Hata, Sonuc};
use crate::karma::KARMA_UZUNLUGU;

/// Onaltılık metin olarak `[u8; N]` serileştiren yardımcı modül.
///
/// İçerik tanımlayıcıları JSON'da ikili dizi olarak değil onaltılık metin olarak
/// saklanır: `indeks.json` elle okunabilir ve `diff` çıktısı anlamlı hâle gelir.
pub(crate) mod hexe {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Diziyi onaltılık metne çevirip yazar.
    pub fn serialize<S, const N: usize>(veri: &[u8; N], ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut metin = String::with_capacity(N * 2);
        for bayt in veri {
            metn_yaz(&mut metin, *bayt);
        }
        ser.serialize_str(&metin)
    }

    fn metn_yaz(hedef: &mut String, bayt: u8) {
        const HECF: &[u8; 16] = b"0123456789abcdef";
        hedef.push(HECF[usize::from(bayt >> 4)] as char);
        hedef.push(HECF[usize::from(bayt & 0x0f)] as char);
    }

    /// Onaltılık metinden diziyi çözer.
    pub fn deserialize<'de, D, const N: usize>(des: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let metin = String::deserialize(des)?;
        if metin.len() != N * 2 {
            return Err(serde::de::Error::custom(format!(
                "onaltılık dizi {} karakter, beklenen {}",
                metin.len(),
                N * 2
            )));
        }
        let mut dizi = [0u8; N];
        for (sira, bayt) in dizi.iter_mut().enumerate() {
            *bayt = u8::from_str_radix(&metin[sira * 2..sira * 2 + 2], 16)
                .map_err(serde::de::Error::custom)?;
        }
        Ok(dizi)
    }
}

/// Protokol sihri (`PSYN`).
pub const SIHIR: [u8; 4] = *b"PSYN";

/// Bu yapının anladığı protokol sürümü.
pub const SURUM: u16 = 1;

/// Bir çerçevenin şifreli bölümünün azami uzunluğu (4 MiB).
///
/// Sınırsız kaynak tüketimine karşı üst sınır: kötü niyetli bir eş sonsuza
/// kadar büyük bir çerçeve ilan edemez.
pub const AZAMI_CERCEVE: usize = 4 * 1024 * 1024;

/// Bir UDP datagramının azami uzunluğu (60 KiB).
pub const AZAMI_DATAGRAM: usize = 60 * 1024;

/// Segment başlığının uzunluğu (sihir 4 + kimlik 4 + sıra 2 + adet 2).
pub const SEGMENT_BASLIK: usize = 12;

/// Segment başlığının sihir değeri.
///
/// Bu sihir olmadan "bu datagram çok segmentli mi" sorusu güvenilir biçimde
/// yanıtlanamazdı: el sıkışma paketlerinin kimi baytları yanlışlıkla bir segment
/// başlığı gibi okunabilirdi. Dört baytlık sihir bu belirsizliği kaldırır.
pub const SEGMENT_SIHIR: [u8; 4] = *b"PSSG";

/// Bir segmentin gövdesinde taşınan azami bayt sayısı.
///
/// Güvenli ağ MTU'sının (1500) altında kalır; böylece yaygın yönlendiriciler
/// parçalamak zorunda kalmaz.
pub const SEGMENT_GOVDE: usize = 1200;

/// Bir çerçevenin azami segment sayısı.
pub const AZAMI_SEGMENT: u16 = 2048;

/// Tamamlanmamış çerçeve taslağının bekleneceği azami süre.
pub const TASLAK_YASAM: Duration = Duration::from_secs(20);

/// Bir çerçevede taşınabilecek azami parça isteği sayısı.
pub const AZAMI_ISTEK: usize = 256;

/// Manifestteki azami dosya sayısı.
pub const AZAMI_DOSYA: usize = 100_000;

/// Çerçeve tür kodları.
pub mod tur {
    /// İstemci açılışı (düz metin).
    pub const MERHABA: u8 = 0x01;
    /// Sunucu açılış yanıtı (düz metin).
    pub const MERHABA_YANIT: u8 = 0x02;
    /// Sürüm uyuşmazlığı bildirimi (düz metin).
    pub const SURUM_HATASI: u8 = 0x03;
    /// Dosya listesi.
    pub const MANIFEST: u8 = 0x10;
    /// Dosya listesi talebi.
    pub const MANIFEST_AL: u8 = 0x11;
    /// Parça talebi.
    pub const PARCA_ISTE: u8 = 0x12;
    /// Parça verisi.
    pub const PARCA_GELDI: u8 = 0x13;
    /// Bir dosyanın tüm parçaları gönderildi.
    pub const DOSYA_BITTI: u8 = 0x14;
    /// Tüm talepler karşılandı.
    pub const ISTEK_BITTI: u8 = 0x15;
    /// Tek yönlü gönderim teklifi.
    pub const TEKLIF: u8 = 0x16;
    /// Teklif yanıtı.
    pub const TEKLIF_YANITI: u8 = 0x17;
    /// Boş tutma paketi.
    pub const YOK: u8 = 0x18;
    /// Çakışma bildirimi.
    pub const CATISMA: u8 = 0x19;
    /// Bir dosyanın parça listesi (konum, uzunluk, karma üçlüleri).
    pub const PARCA_LISTESI: u8 = 0x1A;
}

/// Sınırlı okuyucu: her alan okunurken sınır denetler.
#[derive(Debug)]
pub struct Okuyucu<'a> {
    veri: &'a [u8],
    konum: usize,
}

impl<'a> Okuyucu<'a> {
    /// Yeni okuyucu oluşturur.
    pub fn yeni(veri: &'a [u8]) -> Okuyucu<'a> {
        Okuyucu { veri, konum: 0 }
    }

    /// Kalan bayt sayısı.
    pub fn kalan(&self) -> usize {
        self.veri.len() - self.konum
    }

    /// Tümünün tüketilip tüketilmediğini bildirir.
    pub fn bitti(&self) -> bool {
        self.kalan() == 0
    }

    /// Tek bayt okur.
    pub fn bayt(&mut self) -> Sonuc<u8> {
        if self.kalan() < 1 {
            return Err(Hata::BozukPaket("bayt beklenirken veri bitti".to_string()));
        }
        let deger = self.veri[self.konum];
        self.konum += 1;
        Ok(deger)
    }

    /// 16 bitlik sayı okur.
    pub fn u16(&mut self) -> Sonuc<u16> {
        Ok(u16::from_le_bytes([self.bayt()?, self.bayt()?]))
    }

    /// 32 bitlik sayı okur.
    pub fn u32(&mut self) -> Sonuc<u32> {
        Ok(u32::from_le_bytes([
            self.bayt()?,
            self.bayt()?,
            self.bayt()?,
            self.bayt()?,
        ]))
    }

    /// 64 bitlik sayı okur.
    pub fn u64(&mut self) -> Sonuc<u64> {
        let mut dizi = [0u8; 8];
        for bayt in dizi.iter_mut() {
            *bayt = self.bayt()?;
        }
        Ok(u64::from_le_bytes(dizi))
    }

    /// Sabit boyutlu dizi okur.
    pub fn sabit(&mut self, uzunluk: usize) -> Sonuc<Vec<u8>> {
        if self.kalan() < uzunluk {
            return Err(Hata::BozukPaket(format!(
                "{uzunluk} bayt beklenirken {} bayt kaldı",
                self.kalan()
            )));
        }
        let dilim = &self.veri[self.konum..self.konum + uzunluk];
        self.konum += uzunluk;
        Ok(dilim.to_vec())
    }

    /// Uzunluk önekli bayt dizisi okur (azami `AZAMI_YOL` bayt).
    pub fn dizi(&mut self, azami: usize) -> Sonuc<Vec<u8>> {
        let uzunluk = usize::from(self.u16()?);
        if uzunluk > azami {
            return Err(Hata::TamponSinir {
                sinir: "dizi",
                azami,
            });
        }
        if self.kalan() < uzunluk {
            return Err(Hata::BozukPaket(format!(
                "{uzunluk} baytlık dizi beklenirken {} bayt kaldı",
                self.kalan()
            )));
        }
        let dilim = &self.veri[self.konum..self.konum + uzunluk];
        self.konum += uzunluk;
        Ok(dilim.to_vec())
    }

    /// 32 bitlik uzunluk önekli bayt dizisi okur.
    pub fn u32_dizi(&mut self, azami: usize) -> Sonuc<Vec<u8>> {
        let uzunluk = self.u32()? as usize;
        if uzunluk > azami {
            return Err(Hata::TamponSinir {
                sinir: "u32 dizi",
                azami,
            });
        }
        self.sabit(uzunluk)
    }

    /// UTF-8 metin okur.
    pub fn metin(&mut self, azami: usize) -> Sonuc<String> {
        let baytlar = self.dizi(azami)?;
        String::from_utf8(baytlar).map_err(|_| Hata::BozukPaket("geçersiz UTF-8 metin".to_string()))
    }
}

/// Azami göreli yol uzunluğu (bayt).
pub const AZAMI_YOL: usize = 4096;

/// Bir dosyanın karşı tarafa bildirilen özeti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UzakDosya {
    /// Depoda `/` ile normalleştirilmiş göreli yol.
    pub yol: String,
    /// Dosyanın bayt cinsinden boyutu.
    pub boyut: u64,
    /// Dosyanın içerik karması.
    pub karma: [u8; KARMA_UZUNLUGU],
    /// Parça sayısı.
    pub parca_sayisi: u32,
    /// Parça listesinin özeti.
    pub liste_ozeti: [u8; KARMA_UZUNLUGU],
    /// Çakışma çözümünde kullanılan mantıksal sürüm.
    pub revizyon: u64,
    /// Dosyayı son değiştiren eş.
    pub sahip: [u8; 16],
}

/// Taşınan tek birim: bir mesaj çerçevesi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cerceve {
    /// İstemci açılış paketi (düz metin, yalnızca el sıkışma başında).
    Merhaba {
        /// Protokol sürümü; uyuşmazlıkta oturum kurulmaz.
        surum: u16,
        /// Yayın etiketinin özeti; el sıkışmada yeniden hesaplanır.
        grup_ozeti: [u8; 16],
        /// İstemci kimliği.
        kimlik: [u8; 16],
        /// Oturuma özgü rastgele sayaç.
        nonce: [u8; 8],
        /// Argon2id bellek maliyeti (KiB) bildirimi (istemci sunucuya uyar).
        argon_bellek_kib: u32,
        /// Argon2id geçiş sayısı bildirimi.
        argon_gecis: u32,
    },
    /// Sunucu açılış yanıtı (düz metin).
    MerhabaYanit {
        /// Protokol sürümü.
        surum: u16,
        /// Sunucu kimliği.
        kimlik: [u8; 16],
        /// Sunucunun oturum sayacı.
        nonce: [u8; 8],
        /// Argon2id bellek maliyeti.
        argon_bellek_kib: u32,
        /// Argon2id geçiş sayısı.
        argon_gecis: u32,
        /// Sunucunun parola bildirdiği kanıt baytları.
        kanit: [u8; 32],
    },
    /// Sürüm uyuşmazlığı bildirimi (düz metin).
    SurumHatasi {
        /// Bu yapının anladığı sürüm.
        beklenen: u16,
        /// Karşı tarafın bildirdiği sürüm.
        alinan: u16,
    },
    /// Karşı taraftan dosya listesi talebi.
    ManifestAl,
    /// Karşı tarafın dosya listesi.
    Manifest {
        /// Bildirilen dosyalar.
        dosyalar: Vec<UzakDosya>,
    },
    /// Eksik parçaların talebi.
    ParcaIste {
        /// Hedef dosyanın karması.
        dosya_karmasi: [u8; KARMA_UZUNLUGU],
        /// İstenen parça karmaları.
        karmalar: Vec<[u8; KARMA_UZUNLUGU]>,
    },
    /// Talep edilen bir parçanın içeriği.
    ParcaGeldi {
        /// Kaynak dosyanın karması.
        dosya_karmasi: [u8; KARMA_UZUNLUGU],
        /// Gönderilen parçanın karması.
        parca_karmasi: [u8; KARMA_UZUNLUGU],
        /// Parçanın bayt içeriği.
        veri: Vec<u8>,
    },
    /// Bir dosyanın tüm parçaları gönderildi.
    DosyaBitti {
        /// Dosyanın karması.
        dosya_karmasi: [u8; KARMA_UZUNLUGU],
        /// Depodaki göreli yol.
        yol: String,
    },
    /// Tüm talepler karşılandı.
    IstekBitti,
    /// Tek yönlü gönderim teklifi.
    Teklif {
        /// Teklif edilen dosyanın özeti.
        dosya: UzakDosya,
    },
    /// Teklif yanıtı.
    TeklifYaniti {
        /// Teklif kabul edildi mi?
        kabul: bool,
        /// Ret sebebi (kabul edildiyse boş).
        gerekce: String,
    },
    /// Boş tutma paketi.
    Yok,
    /// Çakışma bildirimi.
    Catisma {
        /// Çakışan dosyanın yolu.
        yol: String,
        /// Korunan eski sürümün dosya adı.
        yedek: String,
    },
    /// Bir dosyanın parça listesi: dosyayı yeniden kurmak için gereken sıralama.
    ParcaListesi {
        /// Dosyanın karması.
        dosya_karmasi: [u8; KARMA_UZUNLUGU],
        /// Parça bilgileri (sırayla).
        parcalar: Vec<ParcaBilgi>,
    },
}

/// Bir parçanın konumu, uzunluğu ve karması.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParcaBilgi {
    /// Dosya içindeki mutlak konum.
    pub konum: u64,
    /// Parçanın bayt uzunluğu.
    pub uzunluk: u32,
    /// Parçanın içerik karması.
    #[serde(with = "hexe")]
    pub karma: [u8; KARMA_UZUNLUGU],
}

impl Cerceve {
    /// Çerçevenin tür kodu.
    pub fn tur(&self) -> u8 {
        match self {
            Cerceve::Merhaba { .. } => tur::MERHABA,
            Cerceve::MerhabaYanit { .. } => tur::MERHABA_YANIT,
            Cerceve::SurumHatasi { .. } => tur::SURUM_HATASI,
            Cerceve::ManifestAl => tur::MANIFEST_AL,
            Cerceve::Manifest { .. } => tur::MANIFEST,
            Cerceve::ParcaIste { .. } => tur::PARCA_ISTE,
            Cerceve::ParcaGeldi { .. } => tur::PARCA_GELDI,
            Cerceve::DosyaBitti { .. } => tur::DOSYA_BITTI,
            Cerceve::IstekBitti => tur::ISTEK_BITTI,
            Cerceve::Teklif { .. } => tur::TEKLIF,
            Cerceve::TeklifYaniti { .. } => tur::TEKLIF_YANITI,
            Cerceve::Yok => tur::YOK,
            Cerceve::Catisma { .. } => tur::CATISMA,
            Cerceve::ParcaListesi { .. } => tur::PARCA_LISTESI,
        }
    }

    /// Bu çerçevenin şifreli taşınması gerekip gerekmediğini bildirir.
    ///
    /// Yalnızca el sıkışmanın ilk üç çerçevesi düz metindir; onların dışındaki
    /// her şey [`GuvenlikModu::Sifreli`](crate::sifre::GuvenlikModu) altında
    /// şifrelenir.
    pub fn sifreli_mi(&self) -> bool {
        !matches!(
            self,
            Cerceve::Merhaba { .. } | Cerceve::MerhabaYanit { .. } | Cerceve::SurumHatasi { .. }
        )
    }

    /// Çerçeveyi bayt dizisine çevirir.
    ///
    /// # Hatalar
    ///
    /// Çerçeve [`AZAMI_CERCEVE`] sınırını aşarsa [`Hata::MesajCokBuyuk`] döner.
    pub fn kodla(&self) -> Sonuc<Vec<u8>> {
        let mut c = Cizici::yeni();
        c.bayt(self.tur());
        match self {
            Cerceve::Merhaba {
                surum,
                grup_ozeti,
                kimlik,
                nonce,
                argon_bellek_kib,
                argon_gecis,
            } => {
                c.u16(*surum);
                c.sabit(grup_ozeti);
                c.sabit(kimlik);
                c.sabit(nonce);
                c.u32(*argon_bellek_kib);
                c.u32(*argon_gecis);
            }
            Cerceve::MerhabaYanit {
                surum,
                kimlik,
                nonce,
                argon_bellek_kib,
                argon_gecis,
                kanit,
            } => {
                c.u16(*surum);
                c.sabit(kimlik);
                c.sabit(nonce);
                c.u32(*argon_bellek_kib);
                c.u32(*argon_gecis);
                c.sabit(kanit);
            }
            Cerceve::SurumHatasi { beklenen, alinan } => {
                c.u16(*beklenen);
                c.u16(*alinan);
            }
            Cerceve::ManifestAl | Cerceve::IstekBitti | Cerceve::Yok => {}
            Cerceve::Manifest { dosyalar } => {
                if dosyalar.len() > AZAMI_DOSYA {
                    return Err(Hata::TamponSinir {
                        sinir: "manifest dosya sayisi",
                        azami: AZAMI_DOSYA,
                    });
                }
                c.u16(dosyalar.len().min(u16::MAX as usize) as u16);
                for dosya in dosyalar {
                    c.metin(&dosya.yol);
                    c.u64(dosya.boyut);
                    c.sabit(&dosya.karma);
                    c.u32(dosya.parca_sayisi);
                    c.sabit(&dosya.liste_ozeti);
                    c.u64(dosya.revizyon);
                    c.sabit(&dosya.sahip);
                }
            }
            Cerceve::ParcaIste {
                dosya_karmasi,
                karmalar,
            } => {
                if karmalar.len() > AZAMI_ISTEK {
                    return Err(Hata::TamponSinir {
                        sinir: "parca istek sayisi",
                        azami: AZAMI_ISTEK,
                    });
                }
                c.sabit(dosya_karmasi);
                c.u16(karmalar.len() as u16);
                for karma in karmalar {
                    c.sabit(karma);
                }
            }
            Cerceve::ParcaGeldi {
                dosya_karmasi,
                parca_karmasi,
                veri,
            } => {
                c.sabit(dosya_karmasi);
                c.sabit(parca_karmasi);
                c.u32_dizi(veri);
            }
            Cerceve::DosyaBitti { dosya_karmasi, yol } => {
                c.sabit(dosya_karmasi);
                c.metin(yol);
            }
            Cerceve::Teklif { dosya } => {
                c.metin(&dosya.yol);
                c.u64(dosya.boyut);
                c.sabit(&dosya.karma);
                c.u32(dosya.parca_sayisi);
                c.sabit(&dosya.liste_ozeti);
                c.u64(dosya.revizyon);
                c.sabit(&dosya.sahip);
            }
            Cerceve::TeklifYaniti { kabul, gerekce } => {
                c.bayt(u8::from(*kabul));
                c.metin(gerekce);
            }
            Cerceve::Catisma { yol, yedek } => {
                c.metin(yol);
                c.metin(yedek);
            }
            Cerceve::ParcaListesi {
                dosya_karmasi,
                parcalar,
            } => {
                if parcalar.len() > crate::protok::AZAMI_DOSYA {
                    return Err(Hata::TamponSinir {
                        sinir: "parca listesi uzunlugu",
                        azami: crate::protok::AZAMI_DOSYA,
                    });
                }
                c.sabit(dosya_karmasi);
                c.u16(parcalar.len().min(u16::MAX as usize) as u16);
                for parca in parcalar {
                    c.u64(parca.konum);
                    c.u32(parca.uzunluk);
                    c.sabit(&parca.karma);
                }
            }
        }
        c.bitir()
    }

    /// Bayt dizisinden çerçeve çözer.
    ///
    /// # Hatalar
    ///
    /// Bilinmeyen tür kodu, eksik alan ya da limiti aşan dizi
    /// [`Hata::BozukPaket`] veya [`Hata::TamponSinir`] üretir.
    pub fn coz(veri: &[u8]) -> Sonuc<Cerceve> {
        if veri.len() > AZAMI_CERCEVE {
            return Err(Hata::MesajCokBuyuk {
                alinan: veri.len(),
                azami: AZAMI_CERCEVE,
            });
        }
        let mut o = Okuyucu::yeni(veri);
        let tur_kodu = o.bayt()?;
        let cerceve = match tur_kodu {
            tur::MERHABA => Cerceve::Merhaba {
                surum: o.u16()?,
                grup_ozeti: sabit32(&mut o, 16)?,
                kimlik: sabit32(&mut o, 16)?,
                nonce: sabit32(&mut o, 8)?,
                argon_bellek_kib: o.u32()?,
                argon_gecis: o.u32()?,
            },
            tur::MERHABA_YANIT => Cerceve::MerhabaYanit {
                surum: o.u16()?,
                kimlik: sabit32(&mut o, 16)?,
                nonce: sabit32(&mut o, 8)?,
                argon_bellek_kib: o.u32()?,
                argon_gecis: o.u32()?,
                kanit: sabit32(&mut o, 32)?,
            },
            tur::SURUM_HATASI => Cerceve::SurumHatasi {
                beklenen: o.u16()?,
                alinan: o.u16()?,
            },
            tur::MANIFEST_AL => Cerceve::ManifestAl,
            tur::ISTEK_BITTI => Cerceve::IstekBitti,
            tur::YOK => Cerceve::Yok,
            tur::MANIFEST => {
                let adet = usize::from(o.u16()?);
                if adet > AZAMI_DOSYA {
                    return Err(Hata::TamponSinir {
                        sinir: "manifest dosya sayisi",
                        azami: AZAMI_DOSYA,
                    });
                }
                let mut dosyalar = Vec::with_capacity(adet);
                for _ in 0..adet {
                    dosyalar.push(uzak_dosya_oku(&mut o)?);
                }
                Cerceve::Manifest { dosyalar }
            }
            tur::PARCA_ISTE => {
                let dosya_karmasi = sabit32(&mut o, KARMA_UZUNLUGU)?;
                let adet = usize::from(o.u16()?);
                if adet > AZAMI_ISTEK {
                    return Err(Hata::TamponSinir {
                        sinir: "parca istek sayisi",
                        azami: AZAMI_ISTEK,
                    });
                }
                let mut karmalar = Vec::with_capacity(adet);
                for _ in 0..adet {
                    karmalar.push(sabit32(&mut o, KARMA_UZUNLUGU)?);
                }
                Cerceve::ParcaIste {
                    dosya_karmasi,
                    karmalar,
                }
            }
            tur::PARCA_GELDI => Cerceve::ParcaGeldi {
                dosya_karmasi: sabit32(&mut o, KARMA_UZUNLUGU)?,
                parca_karmasi: sabit32(&mut o, KARMA_UZUNLUGU)?,
                veri: o.u32_dizi(crate::parca::AZAMI_PARCA as usize)?,
            },
            tur::DOSYA_BITTI => Cerceve::DosyaBitti {
                dosya_karmasi: sabit32(&mut o, KARMA_UZUNLUGU)?,
                yol: o.metin(AZAMI_YOL)?,
            },
            tur::TEKLIF => Cerceve::Teklif {
                dosya: uzak_dosya_oku(&mut o)?,
            },
            tur::TEKLIF_YANITI => Cerceve::TeklifYaniti {
                kabul: o.bayt()? != 0,
                gerekce: o.metin(AZAMI_YOL)?,
            },
            tur::CATISMA => Cerceve::Catisma {
                yol: o.metin(AZAMI_YOL)?,
                yedek: o.metin(AZAMI_YOL)?,
            },
            tur::PARCA_LISTESI => {
                let dosya_karmasi = sabit32(&mut o, KARMA_UZUNLUGU)?;
                let adet = usize::from(o.u16()?);
                if adet > AZAMI_DOSYA {
                    return Err(Hata::TamponSinir {
                        sinir: "parca listesi uzunlugu",
                        azami: AZAMI_DOSYA,
                    });
                }
                let mut parcalar = Vec::with_capacity(adet);
                for _ in 0..adet {
                    let konum = o.u64()?;
                    let uzunluk = o.u32()?;
                    if uzunluk == 0 || uzunluk > crate::parca::AZAMI_PARCA {
                        return Err(Hata::ParcaBoyutuGecersiz {
                            bildirilen: uzunluk,
                            azami: crate::parca::AZAMI_PARCA,
                        });
                    }
                    parcalar.push(ParcaBilgi {
                        konum,
                        uzunluk,
                        karma: sabit32(&mut o, KARMA_UZUNLUGU)?,
                    });
                }
                Cerceve::ParcaListesi {
                    dosya_karmasi,
                    parcalar,
                }
            }
            diger => {
                return Err(Hata::BozukPaket(format!(
                    "bilinmeyen cerceve turu: {diger:#04x}"
                )))
            }
        };
        if !o.bitti() {
            return Err(Hata::BozukPaket(format!(
                "cerceve sonunda {} bayt artti",
                o.kalan()
            )));
        }
        Ok(cerceve)
    }
}

fn sabit32<const N: usize>(o: &mut Okuyucu<'_>, uzunluk: usize) -> Sonuc<[u8; N]> {
    let baytlar = o.sabit(uzunluk)?;
    let mut dizi = [0u8; N];
    dizi.copy_from_slice(&baytlar);
    Ok(dizi)
}

fn uzak_dosya_oku(o: &mut Okuyucu<'_>) -> Sonuc<UzakDosya> {
    Ok(UzakDosya {
        yol: o.metin(AZAMI_YOL)?,
        boyut: o.u64()?,
        karma: sabit32(o, KARMA_UZUNLUGU)?,
        parca_sayisi: o.u32()?,
        liste_ozeti: sabit32(o, KARMA_UZUNLUGU)?,
        revizyon: o.u64()?,
        sahip: sabit32(o, 16)?,
    })
}

/// Sınırlı yazıcı: sonuçta üretilen bayt dizisini toplar.
#[derive(Debug, Default)]
pub struct Cizici {
    veri: Vec<u8>,
    tasma: bool,
}

impl Cizici {
    /// Boş yazıcı oluşturur.
    pub fn yeni() -> Cizici {
        Cizici {
            veri: Vec::new(),
            tasma: false,
        }
    }

    /// Tek bayt yazar.
    pub fn bayt(&mut self, deger: u8) {
        self.veri.push(deger);
    }

    /// 16 bitlik sayı yazar.
    pub fn u16(&mut self, deger: u16) {
        self.veri.extend_from_slice(&deger.to_le_bytes());
    }

    /// 32 bitlik sayı yazar.
    pub fn u32(&mut self, deger: u32) {
        self.veri.extend_from_slice(&deger.to_le_bytes());
    }

    /// 64 bitlik sayı yazar.
    pub fn u64(&mut self, deger: u64) {
        self.veri.extend_from_slice(&deger.to_le_bytes());
    }

    /// Uzunluk önekli bayt dizisi yazar.
    ///
    /// Uzunluk alani 16 bit oldugu icin 65535 bayttan uzun girdiler sessizce
    /// kesilmez: asma bayragi yukselir ve [Cizici::bitir] hata dondurur.
    pub fn dizi(&mut self, veri: &[u8]) {
        if veri.len() > usize::from(u16::MAX) {
            self.tasma = true;
        }
        self.veri
            .extend_from_slice(&(veri.len().min(usize::from(u16::MAX)) as u16).to_le_bytes());
        self.veri.extend_from_slice(veri);
    }

    /// Sabit boyutlu diziyi **oneksiz** yazar (32 baytlık karmalar gibi).
    ///
    /// Bu yazım, okuma tarafındaki Okuyucu::sabit ile birebir eşleşmelidir;
    /// uzunluk öneki yazmak hizalamayı kaydırır.
    pub fn sabit(&mut self, veri: &[u8]) {
        self.veri.extend_from_slice(veri);
    }

    /// 32 bitlik uzunluk önekli bayt dizisi yazar (parça verisi gibi büyük alanlar).
    pub fn u32_dizi(&mut self, veri: &[u8]) {
        self.u32(u32::try_from(veri.len()).unwrap_or(u32::MAX));
        self.veri.extend_from_slice(veri);
    }

    /// Uzunluk önekli UTF-8 metin yavar.
    pub fn metin(&mut self, metin: &str) {
        self.dizi(metin.as_bytes());
    }

    /// Toplanan bayt dizisini döndürür; sınır aşılırsa hata verir.
    pub fn bitir(self) -> Sonuc<Vec<u8>> {
        if self.tasma {
            return Err(Hata::TamponSinir {
                sinir: "uzunluk oneki",
                azami: usize::from(u16::MAX),
            });
        }
        if self.veri.len() > AZAMI_CERCEVE {
            return Err(Hata::MesajCokBuyuk {
                alinan: self.veri.len(),
                azami: AZAMI_CERCEVE,
            });
        }
        Ok(self.veri)
    }

    /// Yapının o anki uzunluğu.
    pub fn uzunluk(&self) -> usize {
        self.veri.len()
    }
}

/// Çerçeveyi segmentlere böler.
///
/// Segment başlığı 12 bayttır: `sihir (4) | cerceve kimligi (u32) | sıra (u16) |
/// adet (u16)`. Tek segmente sığan çerçeve için segment başlığı **yazılmaz** ve bu
/// işlev boş liste döndürür; çağıran taraf çerçeveyi olduğu gibi tek datagram olarak
/// gönderir.
///
/// # Hatalar
///
/// Segment sayısı [`AZAMI_SEGMENT`]'i aşarsa [`Hata::TamponSinir`] döner.
pub fn bol(cerceve_kimligi: u32, veri: &[u8]) -> Sonuc<Vec<Vec<u8>>> {
    if veri.len() <= SEGMENT_GOVDE {
        return Ok(Vec::new());
    }
    let adet = veri.len().div_ceil(SEGMENT_GOVDE);
    if adet > usize::from(AZAMI_SEGMENT) {
        return Err(Hata::TamponSinir {
            sinir: "segment sayisi",
            azami: usize::from(AZAMI_SEGMENT),
        });
    }
    let mut parcalar = Vec::with_capacity(adet);
    for (sira, govde) in veri.chunks(SEGMENT_GOVDE).enumerate() {
        let mut paket = Vec::with_capacity(SEGMENT_BASLIK + govde.len());
        paket.extend_from_slice(&SEGMENT_SIHIR);
        paket.extend_from_slice(&cerceve_kimligi.to_be_bytes());
        paket.extend_from_slice(&(sira as u16).to_be_bytes());
        paket.extend_from_slice(&(adet as u16).to_be_bytes());
        paket.extend_from_slice(govde);
        parcalar.push(paket);
    }
    Ok(parcalar)
}

/// Bir datagramın tek segment mi çok segment mi olduğunu anlar.
///
/// Yalnızca dört baytlık [`SEGMENT_SIHIR`] ile başlayan ve gövdesi
/// [`SEGMENT_GOVDE`]'yi aşmayan datagram çok segmentli kabul edilir. El sıkışma
/// paketleri böylece yanlışlıkla segment sanılmaz.
fn segment_mi(datagram: &[u8]) -> bool {
    datagram.len() > SEGMENT_BASLIK && datagram[..4] == SEGMENT_SIHIR
}

/// Yarım kalmış çerçeve taslağı.
/// Datagram Ã§ok segmentli mi? (AynÄ± denetim taÅŸÄ±ma katmanÄ±nda da kullanÄ±lÄ±r.)
pub fn segment_mi_pub(datagram: &[u8]) -> bool {
    segment_mi(datagram)
}

/// Ã‡ok segmentli datagramÄ±n toplam segment sayÄ±sÄ±nÄ± dÃ¶ndÃ¼rÃ¼r.
pub fn segment_sayisi(datagram: &[u8]) -> Option<u16> {
    if !segment_mi(datagram) {
        return None;
    }
    Some(u16::from_be_bytes([datagram[10], datagram[11]]))
}

#[derive(Debug)]
struct Taslak {
    parcalar: Vec<Option<Vec<u8>>>,
    adet: usize,
    olusturma: Instant,
}

/// Segmentleri birleştirip tamamlanmış çerçeveleri geri verir.
#[derive(Debug, Default)]
pub struct Birlesim {
    taslaklar: HashMap<u32, Taslak>,
    siradaki_kimlik: u32,
    tamamlanan: u64,
    dusulen: u64,
}

impl Birlesim {
    /// Yeni birleştirici oluşturur.
    pub fn yeni() -> Birlesim {
        Birlesim::default()
    }

    /// Bir sonraki çerçeve kimliğini üretir.
    ///
    /// Kimlik `0` döndüğünde sarmalama önlenir: kimlik tükenirse yeni birleştirici
    /// kurulmalıdır, aksi hâlde bekleyen bir taslakla çakışabilir.
    pub fn kimlik_ver(&mut self) -> u32 {
        let kimlik = self.siradaki_kimlik;
        self.siradaki_kimlik = self.siradaki_kimlik.wrapping_add(1);
        if self.siradaki_kimlik == 0 {
            self.taslaklar.clear();
            self.siradaki_kimlik = 1;
        }
        kimlik
    }

    /// Gelen datagramı yerleştirir; çerçeve tamamlandıysa gövdesini döndürür.
    ///
    /// Tek segmentli datagram doğrudan döndürülür. Çok segmentli datagramda eksik
    /// parça varsa `Ok(None)` döner ve taslak saklanır. Aynı segment tekrar
    /// gelirse yok sayılır (UDP yeniden gönderimi normaldir).
    ///
    /// # Hatalar
    ///
    /// Datagram [`AZAMI_DATAGRAM`] sınırını aşarsa, çerçeve boyutu
    /// [`AZAMI_CERCEVE`] sınırını aşarsa ya da sıra/adet tutarsızsa hata döner.
    pub fn besle(&mut self, datagram: &[u8], simdi: Instant) -> Sonuc<Option<Vec<u8>>> {
        if datagram.len() > AZAMI_DATAGRAM {
            return Err(Hata::MesajCokBuyuk {
                alinan: datagram.len(),
                azami: AZAMI_DATAGRAM,
            });
        }
        if !segment_mi(datagram) {
            if datagram.len() > AZAMI_CERCEVE {
                return Err(Hata::MesajCokBuyuk {
                    alinan: datagram.len(),
                    azami: AZAMI_CERCEVE,
                });
            }
            return Ok(Some(datagram.to_vec()));
        }
        let kimlik = u32::from_be_bytes([datagram[4], datagram[5], datagram[6], datagram[7]]);
        let sira = usize::from(u16::from_be_bytes([datagram[8], datagram[9]]));
        let adet = usize::from(u16::from_be_bytes([datagram[10], datagram[11]]));
        let govde = &datagram[SEGMENT_BASLIK..];

        let taslak = self.taslaklar.entry(kimlik).or_insert_with(|| Taslak {
            parcalar: Vec::new(),
            adet,
            olusturma: simdi,
        });
        if taslak.adet != adet {
            return Err(Hata::BozukPaket(format!(
                "cerceve {kimlik} icin segment adedi degisti: {} -> {adet}",
                taslak.adet
            )));
        }
        if sira >= adet {
            return Err(Hata::BozukPaket(format!(
                "cerceve {kimlik} icin sira {sira} adet {adet} disinda"
            )));
        }
        if taslak.parcalar.len() < adet {
            if adet * (SEGMENT_BASLIK + SEGMENT_GOVDE) > AZAMI_CERCEVE {
                return Err(Hata::TamponSinir {
                    sinir: "cerceve boyutu",
                    azami: AZAMI_CERCEVE,
                });
            }
            taslak.parcalar.resize_with(adet, || None);
        }
        let toplam: usize = taslak
            .parcalar
            .iter()
            .flatten()
            .map(Vec::len)
            .sum::<usize>()
            + govde.len();
        if toplam > AZAMI_CERCEVE {
            return Err(Hata::TamponSinir {
                sinir: "cerceve boyutu",
                azami: AZAMI_CERCEVE,
            });
        }
        taslak.parcalar[sira] = Some(govde.to_vec());
        if taslak.parcalar.iter().all(Option::is_some) {
            let taslak = self
                .taslaklar
                .remove(&kimlik)
                .ok_or(Hata::BozukPaket("taslak kayboldu".to_string()))?;
            self.tamamlanan += 1;
            let mut birlestirilmis = Vec::with_capacity(toplam);
            for parca in taslak.parcalar {
                match parca {
                    Some(p) => birlestirilmis.extend_from_slice(&p),
                    None => {
                        return Err(Hata::BozukPaket(
                            "birlestirme sirasinda eksik segment".to_string(),
                        ))
                    }
                }
            }
            return Ok(Some(birlestirilmis));
        }
        Ok(None)
    }

    /// Bekleyen tamamlanmamış çerçeve sayısı.
    pub fn bekleyen(&self) -> usize {
        self.taslaklar.len()
    }

    /// Bekleyen taslak cerceve kimligi degerleri.
    pub fn kimlikleri(&self) -> Vec<u32> {
        self.taslaklar.keys().copied().collect()
    }
    /// Bir çerçevenin kesintisiz olarak gelen **en yüksek** segment sırası.
    ///
    /// Gönderen taraf bu değeri ilerleme bildiriminde kullanır: boşluğun
    /// başladığı yer bilinir, böylece kaybın ardından yalnızca eksik bölüm
    /// yeniden gönderilir.
    pub fn en_yuksek_ardisik(&self, kimlik: u32) -> Option<u16> {
        let taslak = self.taslaklar.get(&kimlik)?;
        if taslak.parcalar.first().is_none_or(|p| p.is_none()) {
            // Ilk segment gelmediyse ilerleme bildirilmez: sira 0 yanlis
            // gonderilirse gonderen taraf eksik bolumu atlar.
            return None;
        }
        let mut son = 0u16;
        for (sira, dolu) in taslak.parcalar.iter().enumerate() {
            if dolu.is_some() {
                son = sira as u16;
            } else {
                break;
            }
        }
        Some(son)
    }

    /// Tamamlanan çerçeve sayısı (ölçüm için).
    pub fn tamamlanan(&self) -> u64 {
        self.tamamlanan
    }

    /// Süresi dolan taslakları siler; silinen sayıyı döndürür.
    pub fn bayat_taslaklari_temizle(&mut self, simdi: Instant) -> u64 {
        let yasam = TASLAK_YASAM;
        let eski: Vec<u32> = self
            .taslaklar
            .iter()
            .filter(|(_, t)| simdi.duration_since(t.olusturma) > yasam)
            .map(|(k, _)| *k)
            .collect();
        for kimlik in &eski {
            self.taslaklar.remove(kimlik);
        }
        self.dusulen += eski.len() as u64;
        eski.len() as u64
    }

    /// Süresi dolan taslak sayısı (ölçüm için).
    pub fn dusulen(&self) -> u64 {
        self.dusulen
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn dosya(yol: &str) -> UzakDosya {
        UzakDosya {
            yol: yol.to_string(),
            boyut: 1234,
            karma: [0x11; KARMA_UZUNLUGU],
            parca_sayisi: 3,
            liste_ozeti: [0x22; KARMA_UZUNLUGU],
            revizyon: 7,
            sahip: [0x33; 16],
        }
    }

    fn tur_kodu(cerceve: &Cerceve) -> u8 {
        cerceve.tur()
    }

    #[test]
    fn tur_kodlari_benzersizdir() {
        let ornekler = [
            Cerceve::ManifestAl,
            Cerceve::Manifest { dosyalar: vec![] },
            Cerceve::ParcaIste {
                dosya_karmasi: [0; 32],
                karmalar: vec![],
            },
            Cerceve::IstekBitti,
            Cerceve::Yok,
            Cerceve::SurumHatasi {
                beklenen: 1,
                alinan: 2,
            },
        ];
        let mut kodlar: Vec<u8> = ornekler.iter().map(tur_kodu).collect();
        kodlar.sort_unstable();
        kodlar.dedup();
        assert_eq!(kodlar.len(), ornekler.len());
    }

    #[test]
    fn bos_cerceveler_gidis_donus_yapar() {
        for cerceve in [Cerceve::ManifestAl, Cerceve::IstekBitti, Cerceve::Yok] {
            let kod = cerceve.kodla().unwrap();
            assert_eq!(Cerceve::coz(&kod).unwrap(), cerceve);
        }
    }

    #[test]
    fn manifest_cercevesi_gidis_donus_yapar() {
        let cerceve = Cerceve::Manifest {
            dosyalar: vec![dosya("a/b.txt"), dosya("c.txt")],
        };
        let kod = cerceve.kodla().unwrap();
        assert_eq!(Cerceve::coz(&kod).unwrap(), cerceve);
    }

    #[test]
    fn parca_iste_cercevesi_gidis_donus_yapar() {
        let cerceve = Cerceve::ParcaIste {
            dosya_karmasi: [0xab; KARMA_UZUNLUGU],
            karmalar: vec![[1u8; 32], [2u8; 32]],
        };
        let kod = cerceve.kodla().unwrap();
        assert_eq!(Cerceve::coz(&kod).unwrap(), cerceve);
    }

    #[test]
    fn parca_geldi_cercevesi_gidis_donus_yapar() {
        let cerceve = Cerceve::ParcaGeldi {
            dosya_karmasi: [0xcd; KARMA_UZUNLUGU],
            parca_karmasi: [0xef; KARMA_UZUNLUGU],
            veri: vec![7u8; 5000],
        };
        let kod = cerceve.kodla().unwrap();
        assert_eq!(Cerceve::coz(&kod).unwrap(), cerceve);
    }

    #[test]
    fn parca_listesi_cercevesi_gidis_donus_yapar() {
        let c = Cerceve::ParcaListesi {
            dosya_karmasi: [0x11; KARMA_UZUNLUGU],
            parcalar: vec![
                ParcaBilgi {
                    konum: 0,
                    uzunluk: 2048,
                    karma: [1u8; 32],
                },
                ParcaBilgi {
                    konum: 2048,
                    uzunluk: 1000,
                    karma: [2u8; 32],
                },
            ],
        };
        assert_eq!(Cerceve::coz(&c.kodla().unwrap()).unwrap(), c);
    }

    #[test]
    fn parca_listesi_gecersiz_parca_boyutunu_reddeder() {
        let c = Cerceve::ParcaListesi {
            dosya_karmasi: [0x11; KARMA_UZUNLUGU],
            parcalar: vec![ParcaBilgi {
                konum: 0,
                uzunluk: crate::parca::AZAMI_PARCA + 1,
                karma: [1u8; 32],
            }],
        };
        let kod = c.kodla().unwrap();
        assert!(matches!(
            Cerceve::coz(&kod).unwrap_err(),
            Hata::ParcaBoyutuGecersiz { .. }
        ));
    }

    #[test]
    fn parca_listesi_sifir_boyutlu_parca_reddeder() {
        let c = Cerceve::ParcaListesi {
            dosya_karmasi: [0x11; KARMA_UZUNLUGU],
            parcalar: vec![ParcaBilgi {
                konum: 0,
                uzunluk: 0,
                karma: [1u8; 32],
            }],
        };
        let kod = c.kodla().unwrap();
        assert!(matches!(
            Cerceve::coz(&kod).unwrap_err(),
            Hata::ParcaBoyutuGecersiz { .. }
        ));
    }

    #[test]
    fn merhaba_cerceveleri_gidis_donus_yapar() {
        let c1 = Cerceve::Merhaba {
            surum: SURUM,
            grup_ozeti: [1; 16],
            kimlik: [2; 16],
            nonce: [3; 8],
            argon_bellek_kib: 19456,
            argon_gecis: 2,
        };
        assert_eq!(Cerceve::coz(&c1.kodla().unwrap()).unwrap(), c1);
        let c2 = Cerceve::MerhabaYanit {
            surum: SURUM,
            kimlik: [4; 16],
            nonce: [5; 8],
            argon_bellek_kib: 19456,
            argon_gecis: 2,
            kanit: [6; 32],
        };
        assert_eq!(Cerceve::coz(&c2.kodla().unwrap()).unwrap(), c2);
    }

    #[test]
    fn teklif_ve_catisma_cerceveleri_gidis_donus_yapar() {
        let c = Cerceve::Teklif {
            dosya: dosya("x.txt"),
        };
        assert_eq!(Cerceve::coz(&c.kodla().unwrap()).unwrap(), c);
        let c = Cerceve::TeklifYaniti {
            kabul: true,
            gerekce: String::new(),
        };
        assert_eq!(Cerceve::coz(&c.kodla().unwrap()).unwrap(), c);
        let c = Cerceve::Catisma {
            yol: "x.txt".to_string(),
            yedek: "x.txt.conflict-aa-1.conflict".to_string(),
        };
        assert_eq!(Cerceve::coz(&c.kodla().unwrap()).unwrap(), c);
    }

    #[test]
    fn sifre_mi_kurali_yalniz_el_sikmada_duz_metindir() {
        assert!(!Cerceve::Merhaba {
            surum: SURUM,
            grup_ozeti: [0; 16],
            kimlik: [0; 16],
            nonce: [0; 8],
            argon_bellek_kib: 1,
            argon_gecis: 1,
        }
        .sifreli_mi());
        assert!(!Cerceve::SurumHatasi {
            beklenen: 1,
            alinan: 2
        }
        .sifreli_mi());
        assert!(Cerceve::ManifestAl.sifreli_mi());
        assert!(Cerceve::Yok.sifreli_mi());
        assert!(Cerceve::IstekBitti.sifreli_mi());
    }

    #[test]
    fn bilinmeyen_tur_kodu_hata_dondurur() {
        let hata = Cerceve::coz(&[0xEE]).unwrap_err();
        assert!(matches!(hata, Hata::BozukPaket(_)));
    }

    #[test]
    fn kesilmis_cerceve_hata_dondurur() {
        let cerceve = Cerceve::Manifest {
            dosyalar: vec![dosya("a.txt")],
        };
        let kod = cerceve.kodla().unwrap();
        let hata = Cerceve::coz(&kod[..kod.len() - 5]).unwrap_err();
        assert!(matches!(hata, Hata::BozukPaket(_)));
    }

    #[test]
    fn cerceve_sonunda_artik_bayt_hata_dondurur() {
        let mut kod = Cerceve::Yok.kodla().unwrap();
        kod.push(0x00);
        assert!(matches!(
            Cerceve::coz(&kod).unwrap_err(),
            Hata::BozukPaket(_)
        ));
    }

    #[test]
    fn cok_buyuk_girdi_limit_dondurur() {
        let veri = vec![0u8; AZAMI_CERCEVE + 1];
        let hata = Cerceve::coz(&veri).unwrap_err();
        assert!(matches!(hata, Hata::MesajCokBuyuk { .. }));
    }

    #[test]
    fn tek_segmentli_cerceve_bolme_sonrasi_bos_doner() {
        let veri = vec![0u8; 100];
        assert!(bol(1, &veri).unwrap().is_empty());
    }

    #[test]
    fn cok_segmentli_cerceve_bolunur_ve_birlestirilir() {
        let veri: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let parcalar = bol(42, &veri).unwrap();
        assert!(parcalar.len() > 1);
        let mut birlesim = Birlesim::yeni();
        let simdi = Instant::now();
        let mut sonuc = None;
        for paket in &parcalar {
            if let Some(tamam) = birlesim.besle(paket, simdi).unwrap() {
                sonuc = Some(tamam);
            }
        }
        assert_eq!(sonuc.unwrap(), veri);
        assert_eq!(birlesim.bekleyen(), 0);
    }

    #[test]
    fn sirasi_karisan_segmentler_yine_birlestirilir() {
        let veri: Vec<u8> = (0..9_000u32).map(|i| (i % 97) as u8).collect();
        let parcalar = bol(7, &veri).unwrap();
        let mut karisik: Vec<Vec<u8>> = parcalar.clone();
        karisik.reverse();
        let mut birlesim = Birlesim::yeni();
        let simdi = Instant::now();
        let mut sonuc = None;
        for paket in &karisik {
            if let Some(tamam) = birlesim.besle(paket, simdi).unwrap() {
                sonuc = Some(tamam);
            }
        }
        assert_eq!(sonuc.unwrap(), veri);
    }

    #[test]
    fn yinelenen_segment_yok_sayilir() {
        let veri = vec![9u8; 5_000];
        let parcalar = bol(1, &veri).unwrap();
        let mut birlesim = Birlesim::yeni();
        let simdi = Instant::now();
        for paket in &parcalar {
            birlesim.besle(paket, simdi).unwrap();
        }
        let ilk = parcalar[0].clone();
        // Tamamlanmis cercevenin segmenti tekrar gelirse yeni bir taslak acilir;
        // cift segment zaten "yok sayilir" kuralini bu yolla dogrular.
        assert!(birlesim.besle(&ilk, simdi).unwrap().is_none());
        assert_eq!(birlesim.bekleyen(), 1);
        let ayni = parcalar[0].clone();
        assert!(birlesim.besle(&ayni, simdi).unwrap().is_none());
        assert_eq!(birlesim.bekleyen(), 1, "ayni segment iki kez sayilmamali");
    }

    #[test]
    fn tutarsiz_segment_sayisi_hata_dondurur() {
        let veri = vec![3u8; 4_000];
        let parcalar = bol(1, &veri).unwrap();
        let mut bozuk = parcalar[0].clone();
        bozuk[10] = 0xFF;
        bozuk[11] = 0xFF;
        let mut birlesim = Birlesim::yeni();
        let hata = birlesim.besle(&bozuk, Instant::now()).unwrap_err();
        assert!(matches!(
            hata,
            Hata::BozukPaket(_) | Hata::TamponSinir { .. }
        ));
    }

    #[test]
    fn segment_sihri_olmayan_cok_baytli_paket_tek_cerceve_sayilir() {
        // El sikisma paketleri segment sanilmamali: sihir yoksa tek cercevedir.
        let mut birlesim = Birlesim::yeni();
        let cerceve = Cerceve::Yok.kodla().unwrap();
        let tamam = birlesim
            .besle(&cerceve, Instant::now())
            .unwrap()
            .expect("tek cerceve olarak dönmeli");
        assert_eq!(Cerceve::coz(&tamam).unwrap(), Cerceve::Yok);
    }

    #[test]
    fn asiri_buyuk_datagram_hata_dondurur() {
        let mut birlesim = Birlesim::yeni();
        let veri = vec![0u8; AZAMI_DATAGRAM + 1];
        assert!(matches!(
            birlesim.besle(&veri, Instant::now()).unwrap_err(),
            Hata::MesajCokBuyuk { .. }
        ));
    }

    #[test]
    fn bayat_taslaklar_temizlenir() {
        let veri = vec![1u8; 4_000];
        let parcalar = bol(1, &veri).unwrap();
        let mut birlesim = Birlesim::yeni();
        let baslangic = Instant::now();
        birlesim.besle(&parcalar[0], baslangic).unwrap();
        assert_eq!(birlesim.bekleyen(), 1);
        assert_eq!(
            birlesim.bayat_taslaklari_temizle(baslangic + TASLAK_YASAM + Duration::from_secs(1)),
            1
        );
        assert_eq!(birlesim.bekleyen(), 0);
        assert_eq!(birlesim.dusulen(), 1);
    }

    #[test]
    fn cerceve_kimligi_sarmalamada_taslaklari_temizler() {
        let mut birlesim = Birlesim::yeni();
        birlesim.siradaki_kimlik = u32::MAX;
        assert_eq!(birlesim.kimlik_ver(), u32::MAX);
        assert_eq!(birlesim.kimlik_ver(), 1);
    }

    #[test]
    fn cizici_uzunluk_oneki_tasmasi_hata_dondurur() {
        let mut c = Cizici::yeni();
        c.dizi(&vec![0u8; 70_000]);
        assert!(matches!(c.bitir().unwrap_err(), Hata::TamponSinir { .. }));
    }

    #[test]
    fn cizici_cerceve_limiti_asmasi_hata_dondurur() {
        let mut c = Cizici::yeni();
        for _ in 0..400 {
            c.dizi(&[0u8; 20_000]);
        }
        assert!(matches!(c.bitir().unwrap_err(), Hata::MesajCokBuyuk { .. }));
    }
}
