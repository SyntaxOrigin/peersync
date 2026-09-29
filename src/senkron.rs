//! Delta senkronizasyon: parÃ§a listesi karÅŸÄ±laÅŸtÄ±rmasÄ±, planlama ve Ã§akÄ±ÅŸma Ã§Ã¶zÃ¼mÃ¼.
//!
//! Bu modülün sorumluluğu **karar** vermektir: yerel ile uzak durum karşılaştırılır,
//! hangi parçaların eksik olduğu hesaplanır, hangi dosyanın çekileceği veya
//! gönderileceği belirlenir ve çakışmalar kurala bağlanır. Bu modülün sorumluluğu
//! *değil*: baytları taşımak (bkz. `crate::tasma`) ve diske yazmak (bkz. `crate::depo`).
//!
//! # Delta nedir, ne değildir
//!
//! Buradaki delta **parça seviyesindedir**: eşler önce parça listesi özetini
//! değişir, yalnız karşı tarafta bulunmayan parçalar aktarılır. Parça *içi* yama
//! (rsync/BLAKE3 tarzı) üretilmez; `MANIFEST.md` kart 30 "delta sıkıştırma"yı
//! ertelemiştir. Bunun pratik sonucu, 1 bayt eklenen bir dosyada aktarılan bayt
//! sayısının dosya boyutunun çok altında kalmasıdır (bkz. `crate::parca` testleri).
//!
//! # Çakışma kuralı
//!
//! "Son yazan kazanır" iki alanla uygulanır: mantıksal `revizyon` ve `sahip`
//! kimliği. Eşitlik hâlinde bile sonuç **belirlenimcidir** (kimlik baytlarının
//! sıralaması), yani iki eş aynı anda senkronlandığında da her ikisi de aynı
//! kazananı seçer ve kaybeden taraf kendi sürümünü `*.conflict-*` olarak yedekler.
//! Hiçbir koşulda veri sessizce kaybolmaz.
//!
//! # Akış
//!
//! ```text
//! cekme:  ParcaIste(karmalar=[])  -> ParcaListesi      (dosyayı kurmak için sıralama)
//!         ParcaIste(karmalar=[..]) -> ParcaGeldi * n    (yalnız eksik parçalar)
//! gönderme: Teklif(ozet)         -> TeklifYaniti        (karşı taraf kabul ederse)
//!          ParcaGeldi * n         -> DosyaBitti
//! ```

use std::collections::HashMap;
use std::time::Duration;

use crate::depo::{Depo, DosyaKaydi, TamParcaKaydi};
use crate::gunluk::{Durum, Gunluk};
use crate::hata::{Hata, Sonuc};
use crate::karma::{liste_ozeti, KarmaKumesi, KARMA_UZUNLUGU};
use crate::kimlik::Kimlik;
use crate::parca::AZAMI_PARCA;
use crate::protok::{tur, Cerceve, ParcaBilgi, UzakDosya, AZAMI_ISTEK};
use crate::tasma::Tasima;

/// Tek bir istekte gönderilebilecek azami parça sayısı.
pub const ISTEK_YIGINI: usize = 32;

/// Senkronizasyon ayarı.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenkronAyar {
    /// Çerçeve bekleneceği azami süre.
    pub zaman_asimi: Duration,
    /// Bir çerçeve beklenirken kaç kez yeniden deneneceği.
    pub deneme: u32,
    /// Aktarım sonrası yerinde tarama yapılıp yapılmayacağı.
    pub yeniden_tara: bool,
}

impl Default for SenkronAyar {
    fn default() -> Self {
        SenkronAyar {
            zaman_asimi: Duration::from_secs(10),
            deneme: 3,
            yeniden_tara: true,
        }
    }
}

/// Bir dosya için alınacak karar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Karar {
    /// İçerik aynı; hiçbir şey aktarılmayacak.
    Atla,
    /// Karşı taraftan çekilecek, eksik parçalar listesi.
    Cek {
        /// İstenen parça karmaları.
        eksik: Vec<[u8; KARMA_UZUNLUGU]>,
    },
    /// Karşı tarafa gönderilecek parçalar.
    Itme {
        /// Gönderilecek parça karmaları.
        eksik: Vec<[u8; KARMA_UZUNLUGU]>,
    },
    /// Aynı yolda farklı içerik: çakışma kuralı uygulanacak, kazanan taraf çekilir.
    Catisma {
        /// Kazanan tarafın revizyonu.
        kazanan_revizyon: u64,
        /// Kaybeden tarafın revizyonu.
        kaybeden_revizyon: u64,
        /// Kazanan tarafın kimliği.
        kazanan: Kimlik,
        /// Kazanan taraftan alınacak parçalar.
        eksik: Vec<[u8; KARMA_UZUNLUGU]>,
    },
}

impl Karar {
    /// Kararın aktarılacak parça sayısı.
    pub fn parca_sayisi(&self) -> usize {
        match self {
            Karar::Atla => 0,
            Karar::Cek { eksik } | Karar::Itme { eksik } | Karar::Catisma { eksik, .. } => {
                eksik.len()
            }
        }
    }

    /// Kararın çakışma olup olmadığını bildirir.
    pub fn catisma_mi(&self) -> bool {
        matches!(self, Karar::Catisma { .. })
    }
}

/// "Son yazan kazanır" kuralının saf uygulaması.
///
/// Revizyon büyükse kazanır; eşitse kimlik baytlarının sıralaması belirleyicidir.
/// Saf fonksiyondur: iki eş de aynı sonuca vardığının kanıtıdır.
pub fn kazanan(kendi: (u64, Kimlik), karsi: (u64, Kimlik)) -> bool {
    if karsi.0 != kendi.0 {
        return karsi.0 > kendi.0;
    }
    karsi.1 > kendi.1
}

/// Yerel ve uzak durum karşısında bir dosya için karar verir.
///
/// - `yerel` yoksa dosya çekilir.
/// - Karmalar eşitse [`Karar::Atla`] (parça listesi de birebir aynıysa hiçbir
///   bayt taşınmaz; liste özeti farklıysa yine de Atla, çünkü içerik aynıdır).
/// - Karşı taraf kazanıyorsa [`Karar::Catisma`] (kaybeden taraf yedekler).
/// - Yerel kazanıyorsa [`Karar::Itme`] (kendimiz göndeririz).
pub fn karar_ver(
    yerel: Option<&DosyaKaydi>,
    uzak: &UzakDosya,
    hazir: &KarmaKumesi,
    onun_parcalar: &[ParcaBilgi],
) -> Karar {
    let onun_tum: Vec<[u8; KARMA_UZUNLUGU]> = onun_parcalar.iter().map(|p| p.karma).collect();
    match yerel {
        None => Karar::Cek {
            eksik: karmalarimda_yok(&onun_tum, hazir),
        },
        Some(kayit) if kayit.karma == uzak.karma => Karar::Atla,
        Some(kayit) => {
            let eksik = karmalarimda_yok(&onun_tum, hazir);
            let benim = (kayit.revizyon, Kimlik(kayit.sahip));
            let onun = (uzak.revizyon, Kimlik(uzak.sahip));
            // kazanan(benim, onun) = "karsi taraf kazandi" demektir.
            if kazanan(benim, onun) {
                Karar::Catisma {
                    kazanan_revizyon: uzak.revizyon,
                    kaybeden_revizyon: kayit.revizyon,
                    kazanan: Kimlik(uzak.sahip),
                    eksik,
                }
            } else {
                Karar::Itme { eksik }
            }
        }
    }
}

/// `onlar` içinde benim kümemde bulunmayan karmaları, sırayı koruyarak döndürür.
pub fn karmalarimda_yok(
    onlar: &[[u8; KARMA_UZUNLUGU]],
    benim: &KarmaKumesi,
) -> Vec<[u8; KARMA_UZUNLUGU]> {
    onlar
        .iter()
        .filter(|k| !benim.iceriyor(k))
        .copied()
        .collect()
}

/// Karşı taraftan gelen `DosyaBitti` çerçevesini işler: parçaları birleştirir,
/// doğrular ve hedefe koyar.
///
/// # Hatalar
///
/// Parça listesi alınmadıysa veya dosya karması tutmuyorsa hata döner; hedefe
/// yarım dosya yazılmaz (birlestirme geçici dosyada doğrulanır).
fn gelen_dosya_bildir(
    depo: &mut Depo,
    gunluk: &mut Gunluk,
    ozet: &mut SenkronOzeti,
    parcalar: &[ParcaBilgi],
    dosya_karmasi: [u8; KARMA_UZUNLUGU],
    yol: &str,
) -> Sonuc<()> {
    if parcalar.is_empty() {
        return Err(Hata::DepoBozuk(format!(
            "{yol}: parÃ§a listesi alÄ±nmadan dosya tamamlandÄ± bildirildi"
        )));
    }
    let kaydi = DosyaKaydi {
        yol: yol.to_string(),
        boyut: parcalar.iter().map(|p| u64::from(p.uzunluk)).sum(),
        karma: dosya_karmasi,
        parcalar: parcalar
            .iter()
            .map(|p| TamParcaKaydi {
                konum: p.konum,
                uzunluk: p.uzunluk,
                karma: p.karma,
            })
            .collect(),
        revizyon: 1,
        sahip: [0u8; 16],
    };
    let yedek = depo.catisma_yedekle(yol, &kaydi)?;
    if !yedek.is_empty() {
        gunluk.yaz(
            Durum::CatismaCozuldu,
            format!("{yol} -> eski surum {yedek} korundu"),
        )?;
        ozet.catisma += 1;
    }
    depo.dosya_birlestir(&kaydi)?;
    gunluk.yaz(
        Durum::ParcaAktarildi,
        format!("{yol}: karsi taraftan alindi ve kuruldu"),
    )?;
    Ok(())
}

/// Eksik parça karmalarını istek yığınlarına böler.
///
/// Yığın boyutu [`AZAMI_ISTEK`] sınırına kırpılır; sınırsız istek çerçevesi
/// üretmek kaynak tüketimi açısından tehlikelidir.
pub fn yiginla(karmalar: &[[u8; KARMA_UZUNLUGU]], yigin: usize) -> Vec<Vec<[u8; KARMA_UZUNLUGU]>> {
    let adet = yigin.clamp(1, AZAMI_ISTEK);
    karmalar.chunks(adet).map(|dilim| dilim.to_vec()).collect()
}

/// Parça bilgilerinden liste özeti üretir (manifest ile karşılaştırma için).
pub fn parca_listesi_ozeti(parcalar: &[ParcaBilgi]) -> [u8; KARMA_UZUNLUGU] {
    liste_ozeti(
        &parcalar
            .iter()
            .map(|p| (p.konum, p.uzunluk, p.karma))
            .collect::<Vec<_>>(),
    )
}

/// Senkronizasyonun özeti.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SenkronOzeti {
    /// Karşı taraftan çekilen dosya sayısı.
    pub cekilen: usize,
    /// Karşı tarafa gönderilen dosya sayısı.
    pub gonderilen: usize,
    /// Çakışma olarak çözülen dosya sayısı.
    pub catisma: usize,
    /// Aktarılan toplam bayt.
    pub bayt: u64,
    /// Aktarılan toplam parça.
    pub parca: u64,
}

/// Ağ üzerinden iki yönlü senkronizasyonu yürüten oturum.
pub struct Senkron<'a> {
    tasima: &'a mut Tasima,
    depo: &'a mut Depo,
    gunluk: &'a mut Gunluk,
    ayar: SenkronAyar,
    ozet: SenkronOzeti,
}

impl<'a> Senkron<'a> {
    /// Oturum kurar.
    pub fn yeni(
        tasima: &'a mut Tasima,
        depo: &'a mut Depo,
        gunluk: &'a mut Gunluk,
        ayar: SenkronAyar,
    ) -> Senkron<'a> {
        Senkron {
            tasima,
            depo,
            gunluk,
            ayar,
            ozet: SenkronOzeti::default(),
        }
    }

    /// Şu ana kadarki özet.
    pub fn ozet(&self) -> SenkronOzeti {
        self.ozet
    }

    /// Tam senkronizasyonu çalıştırır: manifest alışverişi, çekme, sonra göndermeyi sunma.
    pub fn calistir(&mut self) -> Sonuc<SenkronOzeti> {
        self.gunluk
            .yaz(Durum::AktarimBasladi, "senkronizasyon basladi")?;
        self.ozet = SenkronOzeti::default();

        // Kendi listemizi gonderiyoruz: karsi taraf da ayni anda bize bildirir.
        self.tasima.gonder(&Cerceve::Manifest {
            dosyalar: self.depo.kayitlar().values().map(|k| k.ozet()).collect(),
        })?;
        self.tasima.gonder(&Cerceve::ManifestAl)?;
        let uzak = self.manifest_al()?;
        self.gunluk.yaz(
            Durum::ManifestAlindi,
            format!("{} dosya bildirildi", uzak.len()),
        )?;

        // Once kendi eksiklerimizi gonderiyoruz: karsi taraf sunucu rolu
        // oldugu icin tekliflerimizi yanitlayip parcalarimizi isteyebilir.
        self.gonder_eksikleri(&uzak)?;
        // Sonra karsi taraftan cekiyoruz.
        self.cek(&uzak)?;

        // Bariyer: cekme bitti. Karsi taraf gonderime geçsin.
        self.tasima.gonder(&Cerceve::IstekBitti)?;
        self.gondermeyi_sun()?;
        self.tasima.gonder(&Cerceve::IstekBitti)?;

        if self.ayar.yeniden_tara {
            self.depo.tara()?;
            self.depo.kaydet()?;
        }
        self.gunluk.yaz(
            Durum::AktarimBitti,
            format!(
                "{} cekildi, {} gonderildi, {} catisma, {} bayt",
                self.ozet.cekilen, self.ozet.gonderilen, self.ozet.catisma, self.ozet.bayt
            ),
        )?;
        Ok(self.ozet)
    }

    /// Karsi tarafin tekliflerini yanitlar (karsi bize gonderim yaparken).
    fn gondermeyi_sun(&mut self) -> Sonuc<()> {
        let turler = [tur::TEKLIF, tur::ISTEK_BITTI, tur::CATISMA];
        let bitis = std::time::Instant::now() + self.ayar.zaman_asimi * (self.ayar.deneme + 2);
        while std::time::Instant::now() < bitis {
            let cerceve = match self.tasima.bekle_birisi(&turler, self.ayar.zaman_asimi) {
                Ok(c) => c,
                Err(Hata::ZamanAsimi { .. }) => continue,
                Err(hata) => return Err(hata),
            };
            match cerceve {
                Cerceve::IstekBitti => return Ok(()),
                Cerceve::Catisma { yol, .. } => {
                    // Kazanan taraf bildirdi: yerel surum kaybetti, yedeklenir.
                    self.catisma_yedekle(&yol)?;
                }
                Cerceve::Teklif { dosya } => {
                    let kabul = self.depo.ara(&dosya.yol).is_none();
                    let gerekce = if kabul {
                        String::new()
                    } else {
                        "yolda farkli icerik var; catisma kurali uygulanmali".to_string()
                    };
                    self.tasima.gonder(&Cerceve::TeklifYaniti {
                        kabul,
                        gerekce: gerekce.clone(),
                    })?;
                    if !kabul {
                        self.gunluk.yaz(
                            Durum::CatismaCozuldu,
                            format!("{} teklifi yerinde dosya oldugu icin reddedildi", dosya.yol),
                        )?;
                        continue;
                    }
                    // Kaynak, kabul ettikten sonra parca listesini kendisi
                    // gonderir; istemci istek yapmaz. Bu, tek yonlu akista
                    // gereksiz bir gidis-donus turunu ortadan kaldirir.
                    let parcalar = self.bekle(tur::PARCA_LISTESI).and_then(|c| match c {
                        Cerceve::ParcaListesi { parcalar, .. } => Ok(parcalar),
                        _ => Err(Hata::BozukPaket(
                            "parÃ§a listesi beklenirken baÅŸka Ã§erÃ§eve geldi".to_string(),
                        )),
                    })?;
                    if parca_listesi_ozeti(&parcalar) != dosya.liste_ozeti {
                        return Err(Hata::DepoBozuk(format!(
                            "{}: teklif edilen parÃ§a listesi Ã¶zeti manifest ile uyuÅŸmuyor",
                            dosya.yol
                        )));
                    }
                    let toplam = parcalar.len();
                    for _ in 0..toplam {
                        match self.bekle(tur::PARCA_GELDI)? {
                            Cerceve::ParcaGeldi {
                                parca_karmasi,
                                veri,
                                ..
                            } => {
                                if veri.len() > AZAMI_PARCA as usize {
                                    return Err(Hata::ParcaBoyutuGecersiz {
                                        bildirilen: veri.len() as u32,
                                        azami: AZAMI_PARCA,
                                    });
                                }
                                self.depo.parca_koy(&parca_karmasi, &veri)?;
                                self.ozet.bayt += veri.len() as u64;
                                self.ozet.parca += 1;
                            }
                            _ => continue,
                        }
                    }
                    self.depo.dosya_birlestir(&DosyaKaydi {
                        yol: dosya.yol.clone(),
                        boyut: dosya.boyut,
                        karma: dosya.karma,
                        parcalar: parcalar
                            .iter()
                            .map(|p| TamParcaKaydi {
                                konum: p.konum,
                                uzunluk: p.uzunluk,
                                karma: p.karma,
                            })
                            .collect(),
                        revizyon: dosya.revizyon,
                        sahip: dosya.sahip,
                    })?;
                    self.depo.kaydet()?;
                    self.ozet.gonderilen += 1;
                }
                _ => continue,
            }
        }
        Ok(())
    }

    /// Yerel kaybetti: sürümü yedekler ve günlüğe yazar.
    ///
    /// Kaybeden tarafın hiçbir koşulda verisi kaybolmaz; eski sürüm
    /// `<ad>.conflict-<sahip>-<revizyon>.conflict` adıyla saklanır.
    fn catisma_yedekle(&mut self, yol: &str) -> Sonuc<()> {
        let Some(kayit) = self.depo.ara(yol).cloned() else {
            self.gunluk.yaz(
                Durum::CatismaCozuldu,
                format!("{yol}: bildirilen dosya yerinde yok, yedeklenecek surum bulunamadi"),
            )?;
            return Ok(());
        };
        let yedek = self.depo.catisma_yedekle(yol, &kayit)?;
        if !yedek.is_empty() {
            self.gunluk.yaz(
                Durum::CatismaCozuldu,
                format!("{yol} -> eski surum {yedek} korundu"),
            )?;
            self.ozet.catisma += 1;
        }
        Ok(())
    }

    /// Karşı taraftan gelen dosya listesini bekler.
    ///
    /// Liste talebi `calistir` tarafından gönderilmiştir; burada yalnızca yanıt
    /// beklenir. Zaman aşımında [`Hata::ZamanAsimi`] döner.
    fn manifest_al(&mut self) -> Sonuc<Vec<UzakDosya>> {
        self.bekle(tur::MANIFEST).and_then(|c| match c {
            Cerceve::Manifest { dosyalar } => Ok(dosyalar),
            _ => Err(Hata::BozukPaket(
                "manifest beklenirken başka çerçeve geldi".to_string(),
            )),
        })
    }

    /// İstenen türdeki çerçeveyi, yeniden deneme payıyla bekler.
    fn bekle(&mut self, istenen: u8) -> Sonuc<Cerceve> {
        for _ in 0..=self.ayar.deneme {
            match self.tasima.bekle(istenen, self.ayar.zaman_asimi) {
                Ok(cerceve) => return Ok(cerceve),
                Err(Hata::ZamanAsimi { .. }) => continue,
                Err(hata) => return Err(hata),
            }
        }
        Err(Hata::ZamanAsimi {
            beklenti: "cerceve",
        })
    }

    /// KarÅŸÄ± tarafta bulunmayan yerel dosyalarÄ± **gÃ¶nderir**.
    ///
    /// Akış: `Teklif` -> `TeklifYaniti` -> `ParcaListesi` -> `ParcaGeldi` * n ->
    /// `DosyaBitti`. İstemci tarafı bu turda sunucu rolünde olduğu için talep
    /// değil **veri** gönderilir; karşı taraf sunucu döngüsünde bunu karşılar.
    fn gonder_eksikleri(&mut self, uzak: &[UzakDosya]) -> Sonuc<()> {
        let karsi_yollar: std::collections::HashMap<&str, &UzakDosya> =
            uzak.iter().map(|d| (d.yol.as_str(), d)).collect();
        let yerel_yollar: Vec<String> = self.depo.kayitlar().keys().cloned().collect();
        for yol in yerel_yollar {
            if karsi_yollar.contains_key(yol.as_str()) {
                continue;
            }
            let kayit = match self.depo.ara(&yol) {
                Some(k) => k.clone(),
                None => continue,
            };
            let ozet = kayit.ozet();
            self.tasima.gonder(&Cerceve::Teklif {
                dosya: ozet.clone(),
            })?;
            let kabul = self.bekle(tur::TEKLIF_YANITI).and_then(|c| match c {
                Cerceve::TeklifYaniti { kabul, gerekce } => {
                    if !kabul {
                        self.gunluk
                            .yaz(Durum::Hata, format!("{yol} teklifi reddedildi: {gerekce}"))?;
                    }
                    Ok(kabul)
                }
                _ => Err(Hata::BozukPaket(
                    "teklif yanıtı beklenirken başka çerçeve geldi".to_string(),
                )),
            })?;
            if !kabul {
                continue;
            }
            let parcalar: Vec<crate::protok::ParcaBilgi> = kayit
                .parcalar
                .iter()
                .map(|p| crate::protok::ParcaBilgi {
                    konum: p.konum,
                    uzunluk: p.uzunluk,
                    karma: p.karma,
                })
                .collect();
            if parcalar.is_empty() {
                continue;
            }
            self.tasima.gonder(&Cerceve::ParcaListesi {
                dosya_karmasi: ozet.karma,
                parcalar: parcalar.clone(),
            })?;
            let mut bayt: u64 = 0;
            for yigin in yiginla(
                &parcalar.iter().map(|p| p.karma).collect::<Vec<_>>(),
                ISTEK_YIGINI,
            ) {
                for karma in yigin {
                    let veri = self.depo.parca_al(&karma)?;
                    self.tasima.gonder(&Cerceve::ParcaGeldi {
                        dosya_karmasi: ozet.karma,
                        parca_karmasi: karma,
                        veri: veri.clone(),
                    })?;
                    bayt += veri.len() as u64;
                    self.ozet.parca += 1;
                }
            }
            self.tasima.gonder(&Cerceve::DosyaBitti {
                dosya_karmasi: ozet.karma,
                yol: yol.clone(),
            })?;
            self.ozet.bayt += bayt;
            self.ozet.gonderilen += 1;
            self.gunluk.yaz(
                Durum::ParcaAktarildi,
                format!("{yol}: {} parca, {bayt} bayt gonderildi", parcalar.len()),
            )?;
        }
        Ok(())
    }

    /// Eksik parÃ§alarÄ± Ã§eker.
    fn cek(&mut self, uzak: &[UzakDosya]) -> Sonuc<()> {
        for dosya in uzak {
            let yerel = self.depo.ara(&dosya.yol).cloned();
            if yerel.as_ref().is_some_and(|k| k.karma == dosya.karma) {
                continue;
            }
            let parcalar = self.uzak_parca_listesi(dosya)?;
            let hazir = self.hazir_kume(&parcalar, yerel.as_ref());
            let karar = karar_ver(yerel.as_ref(), dosya, &hazir, &parcalar);
            let catisma = karar.catisma_mi();
            let eksik = match karar {
                Karar::Atla => continue,
                Karar::Itme { .. } => {
                    self.ozet.catisma += 1;
                    self.tasima.gonder(&Cerceve::Catisma {
                        yol: dosya.yol.clone(),
                        yedek: String::new(),
                    })?;
                    self.gunluk.yaz(
                        Durum::CatismaCozuldu,
                        format!(
                            "{}: yerel surum kazandi, karsi taraf bilgilendirildi",
                            dosya.yol
                        ),
                    )?;
                    continue;
                }
                Karar::Cek { eksik } | Karar::Catisma { eksik, .. } => eksik,
            };
            if eksik.is_empty() {
                continue;
            }
            self.dosya_cek(dosya, &parcalar, &eksik)?;
            self.ozet.cekilen += 1;
            if catisma {
                self.ozet.catisma += 1;
            }
        }
        Ok(())
    }

    /// Karşı taraftan bir dosyanın parça listesini ister ve doğrular.
    fn uzak_parca_listesi(&mut self, dosya: &UzakDosya) -> Sonuc<Vec<ParcaBilgi>> {
        self.tasima.gonder(&Cerceve::ParcaIste {
            dosya_karmasi: dosya.karma,
            karmalar: Vec::new(),
        })?;
        let parcalar = self.bekle(tur::PARCA_LISTESI).and_then(|c| match c {
            Cerceve::ParcaListesi { parcalar, .. } => Ok(parcalar),
            _ => Err(Hata::BozukPaket(
                "parça listesi beklenirken başka çerçeve geldi".to_string(),
            )),
        })?;
        if parcalar.is_empty() {
            return Err(Hata::DepoBozuk(format!(
                "{}: karşı taraf boş parça listesi bildirdi",
                dosya.yol
            )));
        }
        if parca_listesi_ozeti(&parcalar) != dosya.liste_ozeti {
            return Err(Hata::DepoBozuk(format!(
                "{}: parça listesi özeti manifest ile uyuşmuyor",
                dosya.yol
            )));
        }
        let toplam: u64 = parcalar.iter().map(|p| u64::from(p.uzunluk)).sum();
        if toplam != dosya.boyut {
            return Err(Hata::DepoBozuk(format!(
                "{}: parça boyutları toplamı {} beklenen {}",
                dosya.yol, toplam, dosya.boyut
            )));
        }
        Ok(parcalar)
    }

    /// Tek bir dosyanın eksik parçalarını ister ve dosyayı kurar.
    fn dosya_cek(
        &mut self,
        dosya: &UzakDosya,
        parcalar: &[ParcaBilgi],
        eksik: &[[u8; KARMA_UZUNLUGU]],
    ) -> Sonuc<()> {
        let mut alinan: u64 = 0;
        let mut bayt: u64 = 0;
        for yigin in yiginla(eksik, ISTEK_YIGINI) {
            let beklenen = yigin.len();
            self.tasima.gonder(&Cerceve::ParcaIste {
                dosya_karmasi: dosya.karma,
                karmalar: yigin,
            })?;
            // Her yığın için tam olarak o kadar parça beklenir: eksik parça
            // sonucu sessizce atlanırsa dosya kurulamaz ve hata "NotFound" olarak
            // belirir; bu yüzden sayım burada yapılır.
            for _ in 0..beklenen {
                let mut alindi = false;
                for _ in 0..=self.ayar.deneme {
                    match self.bekle(tur::PARCA_GELDI)? {
                        Cerceve::ParcaGeldi {
                            parca_karmasi,
                            veri,
                            ..
                        } => {
                            if veri.len() > AZAMI_PARCA as usize {
                                return Err(Hata::ParcaBoyutuGecersiz {
                                    bildirilen: veri.len() as u32,
                                    azami: AZAMI_PARCA,
                                });
                            }
                            self.depo.parca_koy(&parca_karmasi, &veri)?;
                            bayt += veri.len() as u64;
                            alinan += 1;
                            alindi = true;
                            break;
                        }
                        _ => continue,
                    }
                }
                if !alindi {
                    return Err(Hata::ZamanAsimi {
                        beklenti: "parca geldi",
                    });
                }
            }
        }
        self.ozet.bayt += bayt;
        self.ozet.parca += alinan;
        self.gunluk.yaz(
            Durum::ParcaAktarildi,
            format!("{}: {alinan} parca, {bayt} bayt", dosya.yol),
        )?;

        // Kur, doğrula, çakışmada yedekle ve yerine koy.
        let kaydi = DosyaKaydi {
            yol: dosya.yol.clone(),
            boyut: dosya.boyut,
            karma: dosya.karma,
            parcalar: parcalar
                .iter()
                .map(|p| TamParcaKaydi {
                    konum: p.konum,
                    uzunluk: p.uzunluk,
                    karma: p.karma,
                })
                .collect(),
            revizyon: dosya.revizyon,
            sahip: dosya.sahip,
        };
        let yedek = self.depo.catisma_yedekle(&dosya.yol, &kaydi)?;
        if !yedek.is_empty() {
            self.gunluk.yaz(
                Durum::CatismaCozuldu,
                format!("{} -> eski surum {yedek} korundu", dosya.yol),
            )?;
            self.tasima.gonder(&Cerceve::Catisma {
                yol: dosya.yol.clone(),
                yedek: yedek.clone(),
            })?;
        }
        self.depo.dosya_birlestir(&kaydi)?;
        self.depo.kaydet()?;
        Ok(())
    }

    /// "Bende hangi parçalar var" kümesi: dosyanın parçalarından depoda bulunanlar.
    fn hazir_kume(&self, parcalar: &[ParcaBilgi], yerel: Option<&DosyaKaydi>) -> KarmaKumesi {
        let mut karmalar: Vec<[u8; KARMA_UZUNLUGU]> = parcalar
            .iter()
            .filter(|p| self.depo.parca_var(&p.karma))
            .map(|p| p.karma)
            .collect();
        if let Some(kayit) = yerel {
            for p in &kayit.parcalar {
                if self.depo.parca_var(&p.karma) {
                    karmalar.push(p.karma);
                }
            }
        }
        KarmaKumesi::listeden(&karmalar)
    }
}

fn parca_bilgi_kayit(p: &TamParcaKaydi) -> ParcaBilgi {
    ParcaBilgi {
        konum: p.konum,
        uzunluk: p.uzunluk,
        karma: p.karma,
    }
}

/// Karşı taraftan gelen parça isteğine verilecek standart yanıt (sunucu rolü).
///
/// Bu saf yardımcı, gönderim sırasında hangi parçaların isteneceğini belirler ve
/// testlerde doğrudan doğrulanır.
pub fn gonderilecek_parcalar(
    istenen: &[[u8; KARMA_UZUNLUGU]],
    eldeki: &[ParcaBilgi],
) -> Vec<[u8; KARMA_UZUNLUGU]> {
    let mut sonuc = Vec::new();
    for karma in istenen {
        if eldeki.iter().any(|p| p.karma == *karma) {
            sonuc.push(*karma);
        }
    }
    sonuc
}

/// Sunucu rolünde dinlenilen çerçeve türleri.
pub const SUNUCU_TURLERI: &[u8] = &[
    tur::MANIFEST_AL,
    tur::MANIFEST,
    tur::PARCA_ISTE,
    tur::ISTEK_BITTI,
    tur::TEKLIF,
    tur::TEKLIF_YANITI,
    tur::CATISMA,
    tur::PARCA_LISTESI,
    tur::PARCA_GELDI,
    tur::DOSYA_BITTI,
];

/// **Sunucu rolü**: karşı tarafın taleplerini yanıtlar, sonra kendi eksiklerini gönderir.
///
/// Akış iki fazlıdır ve fazlar arasında sert bir bariyer vardır:
///
/// 1. **Çekme fazı** — gelen `ManifestAl` için kendi manifestini yollar, gelen
///    `ParcaIste` taleplerini yanıtlar, `IstekBitti` gelene kadar bekler.
/// 2. **Gönderme fazı** — bariyerden sonra karşı tarafta bulunmayan dosyaları
///    teklif eder, kabul gelirse parçaları yollar.
///
/// Sert bariyer olmasa iki taraf aynı anda hem çeker hem gönderir ve tek
/// istek/yanıt akışı birbirine karışırdı.
pub fn sunucu_tur(
    tasima: &mut Tasima,
    depo: &mut Depo,
    gunluk: &mut Gunluk,
    ayar: SenkronAyar,
    karsi_manifesti: &mut Vec<UzakDosya>,
    karsi_dosyalari: &mut Vec<ParcaBilgi>,
    ozet: &mut SenkronOzeti,
) -> Sonuc<()> {
    gunluk.yaz(Durum::AktarimBasladi, "sunucu rolu basladi")?;
    // Faz 1: cekme taleplerini yanitla.
    let bitis = std::time::Instant::now() + ayar.zaman_asimi * (ayar.deneme + 1);
    loop {
        if std::time::Instant::now() >= bitis {
            gunluk.yaz(
                Durum::AktarimBitti,
                "sunucu: cekme fazi zaman asimina ugradi",
            )?;
            return Ok(());
        }
        let cerceve = match tasima.bekle_birisi(SUNUCU_TURLERI, ayar.zaman_asimi) {
            Ok(c) => c,
            Err(Hata::ZamanAsimi { .. }) => continue,
            Err(hata) => return Err(hata),
        };
        match cerceve {
            Cerceve::ManifestAl => {
                tasima.gonder(&Cerceve::Manifest {
                    dosyalar: depo.kayitlar().values().map(|k| k.ozet()).collect(),
                })?;
            }
            Cerceve::Manifest { dosyalar } => {
                *karsi_manifesti = dosyalar;
            }
            Cerceve::ParcaIste {
                dosya_karmasi,
                karmalar,
            } => parca_iste_yanitla(
                tasima,
                depo,
                gunluk,
                dosya_karmasi,
                &karmalar,
                karsi_dosyalari,
                ozet,
            )?,
            Cerceve::IstekBitti => {
                // Bariyer: cekme istekleri bitti, simdi kendi gonderimimizi yapabiliriz.
                // Ayrica onay gondermeyiz; isimci taraf yalnizca sonunda IstekBitti
                // bekler, arada ek bir isaret iki tarafin birbirini beklemesine yol acar.
                break;
            }
            Cerceve::Catisma { yol, .. } => {
                if let Some(kayit) = depo.ara(&yol).cloned() {
                    let yedek = depo.catisma_yedekle(&yol, &kayit)?;
                    if !yedek.is_empty() {
                        gunluk.yaz(
                            Durum::CatismaCozuldu,
                            format!("{yol} -> eski surum {yedek} korundu"),
                        )?;
                        ozet.catisma += 1;
                    }
                }
            }

            // Karsi taraf sunucu rolundeyken bize gonderim yapabilir: parca
            // listesini ve parcalarini topla, dosya bildiriminde kur.
            Cerceve::ParcaListesi { parcalar, .. } => {
                *karsi_dosyalari = parcalar;
            }
            Cerceve::ParcaGeldi {
                parca_karmasi,
                veri,
                ..
            } => {
                if veri.len() > AZAMI_PARCA as usize {
                    return Err(Hata::ParcaBoyutuGecersiz {
                        bildirilen: veri.len() as u32,
                        azami: AZAMI_PARCA,
                    });
                }
                depo.parca_koy(&parca_karmasi, &veri)?;
                ozet.bayt += veri.len() as u64;
                ozet.parca += 1;
            }
            Cerceve::DosyaBitti { dosya_karmasi, yol } => {
                gelen_dosya_bildir(depo, gunluk, ozet, karsi_dosyalari, dosya_karmasi, &yol)?;
            }
            // Karsi taraf sunucu rolundeyken bize gonderim yapmak isteyebilir:
            // teklifini yanitla, ardindan normal ParcaIste akisi devam eder.
            Cerceve::Teklif { dosya } => {
                let kabul = depo.ara(&dosya.yol).is_none();
                let gerekce = if kabul {
                    String::new()
                } else {
                    "yolda farkli icerik var".to_string()
                };
                tasima.gonder(&Cerceve::TeklifYaniti {
                    kabul,
                    gerekce: gerekce.clone(),
                })?;
                if !kabul {
                    ozet.catisma += 1;
                    gunluk.yaz(
                        Durum::CatismaCozuldu,
                        format!("{} teklifi yerinde dosya oldugu icin reddedildi", dosya.yol),
                    )?;
                }
            }
            _ => {}
        }
    }
    // Faz 2: karsi tarafta olmayanlari gonder.
    let karsi_yollar: HashMap<&str, &UzakDosya> = karsi_manifesti
        .iter()
        .map(|d| (d.yol.as_str(), d))
        .collect();
    let yerel_yollar: Vec<String> = depo.kayitlar().keys().cloned().collect();
    for yol in yerel_yollar {
        if karsi_yollar.contains_key(yol.as_str()) {
            continue;
        }
        let kayit = match depo.ara(&yol) {
            Some(k) => k.clone(),
            None => continue,
        };
        tasima.gonder(&Cerceve::Teklif {
            dosya: kayit.ozet(),
        })?;
        let kabul = match tasima.bekle(tur::TEKLIF_YANITI, ayar.zaman_asimi) {
            Ok(Cerceve::TeklifYaniti { kabul, .. }) => kabul,
            _ => false,
        };
        if !kabul {
            continue;
        }
        let parcalar = parcalar_bilgileri(depo, &yol)?;
        // Once parca listesini gonder: alici dosyayi bu siralamayla kurar.
        tasima.gonder(&Cerceve::ParcaListesi {
            dosya_karmasi: kayit.karma,
            parcalar: parcalar.clone(),
        })?;
        let eksik: Vec<[u8; KARMA_UZUNLUGU]> = parcalar
            .iter()
            .map(|p| p.karma)
            .filter(|k| !depo.parca_var(k))
            .collect();
        for karma in &eksik {
            let veri = depo.parca_al(karma)?;
            tasima.gonder(&Cerceve::ParcaGeldi {
                dosya_karmasi: kayit.karma,
                parca_karmasi: *karma,
                veri,
            })?;
        }
        tasima.gonder(&Cerceve::DosyaBitti {
            dosya_karmasi: kayit.karma,
            yol: yol.clone(),
        })?;
        ozet.gonderilen += 1;
        ozet.bayt += kayit.boyut;
        ozet.parca += parcalar.len() as u64;
    }
    // Geri besleme: isimcimiz de kendi eksiklerini cekmis olsun diye bariyeri onayla.
    tasima.gonder(&Cerceve::IstekBitti)?;
    gunluk.yaz(
        Durum::AktarimBitti,
        format!("sunucu: {} gonderildi, {} bayt", ozet.gonderilen, ozet.bayt),
    )?;
    Ok(())
}

/// Gelen parça talebini yanıtlar: boş talep ise parça listesi, dolu talep ise veri.
fn parca_iste_yanitla(
    tasima: &mut Tasima,
    depo: &Depo,
    gunluk: &mut Gunluk,
    dosya_karmasi: [u8; KARMA_UZUNLUGU],
    karmalar: &[[u8; KARMA_UZUNLUGU]],
    karsi_dosyalari: &mut Vec<ParcaBilgi>,
    ozet: &mut SenkronOzeti,
) -> Sonuc<()> {
    let kayit = depo
        .kayitlar()
        .values()
        .find(|k| k.karma == dosya_karmasi)
        .cloned();
    let Some(kayit) = kayit else {
        // Bilinmeyen dosya: sessizce yoksay, oturumu bozma.
        return Ok(());
    };
    let parcalar: Vec<ParcaBilgi> = kayit.parcalar.iter().map(parca_bilgi_kayit).collect();
    if karmalar.is_empty() {
        tasima.gonder(&Cerceve::ParcaListesi {
            dosya_karmasi,
            parcalar: parcalar.clone(),
        })?;
        *karsi_dosyalari = parcalar;
        return Ok(());
    }
    let gonderilecek = gonderilecek_parcalar(karmalar, &parcalar);
    for karma in gonderilecek {
        let veri = depo.parca_al(&karma)?;
        let uzunluk = veri.len() as u64;
        gunluk.yaz(
            Durum::ParcaAktarildi,
            format!("{}: {} bayt gonderildi", kayit.yol, veri.len()),
        )?;
        tasima.gonder(&Cerceve::ParcaGeldi {
            dosya_karmasi,
            parca_karmasi: karma,
            veri,
        })?;
        ozet.bayt += uzunluk;
        ozet.parca += 1;
    }
    Ok(())
}

/// Depo kaydından parça bilgilerini üretir.
fn parcalar_bilgileri(depo: &Depo, yol: &str) -> Sonuc<Vec<ParcaBilgi>> {
    match depo.ara(yol) {
        Some(kayit) => Ok(kayit.parcalar.iter().map(parca_bilgi_kayit).collect()),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protok::UzakDosya;

    fn kayit(revizyon: u64, sahip: u8, parcalar: &[[u8; KARMA_UZUNLUGU]]) -> DosyaKaydi {
        DosyaKaydi {
            yol: "a.txt".to_string(),
            boyut: 100,
            karma: [1u8; 32],
            parcalar: parcalar
                .iter()
                .enumerate()
                .map(|(i, k)| TamParcaKaydi {
                    konum: (i * 10) as u64,
                    uzunluk: 10,
                    karma: *k,
                })
                .collect(),
            revizyon,
            sahip: [sahip; 16],
        }
    }

    fn uzak(revizyon: u64, sahip: u8, karma: u8, parcalar: &[[u8; KARMA_UZUNLUGU]]) -> UzakDosya {
        UzakDosya {
            yol: "a.txt".to_string(),
            boyut: 100,
            karma: [karma; 32],
            parca_sayisi: parcalar.len() as u32,
            liste_ozeti: [9u8; 32],
            revizyon,
            sahip: [sahip; 16],
        }
    }

    fn bilgi(karmalar: &[[u8; KARMA_UZUNLUGU]]) -> Vec<ParcaBilgi> {
        karmalar
            .iter()
            .enumerate()
            .map(|(i, k)| ParcaBilgi {
                konum: (i * 10) as u64,
                uzunluk: 10,
                karma: *k,
            })
            .collect()
    }

    #[test]
    fn kazanan_kurali_yuksek_revizyonu_secer() {
        assert!(kazanan((1, Kimlik([1; 16])), (2, Kimlik([0; 16]))));
        assert!(!kazanan((3, Kimlik([0; 16])), (2, Kimlik([9; 16]))));
    }

    #[test]
    fn kazanan_kurali_esit_revizyonda_kimlige_bakar() {
        assert!(kazanan((1, Kimlik([1; 16])), (1, Kimlik([2; 16]))));
        assert!(!kazanan((1, Kimlik([2; 16])), (1, Kimlik([1; 16]))));
    }

    #[test]
    fn kazanan_kurali_her_yonlu_tutarlidir() {
        let a = (5u64, Kimlik([7; 16]));
        let b = (5u64, Kimlik([8; 16]));
        assert!(kazanan(a, b));
        assert!(!kazanan(b, a));
    }

    #[test]
    fn ayni_karmali_dosya_atlanir() {
        let parcalar = [[1u8; 32]];
        let yerel = kayit(1, 1, &parcalar);
        let uzak_dosya = uzak(1, 2, 1, &parcalar);
        let kume = KarmaKumesi::listeden(&parcalar);
        let karar = karar_ver(Some(&yerel), &uzak_dosya, &kume, &bilgi(&parcalar));
        assert_eq!(karar, Karar::Atla);
        assert_eq!(karar.parca_sayisi(), 0);
    }

    #[test]
    fn yerelde_olmayan_dosya_cekilir() {
        let parcalar: Vec<[u8; 32]> = vec![[1u8; 32], [2u8; 32]];
        let uzak_dosya = uzak(1, 2, 5, &parcalar);
        let karar = karar_ver(None, &uzak_dosya, &KarmaKumesi::bos(), &bilgi(&parcalar));
        assert_eq!(
            karar,
            Karar::Cek {
                eksik: parcalar.clone()
            }
        );
        assert_eq!(karar.parca_sayisi(), 2);
    }

    #[test]
    fn kismi_eksik_parcalar_cekilir() {
        let parcalar = [[1u8; 32], [2u8; 32], [3u8; 32]];
        let uzak_dosya = uzak(1, 2, 5, &parcalar);
        let kume = KarmaKumesi::listeden(&[[2u8; 32]]);
        let karar = karar_ver(None, &uzak_dosya, &kume, &bilgi(&parcalar));
        match karar {
            Karar::Cek { eksik } => assert_eq!(eksik, vec![[1u8; 32], [3u8; 32]]),
            diger => panic!("beklenmeyen karar: {diger:?}"),
        }
    }

    #[test]
    fn catismada_uzak_kazanirsa_catisma_karari_uretilir() {
        let parcalar = [[1u8; 32], [2u8; 32]];
        let yerel = kayit(1, 1, &parcalar);
        let uzak_dosya = uzak(5, 2, 5, &parcalar);
        let kume = KarmaKumesi::listeden(&[[1u8; 32]]);
        let karar = karar_ver(Some(&yerel), &uzak_dosya, &kume, &bilgi(&parcalar));
        match &karar {
            Karar::Catisma {
                kazanan_revizyon,
                kaybeden_revizyon,
                kazanan: kazanan_kimlik,
                eksik,
            } => {
                assert_eq!(*kazanan_revizyon, 5);
                assert_eq!(*kaybeden_revizyon, 1);
                assert_eq!(*kazanan_kimlik, Kimlik([2; 16]));
                assert_eq!(eksik, &vec![[2u8; 32]]);
            }
            diger => panic!("beklenmeyen karar: {diger:?}"),
        }
        assert!(karar.catisma_mi());
    }

    #[test]
    fn catismada_yerel_kazanirsa_gonderme_karari_uretilir() {
        let parcalar = [[1u8; 32]];
        let yerel = kayit(9, 1, &parcalar);
        let uzak_dosya = uzak(2, 2, 5, &parcalar);
        let kume = KarmaKumesi::listeden(&parcalar);
        let karar = karar_ver(Some(&yerel), &uzak_dosya, &kume, &bilgi(&parcalar));
        assert!(matches!(karar, Karar::Itme { .. }));
        assert!(!karar.catisma_mi());
    }

    #[test]
    fn karmalarimda_yok_sirayi_korur_ve_tekrar_eklemez() {
        let onlar = [[3u8; 32], [1u8; 32], [2u8; 32], [1u8; 32]];
        let kume = KarmaKumesi::listeden(&[[1u8; 32]]);
        assert_eq!(karmalarimda_yok(&onlar, &kume), vec![[3u8; 32], [2u8; 32]]);
    }

    #[test]
    fn yiginlama_azami_istek_limitine_uyar() {
        let karmalar: Vec<[u8; 32]> = (0..100u8).map(|i| [i; 32]).collect();
        let yiginlar = yiginla(&karmalar, 32);
        assert_eq!(yiginlar.len(), 4);
        assert_eq!(yiginlar[0].len(), 32);
        assert_eq!(yiginlar[3].len(), 4);
        let devasa: Vec<[u8; 32]> = (0..2000u16).map(|i| [i as u8; 32]).collect();
        for yigin in yiginla(&devasa, 10_000usize) {
            assert!(yigin.len() <= AZAMI_ISTEK);
        }
    }

    #[test]
    fn yiginlama_bos_liste_ve_sifir_yigin_boyutu() {
        assert!(yiginla(&[], 32).is_empty());
        assert_eq!(yiginla(&[[1u8; 32]], 0).len(), 1);
    }

    #[test]
    fn parca_listesi_ozeti_siralamaya_duyarlidir() {
        let a = bilgi(&[[1u8; 32], [2u8; 32]]);
        let b = bilgi(&[[2u8; 32], [1u8; 32]]);
        assert_ne!(parca_listesi_ozeti(&a), parca_listesi_ozeti(&b));
        assert_eq!(parca_listesi_ozeti(&a), parca_listesi_ozeti(&a));
    }

    #[test]
    fn gonderilecek_parcalar_yalniz_eldeki_ve_istenen_kesisimi_verir() {
        let eldeki = bilgi(&[[1u8; 32], [2u8; 32]]);
        assert_eq!(
            gonderilecek_parcalar(&[[1u8; 32], [3u8; 32]], &eldeki),
            vec![[1u8; 32]]
        );
        assert!(gonderilecek_parcalar(&[[9u8; 32]], &eldeki).is_empty());
    }
}
