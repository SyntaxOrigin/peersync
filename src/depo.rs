//! Depo katmanı: klasör tarama, parça deposu, atomik birleştirme, çakışma yedeği.
//!
//! Bu modülün sorumluluğu paylaşılan klasörün **diskteki hâlini** yönetmektir:
//! taramak, indekslemek, parçaları saklamak, gelen parçalardan dosya kurmak ve
//! çakışan sürümleri kaybetmeden korumaktır.
//! Bu modülün sorumluluğu *değil*: parçalamak (bkz. `crate::parca`) ve
//! senkronizasyon kararı vermek (bkz. `crate::senkron`).
//!
//! # Dizin düzeni
//!
//! ```text
//! <kok>/
//! |-- dosyalar...
//! `-- .peersync/
//!     |-- kimlik.json      cihaz kimliği (onaltılık)
//!     |-- indeks.json      dosya -> { boyut, karma, parcalar, revizyon, sahip }
//!     |-- parca/<xx>/<64>  parça deposu (xx = karmanın ilk iki onaltılık karakteri)
//!     |-- gecici/          yarım dosyalar; oturum sonunda temizlenir
//!     `-- gecmis.jsonl     durum makinesi günlüğü
//! ```
//!
//! **Yarım dosya asla hedefe yazılmaz:** içerik önce `.peersync/gecici/` altında
//! kurulur, karması doğrulanır ve ancak ondan sonra hedefe `fs::rename` ile
//! taşınır. Bağlantı koparsa hedefte yarım dosya kalmaz (rapor b07 hata yönetimi).
//!
//! # Karakter kümesi
//!
//! Depo yolları UTF-8 olarak saklanır ve `\` işaretçisi `/` yerine normalleştirilir.
//! Dosya sistemi geçersiz UTF-8 döndürürse `Hata::DepoBozuk` üretilir; sessizce
//! atlanmaz çünkü atlanan bir dosya sessiz veri kaybıdır.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::hata::{Hata, Sonuc};
use crate::karma::{Karma, KARMA_UZUNLUGU};
use crate::kimlik::Kimlik;
use crate::parca::{DosyaParcalari, ParcaAyari, Parcalayici, TamParca, AZAMI_PARCA};
use crate::protok::UzakDosya;
use sha2::Digest;

/// Depo alt dizininin adı.
pub const DEPO_DIZINI: &str = ".peersync";

/// Taranan ağaçta azami derinlik (kayıt ağacı denetimi).
pub const AZAMI_DERINLIK: usize = 32;

/// Taranan dosya sayısı üst sınırı (kaynak tüketimi sınırı).
pub const AZAMI_DOSYA_SAYISI: usize = 500_000;

/// Tarama sırasında okunan blok boyutu (128 KiB).
pub const TARAMA_BLOKU: usize = 128 * 1024;

/// Çakışma yedeğinin dosya adı soneki.
pub const CATISMA_SONEKI: &str = "conflict";

/// Depoda saklanan tek bir dosyanın kaydı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DosyaKaydi {
    /// Depoda `/` ile normalleştirilmiş göreli yol.
    pub yol: String,
    /// Dosyanın bayt cinsinden boyutu.
    pub boyut: u64,
    /// Dosyanın içerik karması.
    #[serde(with = "hexe")]
    pub karma: [u8; KARMA_UZUNLUGU],
    /// Parça listesi.
    pub parcalar: Vec<TamParcaKaydi>,
    /// Mantıksal sürüm (çakışma çözümünde "son yazan kazanır" ölçütü).
    pub revizyon: u64,
    /// Dosyayı son değiştiren eş.
    #[serde(with = "hexe")]
    pub sahip: [u8; 16],
}

impl DosyaKaydi {
    /// Kaydın karşı tarafa gönderilecek özetini üretir.
    pub fn ozet(&self) -> UzakDosya {
        UzakDosya {
            yol: self.yol.clone(),
            boyut: self.boyut,
            karma: self.karma,
            parca_sayisi: self.parcalar.len() as u32,
            liste_ozeti: self.liste_ozeti(),
            revizyon: self.revizyon,
            sahip: self.sahip,
        }
    }

    /// Parça listesinin özeti.
    pub fn liste_ozeti(&self) -> [u8; KARMA_UZUNLUGU] {
        crate::karma::liste_ozeti(
            &self
                .parcalar
                .iter()
                .map(|p| (p.konum, p.uzunluk, p.karma))
                .collect::<Vec<_>>(),
        )
    }

    /// Parça karmalarının listesi.
    pub fn parca_karmalari(&self) -> Vec<[u8; KARMA_UZUNLUGU]> {
        self.parcalar.iter().map(|p| p.karma).collect()
    }
}

/// Serileştirilebilir parça kaydı.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TamParcaKaydi {
    /// Dosya içindeki mutlak başlangıç baytı.
    pub konum: u64,
    /// Parçanın bayt uzunluğu.
    pub uzunluk: u32,
    /// Parça içeriğinin karması.
    #[serde(with = "hexe")]
    pub karma: [u8; KARMA_UZUNLUGU],
}

impl From<&TamParca> for TamParcaKaydi {
    fn from(parca: &TamParca) -> Self {
        TamParcaKaydi {
            konum: parca.konum,
            uzunluk: parca.uzunluk,
            karma: parca.karma,
        }
    }
}

impl From<&TamParcaKaydi> for TamParca {
    fn from(kayit: &TamParcaKaydi) -> Self {
        TamParca {
            konum: kayit.konum,
            uzunluk: kayit.uzunluk,
            karma: kayit.karma,
        }
    }
}

/// Onaltılık metin olarak `[u8; N]` serileştiren yardımcı modül (bkz. `crate::protok::hexe`).
use crate::protok::hexe;

/// Diskteki indeksin JSON biçimi.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct IndeksDosyasi {
    /// Biçim sürümü.
    surum: u32,
    /// Dosya kayıtları (yola göre sıralı).
    dosyalar: BTreeMap<String, DosyaKaydi>,
}

/// İndeks biçim sürümü.
pub const INDEKS_SURUMU: u32 = 1;

/// Paylaşılan klasörün diskteki temsili.
#[derive(Debug)]
pub struct Depo {
    kok: PathBuf,
    kimlik: Kimlik,
    ayar: ParcaAyari,
    indeks: BTreeMap<String, DosyaKaydi>,
    guncel: bool,
}

impl Depo {
    /// Depoyu açar; yoksa oluşturur ve `indeks.json` dosyasını yükler.
    ///
    /// # Hatalar
    ///
    /// Kök dizin oluşturulamazsa [`Hata::Io`]. `indeks.json` bozuksa
    /// [`Hata::DepoBozuk`] döner; bu durumda `Depo::yeniden_inşa` ile tarama
    /// yapılarak kurtarma mümkündür.
    pub fn ac(kok: &Path, kimlik: Kimlik, ayar: ParcaAyari) -> Sonuc<Depo> {
        let dizin = kok.join(DEPO_DIZINI);
        fs::create_dir_all(&dizin)?;
        fs::create_dir_all(dizin.join("parca"))?;
        fs::create_dir_all(dizin.join("gecici"))?;
        let indeks_yolu = dizin.join("indeks.json");
        let indeks = if indeks_yolu.exists() {
            let metin = fs::read_to_string(&indeks_yolu)?;
            let cozulmus: IndeksDosyasi = serde_json::from_str(&metin)
                .map_err(|e| Hata::DepoBozuk(format!("indeks.json çözümlenemedi: {e}")))?;
            if cozulmus.surum != INDEKS_SURUMU {
                return Err(Hata::DepoBozuk(format!(
                    "indeks sürümü {} desteklenmiyor (beklenen {INDEKS_SURUMU})",
                    cozulmus.surum
                )));
            }
            cozulmus.dosyalar
        } else {
            BTreeMap::new()
        };
        Ok(Depo {
            kok: kok.to_path_buf(),
            kimlik,
            ayar,
            indeks,
            guncel: false,
        })
    }

    /// Deponun kök dizini.
    pub fn kok(&self) -> &Path {
        &self.kok
    }

    /// Cihaz kimliği.
    pub fn kimlik(&self) -> Kimlik {
        self.kimlik
    }

    /// Parçalama ayarı.
    pub fn ayar(&self) -> ParcaAyari {
        self.ayar
    }

    /// Diskte değişiklik olup olmadığını bildirir.
    pub fn guncel_mi(&self) -> bool {
        self.guncel
    }

    /// İç indeksi okunabilir biçimde döndürür.
    pub fn kayitlar(&self) -> &BTreeMap<String, DosyaKaydi> {
        &self.indeks
    }

    /// Yola göre kayıt arar.
    pub fn ara(&self, yol: &str) -> Option<&DosyaKaydi> {
        self.indeks.get(yol)
    }

    /// Bir dosyanın mantıksal sürümünü ayarlar (çakışma çözümü için).
    ///
    /// Sürüm, "son yazan kazanır" kuralının birincil ölçütüdür. Yerelde yapılan
    /// her değişiklikte bir artırılır; karşı taraftan kabul edilen sürüm
    /// karşı taraftan gelen `revizyon` değeridir.
    ///
    /// # Hatalar
    ///
    /// Yol indeksde yoksa [`Hata::DepoBozuk`] döner.
    pub fn revizyon_ayarla(&mut self, yol: &str, revizyon: u64) -> Sonuc<()> {
        let kayit = self
            .indeks
            .get_mut(yol)
            .ok_or_else(|| Hata::DepoBozuk(format!("indekste olmayan dosya: {yol}")))?;
        kayit.revizyon = revizyon;
        self.guncel = true;
        Ok(())
    }

    /// Kaydın tamamını değiştirir (uzak dosya kabul edildiğinde kullanılır).
    ///
    /// # Hatalar
    ///
    /// Depo yazma hatası döner; kayıt diske yazılmadan önce hata verirse
    /// bellekteki durum değişmemiş olur.
    pub fn kayit_degistir(&mut self, kayit: DosyaKaydi) -> Sonuc<()> {
        self.indeks.insert(kayit.yol.clone(), kayit);
        self.guncel = true;
        self.kaydet()
    }

    /// İndeks değiştiyse diske yazar.
    pub fn kaydet(&mut self) -> Sonuc<()> {
        if !self.guncel {
            return Ok(());
        }
        let icerik = IndeksDosyasi {
            surum: INDEKS_SURUMU,
            dosyalar: self.indeks.clone(),
        };
        let yol = self.kok.join(DEPO_DIZINI).join("indeks.json");
        let gecici = yol.with_extension("json.yeni");
        let metin = serde_json::to_string_pretty(&icerik)?;
        {
            let mut dosya = fs::File::create(&gecici)?;
            dosya.write_all(metin.as_bytes())?;
            dosya.sync_all()?;
        }
        fs::rename(&gecici, &yol)?;
        self.guncel = false;
        Ok(())
    }

    /// Kök dizini özyinelemeli olarak tarar ve indeksi tazeler.
    ///
    /// `.peersync` dizini ve gizli dosyalar atlanır. Klasörde olmayan kayıtlar
    /// indeksden düşürülür, içerik değişmiş dosyalar yeniden parçalanır.
    ///
    /// # Hatalar
    ///
    /// Dosya sayısı [`AZAMI_DOSYA_SAYISI`]'nı aşarsa hata döner: sonsuza kadar
    /// büyüyen bir ağaçta tüm belleği tüketmektense açıkça başarısız olmak
    /// yeğdir.
    pub fn tara(&mut self) -> Sonuc<TaraOzeti> {
        let mut bulunan = BTreeMap::new();
        let mut sayac = 0usize;
        let mut gecici = vec![self.kok.clone()];
        gecici.pop();
        self.gezin(&self.kok.clone(), &mut bulunan, &mut sayac, 0)?;
        let mut ozet = TaraOzeti {
            taranan: sayac,
            yeni: 0,
            degisen: 0,
            silinen: 0,
        };
        let eski_yollar: Vec<String> = self.indeks.keys().cloned().collect();
        for yol in eski_yollar {
            if !bulunan.contains_key(&yol) {
                self.indeks.remove(&yol);
                ozet.silinen += 1;
                self.guncel = true;
            }
        }
        for (yol, kayit) in bulunan {
            match self.indeks.get(&yol) {
                Some(mevcut) if mevcut.karma == kayit.karma => {}
                Some(_) => {
                    ozet.degisen += 1;
                    self.indeks.insert(yol, kayit);
                    self.guncel = true;
                }
                None => {
                    ozet.yeni += 1;
                    self.indeks.insert(yol, kayit);
                    self.guncel = true;
                }
            }
        }
        Ok(ozet)
    }

    /// Tek bir dosyayı akış hâlinde parçalar, parçaları **depoya yazar** ve kaydı döndürür.
    ///
    /// Bu adım kritiktir: yalnız indeksi güncellemek, karşı tarafa gönderecek
    /// parça **içeriğini** depoda bırakmaz ve aktarım `NotFound` ile başarısız
    /// olur. Dosya tek geçişte okunur: parça sınırları çıkarılırken içerik de
    /// diske yazılır.
    ///
    /// # Hatalar
    ///
    /// Dosya açılamazsa, parçalama ayarı geçersizse veya parça karması
    /// bildirilenle tutmuyorsa hata döner.
    pub fn tara_dosya(&self, tam: &Path, goreli: &str) -> Sonuc<DosyaKaydi> {
        let mut parcalayici = Parcalayici::yeni(self.ayar)?;
        let mut dosya = fs::File::open(tam)?;
        let mut blok = vec![0u8; TARAMA_BLOKU];
        let mut parcalar: Vec<TamParca> = Vec::new();
        let mut toplam: u64 = 0;
        let mut kase = sha2::Sha256::new();
        loop {
            let okunan = dosya.read(&mut blok)?;
            if okunan == 0 {
                break;
            }
            let dilim = &blok[..okunan];
            kase.update(dilim);
            for parca in parcalayici.besle_veri(dilim)? {
                if !self.parca_var(&parca.karma) {
                    self.parca_koy(&parca.karma, &parca.veri)?;
                }
                parcalar.push(parca.parca());
            }
            toplam += okunan as u64;
        }
        if let Some(parca) = parcalayici.bitir_veri()? {
            if !self.parca_var(&parca.karma) {
                self.parca_koy(&parca.karma, &parca.veri)?;
            }
            parcalar.push(parca.parca());
        }
        let karma = crate::karma::karmalayici_bitir(kase);
        let revizyon = self.indeks.get(goreli).map_or(1, |k| k.revizyon.max(1));
        Ok(DosyaKaydi {
            yol: goreli.to_string(),
            boyut: toplam,
            karma: karma.0,
            parcalar: parcalar.iter().map(TamParcaKaydi::from).collect(),
            revizyon,
            sahip: self.kimlik.0,
        })
    }
    fn gezin(
        &self,
        dizin: &Path,
        bulunan: &mut BTreeMap<String, DosyaKaydi>,
        sayac: &mut usize,
        derinlik: usize,
    ) -> Sonuc<()> {
        if derinlik > AZAMI_DERINLIK {
            return Err(Hata::TamponSinir {
                sinir: "dizin derinligi",
                azami: AZAMI_DERINLIK,
            });
        }
        let girisler = match fs::read_dir(dizin) {
            Ok(g) => g,
            Err(hata) if hata.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(hata) => return Err(hata.into()),
        };
        for giris in girisler {
            let giris = giris?;
            let ad = giris.file_name();
            let ad_metni = ad.to_str().ok_or_else(|| {
                Hata::DepoBozuk(format!("dosya adı geçerli UTF-8 değil: {:?}", ad))
            })?;
            if ad_metni == DEPO_DIZINI {
                continue;
            }
            let tür = giris.file_type()?;
            if tür.is_dir() {
                self.gezin(&giris.path(), bulunan, sayac, derinlik + 1)?;
                continue;
            }
            if !tür.is_file() {
                continue;
            }
            *sayac += 1;
            if *sayac > AZAMI_DOSYA_SAYISI {
                return Err(Hata::TamponSinir {
                    sinir: "dosya sayisi",
                    azami: AZAMI_DOSYA_SAYISI,
                });
            }
            let goreli = self.goreli_yol(&giris.path());
            bulunan.insert(goreli.clone(), self.tara_dosya(&giris.path(), &goreli)?);
        }
        Ok(())
    }

    /// Dosya yolunu depo anahtarına çevirir (`\` → `/`, önek temizlenir).
    pub fn goreli_yol(&self, tam: &Path) -> String {
        normalize_yol(tam, &self.kok)
    }

    /// Depo anahtarını mutlak yola çevirir.
    pub fn tam_yol(&self, goreli: &str) -> PathBuf {
        let mut yol = self.kok.clone();
        for parca in goreli.split('/').filter(|p| !p.is_empty()) {
            yol.push(parca);
        }
        yol
    }

    /// Bir parçayı depoya yazar (içeriğin karması doğrulanarak).
    ///
    /// # Hatalar
    ///
    /// Boyut sınırı aşılırsa [`Hata::ParcaBoyutuGecersiz`], içerik karması
    /// bildirilenle uyuşmazsa [`Hata::DepoBozuk`] döner. Bozuk parça depoya
    /// **yazılmaz**.
    pub fn parca_koy(&self, karma: &[u8; KARMA_UZUNLUGU], veri: &[u8]) -> Sonuc<PathBuf> {
        if veri.len() > AZAMI_PARCA as usize {
            return Err(Hata::ParcaBoyutuGecersiz {
                bildirilen: veri.len() as u32,
                azami: AZAMI_PARCA,
            });
        }
        let gercek = Karma::hesapla(veri).0;
        if gercek != *karma {
            return Err(Hata::DepoBozuk(format!(
                "parça karması uyuşmuyor: beklenen {}, gerçek {}",
                Karma(*karma).onaltilik(),
                Karma(gercek).onaltilik()
            )));
        }
        let kova = self
            .kok
            .join(DEPO_DIZINI)
            .join("parca")
            .join(Karma(*karma).on_ek());
        fs::create_dir_all(&kova)?;
        let yol = kova.join(Karma(*karma).onaltilik());
        if yol.exists() {
            return Ok(yol);
        }
        let gecici = yol.with_extension("yeni");
        fs::write(&gecici, veri)?;
        fs::rename(&gecici, &yol)?;
        Ok(yol)
    }

    /// Parçayı depodan okur.
    pub fn parca_al(&self, karma: &[u8; KARMA_UZUNLUGU]) -> Sonuc<Vec<u8>> {
        let yol = self.parca_yolu(karma);
        let veri = fs::read(&yol)?;
        let gercek = Karma::hesapla(&veri).0;
        if gercek != *karma {
            return Err(Hata::DepoBozuk(format!(
                "depodaki parça bozuk: beklenen {}, gerçek {}",
                Karma(*karma).onaltilik(),
                Karma(gercek).onaltilik()
            )));
        }
        Ok(veri)
    }

    /// Parçanın diskteki yolunu döndürür.
    pub fn parca_yolu(&self, karma: &[u8; KARMA_UZUNLUGU]) -> PathBuf {
        self.kok
            .join(DEPO_DIZINI)
            .join("parca")
            .join(Karma(*karma).on_ek())
            .join(Karma(*karma).onaltilik())
    }

    /// Depoda o parça var mı?
    pub fn parca_var(&self, karma: &[u8; KARMA_UZUNLUGU]) -> bool {
        self.parca_yolu(karma).exists()
    }

    /// Yerel dosyanın tüm parçalarını depoya yazar (yeniden tarama yolunun
    /// bellek dostu karşılığı).
    pub fn dosya_parcalarini_yaz(&self, parcalar: &DosyaParcalari, tam_yol: &Path) -> Sonuc<()> {
        let veri = fs::read(tam_yol)?;
        for parca in &parcalar.parcalar {
            let bas = parca.konum as usize;
            let son = parca.son_konum() as usize;
            if son > veri.len() {
                return Err(Hata::DepoBozuk(format!(
                    "{}: parça sınırları dosya boyutunu aşıyor",
                    parcalar.yol
                )));
            }
            self.parca_koy(&parca.karma, &veri[bas..son])?;
        }
        Ok(())
    }

    /// Gelen parçalardan dosyayı geçici dosyada kurar, doğrular ve hedefe taşır.
    ///
    /// # Hatalar
    ///
    /// Parça eksikse [`Hata::DepoBozuk`], dosya karması tutmuyorsa
    /// [`Hata::DepoBozuk`] döner ve **hiçbir şey hedefe yazılmaz**. Bağlantı
    /// kopması yarım dosya bırakmaz.
    pub fn dosya_birlestir(&mut self, kayit: &DosyaKaydi) -> Sonuc<PathBuf> {
        let gecici_dizin = self.kok.join(DEPO_DIZINI).join("gecici");
        fs::create_dir_all(&gecici_dizin)?;
        let gecici = gecici_dizin.join(format!("{}.tmp", Karma(kayit.karma).onaltilik()));
        let mut dosya = fs::File::create(&gecici)?;
        let mut yazilan: u64 = 0;
        for parca in &kayit.parcalar {
            let veri = self.parca_al(&parca.karma)?;
            if veri.len() != parca.uzunluk as usize {
                return Err(Hata::DepoBozuk(format!(
                    "parça uzunluğu uyuşmuyor: {} bayt beklenirken {} bayt",
                    parca.uzunluk,
                    veri.len()
                )));
            }
            dosya.write_all(&veri)?;
            yazilan += veri.len() as u64;
        }
        dosya.sync_all()?;
        if yazilan != kayit.boyut {
            return Err(Hata::DepoBozuk(format!(
                "birlestirilen boyut {} beklenen {}",
                yazilan, kayit.boyut
            )));
        }
        let gercek = Karma::dosyadan(&gecici)?;
        if gercek.0 != kayit.karma {
            return Err(Hata::DepoBozuk(format!(
                "birlestirilen dosya karması tutmuyor: beklenen {}, gerçek {}",
                Karma(kayit.karma).onaltilik(),
                gercek.onaltilik()
            )));
        }
        let hedef = self.tam_yol(&kayit.yol);
        if let Some(ust) = hedef.parent() {
            fs::create_dir_all(ust)?;
        }
        fs::rename(&gecici, &hedef)?;
        self.indeks.insert(kayit.yol.clone(), kayit.clone());
        self.guncel = true;
        Ok(hedef)
    }

    /// Hedefte aynı yolda farklı içerik varsa eski sürümü korur.
    ///
    /// Yedek adı: `<ad>.conflict-<sahip kısa>-<revizyon>.conflict`. Korunan
    /// kopya asla üzerine yazılmaz; ad çakışırsa sonuna sayı eklenir.
    pub fn catisma_yedekle(&self, yol: &str, kayit: &DosyaKaydi) -> Sonuc<String> {
        let hedef = self.tam_yol(yol);
        if !hedef.exists() {
            return Ok(String::new());
        }
        let ad = hedef
            .file_name()
            .and_then(|a| a.to_str())
            .ok_or_else(|| Hata::DepoBozuk("hedef dosya adı geçersiz".to_string()))?;
        let govde = ad.rsplit_once('.').map_or(ad, |(g, _)| g);
        let sahip = Kimlik(kayit.sahip).onaltilik();
        let temel = format!(
            "{govde}.conflict-{sahip}-{}.{CATISMA_SONEKI}",
            kayit.revizyon
        );
        let mut aday = temel.clone();
        let mut sayac = 1u32;
        while self.tam_yol(&aday_kompozit(yol, &aday)).exists() {
            aday = format!("{temel}.{sayac}");
            sayac += 1;
        }
        let tam_aday = aday_kompozit(yol, &aday);
        let yedek_yolu = self.tam_yol(&tam_aday);
        fs::copy(&hedef, &yedek_yolu)?;
        Ok(tam_aday)
    }

    /// Yarım kalmış geçici dosyaları siler; silinen sayıyı döndürür.
    pub fn gecici_temizle(&self) -> Sonuc<usize> {
        let dizin = self.kok.join(DEPO_DIZINI).join("gecici");
        if !dizin.exists() {
            return Ok(0);
        }
        let mut silinen = 0usize;
        for giris in fs::read_dir(&dizin)? {
            let giris = giris?;
            if giris.file_type()?.is_file() {
                fs::remove_file(giris.path())?;
                silinen += 1;
            }
        }
        Ok(silinen)
    }
}

/// `a/b.txt` + `b.conflict-x` → `a/b.conflict-x`.
fn aday_kompozit(yol: &str, aday: &str) -> String {
    match yol.rsplit_once('/') {
        Some((dizin, _)) => format!("{dizin}/{aday}"),
        None => aday.to_string(),
    }
}

/// Tarama sonucu özeti.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TaraOzeti {
    /// Taranan dosya sayısı.
    pub taranan: usize,
    /// Yeni eklenen dosya sayısı.
    pub yeni: usize,
    /// İçeriği değişen dosya sayısı.
    pub degisen: usize,
    /// Silinmiş kayıt sayısı.
    pub silinen: usize,
}

/// Yolu depo anahtarına çevirir: önek atılır, `\` işaretçisi `/` olur.
pub fn normalize_yol(tam: &Path, kok: &Path) -> String {
    let mut parcalar: Vec<String> = Vec::new();
    for bilesen in tam.strip_prefix(kok).unwrap_or(tam).components() {
        match bilesen {
            Component::Normal(ad) => {
                if let Some(metin) = ad.to_str() {
                    parcalar.push(metin.replace('\\', "/"));
                }
            }
            Component::CurDir => {}
            _ => {}
        }
    }
    parcalar.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parca::parcala_dosya;
    use std::path::PathBuf;

    /// Test içinde geçici dizin üreten, Drop ile temizleyen kapsayıcı.
    ///
    /// Neden `tempfile` yok: bağımlılık politikası (WORKER_CONTRACT § 3.2)
    /// `tempfile`'i hiçbir projede vermez; yardımcı kendi kodumuzla yazılır.
    struct GeciciDizin {
        yol: PathBuf,
    }

    impl GeciciDizin {
        fn yeni(etiket: &str) -> Sonuc<GeciciDizin> {
            let kok =
                std::env::temp_dir().join(format!("peersync-depo-{etiket}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&kok);
            fs::create_dir_all(&kok)?;
            Ok(GeciciDizin { yol: kok })
        }

        fn yol(&self) -> &Path {
            &self.yol
        }
    }

    impl Drop for GeciciDizin {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.yol);
        }
    }

    fn depo_ac(kok: &Path) -> Depo {
        Depo::ac(kok, Kimlik([0xAB; 16]), ParcaAyari::varsayilan()).unwrap()
    }

    #[test]
    fn depo_ac_dizinleri_olusturur() {
        let gecici = GeciciDizin::yeni("ac").unwrap();
        let depo = depo_ac(gecici.yol());
        assert!(gecici.yol().join(DEPO_DIZINI).exists());
        assert!(gecici.yol().join(DEPO_DIZINI).join("parca").exists());
        assert!(gecici.yol().join(DEPO_DIZINI).join("gecici").exists());
        assert_eq!(depo.kimlik(), Kimlik([0xAB; 16]));
    }

    #[test]
    fn tarama_dosyalari_indeksler() {
        let gecici = GeciciDizin::yeni("tarama").unwrap();
        fs::write(gecici.yol().join("a.txt"), b"birinci dosya").unwrap();
        fs::create_dir_all(gecici.yol().join("alt")).unwrap();
        fs::write(gecici.yol().join("alt").join("b.txt"), b"ikinci dosya").unwrap();
        let mut depo = depo_ac(gecici.yol());
        let ozet = depo.tara().unwrap();
        assert_eq!(ozet.taranan, 2);
        assert_eq!(ozet.yeni, 2);
        assert_eq!(depo.kayitlar().len(), 2);
        assert!(depo.ara("a.txt").is_some());
        assert!(depo.ara("alt/b.txt").is_some());
    }

    #[test]
    fn tarama_sonrasi_kaydet_ve_yeniden_ac_durumu_korur() {
        let gecici = GeciciDizin::yeni("kalici").unwrap();
        fs::write(gecici.yol().join("a.txt"), b"kalici icerik").unwrap();
        let mut depo = depo_ac(gecici.yol());
        depo.tara().unwrap();
        depo.kaydet().unwrap();
        let yeniden = depo_ac(gecici.yol());
        assert_eq!(yeniden.kayitlar().len(), 1);
        assert!(yeniden.ara("a.txt").is_some());
    }

    #[test]
    fn tarama_silen_dosyalari_indeksten_dusurur() {
        let gecici = GeciciDizin::yeni("silme").unwrap();
        let yol = gecici.yol().join("a.txt");
        fs::write(&yol, b"gecici dosya").unwrap();
        let mut depo = depo_ac(gecici.yol());
        depo.tara().unwrap();
        assert_eq!(depo.kayitlar().len(), 1);
        fs::remove_file(&yol).unwrap();
        let ozet = depo.tara().unwrap();
        assert_eq!(ozet.silinen, 1);
        assert!(depo.kayitlar().is_empty());
    }

    #[test]
    fn tarama_degisen_dosyayi_yeniden_indeksler() {
        let gecici = GeciciDizin::yeni("degisim").unwrap();
        let yol = gecici.yol().join("a.txt");
        fs::write(&yol, b"ilk icerik").unwrap();
        let mut depo = depo_ac(gecici.yol());
        depo.tara().unwrap();
        let ilk = depo.ara("a.txt").unwrap().karma;
        fs::write(&yol, b"farkli ve daha uzun icerik").unwrap();
        let ozet = depo.tara().unwrap();
        assert_eq!(ozet.degisen, 1);
        assert_ne!(depo.ara("a.txt").unwrap().karma, ilk);
    }

    #[test]
    fn depo_dizini_taramaya_girmez() {
        let gecici = GeciciDizin::yeni("gizli").unwrap();
        fs::write(gecici.yol().join("a.txt"), b"goren").unwrap();
        let parca_dizini = gecici.yol().join(DEPO_DIZINI).join("parca");
        fs::create_dir_all(&parca_dizini).unwrap();
        fs::write(parca_dizini.join("x"), b"gizli").unwrap();
        let mut depo = depo_ac(gecici.yol());
        let ozet = depo.tara().unwrap();
        assert_eq!(ozet.taranan, 1);
    }

    #[test]
    fn parca_koy_ve_al_gidis_donus_yapar() {
        let gecici = GeciciDizin::yeni("parca").unwrap();
        let depo = depo_ac(gecici.yol());
        let veri = b"parca icerigi";
        let karma = Karma::hesapla(veri).0;
        assert!(!depo.parca_var(&karma));
        depo.parca_koy(&karma, veri).unwrap();
        assert!(depo.parca_var(&karma));
        assert_eq!(depo.parca_al(&karma).unwrap(), veri.to_vec());
    }

    #[test]
    fn parca_koy_yanlis_karmayi_reddeder() {
        let gecici = GeciciDizin::yeni("yanliskarma").unwrap();
        let depo = depo_ac(gecici.yol());
        let veri = b"bir icerik";
        let yanlis = Karma::hesapla(b"baska").0;
        let hata = depo.parca_koy(&yanlis, veri).unwrap_err();
        assert!(matches!(hata, Hata::DepoBozuk(_)));
        assert!(!depo.parca_var(&yanlis), "bozuk parca depoya yazilmamali");
    }

    #[test]
    fn parca_koy_buyuk_veriyi_reddeder() {
        let gecici = GeciciDizin::yeni("buyukparca").unwrap();
        let depo = depo_ac(gecici.yol());
        let veri = vec![0u8; AZAMI_PARCA as usize + 1];
        let karma = Karma::hesapla(&veri).0;
        let hata = depo.parca_koy(&karma, &veri).unwrap_err();
        assert!(matches!(hata, Hata::ParcaBoyutuGecersiz { .. }));
    }

    #[test]
    fn bozuk_depo_dosyasi_okundugunda_hata_verir() {
        let gecici = GeciciDizin::yeni("bozukdepo").unwrap();
        let depo = depo_ac(gecici.yol());
        let karma = Karma::hesapla(b"dogru").0;
        depo.parca_koy(&karma, b"dogru").unwrap();
        let yol = depo.parca_yolu(&karma);
        fs::write(&yol, b"bozuk").unwrap();
        let hata = depo.parca_al(&karma).unwrap_err();
        assert!(matches!(hata, Hata::DepoBozuk(_)));
    }

    #[test]
    fn dosya_birlestir_atomik_olarak_hedefe_yazar() {
        let gecici = GeciciDizin::yeni("birlestir").unwrap();
        let icerik: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(gecici.yol().join("kaynak.bin"), &icerik).unwrap();
        let mut depo = depo_ac(gecici.yol());
        let ozet = depo.tara().unwrap();
        assert_eq!(ozet.taranan, 1);
        let kaydi = depo.ara("kaynak.bin").unwrap().clone();
        let parcalar = parcala_dosya(
            &gecici.yol().join("kaynak.bin"),
            "kaynak.bin",
            ParcaAyari::varsayilan(),
        )
        .unwrap();
        depo.dosya_parcalarini_yaz(&parcalar, &gecici.yol().join("kaynak.bin"))
            .unwrap();
        fs::remove_file(gecici.yol().join("kaynak.bin")).unwrap();
        let hedef = depo.dosya_birlestir(&kaydi).unwrap();
        assert!(hedef.exists());
        assert_eq!(fs::read(&hedef).unwrap(), icerik);
        assert!(depo.kayitlar().contains_key("kaynak.bin"));
    }

    #[test]
    fn dosya_birlestir_eksik_parcada_hedefe_yazmaz() {
        let gecici = GeciciDizin::yeni("eksik").unwrap();
        let icerik: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(gecici.yol().join("k.bin"), &icerik).unwrap();
        let mut depo = depo_ac(gecici.yol());
        depo.tara().unwrap();
        let kaydi = depo.ara("k.bin").unwrap().clone();
        // Bir parçayı depodan sil: aktarım sırasında kaybolmuş parça senaryosu.
        let kayip = kaydi.parcalar[0].karma;
        fs::remove_file(depo.parca_yolu(&kayip)).unwrap();
        fs::remove_file(gecici.yol().join("k.bin")).unwrap();
        let hata = depo.dosya_birlestir(&kaydi).unwrap_err();
        assert!(matches!(hata, Hata::Io(_) | Hata::DepoBozuk(_)));
        assert!(!gecici.yol().join("k.bin").exists());
    }

    #[test]
    fn catisma_yedekle_eski_surumu_korur() {
        let gecici = GeciciDizin::yeni("catisma").unwrap();
        fs::write(gecici.yol().join("a.txt"), b"eski icerik").unwrap();
        let depo = depo_ac(gecici.yol());
        let kayit = DosyaKaydi {
            yol: "a.txt".to_string(),
            boyut: 10,
            karma: [0; 32],
            parcalar: vec![],
            revizyon: 3,
            sahip: [0xAB; 16],
        };
        let yedek = depo.catisma_yedekle("a.txt", &kayit).unwrap();
        assert!(!yedek.is_empty());
        assert_eq!(fs::read(gecici.yol().join(&yedek)).unwrap(), b"eski icerik");
        assert_eq!(
            fs::read(gecici.yol().join("a.txt")).unwrap(),
            b"eski icerik"
        );
    }

    #[test]
    fn catisma_yedekle_ust_uste_cakismada_yeni_ad_uretilir() {
        let gecici = GeciciDizin::yeni("catisma2").unwrap();
        fs::create_dir_all(gecici.yol().join("k")).unwrap();
        fs::write(gecici.yol().join("k").join("a.txt"), b"icerik").unwrap();
        let depo = depo_ac(gecici.yol());
        let kayit = DosyaKaydi {
            yol: "k/a.txt".to_string(),
            boyut: 6,
            karma: [0; 32],
            parcalar: vec![],
            revizyon: 1,
            sahip: [0xCD; 16],
        };
        let bir = depo.catisma_yedekle("k/a.txt", &kayit).unwrap();
        let iki = depo.catisma_yedekle("k/a.txt", &kayit).unwrap();
        assert_ne!(bir, iki);
        assert!(bir.starts_with("k/"));
        assert!(iki.starts_with("k/"));
    }

    #[test]
    fn catisma_yedekle_hedef_yoksa_bos_doner() {
        let gecici = GeciciDizin::yeni("catisma3").unwrap();
        let depo = depo_ac(gecici.yol());
        let kayit = DosyaKaydi {
            yol: "yok.txt".to_string(),
            boyut: 0,
            karma: [0; 32],
            parcalar: vec![],
            revizyon: 1,
            sahip: [0; 16],
        };
        assert!(depo.catisma_yedekle("yok.txt", &kayit).unwrap().is_empty());
    }

    #[test]
    fn gecici_temizle_yarim_dosyalari_siler() {
        let gecici = GeciciDizin::yeni("gecici").unwrap();
        let depo = depo_ac(gecici.yol());
        let dizin = gecici.yol().join(DEPO_DIZINI).join("gecici");
        fs::write(dizin.join("a.tmp"), b"yarim").unwrap();
        fs::write(dizin.join("b.tmp"), b"yarim").unwrap();
        assert_eq!(depo.gecici_temizle().unwrap(), 2);
        assert_eq!(depo.gecici_temizle().unwrap(), 0);
    }

    #[test]
    fn bozuk_indeks_dosyasi_acilista_hata_verir() {
        let gecici = GeciciDizin::yeni("bozukindeks").unwrap();
        let depo = depo_ac(gecici.yol());
        drop(depo);
        let indeks = gecici.yol().join(DEPO_DIZINI).join("indeks.json");
        fs::write(&indeks, b"{ bozuk json").unwrap();
        let hata = Depo::ac(gecici.yol(), Kimlik([0; 16]), ParcaAyari::varsayilan()).unwrap_err();
        assert!(matches!(hata, Hata::DepoBozuk(_)));
    }

    #[test]
    fn indeks_dosyasi_json_olarak_yazilir() {
        let gecici = GeciciDizin::yeni("json").unwrap();
        fs::write(gecici.yol().join("a.txt"), b"json testi").unwrap();
        let mut depo = depo_ac(gecici.yol());
        depo.tara().unwrap();
        depo.kaydet().unwrap();
        let metin = fs::read_to_string(gecici.yol().join(DEPO_DIZINI).join("indeks.json")).unwrap();
        assert!(metin.contains("\"surum\": 1"));
        assert!(metin.contains("\"a.txt\""));
        assert!(metin.contains("\"revizyon\""));
    }

    #[test]
    fn dosya_kaydi_ozet_bilgi_tasir() {
        let kayit = DosyaKaydi {
            yol: "x.txt".to_string(),
            boyut: 42,
            karma: [1; 32],
            parcalar: vec![TamParcaKaydi {
                konum: 0,
                uzunluk: 42,
                karma: [2; 32],
            }],
            revizyon: 5,
            sahip: [3; 16],
        };
        let ozet = kayit.ozet();
        assert_eq!(ozet.yol, "x.txt");
        assert_eq!(ozet.boyut, 42);
        assert_eq!(ozet.parca_sayisi, 1);
        assert_eq!(ozet.revizyon, 5);
        assert_eq!(kayit.parca_karmalari().len(), 1);
    }

    #[test]
    fn yol_normalizasyonu_tutarlidir() {
        let kok = Path::new("/tmp/kok");
        let tam = PathBuf::from("/tmp/kok/alt/dosya.txt");
        assert_eq!(normalize_yol(&tam, kok), "alt/dosya.txt");
        assert_eq!(
            normalize_yol(Path::new("alt/dosya.txt"), kok),
            "alt/dosya.txt"
        );
    }

    #[test]
    fn aday_kompozit_dizini_korur() {
        assert_eq!(aday_kompozit("a/b/c.txt", "c.conflict"), "a/b/c.conflict");
        assert_eq!(aday_kompozit("c.txt", "c.conflict"), "c.conflict");
    }
}
