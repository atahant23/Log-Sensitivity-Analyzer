import tkinter as tk
from tkinter import filedialog, messagebox
import re
import json
from datetime import datetime

# --- ANALİZ VE MASKELEME MANTIĞI ---
KURALLAR = {
    "E-posta": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "IP Adresi": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "Sifre_Ipucu": r'(?i)(password|passwd|secret|token|key)[:=]\s*(\S+)'
}

def maskele(metin, kategori):
    try:
        if kategori == "E-posta":
            parca = metin.split('@')
            return parca[0][0] + "****@" + parca[1]
        elif kategori == "IP Adresi":
            parca = metin.split('.')
            return f"{parca[0]}.{parca[1]}.*.*"
        return metin[:4] + "****"
    except:
        return "****"

# --- ARAYÜZ FONKSİYONLARI ---
bulgular_listesi = []

def dosya_sec_ve_tara():
    global bulgular_listesi
    dosya_yolu = filedialog.askopenfilename(title="Log Dosyası Seç")
    
    if dosya_yolu:
        sonuc_kutusu.delete(0, tk.END)
        bulgular_listesi = []
        
        try:
            with open(dosya_yolu, 'r', encoding='utf-8') as f:
                for no, satir in enumerate(f, 1):
                    for kategori, kural in KURALLAR.items():
                        eslesme = re.search(kural, satir)
                        if eslesme:
                            orjinal = eslesme.group()
                            maskeli = maskele(orjinal, kategori)
                            bulgu = {"satir": no, "kategori": kategori, "orjinal": orjinal, "maskeli": maskeli}
                            bulgular_listesi.append(bulgu)
                            sonuc_kutusu.insert(tk.END, f" [!] SATIR {no} | {kategori}: {maskeli}")
            
            messagebox.showinfo("Başarılı", f"Tarama bitti! {len(bulgular_listesi)} bulgu bulundu.")
        except Exception as e:
            messagebox.showerror("Hata", f"Dosya okunurken hata oluştu: {e}")

def sonuclari_kaydet():
    if not bulgular_listesi:
        messagebox.showwarning("Uyarı", "Kaydedilecek sonuç bulunamadı!")
        return
    
    kayit_yolu = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Dosyası", "*.json")])
    if kayit_yolu:
        with open(kayit_yolu, "w", encoding="utf-8") as f:
            json.dump({"tarih": str(datetime.now()), "bulgular": bulgular_listesi}, f, indent=4)
        messagebox.showinfo("Tamamlandı", "Sonuçlar başarıyla kaydedildi.")

# --- GÖRSEL TASARIM (B ŞIKKI - HACKER STYLE) ---
pencere = tk.Tk()
pencere.title("LOG SENSITIVITY ANALYZER - TERMINAL MODE")
pencere.geometry("600x500")
pencere.configure(bg="#171717")

# Hacker Yeşili Renkleri
mavi= "blue"
acık_mavi = "#ADD8E6"

baslik = tk.Label(pencere, text=">> SENSITIVITY ANALYZER v2.0 <<", font=("Courier", 16, "bold"), bg="#171717", fg=mavi)
baslik.pack(pady=15)

# Butonlar Frame
buton_frame = tk.Frame(pencere, bg="#171717")
buton_frame.pack(pady=10)

btn_tara = tk.Button(buton_frame, text="[ DOSYA TARA ]", command=dosya_sec_ve_tara, bg=acık_mavi, fg=mavi, font=("Courier", 10, "bold"), relief=tk.FLAT, padx=10)
btn_tara.grid(row=0, column=0, padx=10)

btn_kaydet = tk.Button(buton_frame, text="[ RAPORU KAYDET ]", command=sonuclari_kaydet, bg=acık_mavi, fg=mavi, font=("Courier", 10, "bold"), relief=tk.FLAT, padx=10)
btn_kaydet.grid(row=0, column=1, padx=10)

# Liste Kutusu
frame = tk.Frame(pencere, bg="#0c0c0c")
frame.pack(pady=10, fill=tk.BOTH, expand=True, padx=20)

sonuc_kutusu = tk.Listbox(frame, bg="#1a1a1a", fg=mavi, font=("Courier", 10), borderwidth=0, highlightthickness=1, highlightcolor=mavi)
sonuc_kutusu.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# Kaydırma Çubuğu
scrollbar = tk.Scrollbar(frame, bg="#0c0c0c")
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
sonuc_kutusu.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=sonuc_kutusu.yview)

footer = tk.Label(pencere, text="Status: Ready to scan...", font=("Courier", 9), bg="#0c0c0c", fg=mavi)
footer.pack(side=tk.BOTTOM, fill=tk.X)

pencere.mainloop()
