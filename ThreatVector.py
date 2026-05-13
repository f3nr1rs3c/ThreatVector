import tkinter as tk
from tkinter import ttk
import math

class CVSSCalculator(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("ThreatVector - CVSS v3.1 Vector Calculator (Vektör Hesaplayıcı) - Made by Sirius")
        self.geometry("900x850")
        self.configure(bg="#121212")
        self.resizable(False, False)

        # Windows'da bulanıklığı önlemek için DPI farkındalığı
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass

        # Stil Konfigürasyonu
        style = ttk.Style(self)
        style.theme_use('clam')
        
        # Renkler
        bg_color = "#121212"
        panel_color = "#1e1e1e"
        text_color = "#ffffff"
        accent_color = "#ff003c"
        
        style.configure('TFrame', background=bg_color)
        style.configure('Panel.TFrame', background=panel_color)
        style.configure('TLabel', background=bg_color, foreground=text_color, font=('Segoe UI', 10))
        style.configure('Panel.TLabel', background=panel_color, foreground=text_color, font=('Segoe UI', 10, 'bold'))
        style.configure('Header.TLabel', font=('Segoe UI', 18, 'bold'), foreground=accent_color)
        style.configure('Score.TLabel', font=('Segoe UI', 36, 'bold'), foreground=text_color, background=panel_color)
        style.configure('Score.TLabel', font=('Segoe UI', 36, 'bold'), foreground=text_color, background=panel_color)
        
        style.configure('TRadiobutton', background=panel_color, foreground=text_color, font=('Segoe UI', 10), focuscolor=panel_color)
        style.map('TRadiobutton',
                  foreground=[('active', accent_color)],
                  indicatorcolor=[('selected', accent_color)],
                  background=[('active', panel_color)])

        # CVSS 3.1 Metrics and Translations
        self.metrics = {
            'AV': {'name': 'Attack Vector (Saldırı Vektörü)', 'options': [('Network (Ağ)', 'N'), ('Adjacent (Bitişik)', 'A'), ('Local (Yerel)', 'L'), ('Physical (Fiziksel)', 'P')]},
            'AC': {'name': 'Attack Complexity (Karmaşıklık)', 'options': [('Low (Düşük)', 'L'), ('High (Yüksek)', 'H')]},
            'PR': {'name': 'Privileges Required (Ayrıcalıklar)', 'options': [('None (Yok)', 'N'), ('Low (Düşük)', 'L'), ('High (Yüksek)', 'H')]},
            'UI': {'name': 'User Interaction (Etkileşim)', 'options': [('None (Yok)', 'N'), ('Required (Gerekiyor)', 'R')]},
            'S':  {'name': 'Scope (Kapsam)', 'options': [('Unchanged (Değişmez)', 'U'), ('Changed (Değişir)', 'C')]},
            'C':  {'name': 'Confidentiality (Gizlilik)', 'options': [('None (Yok)', 'N'), ('Low (Düşük)', 'L'), ('High (Yüksek)', 'H')]},
            'I':  {'name': 'Integrity (Bütünlük)', 'options': [('None (Yok)', 'N'), ('Low (Düşük)', 'L'), ('High (Yüksek)', 'H')]},
            'A':  {'name': 'Availability (Erişilebilirlik)', 'options': [('None (Yok)', 'N'), ('Low (Düşük)', 'L'), ('High (Yüksek)', 'H')]}
        }

        self.weights = {
            'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
            'AC': {'L': 0.77, 'H': 0.44},
            'PR': {
                'U': {'N': 0.85, 'L': 0.62, 'H': 0.27},
                'C': {'N': 0.85, 'L': 0.68, 'H': 0.50}
            },
            'UI': {'N': 0.85, 'R': 0.62},
            'C': {'N': 0.0, 'L': 0.22, 'H': 0.56},
            'I': {'N': 0.0, 'L': 0.22, 'H': 0.56},
            'A': {'N': 0.0, 'L': 0.22, 'H': 0.56}
        }

        # Değişkenler
        self.vars = {}
        for m in self.metrics:
            self.vars[m] = tk.StringVar(value=self.metrics[m]['options'][0][1])
            self.vars[m].trace_add('write', self.calculate_score)

        self.create_widgets()
        self.calculate_score()

    def create_widgets(self):
        # Başlık
        header = ttk.Label(self, text="ThreatVector - CVSS v3.1 Vector Calculator", style='Header.TLabel')
        header.pack(pady=(20, 5))
        
        subtitle = ttk.Label(self, text="Made by Sirius", font=('Segoe UI', 10, 'italic'), foreground="#a0a0a0", background="#121212")
        subtitle.pack(pady=(0, 15))

        # Ana İçerik Alanı
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=25)

        # Sol Kolon - Sömürülebilirlik Metrikleri
        left_frame = ttk.Frame(main_frame)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 15))

        self.create_metric_group(left_frame, ['AV', 'AC', 'PR', 'UI'])

        # Sağ Kolon - Etki Metrikleri & Kapsam
        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(15, 0))

        self.create_metric_group(right_frame, ['S', 'C', 'I', 'A'])

        # Alt Alan - Sonuçlar
        bottom_frame = ttk.Frame(self, style='Panel.TFrame')
        bottom_frame.pack(fill=tk.X, padx=25, pady=25)

        self.score_label = ttk.Label(bottom_frame, text="0.0 NONE", style='Score.TLabel')
        self.score_label.pack(pady=(20, 5))

        self.vector_entry = tk.Entry(bottom_frame, font=('Consolas', 14, 'bold'), bg="#121212", fg="#00ffcc", bd=0, justify="center", readonlybackground="#121212", cursor="xterm")
        self.vector_entry.pack(fill=tk.X, padx=50, pady=(0, 15), ipady=8)

        # Butonlar ve Bildirim
        btn_frame = tk.Frame(bottom_frame, bg="#1e1e1e")
        btn_frame.pack(pady=(0, 20))

        self.copy_btn = tk.Button(btn_frame, text="Copy Vector (Kopyala)", font=('Segoe UI', 10, 'bold'), 
                             bg="#ff003c", fg="#ffffff", activebackground="#cc0030", activeforeground="#ffffff", 
                             bd=0, cursor="hand2", command=self.copy_vector, padx=20, pady=8)
        self.copy_btn.pack(side=tk.LEFT)
        
        self.toast_label = tk.Label(btn_frame, text="", font=('Segoe UI', 10, 'bold'), bg="#1e1e1e", fg="#00ffcc")
        self.toast_label.pack(side=tk.LEFT, padx=15)

    def create_metric_group(self, parent, metrics_list):
        for m in metrics_list:
            frame = ttk.Frame(parent, style='Panel.TFrame')
            frame.pack(fill=tk.X, pady=6)
            
            lbl = ttk.Label(frame, text=self.metrics[m]['name'], style='Panel.TLabel')
            lbl.pack(anchor=tk.W, padx=15, pady=(12, 5))
            
            btn_frame = ttk.Frame(frame, style='Panel.TFrame')
            btn_frame.pack(fill=tk.X, padx=15, pady=(0, 12))
            
            btn_frame.columnconfigure(0, weight=1)
            btn_frame.columnconfigure(1, weight=1)
            
            for idx, (text, val) in enumerate(self.metrics[m]['options']):
                rb = ttk.Radiobutton(btn_frame, text=text, variable=self.vars[m], value=val)
                row = idx // 2
                col = idx % 2
                rb.grid(row=row, column=col, sticky=tk.W, pady=3)

    def roundup(self, val):
        # CVSS 3.1 standardında belirtilen yuvarlama algoritması
        return math.ceil(round(val, 5) * 10) / 10.0

    def calculate_score(self, *args):
        try:
            av = self.weights['AV'][self.vars['AV'].get()]
            ac = self.weights['AC'][self.vars['AC'].get()]
            s = self.vars['S'].get()
            pr = self.weights['PR'][s][self.vars['PR'].get()]
            ui = self.weights['UI'][self.vars['UI'].get()]
            c = self.weights['C'][self.vars['C'].get()]
            i = self.weights['I'][self.vars['I'].get()]
            a = self.weights['A'][self.vars['A'].get()]

            iss = 1 - ((1 - c) * (1 - i) * (1 - a))
            
            if s == 'U':
                impact = 6.42 * iss
            else:
                impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
                
            exploitability = 8.22 * av * ac * pr * ui
            
            if impact <= 0:
                base_score = 0.0
            elif s == 'U':
                base_score = self.roundup(min(impact + exploitability, 10.0))
            else:
                base_score = self.roundup(min(1.08 * (impact + exploitability), 10.0))
            
            self.update_display(base_score)
        except Exception as e:
            import traceback
            traceback.print_exc()

    def update_display(self, score):
        # Skora göre seviye ve renk belirleme
        if score == 0.0:
            severity = "NONE"
            color = "#a0a0a0"
        elif 0.1 <= score <= 3.9:
            severity = "LOW"
            color = "#00ffcc" # Düşük için cyan
        elif 4.0 <= score <= 6.9:
            severity = "MEDIUM"
            color = "#ffcc00" # Orta için sarı
        elif 7.0 <= score <= 8.9:
            severity = "HIGH"
            color = "#ff6600" # Yüksek için turuncu
        else:
            severity = "CRITICAL"
            color = "#ff003c" # Kritik için kırmızı (Red Team temasına uygun)

        self.score_label.config(text=f"{score:.1f} {severity}", foreground=color)

        # Vektör stringini oluşturma
        vector = f"CVSS:3.1/AV:{self.vars['AV'].get()}/AC:{self.vars['AC'].get()}/PR:{self.vars['PR'].get()}/UI:{self.vars['UI'].get()}/S:{self.vars['S'].get()}/C:{self.vars['C'].get()}/I:{self.vars['I'].get()}/A:{self.vars['A'].get()}"
        self.vector_entry.config(state='normal')
        self.vector_entry.delete(0, tk.END)
        self.vector_entry.insert(0, vector)
        self.vector_entry.config(state='readonly')

    def copy_vector(self):
        try:
            self.clipboard_clear()
            self.clipboard_append(self.vector_entry.get())
            self.update()
            
            self.toast_label.config(text="✓ Vector Copied! (Kopyalandı)")
            self.after(2000, lambda: self.toast_label.config(text=""))
        except Exception:
            self.toast_label.config(text="! Copy failed (Başarısız)", fg="#ff003c")

if __name__ == "__main__":
    app = CVSSCalculator()
    app.mainloop()
