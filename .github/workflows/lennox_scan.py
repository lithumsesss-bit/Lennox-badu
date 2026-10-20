import os, json, hashlib, threading
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_NAME = 'LENNOX SCAN'
TERMS = ['ffpanel', 'aimbot', 'wallhack', 'injector', 'mod menu', 'game guardian', 'cheat', 'crack', 'keygen', 'loader']
TEXT_EXTS = {'.txt', '.ini', '.cfg', '.json', '.xml', '.log', '.lua', '.ps1', '.bat', '.cmd'}

class App:
    def __init__(self, root):
        self.root = root
        root.title(APP_NAME)
        root.geometry('1000x680')
        root.configure(bg='#090a10')
        self.results = []
        tk.Label(root, text='LENNOX SCAN', font=('Segoe UI', 25, 'bold'), fg='#ff0a91', bg='#090a10').pack(pady=(18, 4))
        tk.Label(root, text='GAME SECURITY • FILE ANALYSIS', font=('Segoe UI', 10), fg='#a8adbd', bg='#090a10').pack()
        self.status = tk.Label(root, text='Ready to scan', font=('Segoe UI', 15, 'bold'), fg='#ffffff', bg='#090a10')
        self.status.pack(pady=16)
        bar = tk.Frame(root, bg='#090a10'); bar.pack(pady=4)
        tk.Button(bar, text='START DEEP SCAN', command=self.choose, bg='#ff0a91', fg='white', relief='flat', padx=18, pady=10).pack(side='left', padx=6)
        tk.Button(bar, text='EXPORT JSON', command=self.export, bg='#242633', fg='white', relief='flat', padx=18, pady=10).pack(side='left', padx=6)
        self.tree = ttk.Treeview(root, columns=('kind','path','detail'), show='headings')
        for col, title, width in [('kind','FINDING',180),('path','FILE PATH',420),('detail','REASON',330)]:
            self.tree.heading(col, text=title); self.tree.column(col, width=width)
        self.tree.pack(fill='both', expand=True, padx=16, pady=16)
        tk.Label(root, text='Heuristic indicators are not proof of cheating or malware. No files are changed or deleted.', fg='#a8adbd', bg='#090a10').pack(pady=(0,14))

    def choose(self):
        folder = filedialog.askdirectory(title='Choose folder to scan')
        if not folder: return
        self.status.config(text='Scanning…')
        threading.Thread(target=self.scan, args=(folder,), daemon=True).start()

    def scan(self, folder):
        found = []
        for root, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs if d.lower() not in {'$recycle.bin', 'system volume information'}]
            for filename in files:
                path = Path(root) / filename
                reasons = []
                lowname = filename.lower()
                matches = [t for t in TERMS if t in lowname]
                if matches: reasons.append('Filename indicator: ' + ', '.join(matches))
                try:
                    if path.suffix.lower() in TEXT_EXTS and path.stat().st_size < 2_000_000:
                        content = path.read_text(errors='ignore').lower()
                        hits = [t for t in TERMS if t in content]
                        if hits: reasons.append('Text indicator: ' + ', '.join(hits))
                    h = hashlib.sha256()
                    with path.open('rb') as f:
                        for chunk in iter(lambda: f.read(1024*1024), b''): h.update(chunk)
                    digest = h.hexdigest()
                except (OSError, PermissionError):
                    digest = None
                if reasons:
                    found.append({'path': str(path), 'sha256': digest, 'findings': reasons})
        self.root.after(0, lambda: self.finish(found, folder))

    def finish(self, found, folder):
        self.results = found
        for item in self.tree.get_children(): self.tree.delete(item)
        for item in found:
            for reason in item['findings']:
                self.tree.insert('', 'end', values=('Review', item['path'], reason))
        self.status.config(text=f'Scan complete • {len(found)} files flagged for review')
        messagebox.showinfo('Scan complete', f'Folder: {folder}\nFiles with heuristic indicators: {len(found)}\nA match is not proof of cheating.')

    def export(self):
        if not self.results:
            messagebox.showinfo('No results', 'Run a scan first. A scan with zero findings can also be exported after scanning.')
            return
        dest = filedialog.asksaveasfilename(defaultextension='.json', filetypes=[('JSON', '*.json')], initialfile='lennox-scan-report.json')
        if dest:
            with open(dest, 'w', encoding='utf-8') as f:
                json.dump({'app': APP_NAME, 'created_at': datetime.now().isoformat(), 'results': self.results, 'notice': 'Heuristic indicators are not proof of cheating or malware.'}, f, indent=2)
            messagebox.showinfo('Saved', 'Report saved.')

if __name__ == '__main__':
    root = tk.Tk()
    App(root)
    root.mainloop()
