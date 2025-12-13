import pandas as pd

# 1. Baca file Excel (.xls)
df = pd.read_excel('input.xls', header=None)

# 2. Ambil kolom I (index ke-8 karena index mulai dari 0)
no_hp = df.iloc[:, 8]

# 3. Simpan ke file TXT
no_hp.to_csv('nomor_hp_saja.txt', index=False, header=False)

print("✅ Selesai! File 'nomor_hp_saja.txt' berisi hanya kolom I (No HP).")