import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# 1. Dateien laden
df_results = pd.read_csv("baseline_results.csv")
df_mapping = pd.read_csv("owasp_mapping.csv")  # Spalten: CWE_ID, OWASP_Category

# ---------------------------------------------------------
# 2. CWEs aus "SAST Result" extrahieren & matchen
# ---------------------------------------------------------
# Regex sucht nach allen Vorkommen von "CWE-" gefolgt von Zahlen
def extract_cwes(text):
    if pd.isna(text) or not isinstance(text, str):
        return []
    return re.findall(r'CWE-\d+', text)

# Extrahierte Liste von CWEs pro Zeile anlegen
df_results['extracted_cwes'] = df_results['SAST Result'].apply(extract_cwes)

# "Unnesting / Explode": Mehrfache CWEs in separate Zeilen aufbrechen
df_exploded = df_results.explode('extracted_cwes').rename(columns={'extracted_cwes': 'CWE_ID'})

# Mapping mit der OWASP-Tabelle durchführen
df_merged = df_exploded.merge(df_mapping, on='CWE_ID', how='left')

# ---------------------------------------------------------
# 3. Auswertung 1: Absolute Häufigkeit der OWASP-Kategorien (Gesamt)
# ---------------------------------------------------------
owasp_ranking = (
    df_merged.dropna(subset=['OWASP_Category'])
    ['OWASP_Category']
    .value_counts()
    .reset_index()
)
owasp_ranking.columns = ['OWASP_Kategorie', 'Anzahl_Funde']

print("=== OWASP TOP 10 PRÄVALENZ (GESAMTRANKING) ===")
print(owasp_ranking.to_string(index=False))

# ---------------------------------------------------------
# 4. Auswertung 2: OWASP-Kategorie-Rate (CVR) pro Modell [%]
# ---------------------------------------------------------
# Berechnet, in wie viel % der Prompts eines Modells eine spezifische OWASP-Kategorie auftrat
prompts_per_model = df_results.groupby('model')['prompt_id'].nunique() # oder 'cwe' / 'prompt_name'

owasp_by_model = (
    df_merged.dropna(subset=['OWASP_Category'])
    .groupby(['model', 'OWASP_Category'])['prompt_id'] # eindeutige Prompts zählen
    .nunique()
    .unstack(fill_value=0)
)

# In Prozent umrechnen bezogen auf die Gesamtzahl der Prompts pro Modell
cvr_owasp_pct = owasp_by_model.div(prompts_per_model, axis=0) * 100

print("\n=== OWASP CVR PRO MODELL [%] ===")
print(cvr_owasp_pct)

# ---------------------------------------------------------
# 5. Visualisierung für die Thesis
# ---------------------------------------------------------

# Chart 1: Gesamthäufigkeit der OWASP-Kategorien (Balkendiagramm)
plt.figure(figsize=(10, 5))
ax = sns.barplot(data=owasp_ranking, x='Anzahl_Funde', y='OWASP_Kategorie', palette='Reds_r')
plt.title("Prädominanz der OWASP-Kategorien über alle evaluierten Modelle")
plt.xlabel("Anzahl identifizierter Schwachstellen (SAST Befunde)")
plt.ylabel("OWASP Kategorie")

for p in ax.patches:
    width = p.get_width()
    ax.annotate(f"{int(width)}", 
                (width + 0.3, p.get_y() + p.get_height() / 2.), 
                ha='left', va='center')

plt.tight_layout()
plt.savefig("owasp_prevalence_ranking.pdf", format="pdf")
plt.show()

# Chart 2: Heatmap Modell vs. OWASP Kategorie
plt.figure(figsize=(11, 6))
sns.heatmap(cvr_owasp_pct.T, annot=True, fmt=".1f", cmap="YlOrRd", cbar_kws={'label': 'Prozent der Prompts (%)'})
plt.title("Prävalenz der OWASP-Kategorien nach LLM Modell [%]")
plt.xlabel("Modell")
plt.ylabel("OWASP Kategorie")
plt.tight_layout()
plt.savefig("owasp_model_heatmap.pdf", format="pdf")
plt.show()

# ---------------------------------------------------------
# 6. LaTeX-Export
# ---------------------------------------------------------
print("\n=== LATEX CODE: OWASP RANKING TABLE ===")
print(owasp_ranking.to_latex(
    index=False, 
    caption="Häufigkeitsverteilung der identifizierten Schwachstellen nach OWASP-Kategorien.",
    label="tab:owasp_prevalence"
))