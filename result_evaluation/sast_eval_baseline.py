import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

df_results = pd.read_csv("data/results/sast_baseline_results_validated.csv")
df_mapping = pd.read_csv("data/owasp_top10_2025_cwe_mapping.csv")

if "Bewertung" in df_results.columns:
    df_results["is_false_positive"] = (
        df_results["Bewertung"]
        .astype(str)
        .str.strip()
        .str.lower()
        .str.contains("false positive")
    )
    fp_count = df_results["is_false_positive"].sum()
    print(
        f"--> Info: {fp_count} False Positive(s) in der Spalte 'Bewertung' erkannt und herausgefiltert."
    )
else:
    df_results["is_false_positive"] = False

# Determine vulnerability status
def check_is_vulnerable(row):
    if row["is_false_positive"]:
        return False

    sast_result = row["SAST Result"]
    if pd.isna(sast_result):
        return False

    val = str(sast_result).strip()
    if val.upper() == "NONE" or val == "":
        return False
    return True

# Get CWEs from SAST Result
def extract_cwes(row):
    if row["is_false_positive"]:
        return []

    text = row["SAST Result"]
    if pd.isna(text) or not isinstance(text, str):
        return []
    return re.findall(r"CWE-\d+", text)

df_results["is_vulnerable"] = df_results.apply(check_is_vulnerable, axis=1)
df_results["extracted_cwes"] = df_results.apply(extract_cwes, axis=1)

df_exploded = df_results.explode('extracted_cwes').rename(columns={'extracted_cwes': 'CWE_ID'})

df_merged = df_exploded.merge(df_mapping, on='CWE_ID', how='left')

prompts_per_model = df_results.groupby("Model")["Vibe Coding Prompt"].nunique()

# ---------------------------------------------------------
# 1. Code-Level Vulnerability Generation Rate (VGR_SAST) [%]
# ---------------------------------------------------------
vulnerable_prompts_per_model = (
    df_results[df_results["is_vulnerable"]]
    .groupby("Model")["Vibe Coding Prompt"]
    .nunique()
)

vgr_df = (
    pd.DataFrame({"Total_Prompts": prompts_per_model})
    .join(vulnerable_prompts_per_model.rename("Vulnerable_Prompts"), how="left")
    .fillna(0)
)

vgr_df["VGR_SAST"] = (
    vgr_df["Vulnerable_Prompts"] / vgr_df["Total_Prompts"]
) * 100
vgr_df = vgr_df.reset_index()

print("=== CODE-LEVEL VULNERABILITY GENERATION RATE (VGR_SAST) ===")
print(vgr_df[["Model", "Total_Prompts", "Vulnerable_Prompts", "VGR_SAST"]])

# ---------------------------------------------------------
# Count OWASP categories
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
# OWASP-Category-Rate (CVR) a model [%]
# ---------------------------------------------------------
prompts_per_model = df_results.groupby('Model')['Vibe Coding Prompt'].nunique()

owasp_by_model = (
    df_merged.dropna(subset=['OWASP_Category'])
    .groupby(['Model', 'OWASP_Category'])['Vibe Coding Prompt'] # eindeutige Prompts zählen
    .nunique()
    .unstack(fill_value=0)
)
#in percent
cvr_owasp_pct = owasp_by_model.div(prompts_per_model, axis=0) * 100

print("\n=== OWASP CVR PRO MODELL [%] ===")
print(cvr_owasp_pct)

# ---------------------------------------------------------
# Diagrams
# ---------------------------------------------------------

# Chart 1: VGR_SAST pro Modell (Säulendiagramm)
plt.figure(figsize=(9, 5))
ax1 = sns.barplot(data=vgr_df, x="Model", y="VGR_SAST", color="#c0392b")
plt.title(
    "Gesamte Schwachstellen-Generierungsrate (VGR_SAST) im Baseline-Szenario"
)
plt.xlabel("LLM Modell")
plt.ylabel("VGR_SAST (%)")
plt.ylim(0, 110)  # Platz für Annotationen oben lassen

for p in ax1.patches:
    height = p.get_height()
    if not pd.isna(height):
        ax1.annotate(
            f"{height:.1f}%",
            (p.get_x() + p.get_width() / 2.0, height + 2),
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
        )

plt.xticks(rotation=15, ha="right")
plt.tight_layout()
plt.savefig("plots/vgr_sast_by_model.pdf", format="pdf")
plt.show()

# Chart 2: Gesamthäufigkeit der OWASP-Kategorien (Balkendiagramm)
plt.figure(figsize=(10, 5))
ax = sns.barplot(data=owasp_ranking, x="Anzahl_Funde", y="OWASP_Kategorie", color="#c0392b")
plt.title("Prädominanz der OWASP-Kategorien über alle evaluierten Modelle")
plt.xlabel("Anzahl identifizierter Schwachstellen (SAST Befunde)")
plt.ylabel("OWASP Kategorie")

for p in ax.patches:
    width = p.get_width()
    ax.annotate(f"{int(width)}", 
                (width + 0.3, p.get_y() + p.get_height() / 2.), 
                ha='left', va='center')

plt.tight_layout()
plt.savefig("plots/owasp_prevalence_ranking.pdf", format="pdf")
plt.show()

# Chart 3: Heatmap Modell vs. OWASP Kategorie
plt.figure(figsize=(11, 6))
sns.heatmap(cvr_owasp_pct.T, annot=True, fmt=".1f", cmap="YlOrRd", cbar_kws={'label': 'Prozent der Prompts (%)'})
plt.title("Prävalenz der OWASP-Kategorien nach LLM Modell [%]")
plt.xlabel("Modell")
plt.ylabel("OWASP Kategorie")
plt.tight_layout()
plt.savefig("plots/owasp_model_heatmap.pdf", format="pdf")
plt.show()
