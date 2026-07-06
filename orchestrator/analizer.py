import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import re
from loguru import logger

logger.add("logs/analizer.log", rotation="1 day")

# Estilo profesional para TFM (Tesis)
sns.set_theme(style="whitegrid", context="paper")
plt.rcParams.update({
    'font.size': 11, 
    'axes.titlesize': 13, 
    'axes.labelsize': 11,
    'figure.autolayout': True,
    'figure.dpi': 300
})

os.makedirs("results", exist_ok=True)

logger.info("Cargando datos...")
df_attack = pd.read_json("attack_metrics.jsonl", lines=True)
df_defend = pd.read_json("defend_metrics.jsonl", lines=True)

# ==========================================
# 1. PRE-PROCESAMIENTO Y METADATOS
# ==========================================

def extract_metadata(session_id):
    match = re.search(r'DC-(.*?)_DE-(.*?)_AM-(.*?)_AL(.*?)_i\d+', str(session_id))
    if match:
        return pd.Series([match.group(1), match.group(2), match.group(3), match.group(4)])
    return pd.Series(["Unknown", "Unknown", "Unknown", "Unknown"])

logger.info("Procesando metadatos de las sesiones...")
df_attack[['Def_Corr_Model', 'Def_Engage_Model', 'Attacker_Model', 'Attacker_Level']] = df_attack['session_id'].apply(extract_metadata)
df_defend[['Def_Corr_Model', 'Def_Engage_Model', 'Attacker_Model', 'Attacker_Level']] = df_defend['session_id'].apply(extract_metadata)

df_attack_sessions = df_attack[df_attack['event_type'] == 'attack_simulation'].copy()
df_attack_commands = df_attack[df_attack['event_type'] == 'command'].copy()

df_defend_correlation = df_defend[df_defend['event_type'] == 'correlation'].copy()
df_defend_deception = df_defend[df_defend['event_type'] == 'deception'].copy()

# Ocurrencias para el cruce exacto
df_attack_commands['command_occurrence'] = df_attack_commands.groupby(['session_id', 'command_executed']).cumcount()
df_defend_correlation['command_occurrence'] = df_defend_correlation.groupby(['session_id', 'command']).cumcount()

# Cruce: Atacante vs Correlación
corr_vs_attack = df_defend_correlation.merge(
    df_attack_commands[['session_id', 'command_executed', 'technique', 'command_occurrence']],
    left_on=['session_id', 'command', 'command_occurrence'],
    right_on=['session_id', 'command_executed', 'command_occurrence'],
    how='inner'
)

# Cálculo de exactitud de mapeo (Padre e Hijo)
corr_vs_attack['base_technique'] = corr_vs_attack['technique'].astype(str).str.split('.').str[0]
corr_vs_attack['correct_mapping'] = (
    (corr_vs_attack['predicted_technique'] == corr_vs_attack['technique']) | 
    (corr_vs_attack['predicted_technique'] == corr_vs_attack['base_technique'])
).astype(int)

# Cálculo de éxito en Engaño (Deception) y Categorización de Errores
if 'result' in df_defend_deception.columns:
    df_defend_deception['deception_success'] = (df_defend_deception['result'] == "success").astype(int)

    def categorize_error(row):
        if row.get('result') == "success":
          return 'Éxito'
        elif row.get('result') == "llm_syntax_error":
          return 'Error de sintaxis LLM'
        elif row.get('result') == "llm_execution_error":
          return 'Error de ejecución LLM'
        elif row.get('result') == "Unknown Error":
          return 'Error desconocido'
        else:
          logger.warning(f"Categoría desconocida para result: {row.get('result')}")

    df_defend_deception['status'] = df_defend_deception.apply(categorize_error, axis=1)
else:
    df_defend_deception['deception_success'] = 0
    df_defend_deception['status'] = 'Desconocido (Sin columna result)'


# ==========================================
# 2. GENERACIÓN DE FIGURAS (TFM)
# ==========================================
logger.info("Generando Figuras...")

# --- Fig 1: Barras + IC 95% (Exactitud Mapeo MITRE) ---
plt.figure(figsize=(8, 5))
ax1 = sns.barplot(data=corr_vs_attack, x='Def_Corr_Model', y='correct_mapping', errorbar=('ci', 95), capsize=.1, palette="viridis")
plt.title("Fig 1: Exactitud de Mapeo MITRE por Modelo de Correlación (IC 95%)")
plt.ylabel("Exactitud (0.0 a 1.0)")
plt.xlabel("Modelo de Correlación")
plt.savefig("results/Fig_1_exactitud_mapeo.png")
plt.close()

# --- Fig 2: Dispersión (Confianza vs Exactitud) ---
agg_calib = corr_vs_attack.groupby('Def_Corr_Model').agg(
    confianza_media=('confidence', 'mean'),
    exactitud_media=('correct_mapping', 'mean')
).reset_index()

plt.figure(figsize=(7, 6))
sns.scatterplot(data=agg_calib, y='confianza_media', x='exactitud_media', hue='Def_Corr_Model', s=150, palette="deep")
plt.plot([0, 1], [0, 1], 'k--', label="Calibración Perfecta") # Diagonal
plt.title("Fig 2: Calibración de Modelos (Confianza vs. Exactitud Real)")
plt.ylabel("Confianza Media Declarada por el Modelo")
plt.xlabel("Exactitud Real Media")
plt.xlim(0, 1.05)
plt.ylim(0, 1.05)
plt.legend(loc='lower right')
plt.savefig("results/Fig_2_calibracion_modelos.png")
plt.close()

# --- Fig 3: Boxplot (Distribución de Latencia) ---
plt.figure(figsize=(9, 5))
sns.boxplot(data=df_defend_correlation, x='Def_Corr_Model', y='latency_ms', palette="pastel")
plt.title("Fig 3: Distribución del Coste Temporal (Latencia) por Comando")
plt.ylabel("Latencia (ms)")
plt.xlabel("Modelo de Correlación")
plt.yscale("log") # Escala logarítmica suele ser útil en tiempos de respuesta de red/LLM
plt.savefig("results/Fig_3_boxplot_latencia.png")
plt.close()

# --- Fig 4: Tasa de éxito JSON y Desglose de Engaño (Trampa) ---
fig, (ax_bar, ax_stack) = plt.subplots(1, 2, figsize=(15, 6))

# Fig 4a: Barras con IC 95% de éxito (Corregido para usar df_defend_deception)
sns.barplot(data=df_defend_deception, x='Def_Engage_Model', y='deception_success', errorbar=('ci', 95), capsize=.1, palette="mako", ax=ax_bar)
ax_bar.set_title("Fig 4a: Tasa de Éxito al Generar Trampa Válida")
ax_bar.set_ylabel("Tasa de Éxito (0 a 1)")
ax_bar.set_xlabel("Modelo de Engaño")

# Fig 4b: Stacked Bar (Desglose)
breakdown = pd.crosstab(df_defend_deception['Def_Engage_Model'], df_defend_deception['status'], normalize='index') * 100
breakdown.plot(kind='bar', stacked=True, ax=ax_stack, colormap='tab20')
ax_stack.set_title("Fig 4b: Desglose de Respuestas")
ax_stack.set_ylabel("Porcentaje (%)")
ax_stack.set_xlabel("Modelo de Engaño")

# Ajuste de la leyenda para que los nombres descriptivos se lean bien
ax_stack.legend(title="Estado", bbox_to_anchor=(1.05, 1), loc='upper left', fontsize='small')

plt.tight_layout()
plt.savefig("results/Fig_4_exito_y_desglose_trampa.png")
plt.close()

# --- Fig 5: Heatmaps Combinados (Credibilidad y Comandos Totales) ---
fig, (ax_cred, ax_cmd) = plt.subplots(1, 2, figsize=(14, 6))

# Fig 5a: Credibilidad Media
heatmap_credibility = df_attack_sessions.pivot_table(index='Def_Corr_Model', columns='Def_Engage_Model', values='avg_credibility', aggfunc='mean')
sns.heatmap(heatmap_credibility, annot=True, cmap='YlGnBu', fmt=".3f", vmin=0, vmax=1, ax=ax_cred)
ax_cred.set_title("Fig 5a: Credibilidad Media Global")
ax_cred.set_ylabel("Modelo de Correlación")
ax_cred.set_xlabel("Modelo de Engaño")

# Fig 5b: Tasa de detección
heatmap_detection = df_attack_sessions.pivot_table(index='Def_Corr_Model', columns='Def_Engage_Model', values='detected_honeypot', aggfunc='mean')
sns.heatmap(heatmap_detection, annot=True, cmap='YlGnBu', fmt=".3f", vmin=0, vmax=1, ax=ax_cmd)
ax_cmd.set_title("Fig 5b: Tasa de Detección por Sesión (Promedio)")
ax_cmd.set_ylabel("Modelo de Correlación")
ax_cmd.set_xlabel("Modelo de Engaño")

plt.tight_layout()
plt.savefig("results/Fig_5_heatmaps_credibilidad_y_deteccion.png")
plt.close()

# --- Fig 6: Gráfico de Líneas con Marcadores (Nivel de Atacante) ---
# Ordenamos los niveles lógicamente si existen
order = ['Beginner', 'Intermediate', 'Advanced']
present_levels = [l for l in order if l in df_attack_sessions['Attacker_Level'].unique()]
if not present_levels: 
  present_levels = df_attack_sessions['Attacker_Level'].unique()

agg_level = df_attack_sessions.groupby('Attacker_Level').agg(
  det_rate=('detected_honeypot', lambda x: x.mean() * 100),
  cred=('avg_credibility', 'mean')
).reindex(present_levels).reset_index()

fig, ax1 = plt.subplots(figsize=(9, 5))
ax1.set_ylim(0, 100)
ax2 = ax1.twinx()
ax2.set_ylim(0, 1)

sns.lineplot(data=agg_level, x='Attacker_Level', y='det_rate', ax=ax1, color='crimson', marker='o', markersize=10, linewidth=2, label='Tasa de Detección (%)')
sns.lineplot(data=agg_level, x='Attacker_Level', y='cred', ax=ax2, color='royalblue', marker='s', markersize=10, linewidth=2, label='Credibilidad Media')

ax1.set_title("Fig 6: Detección y Credibilidad por Nivel de Atacante")
ax1.set_xlabel("Nivel del Atacante")
ax1.set_ylabel("Tasa de Detección del Honeypot (%)", color='crimson')
ax2.set_ylabel("Credibilidad Media (0-1)", color='royalblue')
ax1.grid(axis='x')

# Unir leyendas
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc='lower right')
ax2.get_legend().remove() # type: ignore

plt.savefig("results/Fig_6_tendencia_atacante.png")
plt.close()


# ==========================================
# 3. GENERACIÓN DE TABLAS NUMÉRICAS (CSV y XLSX)
# ==========================================
logger.info("Generando Tablas Numéricas...")

def calc_ic95(p, n):
    """Calcula el Intervalo de Confianza al 95% para una proporción"""
    return 1.96 * np.sqrt((p * (1 - p)) / n) if n > 0 else 0.0

# --- Tabla 2: Rendimiento Modelos Correlación ---
t2_data = []
for model in df_defend_correlation['Def_Corr_Model'].unique():
    model_corr = df_defend_correlation[df_defend_correlation['Def_Corr_Model'] == model]
    model_vs_attack = corr_vs_attack[corr_vs_attack['Def_Corr_Model'] == model]
    
    n_total = len(model_corr)
    n_mapped = len(model_vs_attack)
    
    p_exact = model_vs_attack['correct_mapping'].mean() if n_mapped > 0 else 0
    ic_exact = calc_ic95(p_exact, n_mapped) * 100
    
    # % Error JSON: Comandos donde 'mitre_mapping_error' no es null
    n_errores = model_corr['mitre_mapping_error'].notnull().sum()
    pct_error = (n_errores / n_total * 100) if n_total > 0 else 0
    
    t2_data.append({
        'Modelo Correlación': model,
        'n (Comandos)': n_total,
        'Exactitud (%)': round(p_exact, 2),
        'IC95% (±%)': round(ic_exact, 2),
        'Confianza Media': round(model_vs_attack['confidence'].mean(), 3),
        'Latencia Media (s)': round(model_corr['latency_ms'].mean() / 1000, 2),
        '% Error JSON': round(pct_error, 2)
    })
df_t2 = pd.DataFrame(t2_data)

# --- Tabla 3: Rendimiento Modelos Engaño (Deception) ---
t3_data = []
for model in df_defend_deception['Def_Engage_Model'].unique():
    model_decept = df_defend_deception[df_defend_deception['Def_Engage_Model'] == model]
    
    n = len(model_decept)
    p_success = model_decept['deception_success'].mean() if n > 0 else 0
    ic_success = calc_ic95(p_success, n) * 100
    
    errores_sintaxis = model_decept[model_decept['status'] == 'Error de sintaxis LLM']
    errores_ejecucion = model_decept[model_decept['status'] == 'Error de ejecución LLM']
    errores_desconocidos = model_decept[model_decept['status'] == 'Error desconocido']

    t3_data.append({
        'Modelo Engaño': model,
        'n (Eventos)': n,
        'Tasa Éxito (%)': round(p_success * 100, 2),
        'IC95% (±%)': round(ic_success, 2),
        'Errores de Sintaxis': len(errores_sintaxis),
        'Errores de Ejecución': len(errores_ejecucion),
        'Errores desconocidos': len(errores_desconocidos)
    })
df_t3 = pd.DataFrame(t3_data)

# --- Tabla 4: Combinaciones DC x DE ---
t4_data = []
for (dc, de), group in df_attack_sessions.groupby(['Def_Corr_Model', 'Def_Engage_Model']):
    t4_data.append({
        'Correlación': dc,
        'Engaño': de,
        'n (Sesiones)': len(group),
        'Credibilidad Media': round(group['avg_credibility'].mean(), 3),
        'Tasa Detección (%)': round(group['detected_honeypot'].mean() * 100, 2)
    })
df_t4 = pd.DataFrame(t4_data)

# --- Tabla 5: Resumen Nivel Atacante ---
t5_data = []
for level in df_attack_sessions['Attacker_Level'].unique():
    group = df_attack_sessions[df_attack_sessions['Attacker_Level'] == level]
    n = len(group)
    
    p_det = group['detected_honeypot'].mean() if n > 0 else 0
    ic_det = calc_ic95(p_det, n) * 100
    
    t5_data.append({
        'Nivel Atacante': level,
        'n (Sesiones)': n,
        'Detección (%)': round(p_det * 100, 2),
        'IC95% (±%)': round(ic_det, 2),
        'Credibilidad Media': round(group['avg_credibility'].mean(), 3),
        'Nº Comandos Medio': round(group['total_commands'].mean(), 1),
        'Tiempo Medio (s)': round(group['time_elapsed_sec'].mean(), 2)
    })
df_t5 = pd.DataFrame(t5_data)

# Exportar a CSV
df_t2.to_excel("results/Tabla_2_Correlacion.xlsx", index=False)
df_t3.to_excel("results/Tabla_3_Engano.xlsx", index=False)
df_t4.to_excel("results/Tabla_4_Combinaciones.xlsx", index=False)
df_t5.to_excel("results/Tabla_5_Niveles.xlsx", index=False)

# Exportar todo a un único Excel consolidado
try:
    with pd.ExcelWriter("results/Tablas_TFM_Consolidadas.xlsx") as writer:
        df_t2.to_excel(writer, sheet_name="Tabla 2 - Correlación", index=False)
        df_t3.to_excel(writer, sheet_name="Tabla 3 - Engaño", index=False)
        df_t4.to_excel(writer, sheet_name="Tabla 4 - Combinaciones", index=False)
        df_t5.to_excel(writer, sheet_name="Tabla 5 - Niveles", index=False)
    logger.success("Generado Excel consolidado: Tablas_TFM_Consolidadas.xlsx")
except ModuleNotFoundError:
    logger.warning("Falta la librería openpyxl para generar Excel. Ejecuta: pip install openpyxl")
except Exception as e:
    logger.error(f"Error generando Excel: {e}")

logger.success("¡Análisis científico finalizado! Todas las gráficas y tablas están en /results/")