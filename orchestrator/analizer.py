import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns
import os
import re
from loguru import logger

logger.add("logs/analizer.log", rotation="1 day")

sns.set_theme(style="whitegrid", context="paper")
plt.rcParams.update({
  'font.size': 11, 
  'axes.titlesize': 13, 
  'axes.labelsize': 11,
  'figure.autolayout': True,
  'figure.dpi': 300
})

os.makedirs("results", exist_ok=True)


def save_figure(base_name):
  plt.savefig(f"results/{base_name}.png", dpi=300, bbox_inches='tight')
  plt.savefig(f"results/{base_name}.svg", bbox_inches='tight')
  plt.savefig(f"results/{base_name}.pdf", bbox_inches='tight')

logger.info("Loading data...")
df_attack = pd.read_json("attack_metrics.jsonl", lines=True)
df_defend = pd.read_json("defend_metrics.jsonl", lines=True)

# ==========================================
# 1. PRE-PROCESSING AND METADATA
# ==========================================

def extract_metadata(session_id):
  match = re.search(r'DC-(.*?)_DE-(.*?)_AM-(.*?)_AL(.*?)_i\d+', str(session_id))
  if match:
    return pd.Series([match.group(1), match.group(2), match.group(3), match.group(4)])
  return pd.Series(["Unknown", "Unknown", "Unknown", "Unknown"])

logger.info("Processing session metadata...")
df_attack[['Def_Corr_Model', 'Def_Engage_Model', 'Attacker_Model', 'Attacker_Level']] = df_attack['session_id'].apply(extract_metadata)
df_defend[['Def_Corr_Model', 'Def_Engage_Model', 'Attacker_Model', 'Attacker_Level']] = df_defend['session_id'].apply(extract_metadata)

df_attack_sessions = df_attack[df_attack['event_type'] == 'attack_simulation'].copy()
df_attack_commands = df_attack[df_attack['event_type'] == 'command'].copy()

df_defend_correlation = df_defend[df_defend['event_type'] == 'correlation'].copy()
df_defend_deception = df_defend[df_defend['event_type'] == 'deception'].copy()

df_defend_correlation['latency_s'] = df_defend_correlation['latency_ms'] / 1000.0

df_attack_commands['command_occurrence'] = df_attack_commands.groupby(['session_id', 'command_executed']).cumcount()
df_defend_correlation['command_occurrence'] = df_defend_correlation.groupby(['session_id', 'command']).cumcount()

corr_vs_attack = df_defend_correlation.merge(
  df_attack_commands[['session_id', 'command_executed', 'technique', 'command_occurrence']],
  left_on=['session_id', 'command', 'command_occurrence'],
  right_on=['session_id', 'command_executed', 'command_occurrence'],
  how='inner'
)

corr_vs_attack['base_technique'] = corr_vs_attack['technique'].astype(str).str.split('.').str[0]
corr_vs_attack['correct_mapping'] = (
  (corr_vs_attack['predicted_technique'] == corr_vs_attack['technique']) | 
  (corr_vs_attack['predicted_technique'] == corr_vs_attack['base_technique'])
).astype(int)

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
# 2. Chart Generation
# ==========================================
logger.info("Generating Charts...")

# --- Fig 1: Bars + IC 95% (MITRE mapping accuracy) ---
plt.figure(figsize=(8, 5))
ax1 = sns.barplot(data=corr_vs_attack, x='Def_Corr_Model', y='correct_mapping', errorbar=('ci', 95), capsize=.1, palette="viridis")
plt.ylabel("Exactitud (0.0 a 1.0)")
plt.xlabel("Modelo de Correlación")
save_figure("Fig_1_exactitud_mapeo")
plt.close()

# --- Fig 2: Dispersion (Conficence vs Accuracy) ---
agg_calib = corr_vs_attack.groupby('Def_Corr_Model').agg(
  confianza_media=('confidence', 'mean'),
  exactitud_media=('correct_mapping', 'mean')
).reset_index()

plt.figure(figsize=(7, 6))
sns.scatterplot(data=agg_calib, y='confianza_media', x='exactitud_media', hue='Def_Corr_Model', s=150, palette="deep")
plt.plot([0, 1], [0, 1], 'k--', label="Calibración Perfecta") # Diagonal
plt.ylabel("Confianza Media Declarada por el Modelo")
plt.xlabel("Exactitud Real Media")
plt.xlim(0, 1.05)
plt.ylim(0, 1.05)
plt.legend(loc='lower right')
save_figure("Fig_2_calibracion_modelos")
plt.close()

# --- Fig 3: Boxplot (Latency Distribution) ---
plt.figure(figsize=(9, 5))
sns.boxplot(data=df_defend_correlation, x='Def_Corr_Model', y='latency_s', palette="pastel")
plt.ylabel("Latencia (s)")
plt.xlabel("Modelo de Correlación")
plt.yscale("log")

ax = plt.gca()
ax.yaxis.set_major_formatter(ticker.FuncFormatter(lambda y, _: '{:g}'.format(y)))

save_figure("Fig_3_boxplot_latencia")
plt.close()

# --- Fig 4: Success Rate (Valid Trap Generation) ---
plt.figure(figsize=(7, 6))
ax_bar = sns.barplot(data=df_defend_deception, x='Def_Engage_Model', y='deception_success', errorbar=('ci', 95), capsize=.1, palette="mako")
ax_bar.set_ylabel("Tasa de Éxito (0 a 1)")
ax_bar.set_xlabel("Modelo de Engaño")
plt.tight_layout()
save_figure("Fig_4_exito_trampa")
plt.close()

# --- Fig 5: Stacked Bar (Error Breakdown) ---
plt.figure(figsize=(9, 6)) 
ax_stack = plt.gca()
breakdown = pd.crosstab(df_defend_deception['Def_Engage_Model'], df_defend_deception['status'], normalize='index') * 100
breakdown.plot(kind='bar', stacked=True, ax=ax_stack, colormap='tab20')
ax_stack.set_ylabel("Porcentaje (%)")
ax_stack.set_xlabel("Modelo de Engaño")
ax_stack.legend(title="Estado", bbox_to_anchor=(1.05, 1), loc='upper left', fontsize='small')
plt.tight_layout()
save_figure("Fig_5_desglose_errores")
plt.close()

# --- Fig 6: Credibility heatmap ---
plt.figure(figsize=(7, 6))
heatmap_credibility = df_attack_sessions.pivot_table(index='Def_Corr_Model', columns='Def_Engage_Model', values='avg_credibility', aggfunc='mean')
ax_cred = sns.heatmap(heatmap_credibility, annot=True, cmap='YlGnBu', fmt=".3f", vmin=0, vmax=1)
ax_cred.set_ylabel("Modelo de Correlación")
ax_cred.set_xlabel("Modelo de Engaño")
plt.tight_layout()
save_figure("Fig_6_heatmap_credibilidad")
plt.close()

# --- Fig 7: Detection heatmap ---
plt.figure(figsize=(7, 6))
heatmap_detection = df_attack_sessions.pivot_table(index='Def_Corr_Model', columns='Def_Engage_Model', values='detected_honeypot', aggfunc='mean')
ax_cmd = sns.heatmap(heatmap_detection, annot=True, cmap='YlGnBu', fmt=".3f", vmin=0, vmax=1)
ax_cmd.set_ylabel("Modelo de Correlación")
ax_cmd.set_xlabel("Modelo de Engaño")
plt.tight_layout()
save_figure("Fig_7_heatmap_deteccion")
plt.close()

# --- Fig 8: Line Plot chart with Markers (Attacker Level) ---
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

ax1.set_xlabel("Nivel del Atacante")
ax1.set_ylabel("Tasa de Detección del Honeypot (%)", color='crimson')
ax2.set_ylabel("Credibilidad Media (0-1)", color='royalblue')
ax1.grid(axis='x')

# Join legends from both axes
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc='lower right')
ax2.get_legend().remove() # type: ignore

save_figure("Fig_8_tendencia_atacante")
plt.close()


# ==========================================
# 3. Table Generation
# ==========================================
logger.info("Generating Numeric Tables...")

def calc_ic95(p, n):
  return 1.96 * np.sqrt((p * (1 - p)) / n) if n > 0 else 0.0

# --- Table 1: Correlation Models Performance ---
t1_data = []
for model in df_defend_correlation['Def_Corr_Model'].unique():
  model_corr = df_defend_correlation[df_defend_correlation['Def_Corr_Model'] == model]
  model_vs_attack = corr_vs_attack[corr_vs_attack['Def_Corr_Model'] == model]
  
  n_total = len(model_corr)
  n_mapped = len(model_vs_attack)
  
  p_exact = model_vs_attack['correct_mapping'].mean() if n_mapped > 0 else 0
  ic_exact = calc_ic95(p_exact, n_mapped) * 100
  
  n_errores = model_corr['mitre_mapping_error'].notnull().sum()
  pct_error = (n_errores / n_total * 100) if n_total > 0 else 0
  
  t1_data.append({
    'Modelo Correlación': model,
    'n (Comandos)': n_total,
    'Exactitud (%)': round(p_exact, 2),
    'IC95% (±%)': round(ic_exact, 2),
    'Confianza Media': round(model_vs_attack['confidence'].mean(), 3),
    'Latencia Media (s)': round(model_corr['latency_ms'].mean() / 1000, 2),
    '% Error JSON': round(pct_error, 2)
  })
df_t1 = pd.DataFrame(t1_data)

# --- Table 2: Deception Models Performance ---
t2_data = []
for model in df_defend_deception['Def_Engage_Model'].unique():
  model_decept = df_defend_deception[df_defend_deception['Def_Engage_Model'] == model]
  
  n = len(model_decept)
  p_success = model_decept['deception_success'].mean() if n > 0 else 0
  ic_success = calc_ic95(p_success, n) * 100
  
  errores_sintaxis = model_decept[model_decept['status'] == 'Error de sintaxis LLM']
  errores_ejecucion = model_decept[model_decept['status'] == 'Error de ejecución LLM']
  errores_desconocidos = model_decept[model_decept['status'] == 'Error desconocido']

  t2_data.append({
    'Modelo Engaño': model,
    'n (Eventos)': n,
    'Tasa Éxito (%)': round(p_success * 100, 2),
    'IC95% (±%)': round(ic_success, 2),
    'Errores de Sintaxis': len(errores_sintaxis),
    'Errores de Ejecución': len(errores_ejecucion),
    'Errores desconocidos': len(errores_desconocidos)
  })
df_t2 = pd.DataFrame(t2_data)

# --- Table 3: DC x DE Combinations ---
t3_data = []
for (dc, de), group in df_attack_sessions.groupby(['Def_Corr_Model', 'Def_Engage_Model']):
  t3_data.append({
    'Correlación': dc,
    'Engaño': de,
    'n (Sesiones)': len(group),
    'Credibilidad Media': round(group['avg_credibility'].mean(), 3),
    'Tasa Detección (%)': round(group['detected_honeypot'].mean() * 100, 2)
  })
df_t3 = pd.DataFrame(t3_data)

# --- Table 4: Attacker Level Summary ---
t4_data = []
for level in df_attack_sessions['Attacker_Level'].unique():
  group = df_attack_sessions[df_attack_sessions['Attacker_Level'] == level]
  n = len(group)
  
  p_det = group['detected_honeypot'].mean() if n > 0 else 0
  ic_det = calc_ic95(p_det, n) * 100
  
  t4_data.append({
    'Nivel Atacante': level,
    'n (Sesiones)': n,
    'Detección (%)': round(p_det * 100, 2),
    'IC95% (±%)': round(ic_det, 2),
    'Credibilidad Media': round(group['avg_credibility'].mean(), 3),
    'Nº Comandos Medio': round(group['total_commands'].mean(), 1),
    'Tiempo Medio (s)': round(group['time_elapsed_sec'].mean(), 2)
  })
df_t4 = pd.DataFrame(t4_data)

# --- Table 5: Proteus configurations by attacker level ---
config_session = df_attack_sessions[['session_id', 'Def_Corr_Model', 'Def_Engage_Model', 'Attacker_Level', 'avg_credibility', 'detected_honeypot', 'total_commands', 'time_elapsed_sec']].copy()

session_corr = corr_vs_attack.groupby(['session_id', 'Def_Corr_Model', 'Def_Engage_Model', 'Attacker_Level']).agg(
  correlacion_exacta=('correct_mapping', 'mean'),
  confianza_correlacion=('confidence', 'mean'),
  latencia_correlacion_ms=('latency_ms', 'mean')
).reset_index()

config_metrics = config_session.merge(
  session_corr,
  on=['session_id', 'Def_Corr_Model', 'Def_Engage_Model', 'Attacker_Level'],
  how='left'
)

all_configs = pd.MultiIndex.from_product(
  [sorted(df_attack_sessions['Def_Corr_Model'].dropna().unique()),
   sorted(df_attack_sessions['Def_Engage_Model'].dropna().unique()),
   order],
  names=['Def_Corr_Model', 'Def_Engage_Model', 'Attacker_Level']
)

df_t5 = (
  config_metrics.groupby(['Def_Corr_Model', 'Def_Engage_Model', 'Attacker_Level'])
  .agg(
    n_sesiones=('session_id', 'nunique'),
    exactitud_correlacion=('correlacion_exacta', 'mean'),
    confianza_correlacion=('confianza_correlacion', 'mean'),
    latencia_correlacion_ms=('latencia_correlacion_ms', 'mean'),
    credibilidad_media=('avg_credibility', 'mean'),
    tasa_deteccion=('detected_honeypot', 'mean'),
    num_comandos_medio=('total_commands', 'mean'),
    tiempo_medio_s=('time_elapsed_sec', 'mean')
  )
  .reindex(all_configs)
  .reset_index()
)

df_t5['n_sesiones'] = df_t5['n_sesiones'].fillna(0).astype(int)
df_t5['exactitud_correlacion'] = df_t5['exactitud_correlacion'].round(3)
df_t5['confianza_correlacion'] = df_t5['confianza_correlacion'].round(3)
df_t5['latencia_correlacion_ms'] = df_t5['latencia_correlacion_ms'].round(2)
df_t5['credibilidad_media'] = df_t5['credibilidad_media'].round(3)
df_t5['tasa_deteccion'] = (df_t5['tasa_deteccion'] * 100).round(2)
df_t5['num_comandos_medio'] = df_t5['num_comandos_medio'].round(1)
df_t5['tiempo_medio_s'] = df_t5['tiempo_medio_s'].round(2)
df_t5 = df_t5.rename(columns={
  'Def_Corr_Model': 'Modelo Correlación',
  'Def_Engage_Model': 'Modelo Engaño',
  'Attacker_Level': 'Nivel Atacante',
  'exactitud_correlacion': 'Exactitud Correlación',
  'confianza_correlacion': 'Confianza Correlación',
  'latencia_correlacion_ms': 'Latencia Correlación (ms)',
  'credibilidad_media': 'Credibilidad Media',
  'tasa_deteccion': 'Tasa Detección (%)',
  'num_comandos_medio': 'Nº Comandos Medio',
  'tiempo_medio_s': 'Tiempo Medio (s)'
})

try:
  with pd.ExcelWriter("results/Tablas.xlsx") as writer:
    df_t1.to_excel(writer, sheet_name="Tabla 1 - Correlación", index=False)
    df_t2.to_excel(writer, sheet_name="Tabla 2 - Engaño", index=False)
    df_t3.to_excel(writer, sheet_name="Tabla 3 - Combinaciones", index=False)
    df_t4.to_excel(writer, sheet_name="Tabla 4 - Niveles", index=False)
    df_t5.to_excel(writer, sheet_name="Tabla 5 - Configuraciones", index=False)
  logger.success("Excel file 'results/Tablas.xlsx' generated successfully.")
except ModuleNotFoundError:
  logger.warning("library openpyx is needed to generate Excel files. Run: pip install openpyxl")
except Exception as e:
  logger.error(f"Error generating Excel file: {e}")