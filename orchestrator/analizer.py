import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os
import re

from loguru import logger

logger.add("logs/analizer.log", rotation="1 day")

sns.set_theme(style="whitegrid")
plt.rcParams.update({'font.size': 12, 'figure.autolayout': True})

os.makedirs("results", exist_ok=True)

logger.info("Loading data...")
df_attack = pd.read_json("attack_metrics.jsonl", lines=True)
df_defend = pd.read_json("defend_metrics.jsonl", lines=True)

# 1. PRE-PROCESSING

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

# 2. CHART GENERATION

logger.info("Generating charts...")

# --- Chart 1: Detection rate per engage model ---
plt.figure(figsize=(10, 6))
detection_rate = df_attack_sessions.groupby('Def_Engage_Model')['detected_honeypot'].mean() * 100
ax = sns.barplot(x=detection_rate.index, y=detection_rate.values, palette="viridis")
plt.title("Detection Rate of the Honeypot by Engagement Model")
plt.ylabel("Detection Rate (%)")
plt.xlabel("Defender Model (Engage)")
for p in ax.patches:
  ax.annotate(f'{p.get_height():.1f}%', (p.get_x() + p.get_width() / 2., p.get_height()), ha='center', va='bottom') # type: ignore
plt.savefig("results/1_detection_rate.png", dpi=300)
plt.close()

# --- Chart 2: Average Credibility by Attacker Level ---
plt.figure(figsize=(10, 6))
sns.boxplot(data=df_attack_sessions, x="Attacker_Level", y="avg_credibility", hue="Def_Engage_Model", palette="Set2")
plt.title("Credibility score by Attacker level")
plt.ylabel("Average Credibility (0.0 a 1.0)")
plt.xlabel("Attacker Level")
plt.legend(title="defender Model")
plt.savefig("results/2_level_credibility.png", dpi=300)
plt.close()

# --- Chart 3: Correlation engine latency ---
plt.figure(figsize=(10, 6))
df_defend['latency_sec'] = df_defend['latency_ms'] / 1000.0
sns.boxplot(data=df_defend, x="Def_Corr_Model", y="latency_sec", palette="magma")
plt.title("Correlation model latency")
plt.ylabel("Response Time (seconds)")
plt.xlabel("Defender Model (Correlation)")
plt.savefig("results/3_correlation_latency.png", dpi=300)
plt.close()

# --- Chart 4: Error Rate in MITRE Mapping ---
plt.figure(figsize=(10, 6))
df_defend['has_error'] = df_defend['mitre_mapping_error'].notna()
error_rate = df_defend.groupby('Def_Corr_Model')['has_error'].mean() * 100
ax2 = sns.barplot(x=error_rate.index, y=error_rate.values, palette="rocket")
plt.title("Error/Hallucinaton rate for MITRE Mapping")
plt.ylabel("Error Rate (%)")
plt.xlabel("Defender Model (Correlation)")
for p in ax2.patches:
  ax2.annotate(f'{p.get_height():.1f}%', (p.get_x() + p.get_width() / 2., p.get_height()), ha='center', va='bottom') # type: ignore
plt.savefig("results/4_mapping_errors.png", dpi=300)
plt.close()

# 3. Table Generation (CSV)
logger.info("Generating summary tables...")

# Resumen general por combinación exacta de modelos
summary_table = df_attack_sessions.groupby(['Def_Corr_Model', 'Def_Engage_Model', 'Attacker_Model']).agg(
  Total_Sessions=('session_id', 'count'),
  Honeypot_Detection_Rate=('detected_honeypot', 'mean'),
  Average_Credibility=('avg_credibility', 'mean'),
  Average_Simulation_Time=('time_elapsed_sec', 'mean')
).reset_index()

summary_table['Honeypot_Detection_Rate'] = summary_table['Honeypot_Detection_Rate'] * 100

summary_table.to_csv("results/simulation_summary.csv", index=False)
summary_table.to_excel("results/simulation_summary.xlsx", index=False)

logger.info("Summary tables generated.")