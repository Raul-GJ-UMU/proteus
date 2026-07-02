import os

from src.panoptes.interactor.interactor import Interactor
from src.panoptes.attack_engine.attack_engine import AttackEngine

if __name__ == "__main__":
  interactor = Interactor(
    host="127.0.0.1",
    port=2222,
    username="root",
    password="rootPassword"
  )

  attack_engine = AttackEngine(
    atomics_path=os.path.join("src", "panoptes", "atomics"),
    interactor=interactor,
    enable_metrics=os.getenv("ENABLE_METRICS", "false").lower() == "true",
    metrics_file="attack_metrics.jsonl",
  )

  session_id = os.getenv("SESSION_ID", "default_session")

  attack_engine.run_simulation(session_id=session_id)