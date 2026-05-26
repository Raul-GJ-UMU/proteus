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
    interactor=interactor
  )

  attack_engine.run_simulation(config_path=os.path.join("src", "panoptes", "attack_engine", "config.yaml"))