import os
import yaml
from loguru import logger

from src.panoptes.deception_engine.credibility_analyzer import CredibilityAnalyzer
from src.panoptes.interactor.interactor import Interactor

logger.add("logs/attack_engine.log", rotation="1 day")

class AttackEngine:
  def __init__(self, atomics_path: str, interactor: Interactor):
    self.interactor = interactor
    self.atomics_path = atomics_path
    self.analyzer = CredibilityAnalyzer()
  
  def run_simulation(self, config_path: str):
    with open(config_path, 'r', encoding='utf-8') as f:
      config = yaml.safe_load(f)
    
    logger.info(f"Starting attack simulation with config: {config_path}")

    if not self.interactor.connect():
      logger.error("Failed to connect to target. Aborting simulation.")
      return
    
    try:
      for technique_id in config.get("techniques", []):
        logger.info(f"Executing technique: {technique_id}")
        if not self.execute_technique(technique_id):
          break
    finally:
      self.interactor.disconnect()
      logger.info("Attack simulation completed and disconnected from target.")
  
  def execute_technique(self, technique_id: str) -> bool:
    # Return true if technique executed successfully and output appears credible, false otherwise
    yaml_file = os.path.join(self.atomics_path, technique_id, f"{technique_id}.yaml")

    if not os.path.exists(yaml_file):
      logger.error(f"YAML file not found for technique: {technique_id}")
      return False
    
    with open(yaml_file, 'r', encoding='utf-8') as f:
      technique_data = yaml.safe_load(f)
    
    for test in technique_data.get("atomic_tests", []):
      executor = test.get("executor", {})
      if executor.get("name") in ["sh", "bash"] and executor.get("command"):
        logger.info(f"Executing atomic test: {test.get('name')}")
        raw_commands = executor.get("command")
        for command in raw_commands.split("\n"):
          command = command.strip()
          if not command or command.startswith("#"):
            continue

          output = self.interactor.execute_command(command)

          credibility_score = self.analyzer.analyze_response(command, output)
          logger.info(f"Command: {command}\nOutput: {output}\nCredibility Score: {credibility_score:.2f}")

          if credibility_score < self.analyzer.threshold:
            logger.warning(f"Low credibility score for command: {command}. Output may not be consistent with a real Linux system.")
            return False
    return True