import os
import yaml
import json
import time
from datetime import datetime, timezone
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

from src.panoptes.deception_engine.credibility_analyzer import CredibilityAnalyzer
from src.panoptes.interactor.interactor import Interactor

logger.add("logs/attack_engine.log", rotation="1 day")

class AttackEngine:
  def __init__(self, atomics_path: str, interactor: Interactor, enable_metrics: bool, metrics_file: str = "attack_metrics.jsonl"):
    self.interactor = interactor
    self.atomics_path = atomics_path
    self.analyzer = CredibilityAnalyzer()
    self.enable_metrics = enable_metrics
    self.metrics_file = metrics_file
    self.level = os.getenv("PANOPTES_LEVEL", "Beginner")
    self.techniques = os.getenv("PANOPTES_TECHNIQUES", "").split(",") if os.getenv("PANOPTES_TECHNIQUES") else []
    logger.info(f"Techniques to execute: {self.techniques}")

  def _is_linux_supported(self, test: dict) -> bool:
    supported_platforms = [platform.lower() for platform in test.get("supported_platforms", [])]
    return not supported_platforms or "linux" in supported_platforms

  def run_simulation(self, session_id: str):
    logger.info(f"--- Starting Session: {session_id} ---")
    
    if not self.interactor.connect():
      logger.error("Failed to connect to target. Aborting simulation.")
      return
    
    start_time = time.time()
    total_commands = 0
    credibility_scores = []
    honeypot_detected = False
    
    try:
      for technique_id in self.techniques:
        logger.info(f"Executing technique: {technique_id}")
        honeypot_detected, cmds_run, scores = self.execute_technique(session_id, technique_id)
        total_commands += cmds_run
        credibility_scores.extend(scores)
        if honeypot_detected:
          break
    finally:
      self.interactor.disconnect()

      time_elapsed = round(time.time() - start_time, 2)
      avg_credibility = sum(credibility_scores) / len(credibility_scores) if credibility_scores else 0.0
      
      metrics_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "llm_model": self.analyzer.model,
        "event_type": "attack_simulation",
        "attacker_level": self.level,
        "total_commands": total_commands,
        "time_elapsed_sec": time_elapsed,
        "detected_honeypot": honeypot_detected,
        "techniques": self.techniques,
        "avg_credibility": round(avg_credibility, 3)
      }

      with open(self.metrics_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(metrics_data) + "\n")
      
      logger.info("Attack simulation completed and disconnected from target.")

  def execute_technique(self, session_id: str, technique_id: str) -> tuple[bool, int, list]:
    # Return true if technique executed successfully and output appears credible, false otherwise
    yaml_file = os.path.join(self.atomics_path, technique_id, f"{technique_id}.yaml")

    if not os.path.exists(yaml_file):
      logger.error(f"YAML file not found for technique: {technique_id}")
      return False, 0, []
    
    with open(yaml_file, 'r', encoding='utf-8') as f:
      technique_data = yaml.safe_load(f)

    commands_executed = 0
    credibility_scores = []
    
    for test in technique_data.get("atomic_tests", []):
      executor = test.get("executor", {})

      if not self._is_linux_supported(test):
        logger.debug(f"Skipping non-Linux atomic test: {test.get('name')}")
        continue

      if executor.get("name") in ["sh", "bash"] and executor.get("command"):
        logger.info(f"Executing atomic test: {test.get('name')}")
        raw_commands = executor.get("command")

        if not raw_commands:
          continue

        input_args = test.get("input_arguments", {})
        for arg_name, arg_details in input_args.items():
          default_value = arg_details.get("default", "")
          placeholder = f"#{{{arg_name}}}"
          raw_commands = raw_commands.replace(placeholder, str(default_value))

        for command in raw_commands.split("\n"):
          command = command.strip()
          if not command or command.startswith("#"):
            continue

          output = self.interactor.execute_command(command)
          commands_executed += 1

          evaluation_result = self.analyzer.analyze_response(command, output)
          credibility_scores.append(evaluation_result.score)

          honeypot_detected = False

          logger.info(f"Command: {command}\nOutput: {output}\nCredibility Score: {evaluation_result.score:.2f}\nReasoning: {evaluation_result.reasoning}")

          if evaluation_result.score < self.analyzer.threshold:
            logger.warning(f"Low credibility score for command: {command}. Output may not be consistent with a real Linux system.")
            honeypot_detected = True

          metrics_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "llm_model": self.analyzer.model,
            "event_type": "command",
            "command_executed": command,
            "attacker_level": self.level,
            "technique": technique_id,
            "error": evaluation_result.error,
            "credibility_score": round(evaluation_result.score, 3),
            "reasoning": evaluation_result.reasoning,
            "detected_honeypot": honeypot_detected,
          }

          with open(self.metrics_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(metrics_data) + "\n")

          if  honeypot_detected:
            return True, commands_executed, credibility_scores
    return False, commands_executed, credibility_scores