import paramiko
import os
from numpy import random
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
    self.oracle_client = None
    self._connect_oracle()
    
    seed_val = os.getenv("PANOPTES_SEED")
    if seed_val is not None:
        random.seed(int(seed_val))

  def _is_linux_supported(self, test: dict) -> bool:
    supported_platforms = [platform.lower() for platform in test.get("supported_platforms", [])]
    return not supported_platforms or "linux" in supported_platforms

  def _connect_oracle(self) -> bool:
    oracle_host = os.getenv("ORACLE_HOST")
    
    if not oracle_host:
      logger.info("ORACLE_HOST not defined. Oracle Differential Testing is disabled.")
      return False
      
    try:
      self.oracle_client = paramiko.SSHClient()
      self.oracle_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      
      self.oracle_client.connect(
        hostname=oracle_host,
        port=int(os.getenv("ORACLE_PORT", 22)),
        username=os.getenv("ORACLE_USER", "ubuntu"),
        password=os.getenv("ORACLE_PASS", "ubuntu"),
        timeout=10
      )
      logger.success(f"Connected to Oracle VM at {oracle_host}")
      return True
      
    except Exception as e:
      logger.warning(f"Failed to connect to Oracle VM: {e}")
      self.oracle_client = None
      return False

  def _get_oracle_output(self, command: str) -> str:
    if not self.oracle_client:
      logger.warning("Oracle client not connected. Skipping oracle output retrieval.")
      return "ORACLE_NOT_CONNECTED"
      
    try:
      stdin, stdout, stderr = self.oracle_client.exec_command(command, timeout=15)
      
      out = stdout.read().decode('utf-8', errors='ignore')
      err = stderr.read().decode('utf-8', errors='ignore')
      
      return (out + err).strip()
    except Exception as e:
      logger.error(f"Error executing command on Oracle VM: {e}")
      return "ORACLE_TIMEOUT_OR_ERROR"
  
  def add_arguments_to_commands(self, commands: str, input_args: dict) -> str:
    for arg_name, arg_details in input_args.items():
      default_value = arg_details.get("default", "")
      placeholder = f"#{{{arg_name}}}"
      commands = commands.replace(placeholder, str(default_value))
    return commands

  def run_simulation(self, session_id: str):
    logger.info(f"--- Starting Session: {session_id} ---")
    
    if not self.interactor.connect():
      logger.error("Failed to connect to target. Aborting simulation.")
      return
    
    start_time = time.time()
    total_commands = 0
    credibility_scores = []
    honeypot_detected = False
    executed_techniques = []
    
    try:
      for technique_id in self.techniques:
        executed_techniques.append(technique_id)
        logger.info(f"Executing technique: {technique_id}")
        honeypot_detected_in_technique, cmds_run, scores = self.execute_technique(session_id, technique_id)
        total_commands += cmds_run
        credibility_scores.extend(scores)
        if honeypot_detected_in_technique:
          honeypot_detected = True

    except Exception as e:
      logger.error(f"Error during simulation: {e}")

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
        "techniques": executed_techniques,
        "avg_credibility": round(avg_credibility, 3)
      }

      with open(self.metrics_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(metrics_data) + "\n")
      
      logger.info("Attack simulation completed and disconnected from target.")

  def execute_technique(self, session_id: str, technique_id: str) -> tuple[bool, int, list]:
    # Return true if technique executed successfully and output appears credible, false otherwise
    technique_path = os.path.join(self.atomics_path, technique_id, f"{technique_id}.yaml")

    if not os.path.exists(technique_path):
      logger.error(f"YAML file not found for technique: {technique_id}")
      return False, 0, []
    
    try:
      with open(technique_path, "r", encoding="utf-8") as f:
        technique_data = yaml.safe_load(f)
    except Exception as e:
      logger.error(f"Failed to load technique {technique_id}: {e}")
      return False, 0, []
    
    atomic_tests = technique_data.get("atomic_tests", [])

    commands_executed = 0
    credibility_scores = []
    technique_honeypot_detected = False

    # Remove non-Linux supported tests to avoid unnecessary execution and errors.
    atomic_tests = [test for test in atomic_tests if self._is_linux_supported(test)]

    # Execute only one random test, for faster execution
    if os.getenv("PANOPTES_SELECT_RANDOM_TEST", "false").lower() == "true":
      test = random.choice(atomic_tests) if atomic_tests else None
      atomic_tests = [test] if test else []
    
    for test in atomic_tests:
      executor = test.get("executor", {})
      raw_commands = executor.get("command")

      if not raw_commands:
        continue

      input_args = test.get("input_arguments", {})
      raw_commands = self.add_arguments_to_commands(raw_commands, input_args)

      test_honeypot_detected = False

      for command in raw_commands.split("\n"):
        command = command.strip()
        if not command or command.startswith("#"):
          continue

        oracle_output = self._get_oracle_output(command)

        output = self.interactor.execute_command(command)
        commands_executed += 1

        evaluation_result = self.analyzer.analyze_response(command, output, oracle_output)
        credibility_scores.append(evaluation_result.score)

        logger.info(f"Command: {command}\nOutput: {output}\nCredibility Score: {evaluation_result.score:.2f}\nReasoning: {evaluation_result.reasoning}")

        if evaluation_result.score < self.analyzer.threshold:
          logger.warning(f"Low credibility score for command: {command}. Output may not be consistent with a real Linux system.")
          test_honeypot_detected = True
          technique_honeypot_detected = True
        
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
          "detected_honeypot": test_honeypot_detected,
        }

        with open(self.metrics_file, "a", encoding="utf-8") as f:
          f.write(json.dumps(metrics_data) + "\n")

        if test_honeypot_detected:
          break # Stop this test, but continue with the next test in the technique.
      
      cleanup_commands = executor.get("cleanup_command")

      if not cleanup_commands:
        continue

      input_args = test.get("input_arguments", {})
      cleanup_commands = self.add_arguments_to_commands(cleanup_commands, input_args)

      for command in cleanup_commands.split("\n"):
        command = command.strip()
        if not command or command.startswith("#"):
          continue
        self._get_oracle_output(command)
        # No need to execute cleanup commands on the proteus, as it is going to be reset after each session.
    return technique_honeypot_detected, commands_executed, credibility_scores