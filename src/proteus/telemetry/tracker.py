from datetime import datetime, timezone
import json
import os
from pathlib import Path
from pydantic import ValidationError
import time

from src.proteus.engage_engine.engage_parser import EngageParser
from src.proteus.engage_engine.engage_engine import EngageEngine
from src.proteus.correlation_engine.mitre_mapper import MitreMapper
from .models import MitreMapping, NetworkInfo, Session, SessionInfo, AuthenticationInfo, EnvironmentInfo, InteractionInfo, MitreMappingError
import threading
from loguru import logger

DEFAULT_ENGAGE_CONFIDENCE_THRESHOLD = 0.6

logger.add("logs/proteus_tracker.log", rotation="10 MB")

class SessionTracker:
  def __init__(
    self, 
    session_id: str, 
    source_ip: str, 
    source_port: int, 
    client_version: str,
    llm_client,
    engage_parser: EngageParser,
    engage_engine: EngageEngine
  ):
    self.session_id = session_id
    self.start_time = datetime.now(timezone.utc)

    self.network_info = NetworkInfo(
      source_ip=source_ip,
      source_port=source_port,
      ssh_client=client_version
    )
    self.env_info = None
    self.auth_info = None
    self.interactions: list[InteractionInfo] = []
    self.attack_data = self._load_attack_data()
    self.mitre_mapper = MitreMapper(llm_client, os.getenv("PROTEUS_CORRELATION_MODEL", "phi3"), list(self.attack_data.keys()))
    self.mitre_mapping: list[MitreMapping] = []
    self.analysis_threads: list[threading.Thread] = []
    self.engage_parser = engage_parser
    self.engage_engine = engage_engine
    self.enable_metrics = os.getenv("ENABLE_METRICS", "false").lower() == "true"
    if self.enable_metrics:
      self.metrics_file = os.getenv("METRICS_FILE", "defend_metrics.jsonl")
    self.engage_engine_confidence_threshold = float(os.getenv("PROTEUS_ENGAGE_ENGINE_THRESHOLD", DEFAULT_ENGAGE_CONFIDENCE_THRESHOLD))

  def _load_attack_data(self) -> dict[str, str]:
    attack_file = Path("enterprise-attack.json")
    if not attack_file.exists():
      logger.warning(f"ATT&CK data file not found: {attack_file}")
      return {}

    try:
      with attack_file.open("r", encoding="utf-8") as file_handle:
        bundle = json.load(file_handle)
    except Exception as exc:
      logger.error(f"Failed to load ATT&CK data from {attack_file}: {exc}")
      return {}

    attack_map: dict[str, str] = {}
    for obj in bundle.get("objects", []):
      if obj.get("type") != "attack-pattern":
        continue

      external_refs = obj.get("external_references", [])
      attack_id = None
      for reference in external_refs:
        if reference.get("source_name") == "mitre-attack":
          attack_id = reference.get("external_id")
          break

      if not attack_id:
        continue

      description = obj.get("description", "No description available.")
      attack_map[str(attack_id)] = str(description)

    return attack_map

  def add_ssh_client(self, client_version: str):
    self.network_info.ssh_client = client_version

  def add_authentication(self, username: str, password: str):
    self.auth_info = AuthenticationInfo(
      username=username,
      password=password,
      timestamp=datetime.now(timezone.utc)
    )
  
  def add_environment(self, terminal_type: str, shell_width: int, shell_height: int):
    self.env_info = EnvironmentInfo(
      terminal_type=terminal_type,
      shell_width=shell_width,
      shell_height=shell_height
    )

  def add_interaction(self, command: str, backspaces: int):
    interaction = InteractionInfo(
      command=command,
      timestamp=datetime.now(timezone.utc),
      backspaces=backspaces,
      mitre_mapping=None,
      engage_details=None
    )

    self.interactions.append(interaction)

    def background_analisis(command: str, target_interaction: InteractionInfo):
      try:
        start_time = time.time()

        mitre_result = self.mitre_mapper.evaluate_command(command, self.interactions)

        is_error = isinstance(mitre_result, MitreMappingError)

        if is_error:
          logger.error(f"MITRE mapping error for command '{command}': {mitre_result.error_type} - {mitre_result.error_message}")

        latency_ms = round((time.time() - start_time) * 1000, 2)

        if self.enable_metrics:
          metrics_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "session_id": self.session_id,
            "llm_model": self.mitre_mapper.llm_model,
            "event_type": "correlation",
            "command": command,
            "command_history": [interaction.command for interaction in self.interactions],
            "mitre_mapping_error": mitre_result.error_type if is_error else None,
            "predicted_technique": mitre_result.technique_id if not is_error and mitre_result else None,
            "confidence": mitre_result.confidence if not is_error and mitre_result else 0.0,
            "latency_ms": latency_ms
          }
          with open(self.metrics_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(metrics_data) + "\n")

        if not is_error:
          target_interaction.mitre_mapping = mitre_result
          if mitre_result.confidence >= self.engage_engine_confidence_threshold:
            engage_details = self.engage_parser.get_engage_activities_for_technique(mitre_result.technique_id)
            if len(engage_details) == 0:
              logger.warning(f"No Engage activities found for MITRE technique '{mitre_result.technique_id}' for command '{command}'.")
              return
            description = self.attack_data.get(mitre_result.technique_id, "No description available.")
            try:
              engage_result = self.engage_engine.evaluate_and_react(self.session_id, command, description, engage_details)
              target_interaction.engage_details = engage_result
            except ValidationError as e:
              logger.error(f"Error validating fields for command '{command}': {e}")
      except Exception as e:
        logger.error(f"Error during background analysis for command '{command}': {e}")
    
    if command.strip() and not command.startswith("logout") and not command.startswith("exit"):
      ai_thread = threading.Thread(
        target=background_analisis,
        args=(command, interaction),
        daemon=True
      )
      self.analysis_threads.append(ai_thread)
      ai_thread.start()

  
  def finalize_and_export(self, exit_reason: str):
    if self.analysis_threads:
      logger.info(f"Syncronizing threads: Waiting for {len(self.analysis_threads)} MITRE analyses to complete...")
      for thread in self.analysis_threads:
        if thread.is_alive():
          thread.join()
      logger.success("All background analyses have completed.")
    
    session_meta = SessionInfo(
      start_time=self.start_time,
      end_time=datetime.now(timezone.utc),
      total_commands=len(self.interactions),
      exit_reason=exit_reason
    )

    if not self.auth_info:
      raise ValueError("Authentication information is missing. Cannot finalize session without authentication data.")
    
    if not self.env_info:
      raise ValueError("Environment information is missing. Cannot finalize session without environment data.")

    session_data = Session(
      session_id=self.session_id,
      network=self.network_info,
      environment=self.env_info,
      authentication=self.auth_info,
      interactions=self.interactions,
      session_metadata=session_meta
    )
    logger.info(f"Finalizing session: {self.session_id}")
    session_json = session_data.model_dump_json(indent=2)
    # print(session_json)
    return session_json