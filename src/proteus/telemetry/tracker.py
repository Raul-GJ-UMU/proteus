from datetime import datetime, timezone
import json
from pathlib import Path
from pydantic import ValidationError

from src.proteus.engage_engine.engage_parser import EngageParser
from src.proteus.engage_engine.engage_engine import EngageEngine
from src.proteus.correlation_engine.mitre_mapper import MitreMapper
from .models import MitreMapping, NetworkInfo, Session, SessionInfo, AuthenticationInfo, EnvironmentInfo, InteractionInfo
import threading
from loguru import logger

ENGAGE_CONFIDENCE_THRESHOLD = 0.1

logger.add("logs/proteus_tracker.log", rotation="10 MB")

class SessionTracker:
  def __init__(
    self, 
    session_id: str, 
    source_ip: str, 
    source_port: int, 
    client_version: str,
    llm_client,
    llm_model,
    engage_parser: EngageParser,
    decision_engine: EngageEngine
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
    self.mitre_mapper = MitreMapper(llm_client, llm_model)
    self.mitre_mapping: list[MitreMapping] = []
    self.analysis_threads: list[threading.Thread] = []
    self.engage_parser = engage_parser
    self.decision_engine = decision_engine
    self.attack_data = self._load_attack_data()

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

    logger.success(f"Loaded {len(attack_map)} ATT&CK techniques from local JSON data.")
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
      mitre_mapping=None
    )

    self.interactions.append(interaction)

    def background_analisis(command: str):
      try:
        mitre_result = self.mitre_mapper.evaluate_command(command, self.interactions)
        if mitre_result:
          self.interactions[-1].mitre_mapping = mitre_result
          if mitre_result.confidence >= ENGAGE_CONFIDENCE_THRESHOLD:
            engage_details = self.engage_parser.get_engage_activities_for_technique(mitre_result.technique_id)
            description = self.attack_data.get(mitre_result.technique_id, "No description available.")
            try:
              self.decision_engine.evaluate_and_react(command, description, engage_details)
            except ValidationError as e:
              logger.error(f"Error validating fields for command '{command}': {e}")
      except Exception as e:
        logger.error(f"Error during background analysis for command '{command}': {e}")
    
    if command.strip() and not command.startswith("logout") and not command.startswith("exit"):
      ai_thread = threading.Thread(
        target=background_analisis,
        args=(command,),
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