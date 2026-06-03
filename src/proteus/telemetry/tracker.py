from datetime import datetime, timezone

from src.proteus.correlation_engine.mitre_mapper import MitreMapper
from .models import MitreMapping, NetworkInfo, Session, SessionInfo, AuthenticationInfo, EnvironmentInfo, InteractionInfo
import threading
from loguru import logger

logger.add("logs/proteus_tracker.log", rotation="10 MB")

class SessionTracker:
  def __init__(self, session_id: str, source_ip: str, source_port: int, client_version: str):
    self.session_id = session_id
    self.start_time = datetime.now(timezone.utc)

    self.network_info = NetworkInfo(
      source_ip=source_ip,
      source_port=source_port,
      ssh_client=client_version
    )
    self.env_info = None
    self.auth_info = None
    self.interactions = []
    self.mitre_mapper = MitreMapper()
    self.mitre_mapping: list[MitreMapping] = []
    self.analysis_threads: list[threading.Thread] = []
  
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
    )

    self.interactions.append(interaction)

    def background_analisis(command: str):
      try:
        mitre_result = self.mitre_mapper.evaluate_command(command)
        if mitre_result:
          logger.info(f"MITRE mapping for command '{command}': {mitre_result}")
          self.mitre_mapping = mitre_result
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
      mitre_mapping=self.mitre_mapping,
      session_metadata=session_meta
    )
    logger.info(f"Finalizing session: {self.session_id}")
    session_json = session_data.model_dump_json(indent=2)
    # print(session_json)
    return session_json