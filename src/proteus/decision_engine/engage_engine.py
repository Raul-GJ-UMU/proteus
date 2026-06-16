import random
import json
import re
from pathlib import Path
from types import SimpleNamespace

from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import VirtualShell, ProcessData
from src.proteus.decision_engine.engage_parser import EngageParser
from src.proteus.decision_engine.engage_mapping import EngageDetails
from src.proteus.decision_engine.deception_capabilities import DeceptionCapabilites
from src.proteus.decision_engine.capabilities.account_capabilities import CreateFakeUserAccountCapability
from src.proteus.decision_engine.capabilities.credentials_capabilities import (
  CreateFakeAWSCredentialsCapability,
  WeakenPasswordPolicyCapability,
)
from src.proteus.decision_engine.capabilities.file_capabilities import (
  CreateFileCapability,
  DeleteFileCapability,
  ModifyFileContentCapability,
  ModifyFileMetadataCapability,
)
from src.proteus.decision_engine.capabilities.network_capabilites import InjectFakeNetworkConnectionCapability
from src.proteus.decision_engine.capabilities.process_capabilities import InjectFakeProcessCapability

from loguru import logger

logger.add("logs/proteus_engage_engine.log", rotation="10 MB")

class EngageEngine:
  def __init__(
      self,
      vfs: VirtualFileSystem,
      virtual_shell: VirtualShell,
      llm_client, 
      llm_model,
      capabilities_mapping_url: str = "/src/proteus/decision_engine/capabilities_mapping.json",):
    self.vfs = vfs
    self.virtual_shell = virtual_shell
    self.llm_client = llm_client
    self.llm_model = llm_model
    self.engage_parser = EngageParser()
    self.deception_capabilities = DeceptionCapabilites()
    self.deployed_capabilities = set()
    self.capabilities_mapping = self.load_capabilities_mapping(capabilities_mapping_url)
  
  def load_capabilities_mapping(self, capabilities_mapping_url: str) -> dict[str, list[str]]:
    url = Path(capabilities_mapping_url)

    # If provided path does not exist, try resolving relative to project root
    if not url.exists():
      repo_root = Path(__file__).resolve().parents[3]
      candidate = repo_root / capabilities_mapping_url.lstrip("/")
      if candidate.exists():
        url = candidate
      else:
        logger.warning(f"Capabilities mapping file not found at {capabilities_mapping_url}")
        return {}

    logger.info(f"Loading capabilities mapping from {url}...")
    with url.open("r", encoding="utf-8") as cache_file:
      raw = json.load(cache_file)

    mapping: dict[str, list[str]] = {}
    for eac_id, capability_list in raw.items():
      normalized: list[str] = []
      for cls_name in capability_list:
        if not isinstance(cls_name, str) or not cls_name:
          continue

        # Remove trailing 'Capability' if present
        base = cls_name
        if base.endswith("Capability"):
          base = base[: -len("Capability")]

        # Convert CamelCase/PascalCase to snake_case (e.g. CreateFakeUser -> create_fake_user)
        s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", base)
        snake = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()
        normalized.append(snake)

      mapping[str(eac_id)] = normalized

    return mapping

  def evaluate_and_react(self, engage_details: list[EngageDetails]) -> None:
    valid_capabilities: list[str] = []
    for detail in engage_details:
      activity = detail.activity.activity_id
      if not activity in self.capabilities_mapping:
        continue
      valid_capabilities.extend(self.capabilities_mapping[activity])
    valid_capabilities = list(set(valid_capabilities) - self.deployed_capabilities)
    if not valid_capabilities:
      logger.info("No new deception capabilities to deploy for this technique.")
      return
    selected_capability = random.choice(valid_capabilities)
    self.execute_deception(selected_capability)
  
  def execute_deception(self, capability_name: str) -> None:
    capability_key = capability_name.strip().lower()
    capability_options = self._build_capability_options(capability_key)

    capability_registry = {
      "create_fake_user_account": CreateFakeUserAccountCapability,
      "create_fake_user_account_capability": CreateFakeUserAccountCapability,
      "create_fake_aws_credentials": CreateFakeAWSCredentialsCapability,
      "create_fake_aws_credentials_capability": CreateFakeAWSCredentialsCapability,
      "weaken_password_policy": WeakenPasswordPolicyCapability,
      "weaken_password_policy_capability": WeakenPasswordPolicyCapability,
      "create_file": CreateFileCapability,
      "create_file_capability": CreateFileCapability,
      "delete_file": DeleteFileCapability,
      "delete_file_capability": DeleteFileCapability,
      "modify_file_content": ModifyFileContentCapability,
      "modify_file_content_capability": ModifyFileContentCapability,
      "modify_file_metadata": ModifyFileMetadataCapability,
      "modify_file_metadata_capability": ModifyFileMetadataCapability,
      "inject_fake_process": InjectFakeProcessCapability,
      "inject_fake_process_capability": InjectFakeProcessCapability,
      "inject_fake_network_connection": InjectFakeNetworkConnectionCapability,
      "inject_fake_network_connection_capability": InjectFakeNetworkConnectionCapability,
    }

    capability_class = capability_registry.get(capability_key)
    if capability_class is None:
      logger.warning(f"Unsupported deception capability '{capability_name}'.")
      return

    capability = capability_class(self.vfs, self.virtual_shell, capability_options)
    result = capability.execute()

    if result.success:
      self.deployed_capabilities.add(capability_name)
      logger.success(
        f"Executed capability '{capability_name}' ({result.eac_id}/{result.function_name}): {result.message}"
      )
    else:
      logger.warning(
        f"Capability '{capability_name}' failed ({result.eac_id}/{result.function_name}): {result.message}"
      )

  def _build_capability_options(self, capability_name: str) -> object:
    default_process = ProcessData(
      user=self.virtual_shell.current_user,
      pid=1000,
      cpu_usage=0.0,
      memory_usage=0.0,
      vsz=0,
      rss=0,
      tty=self.virtual_shell.current_tty,
      stat="S",
      start_time="00:00",
      time="0:00",
      command="example_process",
    )
    default_connection = (
      self.virtual_shell.network_connections[0].model_dump()
      if self.virtual_shell.network_connections
      else {
        "protocol": "TCP",
        "local_address": "127.0.0.1:0",
        "remote_address": "127.0.0.1:0",
        "state": "ESTABLISHED",
      }
    )

    if capability_name in {"create_fake_user_account", "create_fake_user_account_capability"}:
      return SimpleNamespace(username="user")

    if capability_name in {"create_fake_aws_credentials", "create_fake_aws_credentials_capability"}:
      return SimpleNamespace(user="user")

    if capability_name in {"create_file", "create_file_capability"}:
      return SimpleNamespace(file_path="/tmp/user.txt", file_content="user content")

    if capability_name in {"delete_file", "delete_file_capability"}:
      return SimpleNamespace(file_path="/tmp/user.txt")

    if capability_name in {"modify_file_content", "modify_file_content_capability"}:
      return SimpleNamespace(file_path="/tmp/user.txt", new_content="updated user content")

    if capability_name in {"modify_file_metadata", "modify_file_metadata_capability"}:
      return SimpleNamespace(
        file_path="/tmp/user.txt",
        new_metadata={"mode": "rw-r--r--", "uid": 0, "gid": 0},
      )

    if capability_name in {"inject_fake_process", "inject_fake_process_capability"}:
      return SimpleNamespace(process_data=default_process)

    if capability_name in {"inject_fake_network_connection", "inject_fake_network_connection_capability"}:
      return SimpleNamespace(network_data=default_connection)

    if capability_name in {"weaken_password_policy", "weaken_password_policy_capability"}:
      return SimpleNamespace()

    return SimpleNamespace()