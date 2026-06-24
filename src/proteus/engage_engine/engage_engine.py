import random
import json
import ast
import re
from pathlib import Path
from types import SimpleNamespace

from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import VirtualShell, ProcessData
from src.proteus.engage_engine.engage_parser import EngageParser
from src.proteus.engage_engine.engage_mapping import EngageDetails
from src.proteus.engage_engine.capabilities.account_capabilities import CreateFakeUserAccountCapability
from src.proteus.engage_engine.capabilities.credentials_capabilities import (
  CreateFakeAWSCredentialsCapability,
  WeakenPasswordPolicyCapability,
)
from src.proteus.engage_engine.capabilities.file_capabilities import (
  CreateFileCapability,
  DeleteFileCapability,
  ModifyFileContentCapability,
  ModifyFileMetadataCapability,
)
from src.proteus.engage_engine.capabilities.network_capabilites import InjectFakeNetworkConnectionCapability
from src.proteus.engage_engine.capabilities.process_capabilities import InjectFakeProcessCapability

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

    # logger.info(f"Loading capabilities mapping from {url}...")
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

  def evaluate_and_react(self, command: str, description: str, engage_details: list[EngageDetails]) -> None:
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
    self.execute_deception(selected_capability, command, description)
  
  def execute_deception(self, capability_name: str, command: str, description: str) -> None:
    capability_key = capability_name.strip().lower()
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

    capability_options = self._build_capability_options(
      capability_key, 
      capability_class, 
      command, 
      description
    )

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

  def _build_capability_options(
      self, 
      capability_name: str, 
      capability_class, 
      command: str, 
      description: str
    ) -> object:
    option_fields = capability_class.option_fields()
    if not option_fields:
      return SimpleNamespace()

    if not self.llm_client or not self.llm_model:
      logger.warning(
        f"LLM client or model not configured. Cannot generate options for capability '{capability_name}'."
      )
      return SimpleNamespace()

    field_description_text = "\n".join(
      f"- {field}: {description}" for field, description in option_fields.items()
    )

    system_prompt = (
      "You are an expert system administrator AI generating configuration data "
      "for a highly realistic Ubuntu 22.04 production server. Your output MUST be "
      "strictly valid JSON. DO NOT wrap the output in Markdown blocks.\n"
      "CRITICAL RULES:\n"
      "1. NEVER use words like 'honeypot', 'fake', 'decoy', 'trap', 'test', or 'malware'.\n"
      "2. Data must look indistinguishable from a legitimate corporate server environment.\n"
      "3. ONLY output the exact fields requested. DO NOT hallucinate or add extra fields.\n"
      "4. DO NOT wrap the fields inside objects like command, arguments, options, payload, or data."
    )
    user_prompt = (
      f"Command executed: {command}\n"
      f"Context: '{description}'\n"
      f"Task: Generate configuration data for the system component: '{capability_name}'.\n"
      f"Required Fields and their descriptions:\n{field_description_text}\n\n"
      "INSTRUCTIONS:\n"
      "Fill all required fields with highly convincing, mundane values typical of a busy Linux server. "
      "For example, use names related to common web servers (nginx/apache), databases (mysql/postgres), "
      "or background system services (systemd, cron, sshd). "
      "Return ONLY a raw JSON object."
    )

    logger.debug(f"Requesting options from LLM for capability '{capability_name}': {user_prompt}")

    try:
      response = self.llm_client.chat.completions.create(
        model=self.llm_model,
        messages=[
          {"role": "system", "content": system_prompt},
          {"role": "user", "content": user_prompt},
        ],
        temperature=0.3,
        max_tokens=400,
      )
    except Exception as exc:
      logger.error(f"Error requesting options from LLM for '{capability_name}': {exc}")
      return SimpleNamespace()

    raw_output = response.choices[0].message.content if response.choices else None
    if not raw_output:
      logger.warning(f"LLM returned no content for capability '{capability_name}'.")
      return SimpleNamespace()

    payload = self._parse_options_payload(raw_output)
    if not isinstance(payload, dict):
      logger.warning(f"LLM returned invalid options for capability '{capability_name}': {raw_output}")
      return SimpleNamespace()

    payload = self._coerce_capability_payload(capability_name, payload, option_fields)
    result = SimpleNamespace(**payload)
    logger.info(f"Generated options for capability '{capability_name}': {payload}")
    return result

  def _parse_options_payload(self, raw_output: str) -> object:
    text = raw_output.strip()
    if text.startswith("```"):
      text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
      text = re.sub(r"\s*```$", "", text)

    try:
      return json.loads(text)
    except json.JSONDecodeError:
      match = re.search(r"\{.*\}", text, re.DOTALL)
      if match:
        candidate = match.group(0)
        try:
          return json.loads(candidate)
        except json.JSONDecodeError:
          try:
            return ast.literal_eval(candidate)
          except (ValueError, SyntaxError):
            return None

      try:
        return ast.literal_eval(text)
      except (ValueError, SyntaxError):
        return None

  def _coerce_capability_payload(self, capability_name: str, payload: dict, option_fields: dict[str, str]) -> dict:
    payload = self._unwrap_capability_payload(payload, set(option_fields.keys()))

    if len(payload) == 1 and capability_name in payload:
        payload = payload[capability_name]
    if capability_name in {"inject_fake_process", "inject_fake_process_capability"}:
      process_data = payload.get("process_data")
      if isinstance(process_data, dict):
        payload["process_data"] = ProcessData(**process_data)

    if capability_name in {"inject_fake_network_connection", "inject_fake_network_connection_capability"}:
      network_data = payload.get("network_data")
      if isinstance(network_data, dict):
        payload["network_data"] = network_data

    return payload

  def _unwrap_capability_payload(self, payload: object, required_fields: set[str]) -> dict:
    if not isinstance(payload, dict):
      return {}

    if required_fields and required_fields.issubset(payload.keys()):
      return payload

    wrapper_keys = ("arguments", "args", "options", "payload", "data", "fields", "command")
    for key in wrapper_keys:
      nested = payload.get(key)
      if isinstance(nested, dict):
        candidate = self._unwrap_capability_payload(nested, required_fields)
        if required_fields.issubset(candidate.keys()):
          return candidate

    for value in payload.values():
      if isinstance(value, dict):
        candidate = self._unwrap_capability_payload(value, required_fields)
        if required_fields.issubset(candidate.keys()):
          return candidate

    return payload