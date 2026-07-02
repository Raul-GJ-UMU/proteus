import os
import random
import json
import ast
import re
from pathlib import Path
from types import SimpleNamespace
import importlib
import inspect
import pkgutil
from datetime import datetime, timezone

from src.proteus.engage_engine.capabilities.utils import CapabilityResult
from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import VirtualShell, ProcessData
from src.proteus.engage_engine.engage_parser import EngageParser
from src.proteus.engage_engine.engage_mapping import EngageDetails

from loguru import logger

logger.add("logs/proteus_engage_engine.log", rotation="10 MB")

class LlmSyntaxError(Exception):
  """Custom exception for LLM syntax errors."""
  pass

class EngageEngine:
  def __init__(
      self,
      vfs: VirtualFileSystem,
      virtual_shell: VirtualShell,
      llm_client, 
      capabilities_mapping_url: str = "/src/proteus/engage_engine/activity_capabilities_mapping.json",):
    self.vfs = vfs
    self.virtual_shell = virtual_shell
    self.llm_client = llm_client
    self.llm_model = os.getenv("PROTEUS_ENGAGE_MODEL", "phi3")
    self.temperature = float(os.getenv("PROTEUS_ENGAGE_ENGINE_TEMPERATURE", 0.3))
    self.engage_parser = EngageParser()
    self.capabilities_registry = self.discover_capabilities("src.proteus.engage_engine.capabilities")
    self.activity_capabilities_mapping = self.load_activity_capabilities_mapping(capabilities_mapping_url)
    self.enable_metrics = os.getenv("ENABLE_METRICS", "false").lower() == "true"
    if self.enable_metrics:
      self.metrics_file = os.getenv("METRICS_FILE", "defend_metrics.jsonl")
      
  def discover_capabilities(self, package_name: str) -> dict[str, type]:
    capabilities: dict[str, type] = {}

    try:
      package = importlib.import_module(package_name)
    except ImportError as e:
      logger.error(f"Failed to import package '{package_name}': {e}")
      return capabilities
    
    for _, module_name, is_pkg in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
      if is_pkg:
        continue

      try:
        module = importlib.import_module(module_name)

        for name, obj in inspect.getmembers(module, inspect.isclass):
          if obj.__module__ == module_name:
            if name.endswith("Capability") and hasattr(obj, 'execute') and name != "Capability":
              capabilities[name] = obj
      except ImportError as e:
        logger.error(f"Failed to import module '{module_name}': {e}")
    logger.info(f"Discovered capabilities: {capabilities}")
    return capabilities
      
  
  def load_activity_capabilities_mapping(self, capabilities_mapping_url: str) -> dict[str, list[str]]:
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
    for eac_id, value in raw.items():
      capabilities: list[str] = []
      for capability in value.get("capabilities", []):
        name = capability.get("name")
        if name:
          capabilities.append(name)

      mapping[str(eac_id)] = capabilities

    return mapping

  def evaluate_and_react(self, session_id: str, command: str, description: str, engage_details: list[EngageDetails]) -> None:
    valid_capabilities: list[tuple[str, str]] = []

    for detail in engage_details:
      activity = detail.activity.activity_id
      capabilities = self.activity_capabilities_mapping.get(activity, [])
      valid_capabilities.extend([(activity, cap) for cap in capabilities])

    # logger.info(f"Valid deception capabilities for this technique: {valid_capabilities}")
    selected_capability = random.choice(valid_capabilities) # If a capability appears more than once, it's propability to be chosen increases
    self.execute_deception(session_id, selected_capability[0], selected_capability[1], command, description)

  def execute_deception(self, session_id: str, eac_id: str, capability_name: str, command: str, description: str) -> None:
    logger.info(f"Capabilities registry: {self.capabilities_registry}")
    capability_class = self.capabilities_registry.get(capability_name)
    logger.info(f"Capability class for '{capability_name}': {capability_class}")
    if capability_class is None:
      logger.warning(f"Unsupported deception capability '{capability_name}'.")
      return
    
    llm_syntax_error = False
    llm_execution_error = False
    result: CapabilityResult | None = None
    
    try:

      capability_options = self._build_capability_options(
        capability_name, 
        capability_class, 
        command, 
        description
      )

      capability = capability_class(self.vfs, self.virtual_shell, eac_id, capability_options)
      result = capability.execute()
      
      if result is None:
        return
      
      if result.success:
        logger.success(
          f"Executed capability '{capability_name}' ({result.eac_id}): {result.message}"
        )
      else:
        llm_execution_error = True
        logger.warning(
          f"Capability '{capability_name}' failed ({result.eac_id}): {result.message}"
        )
    except LlmSyntaxError as e:
      llm_syntax_error = True
    except Exception as e:
      logger.error(f"Unexpected error occurred: {e}")
    finally:
      if self.enable_metrics:
        metrics_data = {
          "timestamp": datetime.now(timezone.utc).isoformat(),
          "session_id": session_id,
          "llm_model": self.llm_model,
          "event_type": "deception",
          "command": command,
          "capability_name": capability_name,
          "description": description,
          "result": "llm_syntax_error" if llm_syntax_error else ("llm_execution_error" if llm_execution_error else result.success if result else "unknown"),
          "eac_id": result.eac_id if result else "",
          "message": result.message if result else ""
        }
        with open(self.metrics_file, "a", encoding="utf-8") as f:
          f.write(json.dumps(metrics_data) + "\n")

  def _build_capability_options(
      self, 
      capability_name: str, 
      capability_class: type, 
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
        temperature=self.temperature,
        max_tokens=400,
      )
    except Exception as exc:
      logger.error(f"Error requesting options from LLM for '{capability_name}': {exc}")
      raise LlmSyntaxError(f"Error requesting options from LLM for '{capability_name}': {exc}")

    raw_output = response.choices[0].message.content if response.choices else None
    if not raw_output:
      logger.warning(f"LLM returned no content for capability '{capability_name}'.")
      raise LlmSyntaxError(f"No content returned for capability '{capability_name}'.")

    payload = self._parse_options_payload(raw_output)
    if not isinstance(payload, dict):
      logger.warning(f"LLM returned invalid options for capability '{capability_name}': {raw_output}")
      raise LlmSyntaxError(f"Invalid options payload for capability '{capability_name}': {raw_output}")

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