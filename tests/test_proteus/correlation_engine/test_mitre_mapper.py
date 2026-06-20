from datetime import datetime, timezone
from types import SimpleNamespace

from src.proteus.correlation_engine.mitre_mapper import MitreMapper
from src.proteus.telemetry.models import InteractionInfo


class DummyLLMResponse:
  def __init__(self, content):
    self.choices = [SimpleNamespace(message=SimpleNamespace(content=content))]


class DummyLLMCompletions:
  def __init__(self, content):
    self.content = content
    self.last_request = None

  def create(self, **kwargs):
    self.last_request = kwargs
    return DummyLLMResponse(self.content)


class DummyLLMChat:
  def __init__(self, content):
    self.completions = DummyLLMCompletions(content)


class DummyLLMClient:
  def __init__(self, content):
    self.api_key = "test-key"
    self.chat = DummyLLMChat(content)


def build_interactions(commands: list[str]) -> list[InteractionInfo]:
  return [
    InteractionInfo(
      command=command,
      timestamp=datetime.now(timezone.utc),
      backspaces=0,
      mitre_mapping=None,
    )
    for command in commands
  ]


def test_evaluate_command_uses_interaction_history_and_examples():
  llm_content = (
    '{"command_indexes": "1, 2, 3", "technique_id": "T1033", "confidence": 0.98, '
    '"cti_sentence": "Adversaries may identify the current user and enumerate other logged in users and group memberships in one discovery sequence."}'
  )
  mapper = MitreMapper(DummyLLMClient(llm_content), "test-model")
  interactions = build_interactions(["whoami", "users", "id"])

  result = mapper.evaluate_command("id", interactions)

  assert result is not None
  assert result.command_indexes == "1, 2, 3"
  assert result.technique_id == "T1033"
  assert result.confidence == 0.98
  assert result.cti_sentence == "Adversaries may identify the current user and enumerate other logged in users and group memberships in one discovery sequence."

  last_request = mapper.llm_client.chat.completions.last_request
  assert last_request is not None
  user_prompt = last_request["messages"][1]["content"]
  assert "Interaction history:" in user_prompt
  assert "[1] whoami" in user_prompt
  assert "[2] users" in user_prompt
  assert "[3] id" in user_prompt
  assert "Example interaction history:" in user_prompt
  assert "cd /var/log" in user_prompt
  assert "netstat" in user_prompt


def test_evaluate_command_normalizes_llm_array_payload():
  llm_content = (
    '[{"command_indexes": [1, 2], "technique_id": "T1083", "confidence": 0.35, '
    '"cti_sentence": "Adversaries may use context from earlier commands to discover files and directories."}]'
  )
  mapper = MitreMapper(DummyLLMClient(llm_content), "test-model")
  interactions = build_interactions(["cd /var/log", "ls"])

  result = mapper.evaluate_command("ls", interactions)

  assert result is not None
  assert result.command_indexes == "1, 2"
  assert result.technique_id == "T1083"
  assert result.confidence == 0.35