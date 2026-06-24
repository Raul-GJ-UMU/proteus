from types import SimpleNamespace
from unittest.mock import MagicMock

from src.proteus.engage_engine.engage_parser import EngageParser
import src.proteus.engage_engine.engage_engine as engage_engine_module
from src.proteus.virtual_env.virtual_shell import ProcessData


class DummyParser:
  def __init__(self, *args, **kwargs):
    self.mapper = {}


class DummyConnection:
  def __init__(self, payload):
    self.payload = payload

  def model_dump(self):
    return self.payload


class DummyCapability:
  last_options = None
  required_fields = {}

  def __init__(self, vfs, virtual_shell, options):
    self.vfs = vfs
    self.virtual_shell = virtual_shell
    self.options = options
    DummyCapability.last_options = options

  @classmethod
  def option_fields(cls):
    return cls.required_fields

  def execute(self):
    return SimpleNamespace(success=True, eac_id="TEST", function_name="dummy", message="ok")


class DummyFileCapability(DummyCapability):
  required_fields = {
    "file_path": "Path of the file to modify.",
    "new_content": "Replacement content for the file.",
  }


class DummyNetworkCapability(DummyCapability):
  required_fields = {
    "network_data": "Dictionary with the fake connection data.",
  }


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


def build_engine(monkeypatch, llm_content):
  monkeypatch.setattr(engage_engine_module, "EngageParser", DummyParser)

  monkeypatch.setattr(
    engage_engine_module.EngageEngine,
    "discover_capabilities",
    lambda self, x: {                  
      "modifyFileContentCapability": DummyFileCapability,
      "injectFakeNetworkConnectionCapability": DummyNetworkCapability,
    },
  )

  vfs = MagicMock()
  virtual_shell = MagicMock()
  virtual_shell.current_user = "root"
  virtual_shell.current_tty = "tty1"
  virtual_shell.process_list = [
    ProcessData(
      user="user",
      pid=974,
      cpu_usage=0.0,
      memory_usage=0.2,
      vsz=8744,
      rss=5488,
      tty="tty1",
      stat="S",
      start_time="15:17",
      time="0:00",
      command="bash",
    )
  ]
  virtual_shell.network_connections = [
    DummyConnection(
      {
        "protocol": "TCP",
        "local_address": "127.0.0.1:8080",
        "remote_address": "192.168.1.1:443",
        "state": "ESTABLISHED",
      }
    )
  ]

  return engage_engine_module.EngageEngine(vfs, virtual_shell, DummyLLMClient(llm_content), "test-model")


def test_execute_deception_builds_file_options(monkeypatch):
  engine = build_engine(
    monkeypatch,
    '{"file_path": "/tmp/decoy.txt", "new_content": "updated decoy content"}',
  )

  engine.execute_deception("modifyFileContentCapability", "command", "description")

  assert DummyCapability.last_options is not None
  assert DummyCapability.last_options.file_path == "/tmp/decoy.txt"
  assert DummyCapability.last_options.new_content == "updated decoy content"


def test_execute_deception_flattens_nested_file_options(monkeypatch):
  engine = build_engine(
    monkeypatch,
    '{"command": {"name": "modify_file_content", "arguments": {"file_path": "/tmp/decoy.txt", "new_content": "updated decoy content"}}}',
  )

  engine.execute_deception("modifyFileContentCapability", "command", "description")

  assert DummyCapability.last_options is not None
  assert DummyCapability.last_options.file_path == "/tmp/decoy.txt"
  assert DummyCapability.last_options.new_content == "updated decoy content"


def test_execute_deception_builds_network_options(monkeypatch):
  engine = build_engine(
    monkeypatch,
    '{"network_data": {"protocol": "TCP", "local_address": "127.0.0.1:8080", "remote_address": "192.168.1.1:443", "state": "ESTABLISHED"}}',
  )

  engine.execute_deception("injectFakeNetworkConnectionCapability", "command", "description")

  assert DummyCapability.last_options is not None
  assert DummyCapability.last_options.network_data == {
    "protocol": "TCP",
    "local_address": "127.0.0.1:8080",
    "remote_address": "192.168.1.1:443",
    "state": "ESTABLISHED",
  }