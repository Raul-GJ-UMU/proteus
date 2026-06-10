from types import SimpleNamespace
from unittest.mock import MagicMock

import src.proteus.decision_engine.engage_engine as engage_engine_module
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

  def __init__(self, vfs, virtual_shell, options):
    self.vfs = vfs
    self.virtual_shell = virtual_shell
    self.options = options
    DummyCapability.last_options = options

  def execute(self):
    return SimpleNamespace(success=True, eac_id="TEST", function_name="dummy", message="ok")


def build_engine(monkeypatch):
  monkeypatch.setattr(engage_engine_module, "EngageParser", DummyParser)
  monkeypatch.setattr(engage_engine_module, "ModifyFileContentCapability", DummyCapability)
  monkeypatch.setattr(engage_engine_module, "InjectFakeNetworkConnectionCapability", DummyCapability)

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

  return engage_engine_module.EngageEngine(vfs, virtual_shell)


def test_execute_deception_builds_file_options(monkeypatch):
  engine = build_engine(monkeypatch)

  engine.execute_deception("modify_file_content")

  assert DummyCapability.last_options.file_path == "/tmp/decoy.txt"
  assert DummyCapability.last_options.new_content == "updated decoy content"


def test_execute_deception_builds_network_options(monkeypatch):
  engine = build_engine(monkeypatch)

  engine.execute_deception("inject_fake_network_connection")

  assert DummyCapability.last_options.network_data == {
    "protocol": "TCP",
    "local_address": "127.0.0.1:8080",
    "remote_address": "192.168.1.1:443",
    "state": "ESTABLISHED",
  }