import uuid

import pytest
from pydantic import ValidationError
from datetime import datetime
from src.proteus.telemetry.tracker import SessionTracker
from src.proteus.telemetry.models import NetworkInfo, Session, InteractionInfo, MitreMapping

from unittest.mock import MagicMock, patch

session_id = f"session_{uuid.uuid4().hex}_192.168.1.50"
source_ip = "192.168.1.50"
source_port = 12345
client_version = "OpenSSH_8.0"
dummy_client = "dummy-client"
dummy_model = "dummy-model"
engage_parser = MagicMock()
engage_mapper = MagicMock()

class TestTelemetryTracker:
  def test_tracker_initialization(self):
    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, dummy_model, engage_parser, engage_mapper)

    assert tracker.session_id is not None
    assert tracker.session_id.startswith("session_")

    assert isinstance(tracker.start_time, datetime)

    assert isinstance(tracker.network_info, NetworkInfo)
    assert tracker.network_info.source_ip == source_ip
    assert tracker.network_info.source_port == source_port
    assert tracker.network_info.ssh_client == client_version
  
  def test_add_authentication(self):
    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, dummy_model, engage_parser, engage_mapper)
    tracker.add_authentication("root", "password")

    assert tracker.auth_info is not None
    assert tracker.auth_info.username == "root"
    assert tracker.auth_info.password == "password"
    assert isinstance(tracker.auth_info.timestamp, datetime)
  
  def test_add_environment(self):
    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, dummy_model, engage_parser, engage_mapper)
    terminal_type = "xterm"
    shell_width = 80
    shell_height = 24
    tracker.add_environment(terminal_type, shell_width, shell_height)

    assert tracker.env_info is not None
    assert tracker.env_info.terminal_type == terminal_type
    assert tracker.env_info.shell_width == shell_width
    assert tracker.env_info.shell_height == shell_height
  
  def test_add_interaction(self):
    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, dummy_model, engage_parser, engage_mapper)
    commands = ["ls -la", "cat /etc/passwd"]
    backspaces = [0, 2]
    tracker.add_interaction(commands[0], backspaces[0])
    tracker.add_interaction(commands[1], backspaces[1])

    assert len(tracker.interactions) == 2
    interaction_1 = tracker.interactions[0]
    assert isinstance(interaction_1, InteractionInfo)
    assert interaction_1.command == commands[0]
    assert interaction_1.backspaces == backspaces[0]
    interaction_2 = tracker.interactions[1]
    assert isinstance(interaction_2, InteractionInfo)
    assert interaction_2.command == commands[1]
    assert interaction_2.backspaces == backspaces[1]
    assert isinstance(interaction_2.timestamp, datetime)
  
  @patch("src.proteus.telemetry.tracker.MitreMapper.evaluate_command")
  def test_finalize_and_export(self, mock_evaluate_command):
    mock_evaluate_command.return_value = MitreMapping(
      technique_id="T9999",
      confidence=0.99,
      cti_sentence="This is a fast mock sentence for testing."
    )

    engage_parser = MagicMock()
    engage_mapper = MagicMock()

    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, dummy_model, engage_parser, engage_mapper)
    tracker.add_authentication("root", "password")
    tracker.add_environment("xterm", 60, 18)
    tracker.add_interaction("whoami", 3)

    exit_reason = "User requested logout"
    session_json = tracker.finalize_and_export(exit_reason)

    assert isinstance(session_json, str)

    mock_evaluate_command.assert_called_once()
    called_args, _ = mock_evaluate_command.call_args
    assert called_args[0] == "whoami"
    assert len(called_args[1]) == 1
    assert called_args[1][0].command == "whoami"
        
    assert "technique_id" in session_json
    assert "confidence" in session_json
    assert "cti_sentence" in session_json

    session_data = Session.model_validate_json(session_json)

    assert session_data.session_id == tracker.session_id
    assert session_data.network.source_ip == source_ip
    assert session_data.network.source_port == source_port
    assert session_data.network.ssh_client == client_version
    assert session_data.environment.terminal_type == "xterm"
    assert session_data.environment.shell_width == 60
    assert session_data.environment.shell_height == 18
    assert session_data.authentication.username == "root"
    assert session_data.authentication.password == "password"
    assert len(session_data.interactions) == 1
    assert session_data.interactions[0].command == "whoami"
    assert session_data.interactions[0].backspaces == 3
    assert session_data.session_metadata.exit_reason == exit_reason
  
  @patch("src.proteus.telemetry.tracker.MitreMapper.evaluate_command")
  def test_finalize_without_authentication(self, mock_evaluate_command):
    mock_evaluate_command.return_value = []

    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, dummy_model, engage_parser, engage_mapper)
    tracker.add_environment("xterm", 60, 18)
    tracker.add_interaction("pwd", 0)

    with pytest.raises(ValueError, match="Authentication information is missing"):
      tracker.finalize_and_export("User requested logout")
  
  @patch("src.proteus.telemetry.tracker.MitreMapper.evaluate_command")
  def test_finalize_without_environment(self, mock_evaluate_command):
    mock_evaluate_command.return_value = []

    tracker = SessionTracker(session_id, source_ip, source_port, client_version, dummy_client, dummy_model, engage_parser, engage_mapper)
    tracker.add_authentication("root", "password")
    tracker.add_interaction("pwd", 0)

    with pytest.raises(ValueError, match="Environment information is missing"):
      tracker.finalize_and_export("User requested logout")
  
  def test_pydantic_validation(self):
    with pytest.raises(ValidationError):
      NetworkInfo(source_ip=123, source_port="not_a_port", ssh_client="asdfg") # type: ignore