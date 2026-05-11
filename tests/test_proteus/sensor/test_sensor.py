import pytest
from unittest.mock import MagicMock
from paramiko.common import AUTH_SUCCESSFUL, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED, OPEN_SUCCEEDED
from src.proteus.sensor.sensor import Sensor, handle_session
from src.proteus.telemetry.tracker import SessionTracker

tracker = SessionTracker("192.168.1.50", 12345, "OpenSSH_8.0")

class TestProteusSensor:
  def test_check_channel_request(self):
    sensor = Sensor(tracker)
    assert sensor.check_channel_request("session", 1) == OPEN_SUCCEEDED
    assert sensor.check_channel_request("invalid", 1) == OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
  
  def test_check_auth_password(self):
    sensor = Sensor(tracker)
    assert sensor.check_auth_password("user", "pass") == AUTH_SUCCESSFUL
  
  def test_get_allowed_auths(self):
    sensor = Sensor(tracker)
    assert sensor.get_allowed_auths("user") == "password"
  
  def test_check_channel_pty_request(self):
    sensor = Sensor(tracker)
    mock_channel = MagicMock()
    assert sensor.check_channel_pty_request(mock_channel, b"xterm", 80, 24, 0, 0, b"") is True
  
  def test_check_channel_shell_request(self):
    sensor = Sensor(tracker)
    mock_channel = MagicMock()
    assert sensor.check_channel_shell_request(mock_channel) is True
  
  def test_handle_session_exit_command(self):
        mock_channel = MagicMock()
        mock_channel.recv.side_effect = [b'e', b'x', b'i', b't', b'\n', b'']
        
        fake_ip = ("192.168.1.100", 55555)
        handle_session(mock_channel, fake_ip, tracker)
        
        mock_channel.send.assert_any_call(b"Logout!\r\n")
        mock_channel.close.assert_called_once()