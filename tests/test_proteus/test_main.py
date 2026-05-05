import pytest
from unittest.mock import patch
from src.proteus.proteus_main import main

class TestProteusMain:
  @patch("src.proteus.proteus_main.start_sensor")
  def test_main_calls_sensor_with_correct_arguments(self, mock_start_sensor):
    main()
    mock_start_sensor.assert_called_once_with(host="0.0.0.0", port=2222)
  
  @patch("src.proteus.proteus_main.start_sensor")
  def test_main_handles_keyboard_interrupt(self, mock_start_sensor):
    mock_start_sensor.side_effect = KeyboardInterrupt()
    try:
        main()
    except KeyboardInterrupt:
        pytest.fail("Main didn't handle KeyboardInterrupt properly.")