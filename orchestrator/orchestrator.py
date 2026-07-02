from datetime import datetime
import os
import socket
import time
import yaml
import subprocess
import sys
from loguru import logger

logger.add("logs/orchestrator.log")

def check_port_availability(port: int, host: str = 'localhost', timeout: float = 5.0) -> bool:
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.settimeout(timeout)
    result = sock.connect_ex((host, port))
    return result != 0  # Returns True if the port is available (not in use)

def wait_for_port(port: int, host: str = 'localhost', timeout: float = 60.0) -> bool:
  start_time = time.time()
  while True:
    try:
      with socket.create_connection((host, port), timeout=1.0):
        return True
    except OSError:
      time.sleep(0.5)
      if time.time() - start_time > timeout:
        return False

def run_orchestration(config_path="orchestrator/config.yaml"):
  if not check_port_availability(2222):
    logger.error("Port 2222 is already in use. Please ensure that no other instance of Proteus is running.")
    return
  
  with open(config_path, 'r', encoding='utf-8') as f:
    config = yaml.safe_load(f)

  repetitions = config.get("repetitions", 1)
  proteus_correlation_models = config["proteus"]["correlation_models"]
  proteus_engage_models = config["proteus"]["engage_models"]
  panoptes_models = config["panoptes"]["llm_models"]
  attackers = config["panoptes"]["attackers"]

  total_runs = len(proteus_correlation_models) * len(proteus_engage_models) * len(panoptes_models) * len(attackers) * repetitions
  current_run = 0

  # Layer 1: Defender Correlation Model
  for proteus_correlation_model in proteus_correlation_models:
    # Layer 2: Defender Engage Model
    for proteus_engage_model in proteus_engage_models:
      # Layer 3: Attacker Model
      for panoptes_model in panoptes_models:
        # Layer 4: Attacker Data
        for attacker in config["panoptes"]["attackers"]:
          attacker_name = attacker.get("name") 
          attacker_level = attacker.get("level")
          attacker_techniques = attacker.get("techniques", [])
          # Layer 5: Iterations
          for iteration in range(repetitions):
            current_run += 1
            date_time = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            session_id = f"sim-{date_time}_DC-{proteus_correlation_model.split('/')[0]}_DE-{proteus_engage_model.split('/')[0]}_AM-{panoptes_model.split('/')[0]}_AL{attacker_level}_i{iteration}"
            
            logger.info(f"[{current_run}/{total_runs}] Initiating session: {session_id}")
            
            # 1. Prepare proteus env
            proteus_env = os.environ.copy()
            proteus_env["PROTEUS_CORRELATION_MODEL"] = proteus_correlation_model
            proteus_env["PROTEUS_ENGAGE_MODEL"] = proteus_engage_model
            proteus_env["PROTEUS_CORRELATION_ENGINE_TEMPERATURE"] = str(config["proteus"]["correlation_engine_temperature"])
            proteus_env["PROTEUS_ENGAGE_ENGINE_TEMPERATURE"] = str(config["proteus"]["engage_engine_temperature"])
            proteus_env["PROTEUS_ENGAGE_ENGINE_THRESHOLD"] = str(config["proteus"]["engage_engine_threshold"])
            proteus_env["SESSION_ID"] = session_id
            proteus_env["ENABLE_METRICS"] = "True"
            proteus_env["METRICS_FILE"] = "defend_metrics.jsonl"

            # 2. Start the Honeypot (Proteus)
            # logger.info("-> Starting Honeypot (Proteus)...")
            proteus_process = subprocess.Popen(
              [sys.executable, "-m", "src.proteus.proteus_main"],
              env=proteus_env,
              stdout=subprocess.DEVNULL,
              stderr=subprocess.DEVNULL
            )
                        
            if not wait_for_port(port=2222, timeout=60.0):
              logger.error(f"¡Timeout! Proteus didn't start in time for session {session_id}.")
              proteus_process.terminate()
              continue 
            
            time.sleep(1)  # Give Proteus a moment to fully initialize

            logger.info("-> Honeypot (Proteus) started.")

            # 3. Prepare the environment for Panoptes (Attacker)
            panoptes_env = os.environ.copy()
            panoptes_env["PANOPTES_LLM_MODEL"] = panoptes_model
            panoptes_env["PANOPTES_TEMPERATURE"] = str(config["panoptes"]["temperature"])
            panoptes_env["PANOPTES_THRESHOLD"] = str(config["panoptes"]["threshold"])
            panoptes_env["PANOPTES_LEVEL"] = attacker_level
            panoptes_techniques = ",".join(attacker_techniques)
            logger.debug(f"-> Attacker Techniques: {panoptes_techniques}")
            panoptes_env["PANOPTES_TECHNIQUES"] = panoptes_techniques
            panoptes_env["SESSION_ID"] = session_id
            panoptes_env["ENABLE_METRICS"] = "True"
            panoptes_env["METRICS_FILE"] = "attack_metrics.jsonl"

            # 4. Start the attack simulation (Panoptes)
            logger.info(f"-> Starting attack ({attacker_name})...")
            subprocess.run(
              [sys.executable, "-m", "src.panoptes.panoptes_main"],
              env=panoptes_env,
              stdout=subprocess.DEVNULL,
              stderr=subprocess.DEVNULL
            )

            # 5. Waiting for proteus to finish processing the attack
            logger.info("-> Waiting for Honeypot to finish processing...")
            data_file = f"data/{session_id}.json"
            wait_time = 0
            max_wait = 300 # Avoid infinite waiting, max 5 minutes

            while not os.path.exists(data_file) and wait_time < max_wait:
              time.sleep(1)
              wait_time += 1
            
            # 6. The attack has finished, we turn off the Honeypot

            logger.info("-> Turning off Honeypot and cleaning up...")
            proteus_process.terminate()
            try:
              proteus_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
              proteus_process.kill()

  logger.success("¡Orchestration Completed!")

if __name__ == "__main__":
  run_orchestration()