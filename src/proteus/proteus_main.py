import os

from loguru import logger
from dotenv import load_dotenv
from src.proteus.sensor.sensor import start_sensor

logger.add("logs/proteus_main.log", rotation="10 MB")

def main():

  load_dotenv()
  logger.info("======================================")
  logger.info("Starting Proteus v1.0...")
  logger.info("======================================")
  
  try:
    port = os.getenv("PROTEUS_PORT", "2222")
    start_sensor(host="0.0.0.0", port=int(port))
  
  except KeyboardInterrupt:
    logger.warning("Shutting down Proteus...")
  except Exception as e:
    logger.critical(f"An error occurred: {e}")
  finally:
    logger.info("Proteus has been stopped.")
    return

if __name__ == "__main__":
  main()