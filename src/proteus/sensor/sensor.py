import paramiko
import os
import socket
from dotenv import load_dotenv
from paramiko.common import OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED, AUTH_SUCCESSFUL
from loguru import logger

logger.add("logs/proteus_sensor.log", rotation="10 MB")

load_dotenv()

RSA_KEY_PATH = os.getenv("PROTEUS_RSA_KEY_FILE")

def get_or_generate_rsa_key(path):
  os.makedirs(os.path.dirname(path), exist_ok=True)
  if os.path.exists(path):
    logger.info(f"Loading RSA key from {path}")
    return paramiko.RSAKey(filename=path)
  else:
    logger.info(f"Generating new RSA key on {path}")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key

HOST_KEY = get_or_generate_rsa_key(RSA_KEY_PATH)

class Sensor(paramiko.ServerInterface):
  def check_channel_request(self, kind, chanid):
    if kind == "session":
      return OPEN_SUCCEEDED
    return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
  
  def check_auth_password(self, username, password):
    logger.info(f"Login attempt captured - User: {username} | Password: {password}")
    return AUTH_SUCCESSFUL
  
  def get_allowed_auths(self, username):
    return "password"

def start_sensor(host="0.0.0.0", port=2222):
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    logger.info(f"Sensor SSH listening on {host}:{port}")

    while True:
      client, addr = sock.accept()
      logger.info(f"New conexion from {addr[0]}:{addr[1]}")
      
      transport = paramiko.Transport(client)
      transport.add_server_key(HOST_KEY)

      server = Sensor()

      try:
        transport.start_server(server=server)
      except paramiko.SSHException:
        logger.error("Error negociating SSH session")
        continue

      channel = transport.accept(20)
      if channel is None:
        logger.error("The client did not open a channel")
        continue
      
      logger.info("SSH session established")

      channel.send(b"Welcome to Proteus OS 1.0\r\n")
      channel.send(b"Connection closed by remote host.\r\n")
      channel.close()

  except Exception as e:
    logger.error(f"Sensor error: {e}")

if __name__ == "__main__":
  start_sensor()