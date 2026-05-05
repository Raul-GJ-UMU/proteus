import paramiko
import os
import socket
from dotenv import load_dotenv
from paramiko.common import OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED, AUTH_SUCCESSFUL
from loguru import logger
import threading

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
  
  def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
    return True
  
  def check_channel_shell_request(self, channel):
    return True

def handle_session(channel, addr):
  logger.success("SSH session established")

  channel.send(b"Welcome to Proteus OS 1.0\r\n")
  prompt = b"root@proteus:~# "
  channel.send(prompt)
  
  command_buffer = ""

  while True:
    try:
      char = channel.recv(1).decode("utf-8", errors="ignore")
      if not char:
        logger.warning("Client disconnected")
        break

      channel.send(char.encode("utf-8"))

      if char in ("\r", "\n"):
        # handle command execution
        channel.send(b"\r\n")
        full_command = command_buffer.strip()

        if full_command:
          if full_command.lower() in ("exit", "quit"):
            channel.send(b"Logout!\r\n")
            break

          logger.info(f"Command captured: {full_command}")

          mocked_response = f"bash: {full_command}: command not found\r\n"
          channel.send(mocked_response.encode("utf-8"))
        
        command_buffer = ""
        channel.send(prompt)
      
      elif char in ("\b", "\x7f"):
        # Handle backspace
        if len(command_buffer) > 0:
          command_buffer = command_buffer[:-1]
          channel.send(b"\b \b")
      else:
        command_buffer += char
    except Exception as e:
      logger.error(f"Session error: {e}")
      break
  channel.close()


def start_sensor(host="0.0.0.0", port=2222):
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.settimeout(1.0)
  
  try:
    sock.bind((host, port))
    sock.listen(100)
    logger.success(f"Sensor SSH listening on {host}:{port}")

    while True:
      try:
        client, addr = sock.accept()
      except socket.timeout:
        continue
      
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
      
      client_thread = threading.Thread(target=handle_session, args=(channel, addr))
      client_thread.daemon = True
      client_thread.start()

  except KeyboardInterrupt:
    logger.warning("Sensor shutting down")
  except Exception as e:
    logger.critical(f"Sensor error: {e}")
  finally:
    sock.close()
    os._exit(0)

if __name__ == "__main__":
  start_sensor()