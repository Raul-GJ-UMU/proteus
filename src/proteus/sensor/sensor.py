import paramiko
import os
import socket
from dotenv import load_dotenv
from paramiko.common import OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED, AUTH_SUCCESSFUL
from loguru import logger
import threading

from src.proteus.telemetry.tracker import SessionTracker

from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import VirtualShell

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

class Sensor(paramiko.ServerInterface):
  def __init__(self, tracker):
    self.tracker = tracker
    super().__init__()
  
  def check_channel_request(self, kind, chanid):
    if kind == "session":
      return OPEN_SUCCEEDED
    return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
  
  def check_auth_password(self, username, password):
    self.tracker.add_authentication(username, password)
    logger.info(f"Login attempt captured - User: {username} | Password: {password}")
    return AUTH_SUCCESSFUL
  
  def get_allowed_auths(self, username):
    return "password"
  
  def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
    term_str = term.decode("utf-8") if isinstance(term, bytes) else str(term)
    self.tracker.add_environment(term_str, width, height)
    return True
  
  def check_channel_shell_request(self, channel):
    return True

def handle_session(channel, addr, tracker: SessionTracker, shell: VirtualShell):
  logger.success("SSH session established")

  motd = shell.get_motd()
  channel.send(motd.encode("utf-8"))
  prompt = shell.get_prompt().encode("utf-8")
  channel.send(prompt)
  
  command_buffer = ""
  backspace_count = 0

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

        tracker.add_interaction(full_command, backspace_count)
        backspace_count = 0
        logger.info(f"Command captured: {full_command}")

        if full_command:
          if full_command.lower() in ("exit", "logout"):
            channel.send(b"logout\r\n")
            tracker.finalize_and_export("User requested logout")
            break

          response = shell.execute_command(full_command)
          channel.send(response.encode("utf-8"))
        
        command_buffer = ""
        prompt = shell.get_prompt().encode("utf-8")
        channel.send(prompt)
      
      elif char in ("\b", "\x7f"):
        # Handle backspace
        if len(command_buffer) > 0:
          command_buffer = command_buffer[:-1]
          channel.send(b"\b \b")
          backspace_count += 1
      else:
        command_buffer += char
    except Exception as e:
      logger.error(f"Session error: {e}")
      break
  channel.close()


def start_sensor(host="0.0.0.0", port=2222):
  host_key = get_or_generate_rsa_key(RSA_KEY_PATH)
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.settimeout(1.0)
  
  try:
    sock.bind((host, port))
    sock.listen(100)
    logger.success(f"Sensor SSH listening on {host}:{port}")

    global_vfs = VirtualFileSystem()
    while True:
      try:
        client, addr = sock.accept()
      except socket.timeout:
        continue

      logger.info(f"New conexion from {addr[0]}:{addr[1]}")
      
      transport = paramiko.Transport(client)
      transport.add_server_key(host_key)
      tracker = SessionTracker(addr[0], addr[1], "Pending...")

      server = Sensor(tracker)

      try:
        transport.start_server(server=server)
      except paramiko.SSHException:
        logger.error("Error negociating SSH session")
        continue
      
      client_version = transport.remote_version
      logger.info(f"SSH client version: {client_version}")
      tracker.add_ssh_client(client_version)

      channel = transport.accept(20)
      if channel is None:
        logger.error("The client did not open a channel")
        continue
      
      shell = VirtualShell(global_vfs)
      client_thread = threading.Thread(target=handle_session, args=(channel, addr, tracker, shell))
      client_thread.daemon = True
      client_thread.start()

  except KeyboardInterrupt:
    raise
  except Exception as e:
    logger.critical(f"Sensor error: {e}")
  finally:
    sock.close()