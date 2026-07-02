from datetime import datetime
import uuid

from openai import OpenAI
import paramiko
import os
import socket
from dotenv import load_dotenv
from paramiko.common import OPEN_SUCCEEDED, OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED, AUTH_SUCCESSFUL
from loguru import logger
import threading

from src.proteus.engage_engine.engage_parser import EngageParser
from src.proteus.engage_engine.engage_engine import EngageEngine
from src.proteus.telemetry.tracker import SessionTracker

from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import ShellTerminationError, VirtualShell

logger.add("logs/proteus_sensor.log", rotation="10 MB")

load_dotenv()

RSA_KEY_PATH = os.getenv("PROTEUS_RSA_KEY_FILE")
ENABLE_METRICS = os.getenv("ENABLE_METRICS", "false").lower() == "true"

def get_or_generate_rsa_key(path: str) -> paramiko.RSAKey:
  os.makedirs(os.path.dirname(path), exist_ok=True)
  if os.path.exists(path):
    # logger.info(f"Loading RSA key from {path}")
    return paramiko.RSAKey(filename=path)
  else:
    # logger.info(f"Generating new RSA key on {path}")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    return key

class Sensor(paramiko.ServerInterface):
  def __init__(self, tracker: SessionTracker):
    self.tracker = tracker
    super().__init__()
  
  def check_channel_request(self, kind: str, chanid: int):
    if kind == "session":
      return OPEN_SUCCEEDED
    return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
  
  def check_auth_password(self, username: str, password: str):
    self.tracker.add_authentication(username, password)
    logger.info(f"Login attempt captured - User: {username} | Password: {password}")
    return AUTH_SUCCESSFUL
  
  def get_allowed_auths(self, username: str):
    return "password"
  
  def check_channel_pty_request(self, channel: paramiko.Channel, term: bytes, width: int, height: int, pixelwidth: int, pixelheight: int, modes: bytes):
    term_str = term.decode("utf-8")
    self.tracker.add_environment(term_str, width, height)
    return True
  
  def check_channel_shell_request(self, channel: paramiko.Channel):
    return True

def save_session_data(tracker: SessionTracker, exit_reason: str = "User requested logout"):
  try:
    session_info_str = tracker.finalize_and_export(exit_reason)
    with open(f"data/{tracker.session_id}.json", "w") as f:
      f.write(session_info_str)
    logger.success(f"Session {tracker.session_id} saved successfully.")
  except Exception as e:
    logger.error(f"Error saving the final session: {e}")

def handle_session(channel: paramiko.Channel, addr: tuple, tracker: SessionTracker, shell: VirtualShell):
  # logger.success("SSH session established")

  motd = shell.get_motd()
  channel.send(motd.encode("utf-8"))
  prompt = shell.get_prompt()
  channel.send(prompt.encode("utf-8"))

  command_history: list[str] = []
  command_pointer = 0
  
  command_buffer = ""
  backspace_count = 0

  def redraw_input_line(previous_buffer: str, new_buffer: str):
    clear_padding = " " * max(0, len(previous_buffer) - len(new_buffer))
    rendered_line = f"\r{prompt}{new_buffer}{clear_padding}\r{prompt}{new_buffer}"
    channel.send(rendered_line.encode("utf-8"))

  while True:
    try:
      char = channel.recv(1).decode("utf-8", errors="ignore")
      if not char:
        logger.warning("Client disconnected")
        break

      if char in ("\r", "\n"):
        # handle command execution
        channel.send(b"\r\n")
        full_command = command_buffer.strip()

        if not full_command:
          continue
        
        command_history.append(full_command)
        command_pointer = len(command_history)
        tracker.add_interaction(full_command, backspace_count)
        backspace_count = 0
        logger.info(f"Command captured: {full_command}")

        if full_command.lower() in ("exit", "logout"):
          channel.send(b"logout\r\n")

          try:
            if not channel.closed:
              channel.close()
          except Exception as e:
            pass
          finally:
            save_thread = threading.Thread(target=save_session_data, args=(tracker, "User requested logout"))
            save_thread.start()
          break

        elif full_command.lower() == "history":
          result = ""
          for idx, cmd in enumerate(command_history, start=1):
            result += f"{idx}: {cmd}\r\n"
          channel.send(result.encode("utf-8"))

        try:
          response = shell.execute_command(full_command)
        except ShellTerminationError as termination:
          if termination.output:
            channel.send(termination.output.encode("utf-8"))
          raise
        channel.send(response.encode("utf-8"))
        
        command_buffer = ""
        prompt = shell.get_prompt()
        channel.send(prompt.encode("utf-8"))
      
      elif char in ("\b", "\x7f"):
        # Handle backspace
        if len(command_buffer) > 0:
          command_buffer = command_buffer[:-1]
          channel.send(b"\b \b")
          backspace_count += 1
      elif char == "\x1b":
        # Handle escape sequences (e.g., arrow keys)
        try:
          seq = channel.recv(2)
          if seq == b"[A":
            # Up arrow
            if command_history and command_pointer > 0:
              previous_buffer = command_buffer
              command_pointer -= 1
              command_buffer = command_history[command_pointer]
              redraw_input_line(previous_buffer, command_buffer)
          elif seq == b"[B":
            # Down arrow
            if command_history and command_pointer < len(command_history) - 1:
              previous_buffer = command_buffer
              command_pointer += 1
              command_buffer = command_history[command_pointer]
              redraw_input_line(previous_buffer, command_buffer)
            elif command_pointer == len(command_history) - 1:
              previous_buffer = command_buffer
              command_pointer = len(command_history)
              command_buffer = ""
              redraw_input_line(previous_buffer, command_buffer)
        except Exception:
          pass
      else:
        command_buffer += char
        channel.send(char.encode("utf-8"))
    except ShellTerminationError as termination:
      logger.warning(f"Session terminated by shell command: {termination.exit_reason}")
      try:
        if not channel.closed:
          channel.close()
      except Exception:
        pass
      finally:
        save_thread = threading.Thread(target=save_session_data, args=(tracker, termination.exit_reason))
        save_thread.start()
      break
    except Exception as e:
      logger.error(f"Session error: {e}")
      save_thread = threading.Thread(target=save_session_data, args=(tracker,))
      save_thread.start()
      break
  channel.close()


def start_sensor(host="0.0.0.0", port=2222):
  if not RSA_KEY_PATH:
    logger.error("PROTEUS_RSA_KEY_FILE not configured in the .env file. Cannot start the sensor without an RSA key.")
    return
  host_key = get_or_generate_rsa_key(RSA_KEY_PATH)
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  sock.settimeout(1.0)
  
  try:
    sock.bind((host, port))
    sock.listen(100)
    logger.success(f"Sensor SSH listening on {host}:{port}")

    global_vfs = VirtualFileSystem()

    llm_client = OpenAI(
      base_url=os.getenv("OPENAI_BASE_URL"),
      api_key=os.getenv("OPENAI_API_KEY")
    )
    if not llm_client.api_key:
      logger.error("OPENAI_API_KEY not configured in the .env file. Cannot generate CTI sentence.")
      return
    if not llm_client.base_url:
      logger.error("OPENAI_BASE_URL not configured in the .env file. Cannot generate CTI sentence.")
      return
    
    while True:
      try:
        client, addr = sock.accept()
      except socket.timeout:
        continue

      logger.info(f"New conexion from {addr[0]}:{addr[1]}")

      session_id = os.getenv("SESSION_ID", f"session_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_{uuid.uuid4().hex[-8:]}_{addr[0]}")
      
      shell = VirtualShell(global_vfs)

      engage_parser = EngageParser()

      engage_engine = EngageEngine(
        vfs=global_vfs,
        virtual_shell=shell,
        llm_client=llm_client,
      )

      transport = paramiko.Transport(client)
      transport.add_server_key(host_key)
      tracker = SessionTracker(session_id, addr[0], addr[1], "Pending...", llm_client, engage_parser, engage_engine)

      server = Sensor(tracker)

      try:
        transport.start_server(server=server)
      except paramiko.SSHException:
        logger.error("Error negociating SSH session")
        continue
      
      client_version = transport.remote_version
      tracker.add_ssh_client(client_version)

      channel = transport.accept(60)
      if channel is None:
        logger.error("The client did not open a channel")
        continue
      
      client_thread = threading.Thread(target=handle_session, args=(channel, addr, tracker, shell))
      client_thread.daemon = True
      client_thread.start()

  except KeyboardInterrupt:
    raise
  except Exception as e:
    logger.critical(f"Sensor error: {e}")
  finally:
    sock.close()