import paramiko
import time
from loguru import logger

logger.add("logs/interactor.log", rotation="10 MB")

class Interactor:
  def __init__(self, host: str, port: int, username: str, password: str):
    self.host = host
    self.port = port
    self.username = username
    self.password = password
    self.ssh_client = paramiko.SSHClient()
    self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    self.shell = None
  
  def connect(self) -> bool:
    try:
      logger.info(f"Connecting to {self.host}:{self.port} as {self.username}")
      self.ssh_client.connect(
        hostname=self.host,
        port=self.port,
        username=self.username,
        password=self.password,
        timeout=10
      )
      self.shell = self.ssh_client.invoke_shell()

      time.sleep(1)  # Wait for the shell to be ready
      if self.shell.recv_ready():
        welcome_message = self.shell.recv(4096).decode('utf-8')
        logger.debug(f"Received welcome message: {welcome_message.strip()}")
      
      logger.success(f"Successfully connected to {self.host}")
      return True
    except Exception as e:
      logger.error(f"Failed to connect to {self.host}: {e}")
      return False
  
  def execute_command(self, command: str, wait_time: float = 1.0) -> str:
    if not self.shell:
      raise ConnectionError("Not connected to any host.")
    
    logger.info(f"Executing command on {self.host}: {command}")
    full_command = command + '\n'
    self.shell.send(full_command.encode('utf-8'))
    time.sleep(wait_time)
    output = ""
    while self.shell.recv_ready():
      output += self.shell.recv(4096).decode('utf-8')
    
    clean_output = output.strip()
    # logger.debug(f"Command output: {clean_output}")
    return clean_output
  
  def disconnect(self):
    if self.shell:
      self.shell.send("exit\n".encode('utf-8'))
      time.sleep(1)
    self.ssh_client.close()
    logger.info(f"Disconnected from {self.host}")
