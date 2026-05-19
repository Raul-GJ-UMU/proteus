from datetime import datetime, timedelta
import importlib
import pkgutil
import os
import sys
from loguru import logger
import posixpath
from unittest.mock import MagicMock

from src.proteus.virtual_env.vfs import FSDirectory, FSFile, VirtualFileSystem
from src.proteus.virtual_env.cowrie.shell.command import MockProtocol

sys.modules['treq'] = MagicMock()
sys.modules['twisted'] = MagicMock()
sys.modules['twisted.internet'] = MagicMock()
sys.modules['twisted.internet.defer'] = MagicMock()
sys.modules['twisted.internet.endpoints'] = MagicMock()
sys.modules['twisted.internet.protocol'] = MagicMock()
sys.modules['twisted.python'] = MagicMock()
sys.modules['twisted.web'] = MagicMock()
sys.modules['twisted.conch'] = MagicMock()

sys.modules['cowrie.core.artifact'] = MagicMock()
sys.modules['cowrie.core.network'] = MagicMock()
sys.modules['cowrie.shell.honeypot'] = MagicMock()

mock_pwd = MagicMock()
class FakePasswd:
    def __init__(self, *args, **kwargs): pass
    def getpwnam(self, name): return ["root", "x", 0, 0, "root", "/root", "/bin/bash"]
    def getpwuid(self, uid): return ["root", "x", 0, 0, "root", "/root", "/bin/bash"]
mock_pwd.Passwd = FakePasswd
sys.modules['cowrie.shell.pwd'] = mock_pwd

logger.add("logs/virtual_shell.log", rotation="10 MB")

class VirtualShell:
  def __init__(self, vfs: VirtualFileSystem):
    self.vfs = vfs

    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
      sys.path.insert(0, current_dir)
    
    self.commands = {
      "pwd": self.do_pwd,
      "cd": self.do_cd,
      "ls": self.do_ls,
      "rm": self.do_rm,
      "mkdir": self.do_mkdir,
      "touch": self.do_touch,
      "rmdir": self.do_rmdir,
    }

    self.cowrie_registry = {}
    self.load_cowrie_commands()
  
  def load_cowrie_commands(self):
    logger.info("Scanning for Cowrie command modules...")
    try:
      import src.proteus.virtual_env.commands as cowrie_cmds_pkg
      
      for _, module_name, _ in pkgutil.iter_modules(cowrie_cmds_pkg.__path__):
        try:
          full_mod_name = f"src.proteus.virtual_env.commands.{module_name}"
          module = importlib.import_module(full_mod_name)
          
          if hasattr(module, 'commands') and isinstance(module.commands, dict):
            for cmd_string, cmd_class in module.commands.items():
              base_cmd = cmd_string.split('/')[-1]
              self.cowrie_registry[base_cmd] = cmd_class
                    
        except Exception as e:
          logger.error(f"Error loading module '{module_name}': {e}")
              
      logger.success(f"{len(self.cowrie_registry)} cowrie commands loaded successfully.")
      print(f"Loaded Cowrie commands: {', '.join(self.cowrie_registry.keys())}")
    except Exception as e:
      logger.error(f"Fatal error initializing Cowrie registry: {e}")
  
  def get_motd(self):
    return (
      "Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-179-generic x86_64)\r\n\r\n"
      " * Documentation:  https://help.ubuntu.com\r\n"
      " * Management:     https://landscape.canonical.com\r\n"
      " * Support:        https://ubuntu.com/pro\r\n\r\n"
      "  System information as of " + datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y") + "\r\n\r\n"
      "  System load:  0.0                Processes:               113\r\n"
      "  Usage of /:   36.4% of 19.56GB   Users logged in:         0\r\n"
      "  Memory usage: 15%                IPv4 address for enp0s3: 10.0.2.15\r\n"
      "  Swamp usage:  0%\r\n\r\n"
      "Expanded security Maintenance for Applications is not enabled.\r\n\r\n"
      "0 updates can be applied immediately.\r\n\r\n"
      "Enable ESM Apps to receive additional future security updates.\r\n"
      "See https://ubuntu.com/esm or run: sudo pro status\r\n\r\n"
      "New release '24.04.4 LTS' available.\r\n"
      "Run 'do-release-upgrade' to upgrade to it.\r\n\r\n\r\n"
      "Last login: " + (datetime.now() - timedelta(days=1)).strftime("%a %b %d %H:%M:%S %Y") + " from 192.168.1.15\r\n"
    )
  
  def get_prompt(self, current_user="root"):
    display_path = self.vfs.cwd_path
    if (display_path == f"/{current_user}"):
      display_path = "~"
    elif display_path.startswith(f"/{current_user}/"):
      display_path = "~" + display_path[len(f"/{current_user}"):]
    
    symbol = "#" if current_user == "root" else "$"
    return f"{current_user}@ubuntu:{display_path}{symbol} "
  
  def execute_command(self, command: str):
    if not command.strip():
      return ""
    
    redirect_file = None
    is_append = False

    if '>>' in command:
      parts = command.split('>>', 1)
      command = parts[0].strip()
      redirect_file = parts[1].strip()
      is_append = True
    elif '>' in command:
      parts = command.split('>', 1)
      command = parts[0].strip()
      redirect_file = parts[1].strip()
    
    parts = command.strip().split()
    cmd = parts[0]
    args = parts[1:]

    output = ""

    if cmd in self.commands:
      try:
        output = self.commands[cmd](args)
      except Exception as e:
        logger.error(f"Error executing command '{cmd}': {e}\r\n")
        output = f"Error: {e}"
    else:
      output = self.execute_cowrie_command(cmd, args)

    if redirect_file:
      virtual_path = self.vfs.resolve_path(redirect_file, self.vfs.cwd_path)
      output_to_write = output if output else ""
      if self.vfs.get_node(virtual_path) is None:
        uid = 0
        gid = 0
        size = len(output_to_write)
        mode = "-rw-r--r--"
        realfile = os.path.join("honeyfs", virtual_path.lstrip("/"))
        self.vfs.mkfile(virtual_path, uid, gid, size, mode, realfile)

      node = self.vfs.get_node(virtual_path)

      if not isinstance(node, FSFile):
        return

      if is_append:
        new_content = node.content + output_to_write
        node.content = new_content
        node.size = len(node.content)
      else:
        node.content = output_to_write
        node.size = len(node.content)
    if redirect_file:
      return ""
    return output
  
  def execute_cowrie_command(self, cmd_name: str, args: list):
    CommandClass = self.cowrie_registry.get(cmd_name)

    if not CommandClass:
      return f"bash: {cmd_name}: command not found\r\n"
    
    try:
      mock_protocol = MockProtocol(self.vfs)
      cmd_instance = CommandClass(mock_protocol, *args)
      cmd_instance.start()
            
      raw_output = cmd_instance.output_buffer

      clean_output = raw_output.replace('\r\n', '\n').replace('\n', '\r\n')
            
      return clean_output

    except Exception as e:
      logger.error(f"Error executing Cowrie mock for {cmd_name}: {e}")
      return f"bash: {cmd_name}: internal error\r\n"
    
  # Command implementations

  def do_pwd(self, args: list):
    return self.vfs.cwd_path + "\r\n"
  
  def do_cd(self, args: list):
    if not args:
      target_path = "/root"
    else:
      target_path = args[0]
    
    new_path = posixpath.normpath(posixpath.join(self.vfs.cwd_path, target_path))
    
    node = self.resolve_absolute_path(new_path)

    if node is None:
      return f"-bash: cd: {target_path}: No such file or directory\r\n"
    if isinstance(node, FSDirectory):
      self.vfs.current_directory = node
      self.vfs.cwd_path = new_path
      return ""
    else:
      return f"-bash: cd: {target_path}: Not a directory\r\n"
  
  def resolve_absolute_path(self, target_path: str):
    if target_path == "/":
      return self.vfs.root
    
    parts = target_path.strip("/").split("/")
    node = self.vfs.root
    for part in parts:
      if isinstance(node, FSDirectory) and part in node.children:
        node = node.children[part]
      else:
        return None
    return node
  
  def do_ls(self, args: list):
    current_dir = self.vfs.current_directory
    
    if not current_dir.children:
      return ""
    names = [nodo.name for nodo in current_dir.children.values()]
    
    return "  ".join(names) + "\r\n"
  
  def do_rm(self, args: list):
    if not args:
      return "rm: missing operand\n"
    
    files_to_delete = [arg for arg in args if not arg.startswith('-')]
    
    if not files_to_delete:
      return ""

    output = ""
    for filename in files_to_delete:
      virtual_path = self.vfs.resolve_path(filename, self.vfs.cwd_path)

      if self.vfs.get_node(virtual_path) is None:
        output += f"rm: cannot remove '{filename}': No such file or directory\r\n"
        continue
      elif isinstance(self.vfs.get_node(virtual_path), FSDirectory):
        output += f"rm: cannot remove '{filename}': Is a directory\r\n"
        continue
      
      success = self.vfs.delete_node(virtual_path)
      
      if not success:
        output += f"rm: cannot remove '{filename}': No such file or directory\r\n"
            
    return output
  
  def do_mkdir(self, args: list):
    if not args:
      return "mkdir: missing operand\n"
    
    output = ""
    for dirname in args:
      virtual_path = self.vfs.resolve_path(dirname, self.vfs.cwd_path)
      
      if self.vfs.get_node(virtual_path) is not None:
        output += f"mkdir: cannot create directory '{dirname}': File exists\r\n"
        continue
      
      self.vfs.mkdir(virtual_path, uid=0, gid=0, size=4096, mode="drwxr-xr-x")
    
    return output
  
  def do_touch(self, args: list):
    if not args:
      return "touch: missing file operand\n"
    
    output = ""
    for filename in args:
      virtual_path = self.vfs.resolve_path(filename, self.vfs.cwd_path)
      
      if self.vfs.get_node(virtual_path) is not None:
        continue
      
      self.vfs.mkfile(virtual_path, uid=0, gid=0, size=0, mode="-rw-r--r--")
    
    return output
  
  def do_rmdir(self, args: list):
    if not args:
      return "rmdir: missing operand\n"
    
    output = ""
    for dirname in args:
      virtual_path = self.vfs.resolve_path(dirname, self.vfs.cwd_path)
      
      node = self.vfs.get_node(virtual_path)
      
      if node is None:
        output += f"rmdir: failed to remove '{dirname}': No such file or directory\r\n"
        continue

      if not isinstance(node, FSDirectory):
        output += f"rmdir: failed to remove '{dirname}': Not a directory\r\n"
        continue
      
      if node.children:
        output += f"rmdir: failed to remove '{dirname}': Directory not empty\r\n"
        continue
      
      success = self.vfs.delete_node(virtual_path)
      
      if not success:
        output += f"rmdir: failed to remove '{dirname}': No such file or directory\r\n"
            
    return output