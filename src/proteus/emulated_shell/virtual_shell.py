from datetime import datetime, timedelta

from loguru import logger
import posixpath

from src.proteus.virtual_env.vfs import VirtualFileSystem

logger.add("logs/virtual_shell.log", rotation="10 MB")

class VirtualShell:
  def __init__(self, vfs):
    self.vfs: VirtualFileSystem = vfs
    
    self.commands = {
      "pwd": self.do_pwd,
      "ls": self.do_ls,
      "cd": self.do_cd,
      "whoami": self.do_whoami,
    }
  
  def get_motd(self):
    return (
      "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)\r\n\r\n"
      " * Documentation:  https://help.ubuntu.com\r\n"
      " * Management:     https://landscape.canonical.com\r\n"
      " * Support:        https://ubuntu.com/advantage\r\n\r\n"
      "  System information as of " + datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y") + "\r\n\r\n"
      "  System load:  0.0               Processes:             102\r\n"
      "  Usage of /:   12.4% of 19.56GB   Users logged in:       0\r\n"
      "  Memory usage: 15%               IP address for eth0:   172.17.0.2\r\n\r\n"
      "0 updates can be applied immediately.\r\n\r\n"
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
  
  def execute_command(self, command):
    if not command.strip():
      return ""
    
    parts = command.strip().split()
    cmd = parts[0]
    args = parts[1:]

    if cmd in self.commands:
      try:
        return self.commands[cmd](args)
      except Exception as e:
        logger.error(f"Error executing command '{cmd}': {e}\r\n")
        return f"Error: {e}"
    else:
      return f"bash: {cmd}: command not found\r\n"
    
  # Command implementations

  def do_pwd(self, args):
    return self.vfs.cwd_path + "\r\n"
  
  def do_ls(self, args):
    return self.vfs.list_directory(self.vfs.cwd_path) + "\r\n"
  
  def do_cd(self, args):
    if not args:
      target_path = "/root"
    else:
      target_path = args[0]
    
    new_path = posixpath.normpath(posixpath.join(self.vfs.cwd_path, target_path))
    
    node = self.resolve_absolute_path(new_path)
    
    if node and hasattr(node, "children"):
        self.vfs.current_directory = node
        self.vfs.cwd_path = new_path
        return ""
    else:
        return f"bash: cd: {target_path}: No such file or directory\r\n"
  
  def resolve_absolute_path(self, target_path):
    if target_path == "/":
      return self.vfs.root
    
    parts = target_path.strip("/").split("/")
    node = self.vfs.root
    for part in parts:
      if part in node.children:
        node = node.children[part]
      else:
        return None
    return node

  def do_whoami(self, args):
    return "root\r\n"