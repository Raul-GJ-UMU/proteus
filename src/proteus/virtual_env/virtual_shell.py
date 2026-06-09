from datetime import datetime, timedelta
import hashlib
import importlib
import pkgutil
import getopt
import os
from random import randint
import socket
import sys
import shlex
from loguru import logger
import posixpath
from unittest.mock import MagicMock
from pydantic import BaseModel, Field

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

class ProcessData(BaseModel):
  user: str = Field(..., description="The user who owns the process")
  pid: int = Field(..., description="The process ID")
  cpu_usage: float = Field(..., description="The CPU usage of the process")
  memory_usage: float = Field(..., description="The memory usage of the process")
  vsz: int = Field(..., description="The virtual memory size of the process")
  rss: int = Field(..., description="The resident set size of the process")
  tty: str = Field(..., description="The terminal associated with the process")
  stat: str = Field(..., description="The process state")
  start_time: str = Field(..., description="The start time of the process")
  time: str = Field(..., description="The cumulative CPU time of the process")
  command: str = Field(..., description="The command that started the process")

class VirtualShell:
  def __init__(self, vfs: VirtualFileSystem):
    self.vfs = vfs
    self.current_user = "root"
    self.current_tty = "tty1"
    self.process_list: list[ProcessData] = []
    self.process_list.append(ProcessData(
       user="user",
       pid=974,
       cpu_usage=0.0,
       memory_usage=0.2,
       vsz=8744,
       rss=5488,
       tty="tty1",
       stat="S",
       start_time="15:17",
       time="0:00",
       command="bash"
    ))
    self.process_list.append(ProcessData(
       user="root",
       pid=1,
       cpu_usage=0.0,
       memory_usage=0.5,
       vsz=166256,
       rss=11704,
       tty="?",
       stat="Ss",
       start_time="15:12",
       time="0:01",
       command="/sbin/init"
    ))

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
      "uptime": self.do_uptime,
      "free": self.do_free,
      "w": self.do_w,
      "who": self.do_who,
      "ps": self.do_ps,
      "grep": self.do_grep,
      "head": self.do_head,
      "tail": self.do_tail,
      "wc": self.do_wc,
      "ifconfig": self.do_ifconfig,
      "netstat": self.do_netstat,
      "ping": self.do_ping
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
  
  def execute_command(self, command: str) -> str:
    if not command.strip():
      return ""
    
    redirect_file = None
    is_append = False

    parts = shlex.split(command.strip(), posix=True)
    for index, token in enumerate(parts):
      if token == '>>':
        redirect_file = parts[index + 1] if index + 1 < len(parts) else ""
        is_append = True
        parts = parts[:index]
        break
      if token == '>':
        redirect_file = parts[index + 1] if index + 1 < len(parts) else ""
        parts = parts[:index]
        break
      if token.startswith('>>') and len(token) > 2:
        redirect_file = token[2:]
        is_append = True
        parts = parts[:index]
        break
      if token.startswith('>') and len(token) > 1:
        redirect_file = token[1:]
        parts = parts[:index]
        break

    if not parts:
      return ""

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
      output_to_write = (output if output else "").replace("\r\n", "\n")
      if self.vfs.get_node(virtual_path) is None:
        uid = 0
        gid = 0
        size = len(output_to_write)
        mode = "-rw-r--r--"
        realfile = os.path.join("honeyfs", virtual_path.lstrip("/"))
        self.vfs.mkfile(virtual_path, uid, gid, size, mode, realfile)

      node = self.vfs.get_node(virtual_path)

      if not isinstance(node, FSFile):
        return ""

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

      if cmd_name == "ping" and getattr(cmd_instance, "running", False):
        if getattr(cmd_instance, "max", 0) <= 0:
          cmd_instance.max = 4

        while getattr(cmd_instance, "running", False):
          cmd_instance.showreply()
            
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
  
  def do_uptime(self, args: list):
    return " 16:20:00 up 2 days,  4:30,  1 user,  load average: 0.00, 0.01, 0.05\n"
  
  def do_free(self, args: list):
    return (
      "              total        used        free      shared  buff/cache   available\r\n"
      "Mem:        2010780      300000     1451796       50000       23944     1638988\r\n"
      "Swap:       2097148           0     2097148\r\n"
    )
  
  def do_w(self, args: list):
    return (
      " 16:20:00 up 2 days,  4:30,  1 user,  load average: 0.00, 0.01, 0.05\n"
      "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
      "root     pts/0    192.168.1.100    16:00    1.00s  0.02s  0.00s w\n"
    )
  
  def do_who(self, args: list):
    return "root     pts/0        2026-05-27 16:00 (192.168.1.100)\n"
  
  def do_ps(self, args: list):
    columns: list[str] = ["USER", "PID", "%CPU", "%MEM", "VSZ", "RSS", "TTY", "STAT", "START", "TIME", "COMMAND"]
    field_map = {
      "USER": "user",
      "PID": "pid",
      "%CPU": "cpu_usage",
      "%MEM": "memory_usage",
      "VSZ": "vsz",
      "RSS": "rss",
      "TTY": "tty",
      "STAT": "stat",
      "START": "start_time",
      "TIME": "time",
      "COMMAND": "command",
    }

    command_name = "ps" if not args else f"ps {' '.join(args)}"
    ps_process = ProcessData(
      user=self.current_user,
      pid=randint(1000, 2000),
      cpu_usage=0.1,
      memory_usage=0.5,
      vsz=10276,
      rss=3860,
      tty=self.current_tty,
      stat="R+",
      start_time=datetime.now().strftime("%H:%M"),
      time="0:00",
      command=command_name
    )
    self.process_list.append(ps_process)

    try:
      normalized_args = [arg.lstrip("-") for arg in args if arg and arg != "--"]
      option_flags = "".join(arg for arg in normalized_args if arg.isalpha()).lower()

      if not normalized_args:
        columns_to_show = ["PID", "TTY", "TIME", "COMMAND"]
      elif "aux" in normalized_args or option_flags == "aux" or set(option_flags) >= {"a", "u", "x"}:
        columns_to_show = columns
      elif "ef" in normalized_args or option_flags == "ef" or set(option_flags) >= {"e", "f"}:
        columns_to_show = columns
      else:
        requested_columns = {arg.upper() for arg in normalized_args}
        columns_to_show = [col for col in columns if col in requested_columns]
        if not columns_to_show:
          columns_to_show = ["PID", "TTY", "TIME", "COMMAND"]

      visible_processes = self.process_list
      if not normalized_args:
        visible_processes = [
          proc for proc in self.process_list
          if proc.user == self.current_user and proc.tty == self.current_tty
        ]

      rendered_rows: list[dict[str, str]] = []
      column_widths = {col: len(col) for col in columns_to_show}

      for proc in visible_processes:
        proc_dict = proc.model_dump()
        rendered_row = {}
        for col in columns_to_show:
          value = str(proc_dict[field_map[col]])
          if col in {"%CPU", "%MEM"}:
            value = f"{float(value):.1f}"
          rendered_row[col] = value
          column_widths[col] = max(column_widths[col], len(value))
        rendered_rows.append(rendered_row)

      output_lines = [
        "  ".join(
          col.rjust(column_widths[col]) if col in {"PID", "VSZ", "RSS", "%CPU", "%MEM"}
          else col.ljust(column_widths[col])
          for col in columns_to_show
        )
      ]

      for rendered_row in rendered_rows:
        line_parts = []
        for col in columns_to_show:
          value = rendered_row[col]
          if col in {"PID", "VSZ", "RSS", "%CPU", "%MEM"}:
            line_parts.append(value.rjust(column_widths[col]))
          else:
            line_parts.append(value.ljust(column_widths[col]))
        output_lines.append("  ".join(line_parts))

      return "\r\n".join(output_lines) + "\r\n"
    finally:
      if ps_process in self.process_list:
        self.process_list.remove(ps_process)
  
  def do_grep(self, args: list):
    try:
      _, clean_args = getopt.getopt(args, "")
    except Exception:
      clean_args = [a for a in args if not a.startswith('-')]

    if len(clean_args) < 2:
      return "Usage: grep [OPTIONS] PATTERN [FILE...]\n"

    pattern = clean_args[0]
    files = clean_args[1:]
    output = ""
    
    for file in files:
      try:
        virtual_path = self.vfs.resolve_path(file, getattr(self.vfs, 'cwd_path', '/root'))
        content = self.vfs.file_contents(virtual_path).decode('utf-8', errors='replace')
        for line in content.split('\n'):
          if pattern in line:
            output += f"{line}\n"
      except Exception:
        output += f"grep: {file}: No such file or directory\n"
    return output
  
  def do_head(self, args: list):
    try:
      optlist, clean_args = getopt.getopt(args, "n:")
    except Exception:
      return "Usage: head [OPTIONS] FILE\n"

    if len(clean_args) < 1:
      return "Usage: head [OPTIONS] FILE\n"
    
    file = clean_args[0]
    line_count = 10
    for opt, opt_value in optlist:
      if opt == "-n":
        try:
          line_count = int(opt_value)
        except ValueError:
          return "Usage: head [OPTIONS] FILE\n"

    output = ""
    
    try:
      virtual_path = self.vfs.resolve_path(file, getattr(self.vfs, 'cwd_path', '/root'))
      content = self.vfs.file_contents(virtual_path).decode('utf-8', errors='replace')
      lines = content.splitlines()[:line_count]
      output = "\n".join(lines)
      if output:
        output += "\n"
    except Exception:
      output += f"head: cannot open '{file}' for reading: No such file or directory\n"
    
    return output
  
  def do_tail(self, args: list):
    try:
      optlist, clean_args = getopt.getopt(args, "n:")
    except Exception:
      return "Usage: tail [OPTIONS] FILE\n"

    if len(clean_args) < 1:
      return "Usage: tail [OPTIONS] FILE\n"
    
    file = clean_args[0]
    line_count = 10
    for opt, opt_value in optlist:
      if opt == "-n":
        try:
          line_count = int(opt_value)
        except ValueError:
          return "Usage: tail [OPTIONS] FILE\n"

    output = ""
    
    try:
      virtual_path = self.vfs.resolve_path(file, getattr(self.vfs, 'cwd_path', '/root'))
      content = self.vfs.file_contents(virtual_path).decode('utf-8', errors='replace')
      lines = content.splitlines()[-line_count:]
      output = "\n".join(lines)
      if output:
        output += "\n"
    except Exception:
      output += f"tail: cannot open '{file}' for reading: No such file or directory\n"
    
    return output
  
  def do_wc(self, args: list):
    try:
      optlist, clean_args = getopt.getopt(args, "cmlwhv")
    except Exception:
      return "Usage: wc [OPTIONS] FILE\n"

    if len(clean_args) < 1:
      return "Usage: wc [OPTIONS] FILE\n"
    
    file = clean_args[0]
    output = ""
    
    try:
      virtual_path = self.vfs.resolve_path(file, getattr(self.vfs, 'cwd_path', '/root'))
      content = self.vfs.file_contents(virtual_path).decode('utf-8', errors='replace')
      lines = content.count("\n")
      words = len(content.split())
      chars = len(content.encode("utf-8"))

      selected_options = {opt for opt, _ in optlist}
      selected_counts = []

      if not selected_options or "-l" in selected_options:
        selected_counts.append(str(lines))
      if not selected_options or "-w" in selected_options:
        selected_counts.append(str(words))
      if not selected_options or "-c" in selected_options or "-m" in selected_options:
        selected_counts.append(str(chars))

      output = f"{' '.join(selected_counts)} {file}\n"
    except Exception:
      output += f"wc: cannot open '{file}' for reading: No such file or directory\n"
    
    return output

  def do_ifconfig(self, args: list):
    output = self.execute_cowrie_command("ifconfig", args)
    return output.replace("HWaddr ", "ether ")

  def do_netstat(self, args: list):
    return self.execute_cowrie_command("netstat", args)

  def do_ping(self, args: list):
    try:
      optlist, remaining_args = getopt.getopt(args, "c:i:")
    except Exception:
      return "ping: invalid arguments\n"

    if not remaining_args:
      return (
        "Usage: ping [-LRUbdfnqrvVaA] [-c count] [-i interval] [-w deadline]\n"
        "            [-p pattern] [-s packetsize] [-t ttl] [-I interface or address]\n"
        "            [-M mtu discovery hint] [-S sndbuf]\n"
        "            [ -T timestamp option ] [ -Q tos ] [hop1 ...] destination\n"
      )

    host = remaining_args[0].strip()
    packet_count = 4

    for opt, opt_value in optlist:
      if opt == "-c":
        try:
          packet_count = int(opt_value)
        except Exception:
          packet_count = 0

    if packet_count <= 0:
      return "ping: bad number of packets to transmit.\n"

    try:
      socket.inet_aton(host)
      ip_address = host
    except Exception:
      digest = hashlib.md5(host.encode("utf-8")).hexdigest()
      ip_address = ".".join(str(int(digest[index:index + 2], 16)) for index in range(0, 8, 2))

    output_lines = [f"PING {host} ({ip_address}) 56(84) bytes of data."]

    for seq in range(1, packet_count + 1):
      output_lines.append(
        f"64 bytes from {host} ({ip_address}): icmp_seq={seq} ttl=50 time={40.0 + seq / 10:.1f} ms"
      )

    output_lines.append("")
    output_lines.append(f"--- {host} ping statistics ---")
    output_lines.append(
      f"{packet_count} packets transmitted, {packet_count} received, 0% packet loss, time 907ms"
    )
    output_lines.append("rtt min/avg/max/mdev = 48.264/50.352/52.441/2.100 ms")

    return "\n".join(output_lines) + "\n"