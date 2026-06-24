from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import VirtualShell
from src.proteus.engage_engine.capabilities.utils import Capability, CapabilityResult

class CreateFileCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "file_path": "Path of the file to create.",
      "file_content": "Initial content that should be written to the file.",
    }
  
  def execute(self) -> CapabilityResult:
    file_path = getattr(self.options, "file_path", None)
    if not file_path:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="File path is required to create a file."
      )
    file_content = getattr(self.options, "file_content", None)
    if not file_content:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="File content is required to create a file."
      )
    
    if self.vfs.exists(file_path):
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message=f"File {file_path} already exists. Cannot create file."
      )
    
    self.vfs.mkfile_p(file_path, uid=0, gid=0, size=len(file_content), mode="rw-r--r--")
    
    if not self.vfs.override_file_contents(file_path, file_content):
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message=f"Failed to create file {file_path}."
      )

    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"File {file_path} created successfully with provided content."
    )

class DeleteFileCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "file_path": "Path of the file to delete.",
    }
  
  def execute(self) -> CapabilityResult:
    file_path = getattr(self.options, "file_path", None)
    if not file_path:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="File path is required to delete a file."
      )
    
    if not self.vfs.exists(file_path):
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message=f"File {file_path} does not exist. Cannot delete file."
      )
    
    if not self.vfs.delete_node(file_path):
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message=f"Failed to delete file {file_path}."
      )

    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"File {file_path} deleted successfully."
    )

class ModifyFileContentCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "file_path": "Path of the file whose content should be modified.",
      "new_content": "Replacement content for the file.",
    }
  
  def execute(self) -> CapabilityResult:
    file_path = getattr(self.options, "file_path", None)
    if not file_path:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="File path is required to modify file content."
      )
    new_content = getattr(self.options, "new_content", None)
    if new_content is None:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="New content is required to modify file content."
      )
    
    if not self.vfs.exists(file_path):
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message=f"File {file_path} does not exist. Cannot modify file content."
      )
    
    if not self.vfs.override_file_contents(file_path, new_content):
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message=f"Failed to modify content for file {file_path}."
      )

    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"File {file_path} content modified successfully."
    )

class ModifyFileMetadataCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "file_path": "Path of the file whose metadata should be modified.",
      "new_metadata": "Dictionary of metadata values to apply, such as mode, uid, and gid.",
    }
  
  def execute(self) -> CapabilityResult:
    file_path = getattr(self.options, "file_path", None)
    if not file_path:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="File path is required to modify file metadata."
      )
    new_metadata = getattr(self.options, "new_metadata", None)
    if not new_metadata:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="New metadata is required to modify file metadata."
      )
    
    if not self.vfs.exists(file_path):
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message=f"File {file_path} does not exist. Cannot modify file metadata."
      )
    
    if not self.vfs.override_file_metadata(file_path, new_metadata):
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message=f"Failed to modify metadata for file {file_path}."
      )
    
    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"File {file_path} metadata modified successfully."
    )

class ModifyBashHistoryCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "commands": "Array of commands to add to the bash history.",
      "replace": "Boolean indicating whether to replace the entire history or append to it.",
    }
  
  def execute(self) -> CapabilityResult:
    commands = getattr(self.options, "commands", None)
    if not commands:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="Commands are required to modify bash history."
      )

    replace = getattr(self.options, "replace", False)

    if replace:
      new_history = "\n".join(commands) + "\n"
    else:
      existing_history = str(self.vfs.file_contents("/root/.bash_history") or "")
      new_history = existing_history + "\n".join(commands) + "\n"
    new_history = new_history.encode('utf-8')
    bash_history_path = "/root/.bash_history"
    if not self.vfs.override_file_contents(bash_history_path, new_history):
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message=f"Failed to modify bash history."
      )
    
    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"Bash history modified successfully."
    )

class ModifyHostsFileCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "ip": "IP address to add to the host.",
      "hostname": "Hostname to associate with the IP address.",
    }
  
  def execute(self) -> CapabilityResult:
    ip = getattr(self.options, "ip", None)
    hostname = getattr(self.options, "hostname", None)
    if not ip or not hostname:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="IP address and hostname are required to modify /etc/hosts."
      )
    
    existing_hosts_content = str(self.vfs.file_contents("/etc/hosts") or "")
    new_hosts_content = existing_hosts_content + f"{ip} {hostname}\n"
    
    new_hosts_content = new_hosts_content.encode('utf-8')
    hosts_file_path = "/etc/hosts"
    if not self.vfs.override_file_contents(hosts_file_path, new_hosts_content):
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message=f"Failed to modify /etc/hosts."
      )
    
    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"/etc/hosts modified successfully."
    )

# Almost same as the generic CreateFileCapability, but with specific instructions for a log file
class CreateLogFileCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "log_path": "Path of the log file to create, must begin with '/var/log/'.",
      "log_content": "Content that should be written to the log file.",
    }
  
  def execute(self) -> CapabilityResult:
    log_path = getattr(self.options, "log_path", None)
    if not log_path:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="Log path is required to create a log file."
      )
    log_content = getattr(self.options, "log_content", None)
    if not log_content:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="Log content is required to create a log file."
      )
    
    if self.vfs.exists(log_path):
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message=f"Log file {log_path} already exists. Cannot create log file."
      )
    
    self.vfs.mkfile_p(log_path, uid=0, gid=0, size=len(log_content), mode="rw-r--r--")
    
    if not self.vfs.override_file_contents(log_path, log_content):
      return CapabilityResult(
        success=False,
        eac_id=self.eac_id,
        message=f"Failed to create log file {log_path}."
      )

    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"Log file {log_path} created successfully with provided content."
    )

class GenerateTemporalFilesCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "files": "Array containing a list of paths for the temporal files, should be located in /tmp, /var/tmp, /var/cache or similar directories.",
    }
  
  def execute(self) -> CapabilityResult:
    files = getattr(self.options, "files", None)
    if not files:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="List of files is required to generate temporal files."
      )
    
    for i in range(len(files)):
      temp_file_path = f"/tmp/temp_file_{i}.txt"
      self.vfs.mkfile_p(temp_file_path, uid=0, gid=0, size=files[i]["size"], mode="rw-r--r--")
    
    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"{len(files)} temporal files generated successfully."
    )

# TODO: Create a fake encrypted zip file to make the attacker waste time trying to open it. (EAC0015)