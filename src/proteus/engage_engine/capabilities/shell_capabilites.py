from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import VirtualShell
from src.proteus.engage_engine.capabilities.utils import Capability, CapabilityResult

class ManipulateCommandOutputCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "command": "Full Command whose output should be manipulated.",
      "output": "New output to return for the command.",
    }
  
  def execute(self) -> CapabilityResult:
    command = getattr(self.options, "command", None)
    new_output = getattr(self.options, "output", None)
    if not command or new_output is None:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="Both 'command' and 'output' are required to manipulate command output."
      )
    
    self.virtual_shell.manipulate_command_output(command, new_output)
    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"Output for command '{command}' manipulated successfully."
    )

class AddEnviromentVariableCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "variable_name": "Name of the environment variable to add.",
      "variable_value": "Value of the environment variable to add.",
    }
  
  def execute(self) -> CapabilityResult:
    variable_name = getattr(self.options, "variable_name", None)
    variable_value = getattr(self.options, "variable_value", None)
    if not variable_name or variable_value is None:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="Both 'variable_name' and 'variable_value' are required to add an environment variable."
      )
    
    self.virtual_shell.environ[variable_name] = variable_value
    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"Environment variable '{variable_name}' added successfully."
    )