from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import VirtualShell

class CapabilityResult:
  def __init__(self, success: bool, eac_id: str, function_name: str, message: str = ""):
    self.success = success
    self.eac_id = eac_id
    self.function_name = function_name
    self.message = message

class Capability:
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, options: object):
    self.vfs = vfs
    self.virtual_shell = virtual_shell
    self.options = options
  
  def execute(self) -> CapabilityResult:
    return CapabilityResult(
      success=False, 
      eac_id="None", 
      function_name="execute", 
      message="Base capability does not implement execute method.")

