from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import VirtualShell
from src.proteus.decision_engine.capabilities.utils import Capability, CapabilityResult

class InjectFakeProcessCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, options: object):
    super().__init__(vfs, virtual_shell, options)
  
  def execute(self) -> CapabilityResult:
    process_data = getattr(self.options, "process_data", None)
    if not process_data:
      return CapabilityResult(
        success=False, 
        eac_id="EAC0014", 
        function_name="spoof_discovery_output", 
        message="Process data is required to inject a fake process."
      )
    self.virtual_shell.inject_fake_process(process_data)
    return CapabilityResult(
      success=True, 
      eac_id="EAC0014", 
      function_name="spoof_discovery_output", 
      message="Discovery output spoofed successfully."
    )