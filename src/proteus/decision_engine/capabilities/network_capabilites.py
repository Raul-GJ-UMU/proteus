from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import VirtualShell
from src.proteus.decision_engine.capabilities.utils import Capability, CapabilityResult

class InjectFakeNetworkConnectionCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, options: object):
    super().__init__(vfs, virtual_shell, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "network_data": "Dictionary with the following fields: \n"
      "- protocol: Network protocol (string)\n"
      "- local_address: Local IP address and port (string)\n"
      "- remote_address: Remote IP address and port (string)\n"
      "- state: Connection state (string)",
    }
  
  def execute(self) -> CapabilityResult:
    network_data = getattr(self.options, "network_data", None)
    if not network_data:
      return CapabilityResult(
        success=False, 
        eac_id="EAC0014", 
        function_name="spoof_discovery_output", 
        message="Network data is required to inject a fake network connection."
      )
    self.virtual_shell.inject_fake_network_connection(network_data)
    return CapabilityResult(
      success=True, 
      eac_id="EAC0014", 
      function_name="spoof_discovery_output", 
      message="Discovery output spoofed successfully."
    )