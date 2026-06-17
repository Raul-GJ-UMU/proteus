from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import ProcessData, VirtualShell
from src.proteus.decision_engine.capabilities.utils import Capability, CapabilityResult

class InjectFakeProcessCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, options: object):
    super().__init__(vfs, virtual_shell, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "process_data": "Dictionary with pid, cpu_usage, memory_usage, vsz, rss, stat, start_time, time, and command.",
    }
  
  def execute(self) -> CapabilityResult:
    options = getattr(self.options, "process_data", None)
    if not options:
      return CapabilityResult(
        success=False, 
        eac_id="EAC0014", 
        function_name="spoof_discovery_output", 
        message="Process data is required to inject a fake process."
      )
    process_data = ProcessData(
      user=self.virtual_shell.current_user,
      pid=options.get("pid", 0),
      cpu_usage=options.get("cpu_usage", 0.0),
      memory_usage=options.get("memory_usage", 0.0),
      vsz=options.get("vsz", 0),
      rss=options.get("rss", 0),
      tty=self.virtual_shell.current_tty,
      stat=options.get("stat", ""),
      start_time=options.get("start_time", ""),
      time=options.get("time", ""),
      command=options.get("command", "")
    )
    self.virtual_shell.inject_fake_process(process_data)
    return CapabilityResult(
      success=True, 
      eac_id="EAC0014", 
      function_name="spoof_discovery_output", 
      message="Discovery output spoofed successfully."
    )