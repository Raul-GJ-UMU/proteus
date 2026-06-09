from pydantic import BaseModel, Field

from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import VirtualShell
from src.proteus.decision_engine.capabilities.utils import CapabilityResult

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

class EAC0014_Capabilities:
  @staticmethod
  def spoof_discovery_output(virtual_shell: VirtualShell) -> CapabilityResult:
    # virtual_shell.inject_fake_process()
    # virtual_shell.inject_fake_network_connections()
    return CapabilityResult(
      success=True, 
      eac_id="EAC0014", 
      function_name="spoof_discovery_output", 
      message="Discovery output spoofed successfully."
    )
  
  @staticmethod
  def weaken_password_policy(vfs: VirtualFileSystem) -> CapabilityResult:
    return CapabilityResult(
      success=False, 
      eac_id="EAC0014", 
      function_name="weaken_password_policy", 
      message="Failed to weaken password policy."
    )

  @staticmethod
  def sabotage_destructive_commands(virtual_shell: VirtualShell) -> CapabilityResult:
    return CapabilityResult(
      success=False, 
      eac_id="EAC0014", 
      function_name="sabotage_destructive_commands", 
      message="Failed to sabotage destructive commands."
    )

  @staticmethod
  def degrade_exfiltration_tools(virtual_shell: VirtualShell) -> CapabilityResult:
    return CapabilityResult(
      success=False, 
      eac_id="EAC0014", 
      function_name="degrade_exfiltration_tools", 
      message="Failed to degrade exfiltration tools."
    )