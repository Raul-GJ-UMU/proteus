from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import VirtualShell
from src.proteus.decision_engine.capabilities.utils import Capability, CapabilityResult

class CreateFakeUserAccountCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, options: object):
    super().__init__(vfs, virtual_shell, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "username": "Username for the fake account to create.",
    }
  
  def execute(self) -> CapabilityResult:
    account_name = getattr(self.options, "username", None)
    if not account_name:
      return CapabilityResult(
        success=False, 
        eac_id="EAC0005", 
        function_name="create_fake_user_account", 
        message="Username is required to create a fake user account."
      )
    try:
      current_passwd = self.vfs.file_contents("/etc/passwd").decode('utf-8')
      current_shadow = self.vfs.file_contents("/etc/shadow").decode('utf-8')
    except Exception:
      return CapabilityResult(
        success=False, 
        eac_id="EAC0005", 
        function_name="create_fake_account", 
        message=f"Failed to create fake account '{account_name}'."
      )
        
    new_passwd = current_passwd + f"{account_name}:x:1001:1001:{account_name}:/home/devops:/bin/bash\n"
    # Hash '$1$salt$Gcm6FsVtF/Qa7.ZZsR.X.0' corresponds to the password '123456' in MD5
    new_shadow = current_shadow + f"{account_name}:$1$salt$Gcm6FsVtF/Qa7.ZZsR.X.0:18600:0:99999:7:::\n"
    
    self.vfs.override_file_contents("/etc/passwd", new_passwd.encode('utf-8'))
    self.vfs.override_file_contents("/etc/shadow", new_shadow.encode('utf-8'))
    return CapabilityResult(
      success=True, 
      eac_id="EAC0005", 
      function_name="create_fake_account", 
      message=f"Fake account '{account_name}' created successfully."
    )