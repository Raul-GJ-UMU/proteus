from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import VirtualShell
from src.proteus.decision_engine.capabilities.utils import Capability, CapabilityResult

class WeakenPasswordPolicyCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, options: object):
    super().__init__(vfs, virtual_shell, options)
  
  def execute(self) -> CapabilityResult:
    login_defs_path = "/etc/login.defs"
    if not self.vfs.exists(login_defs_path):
      if not self.vfs.mkfile_p(login_defs_path, uid=0, gid=0, size=4096, mode="rw-r--r--"):
        return CapabilityResult(
          success=False, 
          eac_id="EAC0014", 
          function_name="weaken_password_policy", 
          message="Failed to create /etc/login.defs. Cannot weaken password policy."
        )
    fake_login_defs = b"PASS_MAX_DAYS   99999\nPASS_MIN_DAYS   0\nPASS_MIN_LEN    4\n"
    self.vfs.override_file_contents(login_defs_path, fake_login_defs)
    return CapabilityResult(
      success=True, 
      eac_id="EAC0014", 
      function_name="weaken_password_policy", 
      message="Password policy weakened successfully."
    )
  
class CreateFakeAWSCredentialsCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, options: object):
    super().__init__(vfs, virtual_shell, options)
  
  def execute(self) -> CapabilityResult:
    user = getattr(self.options, "user", None)
    if not user:
      return CapabilityResult(
        success=False, 
        eac_id="EAC0005", 
        function_name="create_fake_aws_credentials", 
        message="User is required to create fake AWS credentials."
      )
    creds_path = f"/home/{user}/.aws/credentials"
    if not self.vfs.exists(creds_path):
      self.vfs.mkfile_p(creds_path, uid=1000, gid=1000, size=4096, mode="rw-------")
    
    aws_credentials = (
      "[default]\n"
      "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
      "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    ).encode('utf-8')
        
    self.vfs.override_file_contents(creds_path, aws_credentials)
    
    return CapabilityResult(
      success=True, 
      eac_id="EAC0005", 
      function_name="create_fake_aws_credentials", 
      message=f"Fake AWS credentials created successfully at {creds_path}."
    )