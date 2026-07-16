from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import VirtualShell
from src.proteus.engage_engine.capabilities.utils import Capability, CapabilityResult

class WeakenPasswordPolicyCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {}
  
  def execute(self) -> CapabilityResult:
    login_defs_path = "/etc/login.defs"
    if not self.vfs.exists(login_defs_path):
      if not self.vfs.mkfile_p(login_defs_path, uid=0, gid=0, size=4096, mode="rw-r--r--"):
        return CapabilityResult(
          success=False, 
          eac_id=self.eac_id, 
          message="Failed to create /etc/login.defs. Cannot weaken password policy."
        )
    fake_login_defs = b"PASS_MAX_DAYS   99999\nPASS_MIN_DAYS   0\nPASS_MIN_LEN    4\n"
    self.vfs.override_file_contents(login_defs_path, fake_login_defs)
    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message="Password policy weakened successfully."
    )
  
class CreateFakeAWSCredentialsCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, eac_id: str, options: object):
    super().__init__(vfs, virtual_shell, eac_id, options)

  @classmethod
  def option_fields(cls) -> dict[str, str]:
    return {
      "user": "Username that should own the fake AWS credentials directory.",
    }
  
  def execute(self) -> CapabilityResult:
    user = getattr(self.options, "user", None)
    if not user:
      return CapabilityResult(
        success=False, 
        eac_id=self.eac_id, 
        message="User is required to create fake AWS credentials."
      )
    creds_path = f"/home/{user}/.aws/credentials"
    if not self.vfs.exists(creds_path):
      self.vfs.mkfile_p(creds_path, uid=1000, gid=1000, size=4096, mode="rw-------")
    
    aws_credentials = (
      "[default]\n"
      "aws_access_key_id=ASIA4F1YTB30ERBYM3I1\n"
      "aws_secret_access_key=gpdh49hZkJb1sVWU1yc3RhLi767OTwcFtQiUpfZc\n"
      "aws_session_token=gjSmwQoonhxCMgbhxXVmv21N9a5ALBw8GZfyrWBVccHCspjXQ63LICVyitkFu4rXyllxk5V/2SSBdKTeaKskVCanotZZfB5UF/Ybm/2Oh7S05aDRnT9z+sYhgIiSIwUyuuquPlnJxF7HBZg6QyVvSruDu7//////////KDglE230R2c34tregUVcnEl2sIbkHm5NaQcMt6y2YmXhO+fip2y7wH5p9e17F20xmGyRYWUWSjbPOUidvGecB6ACUaAP8kYkGh6QGvBK/F+d1IjHV9QNzhJGEq1aLG68yGyIaS7QUcFxJoV5a10AxUtQZZrdi7aalqqSugTw0J9mwj50SrnUr5Oh/O753abVO4tI1tsxO88FZajPvzqO3OYGLG5z6/wbC+blF4LY4hVvCtUG/Qyslaa7CoOQ4P0vtPPablEDQCah3tFttT/5X/7J8UgFFtO4zlHVYekwOfRSDW6GZ+AIGOMbq39RIA6vU2Mnftz/xt+e5PqLti74XeoFeVFBc/Er7+/KeCLMTvu5UFQO2EKyyEhj6MbI+J6ysCNlb04QfwOwgDUhbwB+F02jLQMpRl7onX7eKDUTbuACuI7ZPNZUhVpv0z4k9Bbg8GmA4P9oT4owhX1GaIZ6ZGg0v6NVhxo6EmVZzmvEiUb0/iwO2Dt6EWNU9vTE/4VLM2c6V//H9VSHpKnzQb3Mroo4EeEWqex7OXtmaOE4rrX8UcWI5pEWWFJBCXZMGICreRtE2T48m49NVKz9boMg41LuY1BdLK0U=\n"
      "region = us-east-1"
    ).encode('utf-8')
        
    self.vfs.override_file_contents(creds_path, aws_credentials)
    
    return CapabilityResult(
      success=True, 
      eac_id=self.eac_id, 
      message=f"Fake AWS credentials created successfully at {creds_path}."
    )