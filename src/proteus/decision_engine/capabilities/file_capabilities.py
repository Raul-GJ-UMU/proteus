from src.proteus.virtual_env.vfs import VirtualFileSystem
from src.proteus.virtual_env.virtual_shell import VirtualShell
from src.proteus.decision_engine.capabilities.utils import Capability, CapabilityResult

class CreateFileCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, options: object):
    super().__init__(vfs, virtual_shell, options)

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
        eac_id="FILE001", 
        function_name="create_file_capability", 
        message="File path is required to create a file."
      )
    file_content = getattr(self.options, "file_content", None)
    if not file_content:
      return CapabilityResult(
        success=False, 
        eac_id="FILE001", 
        function_name="create_file_capability", 
        message="File content is required to create a file."
      )
    
    if self.vfs.exists(file_path):
      return CapabilityResult(
        success=False, 
        eac_id="FILE001", 
        function_name="create_file_capability", 
        message=f"File {file_path} already exists. Cannot create file."
      )
    
    self.vfs.mkfile_p(file_path, uid=0, gid=0, size=len(file_content), mode="rw-r--r--")
    self.vfs.override_file_contents(file_path, file_content)
    
    return CapabilityResult(
      success=True, 
      eac_id="FILE001", 
      function_name="create_file_capability", 
      message=f"File {file_path} created successfully with provided content."
    )

class DeleteFileCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, options: object):
    super().__init__(vfs, virtual_shell, options)

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
        eac_id="FILE002", 
        function_name="delete_file_capability", 
        message="File path is required to delete a file."
      )
    
    if not self.vfs.exists(file_path):
      return CapabilityResult(
        success=False, 
        eac_id="FILE002", 
        function_name="delete_file_capability", 
        message=f"File {file_path} does not exist. Cannot delete file."
      )
    
    self.vfs.delete_node(file_path)
    
    return CapabilityResult(
      success=True, 
      eac_id="FILE002", 
      function_name="delete_file_capability", 
      message=f"File {file_path} deleted successfully."
    )

class ModifyFileContentCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, options: object):
    super().__init__(vfs, virtual_shell, options)

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
        eac_id="FILE003", 
        function_name="modify_file_content_capability", 
        message="File path is required to modify file content."
      )
    new_content = getattr(self.options, "new_content", None)
    if new_content is None:
      return CapabilityResult(
        success=False, 
        eac_id="FILE003", 
        function_name="modify_file_content_capability", 
        message="New content is required to modify file content."
      )
    
    if not self.vfs.exists(file_path):
      return CapabilityResult(
        success=False, 
        eac_id="FILE003", 
        function_name="modify_file_content_capability", 
        message=f"File {file_path} does not exist. Cannot modify file content."
      )
    
    self.vfs.override_file_contents(file_path, new_content)
    
    return CapabilityResult(
      success=True, 
      eac_id="FILE003", 
      function_name="modify_file_content_capability", 
      message=f"File {file_path} content modified successfully."
    )

class ModifyFileMetadataCapability(Capability):
  def __init__(self, vfs: VirtualFileSystem, virtual_shell: VirtualShell, options: object):
    super().__init__(vfs, virtual_shell, options)

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
        eac_id="FILE004", 
        function_name="modify_file_metadata_capability", 
        message="File path is required to modify file metadata."
      )
    new_metadata = getattr(self.options, "new_metadata", None)
    if not new_metadata:
      return CapabilityResult(
        success=False, 
        eac_id="FILE004", 
        function_name="modify_file_metadata_capability", 
        message="New metadata is required to modify file metadata."
      )
    
    if not self.vfs.exists(file_path):
      return CapabilityResult(
        success=False, 
        eac_id="FILE004", 
        function_name="modify_file_metadata_capability", 
        message=f"File {file_path} does not exist. Cannot modify file metadata."
      )
    self.vfs.override_file_metadata(file_path, new_metadata)
    return CapabilityResult(
      success=True, 
      eac_id="FILE004", 
      function_name="modify_file_metadata_capability", 
      message=f"File {file_path} metadata modified successfully."
    )
