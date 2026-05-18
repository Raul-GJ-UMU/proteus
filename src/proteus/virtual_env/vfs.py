from importlib.resources import path
import os
import json
from loguru import logger
import posixpath

logger.add("logs/proteus_vfs.log", rotation="10 MB")

class FSNode:
  def __init__(self, name: str, uid=0, gid=0, size=4096, permissions="rwxr-xr-x"):
    self.name = name
    self.uid = uid
    self.gid = gid
    self.size = size
    self.permissions = permissions
  
class FSDirectory(FSNode):
  def __init__(self, name: str, **kwargs):
    super().__init__(name, **kwargs)
    self.children: dict[str, FSNode] = {}

  def add_child(self, child: FSNode):
    self.children[child.name] = child
  
class FSFile(FSNode):
  def __init__(self, name: str, real_honeyfs_path=None, **kwargs):
    super().__init__(name, **kwargs)
    self.real_honeyfs_path = real_honeyfs_path
  
  def read_contents(self):
    if self.real_honeyfs_path and os.path.exists(self.real_honeyfs_path):
      with open(self.real_honeyfs_path, 'r', encoding='utf-8') as f:
        return f.read()
    return ""

class VirtualFileSystem:
  def __init__(self, json_path="src/proteus/virtual_env/filesystem.json"):
    self.root: FSDirectory = FSDirectory("/")
    self.current_directory: FSDirectory = self.root
    self.cwd_path: str = "/"

    self.load_from_json(json_path)
  
  def load_from_json(self, json_path: str):
    if not os.path.exists(json_path):
      logger.error(f"Filesystem JSON file not found: {json_path}")
      return

    logger.info(f"Loading filesystem from {json_path}...")
    with open(json_path, 'r', encoding='utf-8') as f:
      data = json.load(f)
    self.root = self._parse_node(data) # type: ignore

    self._set_initial_directory("/root")
    logger.success("Filesystem loaded successfully.")

  def _parse_node(self, node_data: dict):
    if node_data["type"] == "directory":
      node = FSDirectory(
        name=node_data["name"],
        uid=node_data.get("uid", 0),
        gid=node_data.get("gid", 0),
        size=node_data.get("size", 4096),
        permissions=node_data.get("permissions", "drwxr-xr-x")
      )

      for child_name, child_data in node_data.get("children", {}).items():
        node.add_child(self._parse_node(child_data))

    else:
      node = FSFile(
        name=node_data["name"],
        uid=node_data.get("uid", 0),
        gid=node_data.get("gid", 0),
        size=node_data.get("size", 0),
        permissions=node_data.get("permissions", "-rw-r--r--"),
      )
    return node
  
  def _set_initial_directory(self, target_path: str):
    if target_path == "/root" and "root" in self.root.children:
      root_dir = self.root.children["root"]
      if isinstance(root_dir, FSDirectory):
        self.current_directory = root_dir
        self.cwd_path = "/root"
      else:
        logger.error("Expected 'root' to be a directory in the filesystem JSON.")
    else:
      logger.warning(f"Initial directory {target_path} not found. Starting at root.")
      self.current_directory = self.root
      self.cwd_path = "/"
  
  def list_directory(self, path: str):
    abs_path_str = self.resolve_path(path, self.cwd_path)
    node = self.get_node(abs_path_str)
    if node and isinstance(node, FSDirectory):
      return "  ".join(node.children.keys())
    elif node:
      return node.name + "\r\n"
    else:
      return f"ls: cannot access {path}: No such file or directory\r\n"
  
  def resolve_path(self, path: str, cwd: str):
    return posixpath.normpath(posixpath.join(cwd, path))

  def get_node(self, path: str):
    node: FSNode
    if path == "/":
      return self.root
    
    parts = path.strip("/").split("/")
    node = self.root
    for part in parts:
      if isinstance(node, FSDirectory) and part in node.children:
        node = node.children[part]
      else:
        return None
    return node
  
  # POSIX

  def exists(self, path: str):
    return self.get_node(path) is not None

  def isdir(self, path: str):
    node = self.get_node(path)
    return node is not None and isinstance(node, FSDirectory)

  def isfile(self, path: str):
    node = self.get_node(path)
    return node is not None and isinstance(node, FSFile)
  
  def mkdir(self, path: str, uid: int, gid: int, size: int, mode: str):
    import posixpath
    parent_dir_path = posixpath.dirname(path)
    new_dir_name = posixpath.basename(path)
    
    parent_node = self.get_node(parent_dir_path)
    
    if parent_node and isinstance(parent_node, FSDirectory):
      new_node = FSDirectory(new_dir_name, uid=uid, gid=gid, size=size)
      parent_node.add_child(new_node)
      return True
    return False
  
  def mkfile(self, path: str, uid: int, gid: int, size: int, mode: str, realfile=None):
    import posixpath
    parent_dir_path = posixpath.dirname(path)
    new_file_name = posixpath.basename(path)
    
    parent_node = self.get_node(parent_dir_path)
    
    if parent_node and isinstance(parent_node, FSDirectory):
      new_node = FSFile(new_file_name, uid=uid, gid=gid, size=size)
      parent_node.add_child(new_node)
      return True
    return False