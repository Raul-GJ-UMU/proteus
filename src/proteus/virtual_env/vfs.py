import os
import json
from loguru import logger

logger.add("logs/proteus_vfs.log", rotation="10 MB")

class FSNode:
  def __init__(self, name, uid=0, gid=0, size=4096, permissions="rwxr-xr-x"):
    self.name = name
    self.uid = uid
    self.gid = gid
    self.size = size
    self.permissions = permissions
    self.children = {}
  
class FSDirectory(FSNode):
  def __init__(self, name, **kwargs):
    super().__init__(name, **kwargs)
    self.children = {}

  def add_child(self, child):
    self.children[child.name] = child
  
class FSFile(FSNode):
  def __init__(self, name, real_honeyfs_path=None, **kwargs):
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
  
  def load_from_json(self, json_path):
    if not os.path.exists(json_path):
      logger.error(f"Filesystem JSON file not found: {json_path}")
      return

    logger.info(f"Loading filesystem from {json_path}...")
    with open(json_path, 'r', encoding='utf-8') as f:
      data = json.load(f)
    self.root = self._parse_node(data) # type: ignore

    self._set_initial_directory("/root")
    logger.success("Filesystem loaded successfully.")

  def _parse_node(self, node_data):
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
  
  def _set_initial_directory(self, target_path):
    if target_path == "/root" and "root" in self.root.children:
      self.current_directory = self.root.children["root"]
      self.cwd_path = "/root"
    else:
      logger.warning(f"Initial directory {target_path} not found. Starting at root.")
      self.current_directory = self.root
      self.cwd_path = "/"
  
  def list_directory(self, path):
    node = self.resolve_path(path)
    if node and isinstance(node, FSDirectory):
      return "  ".join(node.children.keys())
    return ""
  
  def resolve_path(self, path):
    if path.startswith("/"):
      node = self.root
      parts = path.strip("/").split("/")
    else:
      node = self.current_directory
      parts = path.split("/")

    for part in parts:
      if part == "" or part == ".":
        continue
      elif part == "..":
        if node.name != "/":
          parent_path = "/".join(self.cwd_path.strip("/").split("/")[:-1])
          new_node = self.resolve_path("/" + parent_path) if parent_path else self.root
          if isinstance(new_node, FSDirectory):
            node = new_node
      else:
        if isinstance(node, FSDirectory) and part in node.children:
          node = node.children[part]
        else:
          return None
    return node