import pytest
from src.proteus.virtual_env.vfs import VirtualFileSystem, FSDirectory, FSFile
from src.proteus.virtual_env.virtual_shell import VirtualShell

@pytest.fixture
def vfs_and_shell():
  vfs = VirtualFileSystem(json_path="dummy_vfs.json")
  vfs.root = FSDirectory("/")
  
  etc = FSDirectory("etc")
  passwd = FSFile("passwd", size=1024)
  etc.add_child(passwd)
  
  root_dir = FSDirectory("root")
  secret = FSFile("secret.txt", size=50)
  root_dir.add_child(secret)
  
  vfs.root.add_child(etc)
  vfs.root.add_child(root_dir)
  
  vfs.current_directory = root_dir
  vfs.cwd_path = "/root"
  
  shell = VirtualShell(vfs)
  
  return vfs, shell

# pwd tests

def test_pwd_initial_state(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("pwd")
  assert response == "/root\r\n"

# ls tests

def test_ls_current_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("ls")
  assert response == "secret.txt\r\n"

def test_ls_empty_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  vfs.current_directory.add_child(FSDirectory("empty_dir"))
  shell.execute_command("cd empty_dir")
  
  response = shell.execute_command("ls")
  assert response == ""

def test_cd_absolute_path(vfs_and_shell):
  vfs, shell = vfs_and_shell
  
  response = shell.execute_command("cd /etc")
  
  assert response == ""
  assert vfs.cwd_path == "/etc"
  assert vfs.current_directory.name == "etc"

def test_cd_parent_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  
  shell.execute_command("cd ..")
  assert vfs.cwd_path == "/"
  
  shell.execute_command("cd ..")
  assert vfs.cwd_path == "/"

def test_cd_relative_path(vfs_and_shell):
  vfs, shell = vfs_and_shell
  
  shell.execute_command("cd /")
  shell.execute_command("cd etc")
  
  assert vfs.cwd_path == "/etc"

def test_cd_invalid_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  
  response = shell.execute_command("cd /false_folder")
  assert response == "-bash: cd: /false_folder: No such file or directory\r\n"
  
  assert vfs.cwd_path == "/root"

def test_cd_to_file_fails(vfs_and_shell):
  vfs, shell = vfs_and_shell
  
  response = shell.execute_command("cd secret.txt")
  assert response == "-bash: cd: secret.txt: Not a directory\r\n"
  assert vfs.cwd_path == "/root"

# echo tests

def test_echo_simple(vfs_and_shell):
    vfs, shell = vfs_and_shell
    response = shell.execute_command("echo hello")
    assert response == "hello\r\n"

def test_echo_multiple_words(vfs_and_shell):
    vfs, shell = vfs_and_shell
    response = shell.execute_command("echo hello world from proteus")
    assert response == "hello world from proteus\r\n"

def test_echo_empty(vfs_and_shell):
    vfs, shell = vfs_and_shell
    response = shell.execute_command("echo")
    assert response == "\r\n"