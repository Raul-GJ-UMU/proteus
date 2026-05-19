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

# touch tests

def test_touch_creates_file(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("touch newfile.txt")
  assert response == ""
  
  ls_response = shell.execute_command("ls")
  assert "newfile.txt" in ls_response

def test_touch_missing_operand(vfs_and_shell):
  vfs, shell = vfs_and_shell
  output = shell.execute_command("touch")
  assert "touch: missing file operand" in output

def test_touch_existing_file(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("touch existing.txt")
  
  response = shell.execute_command("touch existing.txt")
  assert response == ""

# mkdir tests

def test_mkdir_creates_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("mkdir newdir")
  assert response == ""
  
  ls_response = shell.execute_command("ls")
  assert "newdir" in ls_response

def test_mkdir_missing_operand(vfs_and_shell):
  vfs, shell = vfs_and_shell
  output = shell.execute_command("mkdir")
  assert "mkdir: missing operand" in output

def test_mkdir_existing_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("mkdir existingdir")
  
  response = shell.execute_command("mkdir existingdir")
  assert "mkdir: cannot create directory 'existingdir': File exists" in response

# rm tests

def test_rm_deletes_file(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("touch temp.txt")

  ls_response_1 = shell.execute_command("ls")
  assert "temp.txt" in ls_response_1
  
  response = shell.execute_command("rm temp.txt")
  assert response == ""
  
  ls_response_2 = shell.execute_command("ls")
  assert "temp.txt" not in ls_response_2

def test_rm_missing_operand(vfs_and_shell):
  vfs, shell = vfs_and_shell
  output = shell.execute_command("rm")
  assert "rm: missing operand" in output

def test_rm_nonexistent_file(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("rm nonexistent.txt")
  assert response == "rm: cannot remove 'nonexistent.txt': No such file or directory\r\n"

def test_rm_directory_fails(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("mkdir somedir")
  
  response = shell.execute_command("rm somedir")
  assert response == "rm: cannot remove 'somedir': Is a directory\r\n"

# rmdir tests

def test_rmdir_deletes_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("mkdir tempdir")

  ls_response_1 = shell.execute_command("ls")
  assert "tempdir" in ls_response_1
  
  response = shell.execute_command("rmdir tempdir")
  assert response == ""
  
  ls_response_2 = shell.execute_command("ls")
  assert "tempdir" not in ls_response_2

def test_rmdir_missing_operand(vfs_and_shell):
  vfs, shell = vfs_and_shell
  output = shell.execute_command("rmdir")
  assert "rmdir: missing operand" in output

def test_rmdir_nonexistent_directory(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("rmdir nonexistentdir")
  assert response == "rmdir: failed to remove 'nonexistentdir': No such file or directory\r\n"

def test_rmdir_file_fails(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("touch somefile")
  
  response = shell.execute_command("rmdir somefile")
  assert response == "rmdir: failed to remove 'somefile': Not a directory\r\n"

def test_rmdir_nonempty_directory_fails(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("mkdir somedir")
  shell.execute_command("touch somedir/file.txt")
  
  response = shell.execute_command("rmdir somedir")
  assert response == "rmdir: failed to remove 'somedir': Directory not empty\r\n"

# cat tests

def test_cat_existing_file(vfs_and_shell):
  vfs, shell = vfs_and_shell
  shell.execute_command("echo secret content > secret.txt")
  response = shell.execute_command("cat secret.txt")
  assert "secret content" in response

def test_cat_nonexistent_file(vfs_and_shell):
  vfs, shell = vfs_and_shell
  response = shell.execute_command("cat nonexistent.txt")
  assert response == "cat: nonexistent.txt: No such file or directory\r\n"