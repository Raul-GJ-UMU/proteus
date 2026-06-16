import pytest
from src.proteus.virtual_env.vfs import VirtualFileSystem, FSDirectory, FSFile
from src.proteus.virtual_env.virtual_shell import ShellTerminationError, VirtualShell

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

def test_mkdir_p_creates_missing_parents(vfs_and_shell):
  vfs, _ = vfs_and_shell

  assert vfs.mkdir_p("/home/dir1/dir2", uid=0, gid=0, size=4096, mode="drwxr-xr-x")
  assert vfs.isdir("/home")
  assert vfs.isdir("/home/dir1")
  assert vfs.isdir("/home/dir1/dir2")

def test_mkfile_p_creates_missing_parents(vfs_and_shell):
  vfs, _ = vfs_and_shell

  assert vfs.mkfile_p("/home/dir1/dir2/file1.txt", uid=0, gid=0, size=0, mode="-rw-r--r--")
  assert vfs.isdir("/home")
  assert vfs.isdir("/home/dir1")
  assert vfs.isdir("/home/dir1/dir2")
  assert vfs.isfile("/home/dir1/dir2/file1.txt")

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

# whoami tests

def test_whoami_returns_current_user(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("whoami")
  
  assert "root" in output.strip()
  assert len(output.strip().split("\n")) == 1

# id tests

def test_id_returns_user_info(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("id")
  
  assert "uid=" in output
  assert "gid=" in output
  assert "groups=" in output

# uname tests

def test_uname_basic(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output_basica = virtual_shell.execute_command("uname")
  
  assert "Linux" in output_basica.strip()

def test_uname_all(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output_completa = virtual_shell.execute_command("uname -a")
  
  assert "Linux" in output_completa

# hostname tests

def test_hostname_returns_machine_name(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("hostname")
  
  assert len(output.strip()) > 0

# users tests

def test_users_returns_logged_in_users(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("users")
  
  assert "root" in output

# date tests

def test_date_returns_current_time(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("date")
  
  assert len(output.strip()) > 0
  assert any(str(year) in output for year in range(2020, 2030)) or "UTC" in output or "CET" in output

# uptime tests

def test_uptime_returns_system_uptime(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("uptime")
  
  assert "up" in output
  assert "load average" in output

# free tests

def test_free_returns_memory_info(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("free")
  
  assert "Mem:" in output
  assert "Swap:" in output
  assert "total" in output.lower()

# w and who tests

def test_w_and_who_return_logged_users(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output_w = virtual_shell.execute_command("w")
  output_who = virtual_shell.execute_command("who")
  
  assert "root" in output_w or "daniel" in output_w
  assert "pts/" in output_w or "tty" in output_w
  
  assert "root" in output_who or "daniel" in output_who
  assert "pts/" in output_who or "tty" in output_who

# ps tests

def test_ps_returns_process_list(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("ps")
  
  assert "PID" in output
  assert "TTY" in output
  assert "CMD" in output
  assert "bash" in output or "sh" in output

# grep tests

def test_grep_finds_matching_lines(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  virtual_shell.execute_command("echo 'line1\nline2\nline3' > testfile.txt")
  
  output = virtual_shell.execute_command("grep line2 testfile.txt")
  
  assert "line2" in output
  assert "line1" not in output
  assert "line3" not in output

def test_grep_no_matches(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  virtual_shell.execute_command("echo 'line1\nline2\nline3' > testfile.txt")
  
  output = virtual_shell.execute_command("grep nomatch testfile.txt")
  
  assert output == ""

def test_grep_file_not_found(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("grep something nonexistent.txt")
  
  assert "No such file or directory" in output

def test_grep_missing_operand(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("grep")
  
  assert "Usage: grep [OPTIONS] PATTERN [FILE...]" in output

def test_grep_pattern_only(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("grep pattern")
  
  assert "Usage: grep [OPTIONS] PATTERN [FILE...]" in output

# head tests

def test_head_returns_first_lines(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  virtual_shell.execute_command("echo -e 'line1\nline2\nline3\nline4' > testfile.txt")
  
  output = virtual_shell.execute_command("head -n 2 testfile.txt")
  
  assert "line1" in output
  assert "line2" in output
  assert "line3" not in output
  assert "line4" not in output

def test_head_file_not_found(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("head -n 2 nonexistent.txt")
  
  assert "No such file or directory" in output

def test_head_missing_operand(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("head -n 2")
  
  assert "Usage: head [OPTIONS] FILE" in output

# tail tests

def test_tail_returns_last_lines(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  virtual_shell.execute_command("echo -e 'line1\nline2\nline3\nline4' > testfile.txt")
  
  output = virtual_shell.execute_command("tail -n 2 testfile.txt")
  
  assert "line3" in output
  assert "line4" in output
  assert "line1" not in output
  assert "line2" not in output

def test_tail_file_not_found(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("tail -n 2 nonexistent.txt")
  
  assert "No such file or directory" in output

def test_tail_missing_operand(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("tail -n 2")
  
  assert "Usage: tail [OPTIONS] FILE" in output

# wc tests

def test_wc_counts_lines_words_bytes(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  virtual_shell.execute_command("echo -e 'line1 line1\nline2 line2\nline3 line3' > testfile.txt")
  
  output = virtual_shell.execute_command("wc testfile.txt")
  
  assert "3" in output  # lines
  assert "6" in output  # words
  assert "36" in output # bytes (including newlines)

def test_wc_file_not_found(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("wc nonexistent.txt")
  
  assert "No such file or directory" in output

def test_wc_missing_operand(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("wc")
  
  assert "Usage: wc [OPTIONS] FILE" in output

# ifconfig tests

def test_ifconfig_returns_network_info(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("ifconfig")
  
  assert "inet " in output
  assert "ether " in output
  assert "lo" in output or "eth0" in output

# netstat tests

def test_netstat_returns_network_connections(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("netstat -tuln")
  
  assert "Proto" in output
  assert "Local Address" in output
  assert "Foreign Address" in output
  assert "LISTEN" in output

# ping tests

def test_ping_returns_ping_output(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("ping -c 3 8.8.8.8")
        
  assert "PING 8.8.8.8" in output
  assert "bytes from 8.8.8.8" in output
  assert "icmp_seq=1" in output
  assert "packet loss" in output

# traceroute tests



# clear tests

def test_clear_clears_screen(vfs_and_shell):
  vfs, virtual_shell = vfs_and_shell
  output = virtual_shell.execute_command("clear")
  
  assert output == "\033[H\033[2J"  # ANSI escape code for clearing the screen

# shutdown tests

@pytest.mark.parametrize(
  "command, expected_reason, expected_message",
  [
    ("shutdown now", "System shutdown requested", "The system is going down for power off NOW!"),
    ("poweroff", "System power off requested", "The system is going down for power off NOW!"),
    ("reboot", "System reboot requested", "The system is going down for reboot NOW!"),
    ("/sbin/reboot", "System reboot requested", "The system is going down for reboot NOW!"),
  ],
)
def test_termination_commands_disconnect(command, expected_reason, expected_message, vfs_and_shell):
  _, shell = vfs_and_shell

  with pytest.raises(ShellTerminationError) as excinfo:
    shell.execute_command(command)

  assert expected_reason == excinfo.value.exit_reason
  assert expected_message in excinfo.value.output