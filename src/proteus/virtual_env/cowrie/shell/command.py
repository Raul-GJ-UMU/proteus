import time
import random

class MockUser:
    """Simulates the user object that Cowrie expects"""
    def __init__(self, username):
        self.username = username
        self.uid = 0
        self.gid = 0
        self.home = "/root"
        self.shell = "/bin/bash"

class MockProtocol:
    """Simulates the network protocol that Cowrie commands expect"""
    def __init__(self, vfs, current_user="root"):
        self.fs = vfs 
        self.user = MockUser(current_user)
        self.cwd = vfs.cwd_path
        self.terminal = self
        self.startTime = time.time() - random.random() * 100 * 86400.0 # up to 100 days in seconds
        self.output_buffer = ""

    def uptime(self):
        return time.time() - self.startTime
    
    def write(self, data):
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="replace")
        self.output_buffer += data
    
    @property
    def transport(self):
        return self

class HoneyPotCommand:
    def __init__(self, protocol, *args):
        self.protocol = protocol
        self.args = list(args)
        self.output_buffer = ""
        
        self.fs = self.protocol.fs
        
    def write(self, data: str):
        self.output_buffer += data
    
    def writeBytes(self, data: bytes):
        self.output_buffer += data.decode("utf-8", errors="replace")

    def errorWrite(self, data: str):
        self.write(data)

    def check_arguments(self, application, args):
        files = []
        for arg in args:
            path = self.fs.resolve_path(arg, self.protocol.cwd)
            if self.fs.isdir(path):
                self.errorWrite(
                    f"{application}: error reading `{arg}': Is a directory\n"
                )
                continue
            files.append(path)
        return files
    
    def set_input_data(self, data: bytes) -> None:
        self.input_data = data

    def start(self) -> None:
        self.call()
        self.exit()

    def exit(self):
        pass

    def call(self):
        pass