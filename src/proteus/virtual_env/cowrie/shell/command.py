import time
import random

class MockUser:
    """Simula el objeto de usuario que Cowrie espera"""
    def __init__(self, username):
        self.username = username
        self.uid = 0 # root user
        self.gid = 0 # root group
        self.home = "/root"
        self.shell = "/bin/bash"

class MockProtocol:
    """Simula la conexión de red de Cowrie para engañar a los comandos"""
    def __init__(self, vfs, current_user="root"):
        self.fs = vfs 
        self.user = MockUser(current_user)
        self.cwd = vfs.cwd_path
        self.terminal = self
        self.startTime = time.time() - random.random() * 100 * 86400.0 # up to 100 days in seconds
    
    def uptime(self):
        return time.time() - self.startTime
    
    def write(self, data):
        pass 

class HoneyPotCommand:
    def __init__(self, protocol, *args):
        self.protocol = protocol
        self.args = list(args)
        self.output_buffer = ""
        
        self.fs = self.protocol.fs
        
    def write(self, data):
        if isinstance(data, bytes):
            data = data.decode("utf-8", errors="ignore")
        self.output_buffer += data

    def errorWrite(self, data):
        self.write(data)

    def nextLine(self):
        self.write("\r\n")

    def exit(self):
        pass

    def start(self):
        self.call()

    def call(self):
        pass