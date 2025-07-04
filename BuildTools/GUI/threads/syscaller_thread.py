import os
import subprocess
from PyQt5.QtCore import QThread, pyqtSignal
from threading import Thread
from datetime import datetime

class SysCallerThread(QThread):
    output = pyqtSignal(str)
    finished = pyqtSignal()
    
    def __init__(self, script_path, dll_paths=None, *args):
        super().__init__()
        self.script_path = script_path
        if dll_paths is None:
            self.dll_paths = []
        elif isinstance(dll_paths, str):
            self.dll_paths = [dll_paths]
        else:
            self.dll_paths = dll_paths
        self.args = args
        self.process = None
        self.complete_output = []
        self.start_time = datetime.now()

    def run(self):
        try:
            self.start_time = datetime.now()
            cmd = ['python', self.script_path]
            if self.dll_paths:
                os.environ['NTDLL_PATH'] = self.dll_paths[0]
                for i, path in enumerate(self.dll_paths[1:], start=2):
                    os.environ[f'NTDLL_PATH_{i}'] = path
                os.environ['NTDLL_PATH_COUNT'] = str(len(self.dll_paths))
            if self.args:
                cmd.extend(self.args)
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
          
            def read_output():
                while True:
                    if self.process.poll() is not None and not self.complete_output:
                        break
                    output = self.process.stdout.readline()
                    if not output and self.process.poll() is not None:
                        break
                    if output:
                        self.complete_output.append(output.rstrip())
                if self.complete_output:
                    self.output.emit('\n'.join(self.complete_output))
                self.process.stdout.close()
                self.process.wait()
                self.finished.emit()
            output_thread = Thread(target=read_output, daemon=True)
            output_thread.start()
        except Exception as e:
            self.output.emit(f"Error: {str(e)}")
            self.finished.emit()

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            self.process.wait()
