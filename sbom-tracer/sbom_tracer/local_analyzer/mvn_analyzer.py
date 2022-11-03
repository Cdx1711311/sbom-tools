import os
import subprocess

from sbom_tracer.local_analyzer.analyzer_base import AnalyzerBase
from sbom_tracer.util.common_util import copy_definition_files
from sbom_tracer.util.const import MAVEN_DEFINITION_FILE_PATTERNS
from sbom_tracer.util.shell_util import execute


class MvnAnalyzer(AnalyzerBase):
    def __init__(self):
        super(MvnAnalyzer, self).__init__(r"^mvn$", r".*", "")

    def _analyze(self, cmd, full_cmd, cwd, fd, task_workspace):
        try:
            os.chdir(cwd)
            paths = [line for line in
                     execute('mvn -q --also-make exec:exec -Dexec.executable="pwd"', stdout=subprocess.PIPE)[1].strip()
                     if line.startswith("/") or line.startswith("\\")]
            for path in paths:
                copy_definition_files(path, task_workspace, MAVEN_DEFINITION_FILE_PATTERNS)
        except:
            pass
