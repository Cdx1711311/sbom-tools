import os

from sbom_tracer.local_analyzer.analyzer_base import AnalyzerBase
from sbom_tracer.util.common_util import copy_definition_files_recursively
from sbom_tracer.util.const import GRADLE_DEFINITION_FILE_PATTERNS, DEFINITION_FILE_DIR_NAME


class GradleAnalyzer(AnalyzerBase):
    def __init__(self):
        super(GradleAnalyzer, self).__init__(r"^gradle$", r".*", "")

    def _analyze(self, cmd, full_cmd, cwd, fd, task_workspace):
        try:
            copy_definition_files_recursively(cwd, os.path.join(task_workspace, DEFINITION_FILE_DIR_NAME),
                                              GRADLE_DEFINITION_FILE_PATTERNS)
        except:
            pass
