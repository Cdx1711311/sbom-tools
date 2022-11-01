from sbom_tracer.local_analyzer.analyzer_base import AnalyzerBase
from sbom_tracer.util.common_util import copy_definition_files_recursively
from sbom_tracer.util.const import MAVEN_DEFINITION_FILE_PATTERNS


class MvnAnalyzer(AnalyzerBase):
    def __init__(self):
        super(MvnAnalyzer, self).__init__(r"^mvn$", r".*", "")

    def _analyze(self, cmd, full_cmd, cwd, fd, task_workspace):
        try:
            copy_definition_files_recursively(cwd, task_workspace, MAVEN_DEFINITION_FILE_PATTERNS)
        except:
            pass
