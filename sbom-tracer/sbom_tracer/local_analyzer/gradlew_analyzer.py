from sbom_tracer.local_analyzer.analyzer_base import AnalyzerBase
from sbom_tracer.util.common_util import copy_definition_files_recursively
from sbom_tracer.util.const import GRADLE_DEFINITION_FILE_PATTERNS


class GradlewAnalyzer(AnalyzerBase):
    def __init__(self):
        super(GradlewAnalyzer, self).__init__(r"^java$", r".*gradle\.wrapper\.GradleWrapperMain.*", "")

    def _analyze(self, cmd, full_cmd, cwd, fd, task_workspace):
        try:
            copy_definition_files_recursively(cwd, task_workspace, GRADLE_DEFINITION_FILE_PATTERNS)
        except:
            pass
