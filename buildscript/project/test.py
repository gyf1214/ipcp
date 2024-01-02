import os.path as path
from typing import TextIO

from .c import CProject


class TestProject(CProject):
    def __init__(self, root_path: str, **kwargs):
        super().__init__(
            root_path,
            output_name='test', output_type=CProject.OutputType.BINARY,
            **kwargs)

        self.test_command = kwargs['test_command']
        self.test_files = kwargs.get('test_files', [])
        self.test_path = path.join(self.build_root, 'tests')
        self.test_output = path.join(self.test_path, 'summary.out')

    def write_target(self, fout: TextIO):
        super().write_target(fout)

        files = [
            self.get_path(path.join(self.root_path, file))
            for file in self.test_files
        ]

        fout.write(
            f"\ntest: all {' '.join(files)}\n"
            f"\t@echo RUN test\n"
            f"\trm -fr {self.test_path}\n"
            f"\t{self.test_command.format(*files)}\n"
        )
        self.phonies.append('test')
