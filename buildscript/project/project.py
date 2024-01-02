from typing import Iterable, Dict, TextIO

import itertools
import os
import os.path as path
from glob import glob


class Project(object):
    """
    A Makefile project
    """

    def __init__(self, root_path: str, **kwargs):
        self.root_path = path.abspath(root_path)
        self.build_root = path.join(self.root_path, 'target')

        self.depends = kwargs.get('depends', [])

    @staticmethod
    def safe_update(dict1: dict, dict2: dict):
        """
        Update and assert that dicts do not conflicts
        """
        assert dict1.keys().isdisjoint(dict2.keys())
        dict1.update(dict2)

    def scan_files(self, prefixes: Iterable[str], suffixes: Iterable[str]):
        ret: Dict[str, str] = {}
        for prefix, suffix in itertools.product(prefixes, suffixes):
            glob_path = f"{prefix}/**/*.{suffix}".replace(os.sep, '/')
            paths = glob(glob_path, recursive=True)
            ret.update((path.relpath(p, prefix), p) for p in paths)
        return ret

    def scan_sources(self):
        raise NotImplementedError()

    def scan_deps(self):
        raise NotImplementedError()

    def inject_depends(self, projects: Dict[str, 'Project']):
        print(f"Inject {len(self.depends)} dependant projects")
        self.depends_proj = {name: projects[name] for name in self.depends}

    def write_prelude(fout: TextIO):
        raise NotImplementedError()

    def write_rules(fout: TextIO):
        raise NotImplementedError()

    def write_deps(fout: TextIO):
        raise NotImplementedError()

    def write_target(fout: TextIO):
        raise NotImplementedError()

    def write_makefile(self):
        print("Write makefile...")
        self.makefile = path.join(self.build_root, 'Makefile')
        os.makedirs(self.build_root, exist_ok=True)
        with open(self.makefile, 'w') as fout:
            fout.write("\n############# Prelude ############\n")
            self.write_prelude(fout)
            fout.write("\ndefault : all\n")

            fout.write("\n############## Rules #############\n")
            self.write_rules(fout)

            fout.write("\n############## Deps ##############\n")
            self.objs = []
            self.write_deps(fout)

            self.phonies = ['default', 'all']
            fout.write("\n############# Targets ############\n")
            self.write_target(fout)
            fout.write(f"\n.PHONY : {' '.join(self.phonies)}\n")

    def make(self):
        print(f"Begin make project {self.root_path}")
        self.write_makefile()
        print(f"Done!")
