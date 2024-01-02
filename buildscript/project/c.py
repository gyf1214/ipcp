from typing import Dict, List, Optional, TextIO

import re
import os.path as path
from enum import Enum, auto

from .project import Project


class CProject(Project):
    INCLUDE_RE = re.compile(r"#include\s*\"(.*)\"")
    SUFFIX_RE = re.compile(r"\..+$")
    LIB_RE = re.compile(r"lib(.*)\.(a|so)")

    H_RULE = (
        "\t@echo Copy $@\n"
        "\tmkdir -p $(dir $@)\n"
        "\tcp $< $@\n"
    )

    C_CXX_RULE = (
        "\t@echo {0} $<\n"
        "\tmkdir -p $(dir $@)\n"
        "\t$({0}) -c $({1}) -o $@ $<\n"
    )

    C_RULE = C_CXX_RULE.format('CC', 'CFLAGS')

    class OutputType(Enum):
        BINARY = auto()
        STATIC = auto()
        SHARED = auto()

    def __init__(self, root_path: str, **kwargs):
        super().__init__(root_path, **kwargs)

        self.source_path = path.join(self.root_path, 'src')
        self.include_path = path.join(self.root_path, 'include')
        self.internal_path = path.join(self.source_path, 'include')
        self.obj_path = path.join(self.build_root, 'obj')
        self.export_path = path.join(self.build_root, 'include')
        self.generated_path = path.join(self.build_root, 'generated-src')
        self.generated_obj_path = path.join(self.obj_path, 'generated')

        self.output_name = kwargs['output_name']
        self.output_type = kwargs['output_type']
        self.debug = kwargs.get('debug', False)
        self.test = kwargs.get('test', False)
        self.lib_includes = kwargs.get('lib_includes', [])
        self.lib_paths = kwargs.get('lib_paths', [])
        self.libs = kwargs.get('libs', [])

        self.cc = kwargs.get('cc', 'gcc')
        if self.output_type == CProject.OutputType.STATIC:
            self.ar = kwargs.get('ar', 'ar')
        else:
            self.ld = kwargs.get('ld', 'gcc')

        self.all_includes = self.lib_includes + \
            [self.include_path, self.internal_path]

        self.source_suffix = ['c']
        self.header_suffix = ['h']

    def scan_sources(self):
        print("Scan sources and headers...")

        self.sources = self.scan_files([self.source_path], self.source_suffix)
        self.headers = self.scan_files([self.include_path], self.header_suffix)
        self.exports = {
            key: path.join(self.export_path, key)
            for key in self.headers.keys()
        }
        internals = self.scan_files([self.internal_path], self.header_suffix)

        self.all_sources = self.sources.copy()
        self.safe_update(self.all_sources, self.headers)
        self.safe_update(self.all_sources, internals)
        self.all_deps = self.all_sources.copy()
        self.deps = {}
        print(f"Found {len(self.sources)} sources, "
              f"{len(self.headers)} headers, "
              f"{len(internals)} internal headers.")

    def scan_deps_file(self, source: Optional[str]):
        ret: List[str] = []
        with open(source, 'r') as fin:
            for line in fin:
                mat = CProject.INCLUDE_RE.match(line.strip())
                if mat is not None:
                    header = mat.group(1)
                    if header in self.all_deps:
                        ret.append(mat.group(1))
        return ret

    def expand_deps(self, key: str):
        deps = self.deps[key]
        i = 0
        while i < len(deps):
            dep = deps[i]
            if dep in self.deps:
                for f in self.deps[dep]:
                    if f not in deps:
                        deps.append(f)
            i += 1

    def scan_source_dependency(self):
        self.deps.update({
            key: self.scan_deps_file(source)
            for key, source in self.all_sources.items()
        })

    def scan_deps(self):
        print("Scan deps...")
        self.scan_source_dependency()
        for key in self.all_sources.keys():
            self.expand_deps(key)
        print("Deps processed.")
        print(f"all_sources={self.all_sources}")
        print(f"all_deps={self.all_deps}")
        print(f"deps={self.deps}")

    def inject_depends(self, projects: Dict[str, Project]):
        super().inject_depends(projects)

        libs = []
        self.lib_depends = []
        for proj in self.depends_proj.values():
            assert isinstance(proj, CProject), "Depends not a CProject"

            self.all_includes.append(proj.export_path)
            self.safe_update(self.all_deps, proj.exports)
            self.deps.update(proj.deps)

            lib = proj.output_name
            lib_path = path.join(proj.build_root, lib)
            self.lib_depends.append(self.get_path(lib_path))

            mat = CProject.LIB_RE.match(lib)
            if mat is not None:
                lib = mat.group(1)
            libs.append(lib)
            self.lib_paths.append(proj.build_root)

        self.libs = libs + self.libs

    def write_prelude(self, fout: TextIO):
        print("Write C/CPP prelude")

        self.c_flags = ['-Wall']
        if self.debug:
            self.c_flags += ['-g', '-O0']
        else:
            self.c_flags += ['-O2', '-DNDEBUG']
        if not self.test:
            self.c_flags += ['-DNTEST']
        if self.output_type == CProject.OutputType.SHARED:
            self.c_flags += ['-fPIC', '-fvisibility=hidden']
        for inc in self.all_includes:
            inc = path.abspath(inc)
            if path.commonprefix([self.root_path, inc]) == self.root_path:
                inc = path.relpath(inc, self.root_path)
            self.c_flags.append(f"-I{inc}")

        if self.output_type == CProject.OutputType.STATIC:
            self.ar_flags = []
        else:
            self.ld_flags = []
            if self.output_type == CProject.OutputType.SHARED:
                self.ld_flags += ['-shared']
            for lib_path in self.lib_paths:
                self.ld_flags.append(f"-L{lib_path}")

            self.ld_libs = []
            for lib in self.libs:
                self.ld_libs.append(f"-l{lib}")

        fout.write(
            f"CC={self.cc}\n"
            f"CFLAGS={' '.join(self.c_flags)}\n\n"
        )
        if self.output_type == CProject.OutputType.STATIC:
            fout.write(
                f"AR={self.ar}\n"
                f"ARFLAGS={' '.join(self.ar_flags)}\n\n"
            )
        else:
            fout.write(
                f"LD={self.ld}\n"
                f"LDFLAGS={' '.join(self.ld_flags)}\n"
                f"LDLIBS={' '.join(self.ld_libs)}\n\n"
            )

    def write_rule(self, fout: TextIO, source: str, target: str, rule: str):
        source = self.get_path(source)
        target = self.get_path(target)
        fout.write(f"{target} : {source}\n")
        fout.write(f"{rule}\n")

    def write_rules(self, fout: TextIO):
        print("Write C rules")
        self.write_rule(
            fout, f"{self.source_path}/%.c",
            f"{self.obj_path}/%.o", CProject.C_RULE
        )
        self.write_rule(
            fout, f"{self.include_path}/%.h",
            f"{self.export_path}/%.h", CProject.H_RULE
        )

    def get_path(self, source: str):
        source = path.abspath(source)
        if self.root_path == path.commonpath([source, self.root_path]):
            source = path.relpath(source, self.root_path)
        source = source.replace(path.sep, '/')
        return source

    def write_deps(self, fout: TextIO):
        print("Write dependancies")
        for key, source in self.sources.items():
            target = path.join(
                self.obj_path, CProject.SUFFIX_RE.sub('.o', key))
            target = self.get_path(target)

            source = self.get_path(source)

            deps = self.deps[key]
            deps = [
                self.get_path(self.all_deps[key])
                for key in deps
            ]

            self.objs.append(target)
            fout.write(f"{target} : {source} {' '.join(deps)}\n")

    def write_target(self, fout: TextIO):
        print("Write C targets")

        target = self.get_path(path.join(self.build_root, self.output_name))
        if self.output_type == CProject.OutputType.STATIC:
            fout.write(
                f"{target} : {' '.join(self.objs)}\n"
                "\t@echo AR $@\n"
                "\tmkdir -p $(dir $@)\n"
                "\t$(AR) $(ARFLAGS) -rcs $@ $^\n"
            )
        else:
            fout.write(
                f"{target} : {' '.join(self.objs + self.lib_depends)}\n"
                "\t@echo LD $@\n"
                "\tmkdir -p $(dir $@)\n"
                "\t$(LD) $(LDFLAGS) -o $@ $^ $(LDLIBS)\n"
            )

        exports = [self.get_path(p) for p in self.exports.values()]

        fout.write(
            f"\nheaders : {' '.join(exports)}\n"
            f"all : {target} headers\n"
            f"clean : \n"
            f"\trm -fr {self.get_path(self.obj_path)} {target}\n"
            f"rebuild : clean all\n"
        )
        self.phonies += ['headers', 'clean', 'rebuild']
