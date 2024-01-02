from typing import List, Dict, Optional
import os

from project import CProject


def sort_projects(name: str, projects: Dict[str, CProject], sorted: List[str]):
    if name in sorted:
        return
    proj = projects[name]
    for children in proj.depends:
        sort_projects(children, projects, sorted)
    sorted.append(name)


def make_projects(projects: Dict[str, CProject], **kwargs):
    os.makedirs('target', exist_ok=True)

    sorted_names: List[str] = []
    for name in projects.keys():
        sort_projects(name, projects, sorted_names)

    sorted_projs = [(name, projects[name]) for name in sorted_names]

    for name, proj in sorted_projs:
        for k, v in kwargs.items():
            if v is not None:
                setattr(proj, k, v)

    for name, proj in sorted_projs:
        proj.scan_sources()

    for name, proj in sorted_projs:
        proj.inject_depends(projects)
        proj.scan_deps()

    for name, proj in sorted_projs:
        proj.make()

    print("Write meta Makefile")
    with open('target/Projects.mk', 'w') as fout:
        phonies = ['default', 'all-all', 'clean-all', 'rebuild-all']
        fout.write(f"default : all-all\n")
        for name, proj in sorted_projs:
            fout.write(
                f"############ Project {name} ############\n"
                f"{name} : {' '.join(proj.depends)}\n"
                f"\t@echo Project {name}\n"
                f"\t$(MAKE) -C {proj.root_path} -f {proj.makefile}\n\n"
            )
            phonies.append(name)

            for word in proj.phonies:
                target = f"{word}-{name}"
                fout.write(
                    f"{target} : \n"
                    f"\t@echo Project {name} {word}\n"
                    f"\t$(MAKE) -C {proj.root_path} -f {proj.makefile} {word}\n\n"
                )
                phonies.append(target)

        fout.write(
            f"all-all : {' '.join(sorted_names)}\n"
            f"clean-all : {' '.join(f'clean-{name}' for name in sorted_names) }\n"
            f"rebuild-all : clean-all all-all\n"
        )
        fout.write(f".PHONY : {' '.join(phonies)}\n")
