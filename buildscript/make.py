from argparse import ArgumentParser

from mkmake import make_projects
from mkmake.projects import CProject, TestProject


def main(args):
    print(f"Build config={args}")
    projects = {
        'generic': CProject(
            'generic',
            output_name='libgeneric.a', output_type=CProject.OutputType.STATIC,
        ),
        'protocol': CProject(
            'protocol',
            output_name='libprotocol.a', output_type=CProject.OutputType.STATIC,
            depends=['generic'],
        ),
        'daemon': CProject(
            'daemon',
            output_name='ipcpd', output_type=CProject.OutputType.BINARY,
            depends=['protocol', 'generic'],
            libs=[':libsodium.a']
        ),
        'test': TestProject(
            'test',
            depends=['protocol', 'generic'],
            test_command='./target/test',
            libs=[':libsodium.a']
        ),
    }
    make_projects(projects, debug=args.debug, test=args.test)


def add_flag(parser: ArgumentParser, flag: str):
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(f'-{flag}', f'--{flag}', action='store_true')
    group.add_argument(f'-no-{flag}', f'--no-{flag}', action='store_true')


def parse_args():
    parser = ArgumentParser()
    add_flag(parser, 'debug')
    add_flag(parser, 'test')

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()
    main(args)
