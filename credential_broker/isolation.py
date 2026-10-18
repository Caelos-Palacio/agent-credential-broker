"""Fail-closed agent launcher; the trusted custodian runs separately."""
import argparse
import os
from pathlib import Path
import resource
import shutil
import socket
import stat
import subprocess
import sys


def _command(workspace, broker_socket, command):
    executable = shutil.which('bwrap')
    if not executable or not command:
        raise ValueError()
    args = [executable, '--unshare-all', '--die-with-parent', '--new-session', '--clearenv',
            '--setenv', 'HOME', '/home/agent', '--setenv', 'PATH', '/usr/bin:/bin',
            '--ro-bind', '/usr', '/usr', '--ro-bind', '/lib', '/lib',
            '--symlink', 'usr/bin', '/bin', '--proc', '/proc', '--dev', '/dev',
            '--tmpfs', '/tmp', '--dir', '/home/agent', '--dir', '/run',
            '--bind', str(workspace), '/workspace', '--chdir', '/workspace']
    if Path('/lib64').exists():
        args += ['--ro-bind', '/lib64', '/lib64']
    if broker_socket:
        args += ['--ro-bind', str(broker_socket), '/run/broker.sock']
    return args + ['--', *command]


def main(argv=None):
    from .cli import SafeParser
    parser = SafeParser(description='Lanzar agente aislado; requiere UID distinto al custodio.')
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--socket', required=True)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        workspace, sock = Path(args.workspace).absolute(), Path(args.socket).absolute()
        info = sock.lstat()
        if (workspace != workspace.resolve() or not workspace.is_dir()
                or workspace.stat().st_uid != os.getuid()
                or sock.parent != sock.parent.resolve() or not stat.S_ISSOCK(info.st_mode)
                or info.st_uid in (os.getuid(), 0) or stat.S_IMODE(info.st_mode) & 0o007):
            raise ValueError()
        command = args.command[1:] if args.command[:1] == ['--'] else args.command
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        return subprocess.run(_command(workspace, sock, command), check=False,
                              env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}).returncode
    except Exception:
        print('{"ok":false,"error":"ISOLATION_UNAVAILABLE"}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
