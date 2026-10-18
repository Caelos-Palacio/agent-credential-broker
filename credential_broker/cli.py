"""Human GUI launcher and unprivileged agent client. No secret CLI options."""
import argparse
import json
import os
from pathlib import Path
import socket
import stat
import sys
from .server import MAX_MESSAGE, _document


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # Invalid arguments may themselves contain mistakenly supplied secrets.
        self.exit(2, '{"ok":false,"error":"INVALID_ARGUMENTS"}\n')


def call(path, request):
    path = Path(path).absolute()
    info = path.lstat()
    if not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o007:
        raise ValueError()
    encoded = json.dumps(request, allow_nan=False, separators=(',', ':')).encode() + b'\n'
    if len(encoded) > MAX_MESSAGE:
        raise ValueError()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(40)
        conn.connect(str(path))
        conn.sendall(encoded)
        data = bytearray()
        while b'\n' not in data:
            chunk = conn.recv(min(4096, MAX_MESSAGE + 1 - len(data)))
            if not chunk:
                raise ValueError()
            data.extend(chunk)
            if len(data) > MAX_MESSAGE:
                raise ValueError()
        return _document(bytes(data).split(b'\n', 1)[0])


def main(argv=None):
    parser = SafeParser(description='Custodio local de acciones, sin entregar credenciales al agente.')
    sub = parser.add_subparsers(dest='command', required=True)
    gui = sub.add_parser('gui', help='Abrir interfaz humana nativa; nunca desde el sandbox del agente.')
    gui.add_argument('--directory', default=str(Path.home() / '.local/share/agent-credential-broker'))
    client = sub.add_parser('call', help='Leer una solicitud JSON sin secretos desde stdin.')
    client.add_argument('--socket', required=True)
    audit = sub.add_parser('audit-export', help='Custodio: exportar solo metadatos, nunca credenciales.')
    audit.add_argument('--directory', required=True)
    audit.add_argument('--schema-version', type=int, choices=(1, 2), default=1)
    audit_check = sub.add_parser('audit-checkpoint', help='Custodio: crear referencia de integridad de una exportación.')
    audit_check.add_argument('--file', required=True)
    audit_verify = sub.add_parser('audit-verify', help='Verificar exportación contra checkpoint confiable separado.')
    audit_verify.add_argument('--file', required=True)
    audit_verify.add_argument('--checkpoint', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'gui':
            from .gui import run
            return run(args.directory)
        if args.command == 'audit-export':
            from .audit_export import export_audit
            sys.stdout.write(export_audit(args.directory, schema_version=args.schema_version))
            return 0
        if args.command in ('audit-checkpoint', 'audit-verify'):
            from .audit_checkpoint import checkpoint, verify
            if args.command == 'audit-checkpoint':
                print(json.dumps(checkpoint(args.file), separators=(',', ':')))
                return 0
            valid = verify(args.file, args.checkpoint)
            print(json.dumps({'ok': valid, 'integrity': 'matched' if valid else 'mismatch'}, separators=(',', ':')))
            return 0 if valid else 1
        raw = sys.stdin.buffer.read(MAX_MESSAGE + 1)
        if len(raw) > MAX_MESSAGE:
            raise ValueError()
        result = call(args.socket, _document(raw))
        print(json.dumps(result, allow_nan=False, separators=(',', ':')))
        return 0 if result.get('ok') else 1
    except Exception:
        print('{"ok":false,"error":"CLIENT_FAILED"}')
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
