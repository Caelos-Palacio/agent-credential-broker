"""Human-only Tk administration; no browser, clipboard export or secret getters."""
import json
import os
from pathlib import Path
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox
from .vault import Vault, VaultError
from .policy import ActionBroker, PolicyError
from .server import BrokerServer, ServerError
from .governance import TaskGrant, QuotaStore
from .host import AuditLog, load_catalog


class BrokerWindow:
    def __init__(self, root, directory):
        self.root, self.directory = root, Path(directory).absolute()
        self.vault = self.server = None
        self.prompts = queue.Queue(maxsize=2)
        self.pending = []
        self.last_touch = time.monotonic()
        root.title('Custodio de credenciales · Administración humana')
        root.geometry('680x790')
        root.minsize(570, 760)
        root.protocol('WM_DELETE_WINDOW', self.close)
        frame = ttk.Frame(root, padding=22)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Credenciales bajo custodia', font=('Sans', 17, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='Abrir solo en el escritorio confiable, fuera del acceso del agente.',
                  wraplength=580).pack(anchor='w', pady=(7, 18))
        self.status = tk.StringVar(value='Bóveda bloqueada')
        ttk.Label(frame, textvariable=self.status).pack(anchor='w', pady=(0, 10))
        self.password = self.field(frame, 'Contraseña maestra · mínimo 12 bytes', masked=True)
        row = ttk.Frame(frame); row.pack(fill='x', pady=8)
        ttk.Button(row, text='Crear bóveda', command=lambda: self.open_vault(True)).pack(side='left')
        ttk.Button(row, text='Desbloquear', command=lambda: self.open_vault(False)).pack(side='left', padx=8)
        ttk.Button(row, text='Bloquear y detener', command=self.lock).pack(side='right')
        ttk.Separator(frame).pack(fill='x', pady=14)
        self.alias = self.field(frame, 'Alias de credencial · letras, números, guion o guion bajo')
        self.secret = self.field(frame, 'API key o contraseña · solo se guarda, nunca se muestra', masked=True)
        ttk.Button(frame, text='Guardar credencial', command=self.store).pack(anchor='w', pady=7)
        ttk.Separator(frame).pack(fill='x', pady=14)
        self.uid = self.field(frame, 'UID del agente · debe ser diferente del custodio')
        self.gid = self.field(frame, 'GID compartido para el socket · configurado por el administrador')
        self.socket = self.field(frame, 'Ruta absoluta del socket · directorio confiable accesible al grupo')
        self.socket.insert(0, str(self.directory / 'broker.sock'))
        self.catalog = self.field(frame, 'Catálogo JSON de acciones · archivo propietario 0600')
        self.catalog.insert(0, str(self.directory / 'actions.json'))
        ttk.Button(frame, text='Iniciar servicio de acciones', command=self.start).pack(anchor='w', pady=10)
        ttk.Label(frame, text='Cierre automático tras 5 minutos sin actividad. No hay recuperación de la contraseña.',
                  wraplength=580).pack(anchor='w', pady=6)
        self.password.focus_set()
        root.bind_all('<KeyPress>', self.touch, add='+')
        root.bind_all('<ButtonPress>', self.touch, add='+')
        self.tick_task = root.after(100, self.tick)

    def field(self, parent, label, masked=False):
        ttk.Label(parent, text=label).pack(anchor='w', pady=(7, 3))
        entry = ttk.Entry(parent, show='•' if masked else '')
        entry.pack(fill='x')
        if masked:
            # Prevent easy copy/cut of sensitive fields; this is not OS isolation.
            for event in ('<<Copy>>', '<<Cut>>', '<Control-c>', '<Control-x>'):
                entry.bind(event, lambda _: 'break')
        return entry

    def touch(self, _=None):
        self.last_touch = time.monotonic()

    def error(self, exc):
        code = exc.code if isinstance(exc, (VaultError, PolicyError, ServerError)) else 'ADMIN_OPERATION_FAILED'
        messagebox.showerror('Operación no completada', code, parent=self.root)

    def open_vault(self, create):
        password = self.password.get().encode('utf-8')
        self.password.delete(0, 'end')
        try:
            self.lock()
            method = Vault.create if create else Vault.unlock
            self.vault = method(self.directory / 'credentials.vault', password)
            self.touch()
            self.status.set('Bóveda desbloqueada · servicio detenido')
        except Exception as exc:
            self.error(exc)
        finally:
            password = None

    def store(self):
        secret = self.secret.get().encode('utf-8')
        self.secret.delete(0, 'end')
        try:
            if self.vault is None:
                raise VaultError('vault_locked')
            if self.server is not None:
                raise ServerError('STORE_REQUIRES_STOP')
            self.vault.put(self.alias.get(), secret)
            self.status.set('Credencial guardada · el valor no se exporta')
        except Exception as exc:
            self.error(exc)
        finally:
            secret = None

    def approve(self, plan):
        done = threading.Event()
        item = {'plan': plan, 'done': done, 'approved': False, 'expires': time.monotonic()+25}
        try:
            self.prompts.put_nowait(item)
        except queue.Full:
            return False
        done.wait(25)
        return item['approved'] is True and time.monotonic() < item['expires']

    def start(self):
        try:
            if self.vault is None:
                raise VaultError('vault_locked')
            if self.server:
                raise ServerError('SERVER_ALREADY_RUNNING')
            uid, gid = int(self.uid.get()), int(self.gid.get())
            grant = TaskGrant(load_catalog(self.catalog.get() + '.grant.json', _grant=True), uid)
            broker = ActionBroker(self.vault, load_catalog(self.catalog.get()), uid,
                                  approve_host=self.approve, audit=AuditLog(self.directory),
                                  task_grant=grant, quota_store=QuotaStore(self.directory))
            server = BrokerServer(self.socket.get(), broker, socket_group=gid).start()
            self.server = server
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.status.set('Servicio activo · permisos por acción y aprobación humana')
        except Exception as exc:
            self.error(exc)

    def tick(self):
        if self.vault and (time.monotonic()-self.last_touch > 300 or self.server and self.server.stopping.is_set()):
            self.lock()
        try:
            item = self.prompts.get_nowait()
        except queue.Empty:
            item = None
        if item:
            self.show_approval(item)
        self.tick_task = self.root.after(100, self.tick)

    def show_approval(self, item):
        if self.server is None or time.monotonic() >= item['expires']:
            item['done'].set(); return
        dialog = tk.Toplevel(self.root)
        dialog.title('Autorizar una acción exacta')
        dialog.transient(self.root)
        self.pending.append((dialog, item))
        frame = ttk.Frame(dialog, padding=18); frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Comprueba destino, método y todos los valores.', font=('Sans', 12, 'bold')).pack(anchor='w')
        text = tk.Text(frame, width=75, height=18, wrap='word')
        text.insert('1.0', json.dumps(item['plan'], ensure_ascii=False, indent=2))
        text.configure(state='disabled'); text.pack(fill='both', expand=True, pady=12)
        def finish(approved=False):
            if not item['done'].is_set():
                item['approved'] = approved and self.server is not None and time.monotonic() < item['expires']
                item['done'].set()
            if (dialog, item) in self.pending:
                self.pending.remove((dialog, item))
            if dialog.winfo_exists():
                dialog.destroy()
        row = ttk.Frame(frame); row.pack(fill='x')
        ttk.Button(row, text='Rechazar', command=finish).pack(side='left')
        ttk.Button(row, text='Autorizar una vez', command=lambda: finish(True)).pack(side='right')
        dialog.protocol('WM_DELETE_WINDOW', finish)
        dialog.after(25000, finish)

    def lock(self):
        if self.server:
            self.server.lock(); self.server.close(); self.server = None
        elif self.vault:
            self.vault.lock()
        self.vault = None
        self.password.delete(0, 'end'); self.secret.delete(0, 'end')
        for dialog, item in self.pending[:]:
            item['done'].set()
            dialog.destroy()
        self.pending.clear()
        self.status.set('Bóveda bloqueada · servicio detenido')

    def close(self):
        self.root.after_cancel(self.tick_task)
        self.lock()
        self.root.destroy()


def run(directory):
    root = tk.Tk()
    BrokerWindow(root, directory)
    root.mainloop()
    return 0
