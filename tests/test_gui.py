"""Run only inside an explicitly supplied private virtual display; fake data only."""
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
try:
    import tkinter as tk
    from tkinter import ttk
    from credential_broker.gui import BrokerWindow
except ImportError:
    tk = ttk = BrokerWindow = None

@unittest.skipUnless(tk is not None and os.environ.get('BROKER_PRIVATE_QA_DISPLAY') == '1', 'Tk and private virtual display required')
class GuiTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=tk.Tk()
        self.window=BrokerWindow(self.root,self.temp.name)
        self.errors=[]
        self.dialog_patch=patch('credential_broker.gui.messagebox.showerror',side_effect=lambda *a,**k:self.errors.append(a))
        self.dialog_patch.start(); self.root.update()
    def tearDown(self):
        self.window.close(); self.dialog_patch.stop(); self.temp.cleanup()
    def test_create_add_lock_bad_password_unlock(self):
        w=self.window
        self.assertTrue(w.password.cget('show')); self.assertTrue(w.secret.cget('show'))
        self.assertEqual(str(w.alias.tk_focusNext()),str(w.secret))
        w.password.insert(0,'fake-password-only'); w.open_vault(True)
        self.assertIsNotNone(w.vault); self.assertEqual(w.password.get(),'')
        w.alias.insert(0,'demo_key'); w.secret.insert(0,'fake-key-only'); w.store()
        self.assertEqual(w.vault.list_aliases(),['demo_key']); self.assertEqual(w.secret.get(),'')
        w.server=SimpleNamespace()
        w.secret.insert(0,'fake-replacement-key'); w.store()
        self.assertEqual(self.errors[-1][1],'STORE_REQUIRES_STOP')
        self.assertEqual(w.vault.use('demo_key',lambda key:key),b'fake-key-only')
        w.server=None
        w.lock(); self.assertIsNone(w.vault)
        w.password.insert(0,'wrong-password-only'); w.open_vault(False)
        self.assertIsNone(w.vault); self.assertTrue(self.errors)
        w.password.insert(0,'fake-password-only'); w.open_vault(False)
        self.assertEqual(w.vault.list_aliases(),['demo_key'])
        self.assertLessEqual(w.catalog.winfo_rooty()+w.catalog.winfo_height(),self.root.winfo_rooty()+self.root.winfo_height())
    def test_approval_reject_and_expired_never_approve(self):
        import threading
        w=self.window
        w.server=SimpleNamespace()
        item={'plan':{'method':'POST','destination':'https://example.com/draft','input':{'title':'FAKE'}},'done':threading.Event(),'approved':False,'expires':time.monotonic()+25}
        w.show_approval(item); self.root.update()
        dialog=w.pending[0][0]
        def descendants(widget):
            for child in widget.winfo_children():
                yield child
                yield from descendants(child)
        reject=next(x for x in descendants(dialog) if isinstance(x,ttk.Button) and x.cget('text')=='Rechazar')
        reject.invoke(); self.assertTrue(item['done'].is_set()); self.assertFalse(item['approved'])
        item['done'].clear(); item['expires']=time.monotonic()+25
        w.show_approval(item); self.root.update()
        approve=next(x for x in descendants(w.pending[0][0]) if isinstance(x,ttk.Button) and x.cget('text')=='Autorizar una vez')
        approve.invoke(); self.assertTrue(item['approved'])
        item['approved']=False
        item['done'].clear(); item['expires']=time.monotonic()-1
        w.show_approval(item); self.assertTrue(item['done'].is_set()); self.assertFalse(item['approved'])
        w.server=None

if __name__=='__main__':unittest.main()
