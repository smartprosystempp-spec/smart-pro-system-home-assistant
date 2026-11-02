#!/usr/bin/env python3
"""Safely integrate Smart Pro System 3.0.30 into a local Git checkout.

Run only from the root of the matching repo AFTER overlay directories are copied.
Checks exact anchors; fails before writing if source shape is unfamiliar.
Never runs against a live Home Assistant and never touches portal databases.
"""
from pathlib import Path
import sys

BASE=Path('smart-pro-system')
app=BASE/'app.py'
html=BASE/'index.html'
if not app.is_file() or not html.is_file():
    raise SystemExit('Run from the matching smart-pro-system-home-assistant repository root.')
source=app.read_text(encoding='utf-8')
markup=html.read_text(encoding='utf-8')

start_get="    def do_GET(self):\n        request_path = urllib.parse.urlparse(self.path).path\n"
new_get="""    def do_GET(self):
        request_path = urllib.parse.urlparse(self.path).path
        if request_path.endswith('/api/sp-customer-admin/status'):
            import sp_customer_admin_access as _customer_access
            _customer_access.status(self, load_portal_connection())
            return
"""
start_post="    def do_POST(self):\n        if urllib.parse.urlparse(self.path).path.endswith('/api/portal_pair'):"
new_post="""    def do_POST(self):
        if urllib.parse.urlparse(self.path).path.endswith('/api/sp-customer-admin/action'):
            import sp_customer_admin_access as _customer_access
            _customer_access.action(self, load_portal_connection())
            return
        if urllib.parse.urlparse(self.path).path.endswith('/api/portal_pair'):"""
old_html='<script src="script.js?v=3003"></script>'
new_html=old_html+'\n    <script src="sp_customer_admin_access.js?v=3030"></script>'
if source.count(start_get)!=1 or source.count(start_post)!=1 or markup.count(old_html)!=1:
    raise SystemExit('Existing code differs from verified 3.0.29 anchors. No files were changed.')
if 'sp_customer_admin_access' in source or 'sp_customer_admin_access' in markup:
    raise SystemExit('The customer access integration is already present. No files were changed.')
ns=source.replace(start_get,new_get).replace(start_post,new_post)
nh=markup.replace(old_html,new_html)
compile(ns,str(app),'exec')
# Write only after all checks and a syntax check pass.
app.write_text(ns,encoding='utf-8')
html.write_text(nh,encoding='utf-8')
print('PATCH PASS: app.py GET/POST routes and index.html client script integrated')
