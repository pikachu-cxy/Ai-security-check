import os
# ruleid: ai-security.python.command-injection
os.system(input())
# ok: ai-security.python.command-injection
print(input())
# ruleid: ai-security.python.unsafe-eval
eval(input())
# ok: ai-security.python.unsafe-eval
int(input())

import subprocess
# ok: ai-security.python.command-injection
os.system("echo fixed")
fixed = "echo fixed"
# ok: ai-security.python.command-injection
subprocess.run(fixed, shell=True)
# ok: ai-security.python.unsafe-eval
eval("1 + 1")
dynamic = input()
# ruleid: ai-security.python.command-injection
subprocess.run(dynamic, shell=True)
# ruleid: ai-security.python.unsafe-eval
eval(dynamic)
# ok: ai-security.python.command-injection
subprocess.run(["echo", dynamic], shell=False)
# ruleid: ai-security.python.unsafe-eval
exec(input())
# ok: ai-security.python.unsafe-eval
exec("result = 1 + 1")

def execute_statement(value):
    # ruleid: ai-security.python.unsafe-eval
    exec(value)
