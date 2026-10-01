import os
# ruleid: ai-security.python.command-injection
os.system(input())
# ok: ai-security.python.command-injection
print(input())
# ruleid: ai-security.python.unsafe-eval
eval(input())
# ok: ai-security.python.unsafe-eval
int(input())
