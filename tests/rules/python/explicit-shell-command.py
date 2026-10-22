"""Static-only shell argv cases. Never execute this fixture."""
import os
import subprocess
import sys
from flask import request


def literal_shell():
    value = request.args.get("cmd")
    # ruleid: ai-security.python.explicit-shell-command
    subprocess.run(["sh", "-c", value])
    # ruleid: ai-security.python.explicit-shell-command
    subprocess.check_output(["/bin/bash", "-c", "echo " + value])
    # ruleid: ai-security.python.explicit-shell-command
    subprocess.Popen(["cmd.exe", "/c", value], shell=False)
    # ok: ai-security.python.explicit-shell-command
    subprocess.run(["echo", value])
    # ok: ai-security.python.explicit-shell-command
    subprocess.run(["sh", "-c", "printf '%s' \"$1\"", "sh", value])
    # ok: ai-security.python.explicit-shell-command
    subprocess.run(["sh", "-c", value], executable="echo")
    # ok: ai-security.python.explicit-shell-command
    subprocess.run(["sh", "-c", "echo fixed"])
    # ok: ai-security.python.explicit-shell-command
    subprocess.run(["cmd", "-c", value])
    # ok: ai-security.python.explicit-shell-command
    subprocess.run(["bash", value])


def append_prefix():
    command = request.form.get("cmd")
    argv = ["sh", "-c"]
    # ruleid: ai-security.python.explicit-shell-command
    argv.append(command)
    result = subprocess.run(argv, capture_output=True)
    return result


def append_windows():
    command = request.headers.get("x-command")
    argv = []
    argv.append("cmd.exe")
    argv.append("/c")
    # ruleid: ai-security.python.explicit-shell-command
    argv.append(command)
    result = subprocess.check_call(argv)
    return result


def platform_branch():
    command = request.form.getlist("cmd")[0]
    argv = []
    if os.name == "nt":
        argv.append("cmd.exe")
        argv.append("/c")
    else:
        argv.append("sh")
        argv.append("-c")
    # ruleid: ai-security.python.explicit-shell-command
    argv.append(command)
    result = subprocess.run(argv)
    return result


def overwritten_command():
    command = request.args.get("cmd")
    command = "echo fixed"
    argv = ["sh", "-c"]
    # ok: ai-security.python.explicit-shell-command
    argv.append(command)
    result = subprocess.run(argv)
    return result


def replaced_list():
    command = request.args.get("cmd")
    argv = ["sh", "-c"]
    # ok: ai-security.python.explicit-shell-command
    argv.append(command)
    argv = ["echo", command]
    result = subprocess.run(argv)
    return result


def inserted_argument():
    command = request.args.get("cmd")
    argv = ["sh", "-c"]
    # ok: ai-security.python.explicit-shell-command
    argv.append(command)
    argv[2] = "echo fixed"
    result = subprocess.run(argv)
    return result


def executable_override():
    command = request.args.get("cmd")
    argv = ["sh", "-c"]
    # ok: ai-security.python.explicit-shell-command
    argv.append(command)
    result = subprocess.run(argv, executable="echo")
    return result


def safe_platform_branch():
    value = request.args.get("value")
    argv = []
    if sys.platform == "win32":
        argv.append("cmd.exe")
        argv.append("/c")
    else:
        argv.append("sh")
        argv.append("-c")
    # ok: ai-security.python.explicit-shell-command
    argv.append("echo fixed")
    result = subprocess.run(argv, env={"VALUE": value})
    return result


def no_subprocess_use():
    command = request.args.get("cmd")
    argv = ["sh", "-c"]
    # ok: ai-security.python.explicit-shell-command
    argv.append(command)
    return argv


def non_shell_append():
    command = request.args.get("cmd")
    argv = []
    argv.append("echo")
    argv.append("--")
    # ok: ai-security.python.explicit-shell-command
    argv.append(command)
    result = subprocess.run(argv)
    return result


def numeric_data():
    value = request.args.get("value")
    # ok: ai-security.python.explicit-shell-command
    subprocess.run(["sh", "-c", "echo " + str(int(value))])
    # ok: ai-security.python.explicit-shell-command
    subprocess.run(["sh", "-c", "echo " + str(float(value))])


def imported_call_alias():
    from subprocess import call as launch
    command = request.cookies.get("command")
    # ruleid: ai-security.python.explicit-shell-command
    launch(["/usr/bin/dash", "-c", command])


def django_view(request):
    command = request.POST.get("command")
    # ruleid: ai-security.python.explicit-shell-command
    subprocess.run(["CMD.EXE", "/C", command])


def straight_local_list_projection():
    command = request.form.get('command')
    values = []
    values.append('first')
    values.append(command)
    values.append('last')
    values.pop(0)
    selected = values[0]
    # ruleid: ai-security.python.explicit-shell-command
    subprocess.run(['sh', '-c', selected])


def list_selects_a_fixed_element():
    command = request.form.get('command')
    values = []
    values.append('first')
    values.append(command)
    values.append('last')
    values.pop(0)
    selected = values[1]
    # ok: ai-security.python.explicit-shell-command
    subprocess.run(['sh', '-c', selected])


def list_overwritten_before_read():
    command = request.form.get('command')
    values = []
    values.append('first')
    values.append(command)
    values.append('last')
    values.pop(0)
    values = ['fixed']
    selected = values[0]
    # ok: ai-security.python.explicit-shell-command
    subprocess.run(['sh', '-c', selected])


def list_mutated_before_read():
    command = request.form.get('command')
    values = []
    values.append('first')
    values.append(command)
    values.append('last')
    values.pop(0)
    values[0] = 'fixed'
    selected = values[0]
    # ok: ai-security.python.explicit-shell-command
    subprocess.run(['sh', '-c', selected])


def selected_list_value_passed_as_data():
    command = request.form.get('command')
    values = []
    values.append('first')
    values.append(command)
    values.append('last')
    values.pop(0)
    selected = values[0]
    # ok: ai-security.python.explicit-shell-command
    subprocess.run(['echo', selected])


def list_with_unknown_mutating_call():
    command = request.form.get('command')
    values = []
    values.append('first')
    values.append(command)
    values.append(mutate(values))
    values.pop(0)
    selected = values[0]
    # ok: ai-security.python.explicit-shell-command
    subprocess.run(['sh', '-c', selected])
