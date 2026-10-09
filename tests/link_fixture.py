"""Exercise real link boundaries without requiring Windows symlink privilege."""
import os
import shutil
import subprocess


def linked_directory(link,target):
    try:
        link.symlink_to(target,target_is_directory=True)
    except OSError as exc:
        if os.name != 'nt' or getattr(exc,'winerror',None) != 1314: raise
        subprocess.run(['cmd','/c','mklink','/J',str(link),str(target)],
                       check=True,capture_output=True,timeout=10)
        assert link.is_junction()
    return link


def linked_file(link, target):
    try:
        link.symlink_to(target)
        return link
    except OSError as exc:
        if os.name != 'nt' or getattr(exc,'winerror',None) != 1314:
            raise
    # A regular file accessed through a real directory junction exercises both
    # canonical escape and reparse-point rejection. Never fake Path.is_symlink.
    directory=target.parent/(target.name+'-target')
    directory.mkdir()
    shutil.copy2(target,directory/target.name)
    junction=link.parent/(link.name+'-directory')
    linked_directory(junction,directory)
    return junction/target.name
