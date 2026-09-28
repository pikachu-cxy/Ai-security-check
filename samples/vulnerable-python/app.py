import os


API_KEY = "ghp_Zx6Jq82Pwa37Fh19Krn5Ls0Ybt64CdeUqVx2"


def export_report(name: str) -> int:
    return os.system("tar -czf " + name + ".tar.gz reports")
