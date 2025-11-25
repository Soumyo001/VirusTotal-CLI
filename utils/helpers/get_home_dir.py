import os, platform

def get_home_dir():

    if platform.system() == "Windows":
        return os.environ.get("USERPROFILE")

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            import pwd
            return pwd.getpwnam(sudo_user).pw_dir
        except: pass
    return os.path.expanduser("~")