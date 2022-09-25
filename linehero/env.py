import os

from dotenv import load_dotenv, find_dotenv


def _load_dot_env(path):
    dotenv_path = os.path.join(os.path.dirname(__file__), path)
    if os.path.exists(dotenv_path):
        load_dotenv(dotenv_path)
        return True
    else:
        return False


# 越早load的優先順序越高
if int(os.environ.get('IS_IN_TEST') or 0):
    _load_dot_env('.env.test')
_load_dot_env('.env.local')

if not _load_dot_env('.env'):
    print('.env not found')
