class ErrorMessageForUser(Exception):
    pass


class NotRegisteredException(ErrorMessageForUser):
    def __init__(self, message='您尚未註冊', *args):
        super().__init__(message, *args)
