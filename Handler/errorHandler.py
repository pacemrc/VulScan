class CustomException(Exception):
    def __init__(self, message):
        self.message = message

# 手动触发自定义异常
