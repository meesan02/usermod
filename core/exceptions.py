class UserModuleException(Exception):
    """Base exception for this application."""
    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(self.detail)

class NotFoundException(UserModuleException):
    """Raised when an entity is not found."""
    pass

class AlreadyExistsException(UserModuleException):
    """Raised when an entity already exists."""
    pass
