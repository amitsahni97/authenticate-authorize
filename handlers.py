from datetime import datetime, timedelta
from jose import jwt


def verify_password(password, password_2):
    """
    Function to match both passwords
    :param password: str
    :param password_2: str
    :return: bool
    """
    if password == password_2:
        return True
    return False


def get_current_user_password(user_details: list, user_name: str) -> str | None:
    """
    Function to get current user password
    :param user_name: str
    :param user_details: list
    :return: str
    """
    for details in user_details:
        if details['name'] == user_name:
            return details['password']
    return None


def dependency_use() -> bool:
    """
    Thos is for dependency
    :return: bool
    """
    return True


def authenticate_user(bcrypt_context, password: str, hashed_password: str) -> bool:
    """
    Function to authenticate user
    :param bcrypt_context: obj
    :param password: str
    :param hashed_password: str
    :return: bool
    """
    if not bcrypt_context.verify(password, hashed_password):
        return False
    return True


def create_access_token(
        user_name: str,
        user_id: int,
        expires_delta: timedelta,
        secret_key: str,
        algorithm: str
):
    """Method to crate access token"""
    encode = {'name': user_name, 'id': user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, secret_key, algorithm=algorithm)
