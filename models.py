from typing import Optional
from pydantic import BaseModel


# Todo: Complete the camel case
class CamelModel(BaseModel):
    """
    Converts to camel model
    """
    # class Config:
    #     alias_generator = to_came_case
    #     allow_population_by_field_name = True
    pass


class UserDetailsSchema(BaseModel):
    name: str
    password: str
    existingPassword: Optional[str] = None


class UserSignInDetails(UserDetailsSchema):
    pass


class UserResponse(BaseModel):
    userName: str
    userId: int


class CommonMessage(BaseModel):
    """Model to give common response"""
    message: str


class SignInCommonMessage(CommonMessage):
    """Model to give response for Sign in"""
    pass
