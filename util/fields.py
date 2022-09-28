from typing import Union
from pydantic import BaseModel, Field

class CreateAccount(BaseModel):
    username: str = Field(
        min_length=1,
        max_length=20
    )
    email: Union[str, None] = Field(
        min_length=5,
        max_length=255
    )
    password: str = Field(
        min_length=6,
        max_length=255
    )
    child: bool = Field()
    captcha: str = Field(
        min_length=1
    )

class LoginPassword(BaseModel):
    username: str = Field(
        min_length=1,
        max_length=255
    )
    password: str = Field(
        max_length=255
    )

class TOTP(BaseModel):
    token: str = Field(
        min_length=1
    )
    code: str = Field(
        min_length=6,
        max_length=8
    )