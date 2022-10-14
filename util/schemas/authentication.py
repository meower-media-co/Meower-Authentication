from pydantic import BaseModel, Field


class CreateAccount(BaseModel):
    username:str = Field(
        min_length = 1,
        max_length = 20
    )
    display_name:str = Field(
        min_length = 1,
        max_length = 20
    )
    password:str = Field(
        min_length = 6,
        max_length = 255
    )
    child:bool = Field()
    captcha:str = Field(
        min_length = 1,
        max_length = 500
    )


class LoginPassword(BaseModel):
    username:str = Field(
        min_length = 1,
        max_length = 255
    )
    password:str = Field(
        min_length = 1,
        max_length = 255
    )
    captcha:str = Field(
        min_length = 1,
        max_length = 500
    )


class TOTP(BaseModel):
    token:str = Field(
        min_length = 1
    )
    code:str = Field(
        min_length = 6,
        max_length = 6
    )


class PasswordRecovery(BaseModel):
    email:str = Field(
        min_length = 5,
        max_length = 255
    )
    captcha:str = Field(
        min_length = 1,
        max_length = 500
    )


class MFARecovery(BaseModel):
    token:str = Field(
        min_length = 1
    )
    code:str = Field(
        min_length = 8,
        max_length = 8
    )
