from pydantic import BaseModel, Field


class ExtraAuth(BaseModel):
    password:str = Field(
        required = False,
        default = None,
        min_length = 1,
        max_length = 255
    )
    totp:str = Field(
        required = False,
        default = None,
        min_length = 6,
        max_length = 8
    )


class ChangeEmail(BaseModel):
    new_email:str = Field(
        min_length = 5,
        max_length = 255
    )


class ChangePassword(BaseModel):
    new_password:str = Field(
        min_length = 6,
        max_length = 255
    )


class NewTOTP(BaseModel):
    name:str = Field(
        min_length = 1,
        max_length = 20
    )
    secret:str = Field(
        min_length = 32,
        max_length = 32
    )
    code:str = Field(
        min_length = 6,
        max_length = 6
    )
