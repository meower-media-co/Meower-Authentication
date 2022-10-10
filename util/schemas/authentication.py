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
        min_length = 1
    )

class LoginPassword(BaseModel):
    username:str = Field(
        min_length = 1,
        max_length = 255
    )
    password:str = Field(
        max_length = 255
    )

class MFA(BaseModel):
    token:str = Field(
        min_length = 1
    )
    code:str = Field(
        min_length = 6,
        max_length = 8
    )