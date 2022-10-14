from pydantic import BaseModel, Field


class ResetPassword(BaseModel):
    new_password:str = Field(
        min_length = 6,
        max_length = 255
    )


class VerifyChild(BaseModel):
    mode:int = Field(
        ge = 0,
        le = 2
    )
