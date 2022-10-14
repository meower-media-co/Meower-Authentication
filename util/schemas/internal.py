from pydantic import BaseModel, Field


class SendEmail(BaseModel):
    user:str = Field(
        min_length = 1,
        max_length = 255
    )
    template:str = Field(
        min_length = 1,
        max_length = 255
    )
    details:dict = Field()


class LockAccount(BaseModel):
    user:str = Field(
        min_length = 1,
        max_length = 255
    )
    mode:int = Field()


class DeleteAccount(BaseModel):
    user:str = Field(
        min_length = 1,
        max_length = 255
    )
    immediate:bool = Field(
        default = False
    )
