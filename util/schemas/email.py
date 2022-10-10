from pydantic import BaseModel, Field

class ResetPassword(BaseModel):
    new_password:str = Field(
        min_length = 6,
        max_length = 255
    )