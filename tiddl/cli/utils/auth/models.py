from pydantic import BaseModel


class AuthData(BaseModel):
    token: str | None = None
    refresh_token: str | None = None
    expires_at: int = 0
    user_id: str | None = None
    country_code: str | None = None

    secondary_token: str | None = None
    secondary_refresh_token: str | None = None
    secondary_expires_at: int = 0
    secondary_user_id: str | None = None
    secondary_country_code: str | None = None
