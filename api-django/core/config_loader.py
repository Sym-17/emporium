import toml
from pydantic import BaseModel


class ConfigLoader:
    def __init__(self, config_filepath):
        self.config_filepath = config_filepath

    def load_config(self):
        with open(self.config_filepath, "r", encoding="utf-8") as file:
            return toml.load(file)


class UserAuthentication(BaseModel):
    signing_key: str
    access_token_lifetime_in_seconds: float
    refresh_token_lifetime_in_hours: float
    algorithm: str


class DatabaseConfig(BaseModel):
    host: str
    user: str
    password: str
    port: str
    db_name: str


class ServerConfig(BaseModel):
    debug: bool
    env: str
    secret_key: str
    allowed_hosts: list[str]


class Config(BaseModel):
    server: ServerConfig
    database: DatabaseConfig
    user_authentication: UserAuthentication
