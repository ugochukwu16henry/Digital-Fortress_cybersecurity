from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Digital Fortress API"
    app_env: str = "dev"
    api_prefix: str = "/api/v1"

    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/digital_fortress"
    jwt_secret: str = "change-me"
    jwt_algorithm: str = "HS256"

    compliance_mode_default: bool = True
    require_tenant_header: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
