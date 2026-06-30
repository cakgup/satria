from functools import lru_cache
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', extra='ignore')

    app_env: str = Field(default='development', alias='APP_ENV')
    demo_mode: bool = Field(default=True, alias='SATRIA_DEMO_MODE')
    secret_key: str = Field(default='change-me', alias='SATRIA_SECRET_KEY')
    database_url: str = Field(default='postgresql+psycopg://satria:satria_password@satria-db:5432/satria', alias='DATABASE_URL')
    celery_broker_url: str = Field(default='redis://satria-redis:6379/0', alias='CELERY_BROKER_URL')
    celery_result_backend: str = Field(default='redis://satria-redis:6379/1', alias='CELERY_RESULT_BACKEND')
    report_dir: str = Field(default='/data/reports', alias='REPORT_DIR')
    iris_url: str | None = Field(default=None, alias='IRIS_URL')
    iris_api_key: str | None = Field(default=None, alias='IRIS_API_KEY')
    iris_verify_ssl: bool = Field(default=False, alias='IRIS_VERIFY_SSL')
    iris_customer_name: str = Field(default='SATRIA', alias='IRIS_CUSTOMER_NAME')
    iris_customer_description: str = Field(default='Customer placeholder created by SATRIA automation', alias='IRIS_CUSTOMER_DESCRIPTION')
    iris_customer_sla: str = Field(default='Standard incident response workflow', alias='IRIS_CUSTOMER_SLA')
    iris_case_classification: str | None = Field(default=None, alias='IRIS_CASE_CLASSIFICATION')
    iris_case_template_id: int | None = Field(default=None, alias='IRIS_CASE_TEMPLATE_ID')
    iris_case_tags: str = Field(default='satria,security-assessment', alias='IRIS_CASE_TAGS')
    iris_task_status: str = Field(default='To be done', alias='IRIS_TASK_STATUS')
    iris_analysis_status: str = Field(default='Unspecified', alias='IRIS_ANALYSIS_STATUS')
    iris_note_directory: str = Field(default='SATRIA Timeline', alias='IRIS_NOTE_DIRECTORY')
    iris_evidence_folder: str = Field(default='SATRIA Evidence', alias='IRIS_EVIDENCE_FOLDER')
    soc_l1_user: str = Field(default='cakgup1', alias='SOC_L1_USER')
    soc_l2_user: str = Field(default='cakgup2', alias='SOC_L2_USER')
    soc_l3_user: str = Field(default='cakgup3', alias='SOC_L3_USER')
    greenbone_host: str | None = Field(default=None, alias='GREENBONE_HOST')
    greenbone_port: int = Field(default=9390, alias='GREENBONE_PORT')
    greenbone_socket_path: str | None = Field(default='/run/gvmd/gvmd.sock', alias='GREENBONE_SOCKET_PATH')
    greenbone_username: str | None = Field(default=None, alias='GREENBONE_USERNAME')
    greenbone_password: str | None = Field(default=None, alias='GREENBONE_PASSWORD')
    greenbone_verify_ssl: bool = Field(default=False, alias='GREENBONE_VERIFY_SSL')
    greenbone_scan_config: str = Field(default='Full and fast', alias='GREENBONE_SCAN_CONFIG')
    greenbone_scanner_name: str = Field(default='OpenVAS Default', alias='GREENBONE_SCANNER_NAME')
    greenbone_port_list: str = Field(default='All IANA assigned TCP and UDP', alias='GREENBONE_PORT_LIST')
    greenbone_timeout: int = Field(default=60, alias='GREENBONE_TIMEOUT')
    greenbone_poll_interval: int = Field(default=15, alias='GREENBONE_POLL_INTERVAL')
    greenbone_max_wait_seconds: int = Field(default=5400, alias='GREENBONE_MAX_WAIT_SECONDS')
    zap_container_name: str = Field(default='satria-zap', alias='ZAP_CONTAINER_NAME')
    allow_active_scan: bool = Field(default=False, alias='ALLOW_ACTIVE_SCAN')
    scan_target_allowlist: str = Field(default='localhost,127.0.0.1', alias='SCAN_TARGET_ALLOWLIST')

    def allowlist(self) -> list[str]:
        return [item.strip() for item in self.scan_target_allowlist.split(',') if item.strip()]

@lru_cache
def get_settings() -> Settings:
    return Settings()
