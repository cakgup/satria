from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from .config import get_settings

settings = get_settings()
engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Base(DeclarativeBase):
    pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    from . import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    _ensure_runtime_schema()


def _ensure_runtime_schema():
    inspector = inspect(engine)

    if inspector.has_table('scan_jobs'):
        scan_job_columns = {column['name'] for column in inspector.get_columns('scan_jobs')}
        _add_missing_columns('scan_jobs', {
            'is_visible': "BOOLEAN DEFAULT TRUE",
        }, scan_job_columns)

    if inspector.has_table('ticket_cases'):
        ticket_case_columns = {column['name'] for column in inspector.get_columns('ticket_cases')}
        _add_missing_columns('ticket_cases', {
            'case_kind': "VARCHAR(30) DEFAULT 'finding'",
            'incident_type': "VARCHAR(80)",
            'priority': "VARCHAR(30) DEFAULT 'medium'",
            'source_channel': "VARCHAR(80)",
            'organization_unit': "VARCHAR(255)",
            'reporter': "VARCHAR(255)",
            'current_role': "VARCHAR(30)",
            'current_owner': "VARCHAR(120)",
            'playbook': "VARCHAR(120)",
            'resolution_summary': "TEXT",
            'remote_notes_directory_id': "VARCHAR(120)",
            'remote_evidence_folder_id': "VARCHAR(120)",
        }, ticket_case_columns)
        if engine.dialect.name == 'postgresql':
            with engine.begin() as conn:
                conn.execute(text('ALTER TABLE "ticket_cases" ALTER COLUMN "finding_id" DROP NOT NULL'))

    if inspector.has_table('ticket_tasks'):
        ticket_task_columns = {column['name'] for column in inspector.get_columns('ticket_tasks')}
        _add_missing_columns('ticket_tasks', {
            'role': "VARCHAR(30)",
            'sort_order': "INTEGER DEFAULT 0",
        }, ticket_task_columns)

    if inspector.has_table('ticket_evidences'):
        ticket_evidence_columns = {column['name'] for column in inspector.get_columns('ticket_evidences')}
        _add_missing_columns('ticket_evidences', {
            'remote_file_id': "VARCHAR(120)",
        }, ticket_evidence_columns)


def _add_missing_columns(table_name: str, columns: dict[str, str], existing_columns: set[str]):
    for column_name, ddl in columns.items():
        if column_name in existing_columns:
            continue
        with engine.begin() as conn:
            conn.execute(text(f'ALTER TABLE "{table_name}" ADD COLUMN "{column_name}" {ddl}'))
