import os
import yaml
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

class ConfigLoader:
    def __init__(self, env_file='.env', rules_file='config/rules.yaml'):
        load_dotenv(env_file)
        self.rules = self.load_rules(rules_file)

    def load_rules(self, rules_file):
        with open(rules_file, 'r') as file:
            return yaml.safe_load(file)

    def get(self, key, default=None):
        return os.getenv(key, default)

    def get_rules(self):
        return self.rules

# Database setup
DB_ENGINE = os.getenv("DB_ENGINE", "sqlite")
DB_NAME = os.getenv("DB_NAME", "db.sqlite3")

if DB_ENGINE == "sqlite":
    DATABASE_URL = f"sqlite:///{DB_NAME}"
else:
    raise ValueError("Unsupported database engine")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Utility function to get a database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Example usage
if __name__ == "__main__":
    config_loader = ConfigLoader()
    print(config_loader.get('SOME_ENV_VARIABLE'))
    print(config_loader.get_rules())