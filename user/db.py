from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .config import settings

 
engine = create_engine(
    settings.SQLALCHEMY_DATABASE_URI,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    pool_recycle=3600,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
 

def create_db_and_tables():
    """
    Creates database tables if they don't exist.
    This should be called on application startup.
    """
    # Import the Base and all models here to ensure they are registered with
    # SQLAlchemy's metadata before create_all is called. This is a robust way
    # to prevent issues where models might not be loaded yet due to the order
    # of imports in other parts of the application.
    from .models import UserBase, User, Role
    UserBase.metadata.create_all(bind=engine)


 
def get_db():
    """
    FastAPI dependency that provides a SQLAlchemy session.
    It ensures the session is always closed after the request.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()