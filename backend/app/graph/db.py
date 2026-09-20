"""Neo4j database connection and utilities."""
from neo4j import GraphDatabase, Driver
from typing import Optional, Any
import logging
from app.config import Settings, settings as default_settings

logger = logging.getLogger(__name__)

# Global driver instance
_driver: Optional[Any] = None


class InMemoryDriver:
    """Fallback in-memory driver when Neo4j is not running."""
    def __init__(self):
        self.is_in_memory = True

    def close(self):
        pass

    def session(self):
        return InMemorySession()


class InMemorySession:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def run(self, query: str, **params):
        return InMemoryResult()


class InMemoryResult:
    def single(self):
        return None

    def __iter__(self):
        return iter([])


def get_db_connection(settings: Optional[Settings] = None) -> Any:
    """
    Get or create Neo4j driver instance, or fallback to in-memory driver.
    
    Args:
        settings: Application settings (optional)
        
    Returns:
        Driver instance
    """
    global _driver
    
    cfg = settings or default_settings
    
    if _driver is None:
        try:
            driver = GraphDatabase.driver(
                cfg.neo4j.uri,
                auth=(cfg.neo4j.user, cfg.neo4j.password),
                connection_timeout=2,
            )
            # Test connection quickly
            with driver.session() as session:
                session.run("RETURN 1")
            _driver = driver
            logger.info(f"Connected to Neo4j at {cfg.neo4j.uri}")
        except Exception as e:
            logger.info(f"Neo4j not reachable at {cfg.neo4j.uri} ({e}), using in-memory graph repository")
            _driver = InMemoryDriver()
    
    return _driver


async def check_neo4j_connection(settings: Optional[Settings] = None) -> bool:
    """
    Check if Neo4j is accessible.
    
    Args:
        settings: Application settings
        
    Returns:
        True if connection successful, False otherwise
    """
    cfg = settings or default_settings
    try:
        driver = GraphDatabase.driver(
            cfg.neo4j.uri,
            auth=(cfg.neo4j.user, cfg.neo4j.password),
            connection_timeout=2,
        )
        with driver.session() as session:
            session.run("RETURN 1")
        return True
    except Exception:
        return False


def close_db_connection():
    """Close the global database driver."""
    global _driver
    if _driver is not None:
        try:
            _driver.close()
        except Exception:
            pass
        _driver = None
        logger.info("Closed database connection")
