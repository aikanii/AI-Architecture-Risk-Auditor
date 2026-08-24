"""Neo4j database connection and utilities."""
from neo4j import GraphDatabase, Driver
from typing import Optional
import logging
from app.config import Settings

logger = logging.getLogger(__name__)

# Global driver instance
_driver: Optional[Driver] = None


def get_db_connection(settings: Settings) -> Driver:
    """
    Get or create Neo4j driver instance.
    
    Args:
        settings: Application settings
        
    Returns:
        Neo4j driver instance
    """
    global _driver
    
    if _driver is None:
        try:
            _driver = GraphDatabase.driver(
                settings.neo4j.uri,
                auth=(settings.neo4j.user, settings.neo4j.password),
                connection_timeout=settings.neo4j.timeout,
            )
            logger.info(f"Connected to Neo4j at {settings.neo4j.uri}")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise
    
    return _driver


async def check_neo4j_connection(settings: Settings) -> bool:
    """
    Check if Neo4j is accessible.
    
    Args:
        settings: Application settings
        
    Returns:
        True if connection successful, False otherwise
    """
    try:
        driver = get_db_connection(settings)
        with driver.session() as session:
            session.run("RETURN 1")
        return True
    except Exception as e:
        logger.warning(f"Neo4j connection check failed: {e}")
        return False


def close_db_connection():
    """Close the global Neo4j driver."""
    global _driver
    if _driver is not None:
        _driver.close()
        _driver = None
        logger.info("Closed Neo4j connection")
