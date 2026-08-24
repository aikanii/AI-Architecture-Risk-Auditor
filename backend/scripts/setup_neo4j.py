"""Setup scripts for Neo4j and database initialization."""
import sys
import logging
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.config import settings
from app.graph.db import get_db_connection
from app.graph.schema import SCHEMA_STATEMENTS

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def setup_neo4j():
    """Initialize Neo4j schema and indexes."""
    try:
        logger.info("Connecting to Neo4j...")
        driver = get_db_connection(settings)
        
        with driver.session() as session:
            logger.info("Creating schema constraints and indexes...")
            
            for i, statement in enumerate(SCHEMA_STATEMENTS):
                try:
                    session.run(statement)
                    logger.info(f"  ✓ Statement {i+1}/{len(SCHEMA_STATEMENTS)}")
                except Exception as e:
                    # Some statements might fail if already exist, that's OK
                    logger.warning(f"  ⚠ Statement {i+1}: {e}")
        
        logger.info("✅ Neo4j setup completed")
        return True
    
    except Exception as e:
        logger.error(f"❌ Neo4j setup failed: {e}")
        return False


if __name__ == "__main__":
    success = setup_neo4j()
    sys.exit(0 if success else 1)
