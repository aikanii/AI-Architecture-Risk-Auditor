"""Repository ingestion - cloning and scanning repos."""
import logging
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RepositoryInfo:
    """Information about an ingested repository."""
    path: str
    url: Optional[str]
    branch: str
    languages: List[str]
    files: List[str]


class RepositoryIngester:
    """Handles repository ingestion from various sources."""
    
    def __init__(self, include_patterns: Optional[List[str]] = None, exclude_patterns: Optional[List[str]] = None):
        self.include_patterns = include_patterns or ["**/*"]
        self.exclude_patterns = exclude_patterns or [
            "node_modules/**",
            "vendor/**",
            "dist/**",
            "build/**",
            ".git/**",
            "**/*.test.*",
            "**/*.spec.*",
            "**/*test*",
        ]
    
    def ingest_local(self, path: str) -> RepositoryInfo:
        """
        Ingest a local repository.
        
        Args:
            path: Local path to repository
            
        Returns:
            Repository info
        """
        repo_path = Path(path)
        
        if not repo_path.exists():
            raise ValueError(f"Repository path does not exist: {path}")
        
        logger.info(f"Ingesting local repository: {path}")
        
        # Collect files
        files = self._collect_files(repo_path)
        
        # Detect languages
        languages = self._detect_languages(files)
        
        return RepositoryInfo(
            path=str(repo_path),
            url=None,
            branch="local",
            languages=languages,
            files=files,
        )
    
    def ingest_git(self, url: str, branch: str = "main", token: Optional[str] = None) -> RepositoryInfo:
        """
        Clone and ingest a Git repository.
        
        Args:
            url: Git repository URL
            branch: Branch to checkout
            token: Optional Git token for private repos
            
        Returns:
            Repository info
        """
        logger.info(f"Ingesting Git repository: {url} (branch: {branch})")
        
        try:
            import git
        except ImportError:
            logger.error("GitPython not installed")
            raise
        
        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix="aiara_")
        
        try:
            # Prepare URL with token if provided
            repo_url = url
            if token:
                # Add token to HTTPS URL
                if url.startswith("https://"):
                    repo_url = url.replace("https://", f"https://{token}:x-oauth-basic@")
            
            # Clone repository
            repo = git.Repo.clone_from(repo_url, temp_dir, branch=branch)
            logger.info(f"Cloned to {temp_dir}")
            
            # Collect files
            files = self._collect_files(Path(temp_dir))
            
            # Detect languages
            languages = self._detect_languages(files)
            
            return RepositoryInfo(
                path=temp_dir,
                url=url,
                branch=branch,
                languages=languages,
                files=files,
            )
        
        except Exception as e:
            logger.error(f"Failed to clone repository: {e}")
            if Path(temp_dir).exists():
                shutil.rmtree(temp_dir)
            raise
    
    def ingest_archive(self, archive_path: str) -> RepositoryInfo:
        """
        Extract and ingest a repository archive (.zip, .tar.gz).
        
        Args:
            archive_path: Path to archive file
            
        Returns:
            Repository info
        """
        logger.info(f"Ingesting archive: {archive_path}")
        
        import tarfile
        import zipfile
        
        temp_dir = tempfile.mkdtemp(prefix="aiara_")
        
        try:
            # Extract archive
            if archive_path.endswith('.tar.gz') or archive_path.endswith('.tar'):
                with tarfile.open(archive_path, 'r:*') as tar:
                    tar.extractall(temp_dir)
            elif archive_path.endswith('.zip'):
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
            else:
                raise ValueError(f"Unsupported archive format: {archive_path}")
            
            logger.info(f"Extracted to {temp_dir}")
            
            # Collect files
            files = self._collect_files(Path(temp_dir))
            
            # Detect languages
            languages = self._detect_languages(files)
            
            return RepositoryInfo(
                path=temp_dir,
                url=None,
                branch="archive",
                languages=languages,
                files=files,
            )
        
        except Exception as e:
            logger.error(f"Failed to extract archive: {e}")
            if Path(temp_dir).exists():
                shutil.rmtree(temp_dir)
            raise
    
    def _collect_files(self, root: Path, max_files: int = 10000) -> List[str]:
        """Collect all files matching include/exclude patterns."""
        import fnmatch
        
        files = []
        count = 0
        
        for file_path in root.rglob("*"):
            if count >= max_files:
                logger.warning(f"Reached max file limit ({max_files})")
                break
            
            if not file_path.is_file():
                continue
            
            rel_path = str(file_path.relative_to(root))
            
            # Check include patterns
            if not any(fnmatch.fnmatch(rel_path, p) for p in self.include_patterns):
                continue
            
            # Check exclude patterns
            if any(fnmatch.fnmatch(rel_path, p) for p in self.exclude_patterns):
                continue
            
            files.append(rel_path)
            count += 1
        
        logger.info(f"Collected {len(files)} files")
        return files
    
    def _detect_languages(self, files: List[str]) -> List[str]:
        """Detect programming languages from file extensions."""
        language_extensions = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".go": "go",
            ".java": "java",
            ".cs": "csharp",
            ".rb": "ruby",
            ".php": "php",
        }
        
        detected = set()
        for file_path in files:
            ext = Path(file_path).suffix.lower()
            if ext in language_extensions:
                detected.add(language_extensions[ext])
        
        return sorted(list(detected))
    
    def cleanup(self, repo_info: RepositoryInfo):
        """Clean up temporary files."""
        if repo_info.url is not None or repo_info.branch == "archive":
            # This was a cloned/extracted repo in temp directory
            path = Path(repo_info.path)
            if path.exists():
                shutil.rmtree(path)
                logger.info(f"Cleaned up {repo_info.path}")
