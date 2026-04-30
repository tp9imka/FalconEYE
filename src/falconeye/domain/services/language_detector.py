"""Language detection domain service."""

from pathlib import Path
from typing import Dict, Optional, List
from collections import Counter
from ..exceptions import LanguageDetectionError


class LanguageDetector:
    """
    Domain service for detecting the primary language of a codebase.

    Uses file extension analysis and intelligent heuristics.
    NO pattern matching for vulnerabilities - just language detection.
    """

    # Language to extensions mapping
    LANGUAGE_EXTENSIONS = {
        "c": [".c", ".h"],
        "cpp": [".cpp", ".cc", ".cxx", ".hpp", ".hh"],
        "python": [".py"],
        "rust": [".rs"],
        "go": [".go"],
        "php": [".php"],
        "java": [".java"],
        "dart": [".dart"],
        "javascript": [".js", ".jsx", ".mjs", ".cjs"],
        "typescript": [".ts", ".tsx"],
        "ruby": [".rb", ".rake"],
        "csharp": [".cs", ".csx", ".cshtml", ".razor"],
    }

    # Extensions to language mapping (reverse)
    EXTENSION_TO_LANGUAGE = {
        ext: lang
        for lang, exts in LANGUAGE_EXTENSIONS.items()
        for ext in exts
    }

    # Directories to skip during detection
    SKIP_DIRS = {
        "node_modules", "__pycache__", "venv", ".venv", "env",
        "build", "dist", "target", ".git", ".svn", "vendor",
        ".dart_tool", "Pods", "DerivedData",
    }

    # File patterns to skip
    SKIP_PATTERNS = {".pyc", ".class", ".o", ".so", ".dylib"}

    def detect_language(
        self,
        codebase_path: Path,
        force_language: Optional[str] = None,
    ) -> str:
        """
        Detect the primary language of a codebase or single file.

        Args:
            codebase_path: Root path of codebase or single file
            force_language: Force specific language (skip detection)

        Returns:
            Primary language name

        Raises:
            LanguageDetectionError: If detection fails
        """
        if force_language:
            if not self._is_valid_language(force_language):
                raise LanguageDetectionError(
                    f"Unsupported language: {force_language}"
                )
            return force_language

        # If single file, detect from extension
        if codebase_path.is_file():
            extension = codebase_path.suffix.lower()
            language = self.EXTENSION_TO_LANGUAGE.get(extension)
            if not language:
                raise LanguageDetectionError(
                    f"Unsupported file type: {extension}"
                )
            return language

        # Count files by language (for directories)
        language_counts = self._count_files_by_language(codebase_path)

        if not language_counts:
            raise LanguageDetectionError(
                f"No supported source files found in {codebase_path}"
            )

        # Determine primary language
        primary_language = self._determine_primary_language(language_counts)

        return primary_language

    def _count_files_by_language(self, root_path: Path) -> Dict[str, int]:
        """
        Count source files by language.

        Args:
            root_path: Root directory to scan

        Returns:
            Dictionary mapping language to file count
        """
        language_counts: Counter = Counter()

        for file_path in self._walk_codebase(root_path):
            extension = file_path.suffix.lower()
            if language := self.EXTENSION_TO_LANGUAGE.get(extension):
                language_counts[language] += 1

        return dict(language_counts)

    def _walk_codebase(self, root_path: Path):
        """
        Walk codebase and yield source files.

        Skips common non-source directories and files.

        Args:
            root_path: Root directory

        Yields:
            Path objects for source files
        """
        for item in root_path.rglob("*"):
            # Skip directories
            if item.is_dir():
                continue

            # Skip if in excluded directory
            if any(skip_dir in item.parts for skip_dir in self.SKIP_DIRS):
                continue

            # Skip hidden files
            if item.name.startswith("."):
                continue

            # Skip by pattern
            if any(item.name.endswith(pattern) for pattern in self.SKIP_PATTERNS):
                continue

            # Yield if it's a source file
            if item.suffix.lower() in self.EXTENSION_TO_LANGUAGE:
                yield item

    def _determine_primary_language(
        self,
        language_counts: Dict[str, int],
    ) -> str:
        """
        Determine primary language from counts.

        Applies intelligent heuristics for mixed-language projects.

        Args:
            language_counts: Language to file count mapping

        Returns:
            Primary language name
        """
        if not language_counts:
            raise LanguageDetectionError("No languages detected")

        # Sort by count
        sorted_languages = sorted(
            language_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        primary_lang, primary_count = sorted_languages[0]
        total_files = sum(language_counts.values())
        primary_percentage = (primary_count / total_files) * 100

        # If clearly dominant (>60%), use it
        if primary_percentage > 60:
            return primary_lang

        # Mixed-language project - apply heuristics
        return self._apply_mixed_language_heuristics(
            sorted_languages,
            total_files,
        )

    def _apply_mixed_language_heuristics(
        self,
        sorted_languages: list,
        total_files: int,
    ) -> str:
        """
        Apply heuristics for mixed-language projects.

        Args:
            sorted_languages: Languages sorted by file count
            total_files: Total number of files

        Returns:
            Selected primary language
        """
        languages = {lang: count for lang, count in sorted_languages}

        # C/Rust mix - prefer Rust (more modern)
        if "c" in languages and "rust" in languages:
            return "rust"

        # Dart with significant presence - likely Flutter
        if "dart" in languages:
            dart_percentage = (languages["dart"] / total_files) * 100
            if dart_percentage > 20:
                return "dart"

        # Python with significant presence
        if "python" in languages:
            python_percentage = (languages["python"] / total_files) * 100
            if python_percentage > 25:
                return "python"

        # JavaScript/TypeScript - prefer TypeScript if present
        if "typescript" in languages and "javascript" in languages:
            return "typescript"

        # Default to most common
        return sorted_languages[0][0]

    def _is_valid_language(self, language: str) -> bool:
        """
        Check if language is supported.

        Args:
            language: Language name

        Returns:
            True if supported
        """
        return language.lower() in self.LANGUAGE_EXTENSIONS

    def get_supported_languages(self) -> list[str]:
        """
        Get list of supported languages.

        Returns:
            List of language names
        """
        return list(self.LANGUAGE_EXTENSIONS.keys())

    def detect_all_languages(
        self,
        codebase_path: Path,
        min_file_threshold: int = 1,
    ) -> List[str]:
        """
        Detect all languages present in a codebase.

        This method identifies ALL languages with files in the codebase,
        not just the primary one. Useful for multi-language projects.

        Args:
            codebase_path: Root path of codebase
            min_file_threshold: Minimum number of files required to include a language

        Returns:
            List of language names sorted by file count (descending)

        Raises:
            LanguageDetectionError: If no supported files found
        """
        # If single file, return its language
        if codebase_path.is_file():
            extension = codebase_path.suffix.lower()
            language = self.EXTENSION_TO_LANGUAGE.get(extension)
            if not language:
                raise LanguageDetectionError(
                    f"Unsupported file type: {extension}"
                )
            return [language]

        # Count files by language
        language_counts = self._count_files_by_language(codebase_path)

        if not language_counts:
            raise LanguageDetectionError(
                f"No supported source files found in {codebase_path}"
            )

        # Filter by threshold and sort by count
        filtered_languages = [
            lang for lang, count in language_counts.items()
            if count >= min_file_threshold
        ]

        # Sort by file count (descending)
        sorted_languages = sorted(
            filtered_languages,
            key=lambda lang: language_counts[lang],
            reverse=True,
        )

        return sorted_languages