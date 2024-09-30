"""
Logger configurator for handling logger
"""

import os
import logging
from dotenv import load_dotenv
import json
from typing import Optional, List, Set
from pathlib import Path
import logging
import logging.config
import os
from threading import Lock
from typing import Optional


class LoggerConfigurator:
    """
    A singleton class responsible for configuring and providing loggers.
    
    This class ensures that the logging configuration is applied only once.
    """

    _env_loaded: bool = False
    _configured: bool = False
    _lock: Lock = Lock()

    @classmethod
    def _load_env_file(cls, env_path: Optional[str] = '.env'):
        if not cls._env_loaded:
            # Load environment variables from .env file if provided
            if env_path and os.path.exists(env_path):
                load_dotenv(dotenv_path=env_path)
                cls._env_loaded = True

    @classmethod
    def _get_logger_config_filepath(cls):
        cls._load_env_file()

        return os.getenv('LOG_CONFIGURATION', 'logger-config.json')

    @classmethod
    def configure_logger(
        cls,
        config_path: str = 'logger-config.json',
        default_level: int = logging.INFO,
    ) -> None:
        """
        Configure the logging system.

        This method sets up the logging configuration from a JSON file if available.
        Otherwise, it falls back to a basic configuration.

        Args:
            default_path (str): Path to the JSON logging configuration file.
            default_level (int): Default logging level if configuration file is not found.
            env_path (Optional[str]): Path to the .env file for environment variables.
        """
        with cls._lock:
            if cls._configured:
                return
            
            # Retrieve log level from environment variable or use default
            log_level_str = os.getenv('LOG_LEVEL')
            if log_level_str:
                log_level = getattr(logging, log_level_str.upper(), default_level)
            else:
                log_level = default_level

            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        config = json.load(f)
                    logging.config.dictConfig(config)
                except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
                    logging.basicConfig(level=log_level)
                    message = (
                        "Failed to load logging configuration from "
                        f"{config_path}: {e}. Using basicConfig."
                    )
                    logging.getLogger(__name__).error(message)
            else:
                logging.basicConfig(level=log_level)

            cls._configured = True

    @classmethod
    def get_logger(cls, channel: str = 'main-app-logger') -> logging.Logger:
        """
        Retrieve a logger with the specified channel name.

        If the logger is not configured yet, it configures it with default settings.

        Args:
            channel (str): The name of the logger to retrieve.

        Returns:
            logging.Logger: The logger instance.
        """
        if not cls._configured:
            cls._load_env_file()
            
            file_path = cls._get_logger_config_filepath()
            
            cls._create_log_folders(
                cls._list_log_folders(config_path=file_path)
            )
            cls.configure_logger(config_path=file_path)

        return logging.getLogger(channel)

    @classmethod
    def _list_log_folders(cls, config_path: str = 'logger-config.json') -> List[str]:
        """
        List all unique log directories from the logging configuration file.

        Args:
            config_path (str): Path to the JSON logging configuration file.

        Returns:
            List[str]: A list of unique log directory paths.
        """
        log_folders: Set[str] = set()

        if not os.path.exists(config_path):
            return []

        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            
            handlers = config.get('handlers', {})
            for _, handler in handlers.items():
                handler_class = handler.get('class', '')
                
                # Identify handlers that write to files
                if handler_class in [
                    'logging.FileHandler',
                    'logging.handlers.RotatingFileHandler',
                    'logging.handlers.TimedRotatingFileHandler',
                    'logging.handlers.WatchedFileHandler'
                ]:
                    filename = handler.get('filename')
                    if filename:
                        path = Path(filename).parent
                        log_folders.add(str(path.resolve()))
        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            logging.getLogger(__name__).error(
                f"Failed to parse logging configuration for listing log folders: {e}."
            )
        
        return list(log_folders)

    @classmethod
    def _create_log_folders(cls, folders: List[str]) -> None:
        """
        Create log directories if they do not exist.

        Args:
            folders (List[str]): A list of directory paths to create.
        """
        for folder in folders:
            path = Path(folder)
            if not path.exists():
                try:
                    path.mkdir(parents=True, exist_ok=True)
                    logging.getLogger(__name__).info(f"Created log directory: {folder}")
                except Exception as e:
                    message = (
                        f"Failed to create log directory {folder}: {e}"
                    )
                    logging.getLogger(__name__).error(message)
