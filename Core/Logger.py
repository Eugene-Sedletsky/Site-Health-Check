import os
import logging
from colorlog import ColoredFormatter
from dotenv import load_dotenv

load_dotenv()

def configure_logger():
    """Set Logger for configuration"""
    log_level = os.getenv('LOG_LEVEL', 'DEBUG').upper()
    log_format = os.getenv('LOG_FORMAT', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    logger = logging.getLogger(__name__)
    logger.setLevel('CRITICAL')

    c_handler = logging.StreamHandler()
    c_handler.setLevel(log_level)

    log_colors = {
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    }
    secondary_log_colors = {
       'message': {
			'ERROR':    'red',
			'CRITICAL': 'red,bg_white'
		},
        'asctime': {
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
        }
    }
    c_format = ColoredFormatter(log_format, log_colors=log_colors, secondary_log_colors=secondary_log_colors)
    c_handler.setFormatter(c_format)

    logger.addHandler(c_handler)

    return logger
