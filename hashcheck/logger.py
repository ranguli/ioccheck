import logging

# Create a custom logger
logger = logging.getLogger(__name__)

# Create handlers
f_handler = logging.FileHandler("hashcheck.log")
f_handler.setLevel(logging.INFO)

# Create formatters and add it to handlers
f_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
f_handler.setFormatter(f_format)

# Add handlers to the logger
logger.addHandler(f_handler)
