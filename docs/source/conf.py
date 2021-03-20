from datetime import datetime

year = datetime.today().year

project = 'ioccheck'
copyright = f'{year}, ranguli'
author = 'ranguli'

extensions = ['sphinx.ext.autodoc', 'sphinx.ext.coverage', 'sphinx.ext.napoleon']

templates_path = ['_templates']

exclude_patterns = []

html_theme = 'sphinx_rtd_theme'
html_static_path = []
