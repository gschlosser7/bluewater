from setuptools import setup, find_packages

setup(
name='app',
version='0.1',
packages=find_packages(),
install_requires=[
'alembic', 'bcrypt', 'blinker', 'bokeh', 'Brotli', 'certifi', 'charset-normalizer', 'chart-studio', 'click', 'colorama', 'contourpy', 'customtkinter', 'darkdetect', 'dash', 'dash-bootstrap-components', 'dash-core-components', 'dash-html-components', 'dash-table', 'distlib', 'dnspython', 'email-validator', 'filelock', 'Flask', 'Flask-Bcrypt', 'Flask-Dance', 'flask-htmx', 'Flask-JWT-Extended', 'Flask-Login', 'Flask-Migrate', 'Flask-SQLAlchemy', 'Flask-WTF', 'git-bash', 'greenlet', 'gunicorn', 'idna', 'importlib_metadata', 'itsdangerous', 
'Jinja2', 'Mako', 'MarkupSafe', 'marshmallow', 'mutagen', 'nano', 'nest-asyncio', 'numpy', 'oauthlib', 'packaging', 'pandas', 'pillow', 'platformdirs', 'plotly', 'psycopg', 'psycopg2', 'psycopg2-binary', 'pycoingecko', 'pycryptodomex', 'PyJWT', 'python-dateutil', 'pytz', 'PyYAML', 'requests', 'requests-oauthlib', 'retrying', 'six', 'SQLAlchemy', 'sqlalchemy-json', 'tenacity', 'tornado', 'typing_extensions', 'tzdata', 'urllib3', 'URLObject', 'virtualenv', 'waitress', 'websockets', 'Werkzeug', 'WTForms', 'xyzservices', 'yt-dlp', 'zipp'
# Add other dependencies here
],
)