from app import create_app

if __name__ == '__main__':
    application = create_app()
    application.run()
    #app.run()
else:
    gunicorn_app = create_app()