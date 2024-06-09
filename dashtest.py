import dash
from dash import html, dcc, Dash
import flask
import plotly.express as px
import pandas as pd
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple

server = flask.Flask(__name__)


@server.route("/")
def home():
    return "Hello, Flask!"

df = pd.DataFrame({
    "Fruit": ["Apples", "Oranges", "Bananas", "Apples", "Oranges", "Bananas"],
    "Amount": [4, 1, 2, 2, 4, 5],
    "City": ["SF", "SF", "SF", "Montreal", "Montreal", "Montreal"]
})

fig = px.bar(df, x="Fruit", y="Amount", color="City", barmode="group")

app1 = dash.Dash(requests_pathname_prefix="/app1/")
app1.layout = html.Div(children=[
    html.H1(children='Hello Dash'),

    html.Div(children='''
        Dash: A web application framework for your data.
    '''),

    dcc.Graph(
        id='example-graph',
        figure=fig
    )
])

app2 = dash.Dash(requests_pathname_prefix="/app2/")
app2.layout = html.Div("Hello, Dash app 2!")

application = DispatcherMiddleware(
    server,
    {"/app1": app1.server, "/app2": app2.server},
)

if __name__ == "__main__":
    run_simple("localhost", 8050, application)

    #app = flask.Flask(__name__)
    #board=Dash(__name__,server=app,requests_pathname_prefix="/app1/")
    #board.layout = html.Div("Hello, Dash app 2!")
    '''application = DispatcherMiddleware(
    app,
    {"/app1": board.server}
)

if __name__== '__main__':
    #dash.run(debug=True)
    run_simple("localhost", 5000, application)

'''

'''
from app import app

if __name__ == '__main__':
'''