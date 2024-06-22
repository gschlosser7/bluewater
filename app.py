from flask import Flask, render_template, url_for, redirect, request, jsonify, Request, render_template_string, session, flash
import flask
import requests, json
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from json import JSONEncoder, loads, load
from flask_sqlalchemy import SQLAlchemy, table
import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy import Table, Column, Integer, String, MetaData, ForeignKey
from sqlalchemy import inspect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, ValidationError, SelectField, SelectMultipleField
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import TextArea
from sqlalchemy import JSON, String, TypeDecorator
from sqlalchemy.dialects.postgresql import JSONB
from flask_jwt_extended import create_access_token
from datetime import datetime, date
import os
from flask_migrate import Migrate
import bcrypt
from flask_bcrypt import Bcrypt, generate_password_hash
#plotly
import plotly
import plotly.express as px
import chart_studio.tools as tls
from dash import dash, Dash, html, dcc, Input, Output
import pandas as pd
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple
import dash_bootstrap_components as dbc
from pycoingecko import CoinGeckoAPI
import psycopg2 as pg
import datetime
from flask_htmx import HTMX
#^something in this will fix the cannot import url_decode from werkzeug.urls error. 
#oauth or something else for AAA
#import hashlib or better hashing package
loginmanager =  LoginManager()
app = Flask(__name__)
#dash = Dash(__name__)
htmx=HTMX()

#class Config:
#reminder: will have to set environ vars on web server machine
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
#pass pgpass.conf, wherever that is, instead of raw pass
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') #'secretkey'
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = None
#SESSION_COOKIE_SECURE and REMEMBER_COOKIE_SECURE = True
ACCESS_TOKEN = os.getenv('ACCESS_TOKEN')
GOOGLE_RECAPTCHA_SITE_KEY=os.getenv('GOOGLE_RECAPTCHA_SITE_KEY')
GOOGLE_RECAPTCHA_SECRET_KEY=os.getenv('GOOGLE_RECAPTCHA_SECRET_KEY')
url = os.getenv('DATABASE_URL')
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
migrate=Migrate(app,db, command='migrate', compare_type=True) # think this was alr fixed because migrate isnt used anymore but idk leaving this just in case
htmx=HTMX(app)

loginmanager.init_app(app)
loginmanager.login_view='/'

'''The class that you use to represent users needs to implement these properties and methods:is_authenticated
    This property should return True if the user is authenticated, i.e. they have provided valid credentials. (Only authenticated users will fulfill the criteria of login_required.)is_active
    This property should return True if this is an active user - in addition to being authenticated, they also have activated their account, not been suspended, or any condition your application has for rejecting an account. Inactive accounts may not log in (without being forced of course).is_anonymous
    This property should return True if this is an anonymous user. (Actual users should return False instead.)get_id()
    Ths method must return a str that uniquely identifies this user, and can be used to load the user from the user_loader callback. Note that this must be a str - if the ID is natively an int or some other type, you will need to convert it to str.
'''

with app.app_context():
    db.Session()
    
class User(db.Model, UserMixin):
    __tablename__ = 'moneyusers'
    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    #created_date= db.Column(db.DateTime, default=datetime.time.time(), nullable=True)
    def __init__(self, username, password):
        self.username=username
        self.password=password
    
    @staticmethod
    def get(username, password):
        userinfo1 = User(db.Model).Table['moneyusers'].Column[username].row(0)
    
        if userinfo1:
            grabid=db.execute(f'SELECT id FROM moneyusers WHERE username = ? and password = ?', (username, password))
            return grabid
    
    def coinize(id):
        coin = flask_jwt_extended().create_access_token(id)
        return coin
    
    @loginmanager.user_loader
    def load_user(id):
        return db.session.get(User, int(id)) #return str(self.id)
    
    @property
    def is_authenticated(self):
        return True

class Comments(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer(), primary_key=True)
    user=db.Column(db.String(255))
    content=db.Column(db.Text)
    timeposted=db.Column(db.DateTime, default=datetime.datetime.now(datetime.UTC))
    slug=db.Column(db.String(255))
class Purchases(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    user=db.Column(db.String(255))
    coinpurchased = db.Column(db.String(255))
    quantity = db.Column(db.String(255))
    timepurchased = db.Column(db.String(255))
    #bio=db.Column(db.String(255))
    #separate bio column. try to reuse content for bio too  
class userCoinlist(db.Model):
    id=db.Column(db.Integer(), primary_key=True)
    curruser=db.Column(db.String(255), nullable=False, unique=True)
    coin= db.Column(db.String(255), nullable=True)
    def __init__(self, curruser, coin):
        self.curruser=curruser
        self.coin=coin

class currentView(db.Model):
    id=db.Column(db.Integer(), primary_key=True)
    curr_user=db.Column(db.String(255), nullable=False, unique=True)
    coinBeingViewed= db.Column(db.String(255), nullable=True)
    def __init__(self, curr_user, coinBeingViewed):
        self.curr_user=curr_user
        self.coinBeingViewed=coinBeingViewed

class userAccountValue(db.Model):
    id=db.Column(db.Integer(), primary_key=True)
    accountHolder=db.Column(db.String(255), nullable=False, unique=True)
    portfolioValue=db.Column(db.String(255), nullable=True)
    coinHoldings=db.Column(db.String(255), nullable=True)
    transations=db.Column(db.String(255), nullable=True)
    #timeOfTransaction=db.Column(db.DateTime, default=datetime.datetime.now(datetime.UTC))
    def __init__(self, portfolioValue, accountHolder, coinHoldings, transations):
        self.portfolioValue=portfolioValue
        self.coinHoldings=coinHoldings
        self.accountHolder=accountHolder
        self.transations=transations

class coinGeckoCoinList(db.Model):
    id=db.Column(db.Integer(), primary_key=True)
    coin=db.Column(db.String(80), unique=False)
    def __init__(self, coin):
        self.coin=coin
class coinGeckoCoinsList(db.Model):
    id=db.Column(db.Integer(), primary_key=True)
    coin=db.Column(db.String(255), unique=False)
    def __init__(self, coin):
        self.coin=coin
class coinGeckoCoinsList2(db.Model):
    __tablename__='coin_geck_coins_list2'
    id=db.Column(db.Integer(), primary_key=True)
    coin=db.Column(db.String(255), unique=True)
    def __init__(self, coin):
        self.coin=coin

class coinGeckoCoinsList3(db.Model):

    id=db.Column(db.Integer(), primary_key=True)
    coin=db.Column(db.String(255), unique=False)
    def __init__(self, coin):
        self.coin=coin
class cgList(db.Model):
    id=db.Column(db.Integer(), primary_key=True)
    coin=db.Column(db.String(80), unique=False)
    def __init__(self, cgcoin):
        self.cgcoin=cgcoin
#USER MAkes purchase --> form containing account dollar value auto updates default=1mil into default - purchaseamount=new default? or change it to db value

'''class userEmail(db.Model):
    id=db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email= db.Column(db.String(50), nullable=True, unique=True)
    def __init__(self, username, email):
        self.username=username
        self.email=email
'''
'''@loginmanager.user_loader
def load(userid):
    User.query.filter_by(username=username).first()'''

class LoginForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('submit')
class registerForm(FlaskForm):
    username= StringField('username', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    
class commentForm(FlaskForm):
    #coin=id of coin being commented on
    username = StringField('username:', validators=[DataRequired()])
    content = StringField('comment:', validators=[DataRequired()], widget=TextArea())
    slug=StringField('slug', validators=[DataRequired()])
    save=SubmitField('save')
class purchaseForm(FlaskForm):
    coinpurchased=StringField('coin', validators=[DataRequired()])
    quantity=StringField('quantity', validators=[DataRequired()])
    timepurchased=StringField('time')
    buybutton=SubmitField('BUY')
#class watchNewCoin(FlaskForm):
  #  coin=StringField('coin', validators=[DataRequired()])
   # submit=SubmitField('add coin')
preselectedBuyAmounts=[(None,''),('10','10'),('100','100'),('1000','1000')]

coinOptions=[]
#def coinOptions(desiredcoin):
    #watchlist.coinBeingViewed
class newPurchase(FlaskForm):
    coin=StringField('coin' )
    #price get price value from currentView THEN make ohlc or simple price request at point of transaction.
    pricepercoin=StringField('price')
    quantity=SelectField('quantity', choices=[(None,''),('10','10'),('100','100'),('1000','1000')], default='', validate_choice=False)
    totalcost=StringField('total' )
    #time will be datetime column, maybe use the time from the coingecko data?
    buy=SubmitField('BUY')
class newSell(FlaskForm):
    coindrop=StringField('coin')
    pricepercoinSell=StringField('price')
    quantitySell=StringField('quantity', validators=[DataRequired()])
    totalcostSell=StringField('total' )
    #time will be datetime column, maybe use the time from the coingecko data?
    sell=SubmitField('sell')

preselectedBuyAmounts2=[(None,''),('10','10'),('100','100'),('1000','1000')]
class nestedQuantityForm(FlaskForm):
    quantize=SelectField('quantity', choices=preselectedBuyAmounts2, validators=[DataRequired()], validate_choice=False)
    buy=SubmitField('BUY')#use submit buttons plural that auto update a "total" outside of the form

#class GRCForm(FlaskForm):


#app.context().push() possibly
with app.app_context():
    db.create_all() #create above tables, forms are there for convenience they aren't committed
    db.session.commit()

@app.route('/', methods=['POST','GET'])
def hmpg():
    form = LoginForm()
    if request.method == 'POST':
        print('csrf')
        if form.username.data and form.validate_on_submit():
            print('form validated')
            usernameinput = str(form.username.data)
            user = User.query.filter_by(username=usernameinput).first()
            if user:
                if bcrypt.check_password_hash(user.password, form.password.data)==True:
                    print('in here')
                    flash('loggedin')
                    login_user(user)
                    session['username'] = usernameinput
                    if 'username' in session:
                        print('aa')
                        return redirect(url_for('forummain'))
                else:
                    form=LoginForm(object=user)
                    try: 
                        if bcrypt.check_password_hash(user.password, form.password.data):
                            return flash('login failed') 
                    except: 
                        return flash('login failed') 
            
    print('last')
    return render_template('home.html', form=form)

@app.route('/submit', methods=['POST', 'GET'])
def submit():
    form=registerForm()
    GOOGLE_VERIFY_URL='https://www.google.com/recaptcha/api/siteverify'
    if request.method == ['POST']:
        if form.validate_on_submit():

            username=str(form.username.data)
            password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            print(password)
            user=User(username, password)
            
            gsecret = request.form['g-recaptcha-response']
            gresponse=requests.post(url=f'{GOOGLE_VERIFY_URL}?=secret={GOOGLE_RECAPTCHA_SECRET_KEY}&response={gsecret}')
            print(gresponse)
            if not gresponse['success'] or gresponse['score'] < 0.5:
                print('fail')
                ('captcha failed please try again')
                redirect(url_for('hmpg'))
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('hmpg'))
    return render_template('register.html', form=form, site_key=GOOGLE_RECAPTCHA_SITE_KEY)
    
@app.route('/logout')
def logout():
    # remove the username from the session if it's there
    session.pop('username', None)
    logout_user()
    return redirect(url_for('hmpg'))

watch=[{}]

@app.route('/forum', methods=['GET', 'POST'])
@login_required
def forummain():
#emailform=emailForm()
#getuseremail=userEmail.query.filter_by(username=session['username']).first()

#if getuseremail.email==True:
    #
#else:
    #email=emailform.email.data
    #username=session['username']
    #addEmail=userEmail(username, email)
    #db.session.add(addEmail)
    #db.session.commit()

    #ai template: does {purchaseform} and current technical analysis seem like a good trade in comparison to other trades?
    #def forummain(currently_viewing)

    #at the top here somewhere do usercoinquantity * current price for each coin... add total to buying power
    #userAccountValue.query.filter_by(accountHolder=session['username']).delete()
    #db.session.commit()
    #userCoinlistDel = userCoinlist.query.delete()
    #
    #coinGeckoCoinsList2.__tablename__.drop(create_engine)
    #rollback after the above
    '''cgheaders = {"Authorization": ACCESS_TOKEN, "accept": "application/json"}
    coinlisturl = "https://api.coingecko.com/api/v3/coins/list"
    
    getcoinsfromCG= requests.get(coinlisturl, cgheaders)
    parseCoinForID = json.loads(getcoinsfromCG.text)
    cgCheck=cgList.coin
    if not cgCheck:
        for xx in parseCoinForID:
            try:
                addcgcoin=cgList(xx['name'])
                db.session.add(addcgcoin)
                db.session.commit()
                
            except Exception as e:
                print(e)'''
#the above code is a static method of loading all coin names into DB for instant query purposes later
    
    testing=coinGeckoCoinsList3.query.filter(coinGeckoCoinsList3.coin.icontains('bitcoin')).limit(5).all()
    print(testing)

    watching=watch
    #make watchlist the default ohlc pandas frames in server. user can add to list and trigger ohlc pandas frame post event to server... default=newdefault
    purchaseform=purchaseForm()
    newpurchase=newPurchase()
    newpurchase.quantity.choices=[('',''),('10','10'),('100','100'),('1000','1000')]
    NestedQuantityForm=nestedQuantityForm()
    newsell=newSell()
    
    cg = CoinGeckoAPI()
    watchlist=currentView.query.filter_by(curr_user=session['username']).first()
    #raise exception for response 500 to change watchlist.coin to bitcoin or something. coingecko data doesnt come through for some coins.

    
    #get accValue
    getValue=userAccountValue.query.filter_by(accountHolder=session['username']).first()
    if getValue:
        topPageHoldsView=[]
        makeValue='$'+str(userAccountValue.query.filter_by(accountHolder=session['username']).first().portfolioValue)
        showHoldings=json.loads(getValue.coinHoldings)
        for coin in showHoldings:
            vals=showHoldings[coin]
            topPageHoldsView.append(coin)
            #newsell.coindrop.choices.append(tuple((coin, coin)))
            
            print('new SELL', newsell.coindrop.data)
            for x in vals:
                
                topPageHoldsView.append((round(float(x),3)))
            
            print(topPageHoldsView,'TPV')
    
    else:
        makeValue='$1000000.00'
        topPageHoldsView=None
        #makeValue=userAccountValue.query.filter_by(accountHolder=session['username']).first().portfolioValue
        #makeValue='1000000'
        #db.session.add(makeValue)
        #db.session.commit()

    try:
        if watchlist.coinBeingViewed:
            print(watchlist.coinBeingViewed)
            #coinOptions.append(watchlist.coinBeingViewed)
            setgraphcoin=watchlist.coinBeingViewed #change graph data to data of coin user just clicked on
            setPurchaseFormCoin=watchlist.coinBeingViewed #change green highlighted 'coin' text in newpurchase
            newpurchase.coin.data = setPurchaseFormCoin
            newsell.coindrop.data= str(setPurchaseFormCoin)

            ohlc = cg.get_coin_ohlc_by_id(id=setgraphcoin, vs_currency='usd', days='30')
            error=''
            
        else:
            print('made it')
            watchlist.coinBeingViewed='bitcoin' 
            db.session.commit()
            setPurchaseFormCoin=watchlist.coinBeingViewed
            newpurchase.coin.data = setPurchaseFormCoin
            ohlc = cg.get_coin_ohlc_by_id(id='bitcoin', vs_currency='usd', days='30')
    except:
        errorCoin=currentView(curr_user=session['username'], coinBeingViewed='bitcoin')
        db.session.add(errorCoin)
        db.session.commit()
        return redirect(url_for('forummain'))
    parseohlc = pd.DataFrame(ohlc)
    clist=[]
    dlist=[]
    for x in ohlc:
        clist.append(int(round(x[0])))
    
    #print(clist)
    parseohlc.columns=['date','open','high','low','close']
    parseohlc['date'] = pd.to_datetime(parseohlc['date'], unit='ms')
    check=(parseohlc['date'].dt.strftime("%m%d-%m-%Y"))
    #print(parseohlc['date'],check)
    chartcoords=[]
    chartdata={}
    i=0
    while i < len(parseohlc['date']):
        chartcoords.append((parseohlc['date'][i], parseohlc['close'][i]))
        #chartdata+=dict((parseohlc['date'][i], parseohlc['close'][i]) for (parseohlc['date'][i], parseohlc['close'][i]) in parseohlc['date'])
        chartdata[parseohlc['date'][i]]=parseohlc['close'][i]
        i+=1

    ycoords=list(chartdata.values())
    print('clist,yscoords here, sma9=clist[::9], go backwards adding each 9 days before the current date( x value) and calc the total/9days. store these in database in poppable format?')
    xcoords=list(chartdata.keys())
    priceper=ycoords[((len(ycoords)-1))]
    #print(len(ycoords), len(clist))
    #get x,y coordinates for graph    
    #print(xcoords)
    #usercoins=userCoinlist.query.filter_by(curruser=session['username']).first().coin
    #print(usercoins)
    #usercoins=json.loads(usercoins)
    #for x in usercoins:
    #    print(x, 'here')
    watchlistcoins= userCoinlist.query.filter_by(curruser=session['username']).first()
    if not watchlistcoins:
        url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin%2Cethereum%2Cchainlink%2Csolana%2Chex%2Ctether&vs_currencies=usd&include_market_cap=false&include_24hr_vol=false&include_24hr_change=false&include_last_updated_at=false&precision=0"
    else:
        try:
            mystr=''
            loadwatchlist=json.loads(watchlistcoins.coin)
            for x in loadwatchlist:
                print(x)
                mystr=mystr+''.join('%2C'+ x)
                print(mystr,' okkokkokokokokokoookokkokokokokookookokookokokokoko')
        except:
            mystr=''.join('%2C'+ watchlistcoins.coin)
        furl = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin%2Cethereum%2Csolana%2Chex%2Ctether"+mystr+"&vs_currencies=usd&include_market_cap=false&include_24hr_vol=false&include_24hr_change=false&include_last_updated_at=false&precision=0"
        print('1',furl)
        url=furl
    #url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin%2Cethereum%2Cchainlink%2Csolana%2Chex%2Ctether&vs_currencies=usd&include_market_cap=false&include_24hr_vol=false&include_24hr_change=false&include_last_updated_at=false&precision=0"
    print('url=',url)
    #https://api.coingecko.com/api/v3/simple/price?ids=bitcoin%2Cethereum&vs_currencies=usd&include_market_cap=false&include_24hr_vol=false&include_24hr_change=false&include_last_updated_at=false&precision=0
    #https://api.coingecko.com/api/v3/simple/price?ids=${str}&vs_currencies=usd
    #GET RID OF RAW URLs
    headers = {"Authorization": ACCESS_TOKEN, "accept": "application/json"}
    response = requests.get(url, headers=headers)
    newmessage='test message'
    if request.method=='POST':
        print('kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk')
        if purchaseform.validate_on_submit():
            purchase=Purchases(coinpurchased=purchaseform.coinpurchased.data, quantity=purchaseform.quantity.data, timepurchased=purchaseform.timepurchased.data)
            #user = User.query.filter_by(username=form.username.data).first()
            #filter_by(id=current_user)  ??
            #form.username.data=''
            #form.content.data=''
            #form.slug.data=''
            newmessage=watch
            db.session.add(purchase)
            db.session.commit()
            return render_template('forum.html', watch=watch, tableh=tableh, test=cointlist, clist=clist, ycoords=ycoords, ohlc=ohlc, purchaseform=purchaseform, newmessage=newmessage)
        newpurchase.quantity.choices=[(None,''),('10','10'),('100','100'),('1000','1000')]
        qChoices=newpurchase.quantity.choices
        print(newpurchase.quantity.data,newpurchase.coin.data, newpurchase.totalcost.render_kw, newpurchase.pricepercoin.raw_data,'p[[pp[p[pppp[]]]]]')
        if newpurchase.buy.data and newpurchase.validate_on_submit():
            print('383')
            userVal=userAccountValue.query.filter_by(accountHolder=session['username']).first()
          
            qChoices=newpurchase.quantity.choices
            coin = newpurchase.coin.data
            newpurchase.pricepercoin.data = ycoords[(len(ycoords)-1)]
            quantity = request.form.get('quantity')
            totalcost = str(newpurchase.pricepercoin.data * float(quantity))
            print(coin, quantity, totalcost, newpurchase.pricepercoin.data, '$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$')
            
            empty={str(coin):(str(quantity), str(newpurchase.pricepercoin.data))} #transaction seen here. this will serve order history and the timeofpurchase value of coin
            #userAccountValue portfolioValue coinHoldings accountHolder transactions
            #json dumps loads here probably
            fullOrder={str(coin):(str(newpurchase.pricepercoin.data),(str(quantity)+".0"), str(totalcost))}
            fullOrder=json.dumps(fullOrder)
            
            empty=json.dumps(empty)
           
            print(empty,'emptyemptyempty')
            #order=userVal.transactions
            #order+=empty
        
            if userVal:
                userVal.transations=userVal.transations+(fullOrder)
            
                db.session.commit()
                
                portVal=userVal.portfolioValue
                portVal=float(portVal)
                
                print(portVal, 'portval')
                db.session.commit()
                print(userVal.coinHoldings,'  14141414')
                
                loadHolds=json.loads((userVal.coinHoldings))
                #loadHolds=loadHolds.keys()
                
                
                if coin in loadHolds:
                    #add to the coins dict values of quantity and priceper
                    print('IN KEYS .............................')
                    
                    coinVals= loadHolds.get(coin) #THE PROBLEM IS HERE
                    #THE COINHOLDINGS REPLACE VALUES AFTER THE INITIAL POST ISNT WORKING
                    #{"solana": [140.0, 12.681571428571429]}
                    #{"chainlink": ["17.66", "1000"],"ethereum": ["10", "3776.15"]}

                    print(coinVals)
                    print(float(totalcost),'floatalcost', float(coinVals[0]),float(coinVals[1]) )
                    roundedNum2 = float(coinVals[0]) + float(quantity) 
                    roundedNum1 = (float(coinVals[1])*float(coinVals[0])) + float(totalcost) 
                    print(roundedNum2, roundedNum1, 'r1r2---------')
                    
                    roundedNum2=round(roundedNum2, 5)
                    roundedNum1=round(roundedNum1, 5)
                    
                    empty={str(coin):(str(float(roundedNum1)/float(roundedNum2)), roundedNum2,roundedNum1)}
                    loadHolds[coin]=[str(roundedNum2), str(float(roundedNum1)/float(roundedNum2))]
                    print(loadHolds,'replaceholdingvals')
                    
                    
                    userVal.coinHoldings=json.dumps(loadHolds) #coin is being detected  for multiCoin but only posts the  detected coin instead of keeping both
                    #userVal.coinHoldings=json.dumps(loadHolds+replacePrevHoldingVals)
                    userVal.portfolioValue=float(userVal.portfolioValue) - roundedNum1
                    db.session.commit()
                    return redirect(url_for('forummain'))
                
                else:
                    addHold={str(coin):(quantity, str(float(totalcost)/float(quantity)))}
                    loadHolds[coin]=[quantity, str(float(totalcost)/float(quantity))]
                    print(loadHolds)
                    
                    userVal.coinHoldings=json.dumps(loadHolds)
                    userVal.portfolioValue=float(userVal.portfolioValue) - float(totalcost)
                    #userVal.coin={str(coin):('','')}
                    #coin=json.dumps(coin+empty)
                    db.session.commit()
                    return redirect(url_for('forummain'))
            
            else:
                print(float(totalcost), totalcost)
                portVal=float(1000000.00)-float(totalcost)
                portVal=round(portVal, 3)
                portVal=str(portVal)
                print(portVal, 'portVal ##############')
                #userVal.transations=fullOrder
                #db.session.commit()
                newUserPurchaseRow=userAccountValue(portfolioValue=portVal, coinHoldings=empty, accountHolder=session['username'], transations=fullOrder)
                
                db.session.add(newUserPurchaseRow) #only use this if they don't have a row at all
                db.session.commit()

            return redirect(url_for('forummain'))
        
        if newsell.sell.data and newsell.validate_on_submit():
            coindrop=newsell.coindrop.data
            print(coindrop, newsell.quantitySell.data, newsell.pricepercoinSell.data, newsell.pricepercoinSell.raw_data)
            print('in theorruyyyyyy ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;')
            if coindrop in showHoldings:
                print(coindrop, showHoldings)
                amountSold = float(newsell.quantitySell.data)
                currVals = showHoldings[coindrop]
                quantity=float(currVals[0]) - abs(float(newsell.quantitySell.data)) 
                holdingValue=float(currVals[1])*float(currVals[0]) - float(newsell.quantitySell.data)*float(ycoords[(len(ycoords)-1)])
                
                try:
                    newAvg=holdingValue/quantity
                    quantity=str(quantity)
                    print(str((coindrop, quantity, newAvg)))
                    showHoldings[coindrop]=(str(quantity), str(newAvg))
                    print(showHoldings, '22222222222222222222222222222')
                    getValue.coinHoldings=json.dumps(showHoldings)
                    getValue.portfolioValue=float(getValue.portfolioValue) + (amountSold*float(ycoords[((len(ycoords)-1))]))

                    db.session.commit()
                    return redirect(url_for('forummain'))
                except:
                    if quantity <= 0: #this is hit if the user sells the whole stack
                        print('bong')
                        showHoldings.pop(coindrop)
                        getValue.coinHoldings=json.dumps(showHoldings)
                        if showHoldings=='{}':
                            try:
                                db.session.delete(getValue.coinHoldings)
                                db.session.commit()
                            except:
                                getValue.coinHoldings=''
                                db.session.commit()

                        getValue.portfolioValue=float(getValue.portfolioValue) + (amountSold*float(ycoords[((len(ycoords)-1))]))

                        db.session.commit()
                    return redirect(url_for('forummain'))
            else:
                print('noadsijaiqsjdi')
                return 'adas'
            

    elif request.method=='GET':
        print((response.text), 'response text')
        print(response, current_user)
        new = json.loads(response.text)
        
        cointlist=[]
        buttonlist=[]
        tableh=['coin', 'price']
        tablew=['coin','quantity','avg. cost']
        #make cointlist[::-1] column in new table that newpurchase form can get currentView price info from
        for i, v in enumerate(new):
            i = new[v]
            print('i', i)
            for j, b in enumerate(i):
                j = i[b]
                print('v,j', v, j)
                buttonlist.append(v)
                cointlist+=[(v,j)]
        print(cointlist, buttonlist)
        for x in cointlist:
            try:
                if x[0] == currentView.query.filter_by(curr_user=str(session['username'])).first().coinBeingViewed:
                    newpurchase.pricepercoin.data=ycoords[((len(ycoords)-1))]
                    priceper=int(newpurchase.pricepercoin.data)
                    print('77')
                    print(priceper)
            except:
                print('778')
                errorCoin=currentView(curr_user=session['username'], coinBeingViewed='bitcoin')
                db.session.add(errorCoin)
                db.session.commit()
                print('88')
                return redirect(url_for('forummain'))
    try:   
        for x in cointlist:
            if x[0] == currentView.query.filter_by(curr_user=session['username']).first().coinBeingViewed:
                print('893')
                print(newpurchase.pricepercoin.data)
                newpurchase.pricepercoin.data=ycoords[((len(ycoords)-1))]
                priceper=float(newpurchase.pricepercoin.data)
                newsell.pricepercoinSell.data=priceper
                print(newpurchase.coin.data, priceper)
                print('add try except HERE BECAUSE THE THING ISNT GETTING THE PURCHASEFORM COIN PRICEPER DATA. MAYBE CONVERT WATCHLIST TO OHLC PRICE DATA')
                
                
                #make x[1] the price field in the purchase form
                #newpurchase.totalcost.data=x[1]*(int(newpurchase.quantity.data))
                #create list of tuples(coinid, price_in_usd)
                #return said list of tuples as test, seen below
    except:
        priceper=ycoords[((len(ycoords)-1))]
        newsell.pricepercoinSell.data=priceper
    
       

        '''empty=''
        newpurchase.quantity.choices=[(None,''),('10','10'),('100','100'),('1000','1000')]
        if newpurchase.validate_on_submit():
            print('293')
            qChoices=newpurchase.quantity.choices
            coin = newpurchase.coin.data
            pricer=newpurchase.pricepercoin.data
            pricepercoin = request.form.get('pricepercoin')
            quantity = newpurchase.quantity.data
            totalcost = newpurchase.totalcost.data
            #empty.append({str(coin):str((pricepercoin,quantity))})
            #print(empty,'emptyemptyempty')
            #accValue = userAccountValue.query.filter_by(curr_user=session['username']).first()
            #accValue.portfolioValue -= totalcost
            #accValue.portfolioValue += dollarAmountOfAllHoldings
            #store {str(coin):str((priceper,quantity))} values at time of purchase and compare them to currentdate values
            #addHolding = {'bitcoin':'(10 quantity, 63450 priceper)'} {str(coin):str((priceper,quantity))} format for keeping track of current coin holdings
            #if str(coin) in coinHoldings.keys():
                #coinHoldings[str(coin)]+=str((priceper,quantity))
            #else:    
                #coinHoldings.append({str(coin):str((priceper,quantity))})
            print(coin,pricepercoin,quantity,totalcost, pricer,';;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;')
            return redirect(url_for('forummain'))'''
    #make button press on watchlist trigger searchform event? how to get instant search?
    #make watchlist a class? a class of coins?
    if htmx:
        return render_template('coinsearch.html')
    return render_template('forum.html', tablew=tablew, newsell=newsell, topPageHoldsView=topPageHoldsView, makeValue=makeValue, priceper=priceper, setgraphcoin=setgraphcoin,newpurchase=newpurchase, NestedQuantityForm=NestedQuantityForm,error=error, buttonlist=buttonlist, watch=watching, tableh=tableh, test=cointlist, clist=clist, ycoords=ycoords, ohlc=ohlc, purchaseform=purchaseform, newmessage=newmessage)
@app.route('/search', methods=['GET','POST'])
@login_required
def instasearch():
    print('here')
    coinsearch = request.args.get('q')
    #clist = json.loads(coinGeckoCoinsList3.coin)
    #rint(clist)
    print(coinsearch)
    if coinsearch:
        print('SEARCHING...')
        results= coinGeckoCoinsList3.query.filter(coinGeckoCoinsList3.coin.icontains(coinsearch)).limit(100).all()
        print('SEARCHING')
        for x in results:
            try:
                coinsearch=coinsearch.upper()
                try:
                    ec=json.loads(x.coin)    
                    if len(coinsearch)>1:
                        print('it does')
                        grabname = ec.pop('name')        
                        results.append(grabname)
                except Exception as e:
                    print(e)
            except Exception as e:
                print(e)
    else:
        results=[]
    results2=[]
    for y in results:
        if type(y)==str:
            print(y,'passed')
            results2.append(y)
        else:
            results.remove(y)
    print(results[::-1])
    print(results2)
    if htmx:
        return render_template('coinsearch.html', results=results2)
    return render_template('coinsearch.html', results=results2)

@app.route('/quantity', methods=['GET','POST'])
@login_required
def quantize():
    print('quantizinated')
    newpurchase=newPurchase(request.form)
    
    if request.method=='POST':
        print('quantity check')
        #getjason=request.get_json(force=True)
        #print(getjason['coin'])

        coin = newpurchase.coin.data
        pricepercoin = newpurchase.pricepercoin.data
        quantity = newpurchase.quantity.data
        qshow=request.form['qform']
        totalcost = request.form.get('mytotal')
        empty=''
        print(qshow)        
        print( type(coin),coin,type(quantity),quantity, type(pricepercoin), pricepercoin, totalcost )
        if newpurchase.validate_on_submit():
            coin = newpurchase.coin.data
            pricepercoin = newpurchase.pricepercoin.data
            quantity = newpurchase.quantity.data
            totalcost = request.form.get('totalcost')
            print(coin, pricepercoin, quantity, totalcost)
            return 'a'

@app.route('/addtowatchlist', methods=['GET','POST'])
@login_required
def add():
    #id, curruser, coin
    if request.method=='POST':
        #preselected = coinGeckoCoinsList3.query.filter_by(cgcoin=)
        curruser = session['username']
        print(curruser, 'curr')
        item = request.form['watch']
        print(item)
        try:
            if coinGeckoCoinsList3.query.filter_by(coin=item):
                currlist=userCoinlist.query.filter_by(curruser=session['username']).first()
                #currlist2=db.session.execute(db.select(userCoinlist).order_by(userCoinlist.curruser)).scalars()
                print(currlist, 'currlist')
                watch.append({'watch':item, 'removed':False})
                if currlist:
                #currlist=json.dumps(currlist)
                #currlist=json.dumps(currlist+item)
                    try:
                        addWatch=json.loads(currlist.coin)
                        addWatch[item]='True'
                        print(addWatch)
                        print('watchlist updated')
                        currlist.coin=json.dumps(addWatch)
                        db.session.commit()
                     
                    except:
                        addWatch={}
                        addWatch[item]='True'
                        currlist.coin=json.dumps(addWatch)
                        print('watchlist updated 2')
                        db.session.commit()
                    
                    print(currlist,'71233123')
                #print(json.dumps(watch))
                #jsondumpswatch=json.dumps(watch)
                #currlist=currlist+jsondumpswatch
                #currlist=json.dumps(currlist)
                else:
                    print('8')
                    item={str(item):'True'}
                    item=json.dumps(item)
                    newcoin=userCoinlist(curruser, item)
                    db.session.add(newcoin)
                    db.session.commit()
        except:
            flash('Coin not recognized')
    return redirect(url_for('forummain'))

@app.route('/<coin>', methods=['GET','POST'])
@login_required
def graphview(coin):
    if request.method=='POST':
        coin=request.form['kvform']
        curr_user = session['username']
        coinViewColumn=currentView.query.filter_by(curr_user=session['username']).first()
        if coinViewColumn:
            coinViewColumn.coinBeingViewed=coin
            db.session.commit()
        else:
        #make db table current_view for clickable watchlist
            print(coin, curr_user)
            coinToGraph=currentView(curr_user, coin)
            db.session.add(coinToGraph)
            db.session.commit()
        return redirect(url_for('forummain'))

@app.route('/editwatchlist', methods=['GET','POST'])
def edit(watchlist):
    item=watch[watchlist]
    if request.method=='POST':
        watch['watch'] = request.form['watch']
        #user = User.query.get(current_user.get_id())
        return redirect(url_for('forummain'))
    else:
        return render_template('forum.html', item=item, watchlist=watchlist)
    
@app.route('/place_order', methods=['GET'])
@login_required
def placeOrder():
    if request.method=='POST':
        #if column has data in it:
            #purchases.append(purchase)
            #accountValue-costOfPurchase=accountValue
            #accountValue has to be constantly be updating based on price flux of coin that was purchased
        #else:
            #purchase=
        return 'a'

'''def check(watchlist):
    watch[watchlist]['done'] = not watch[watchlist]['done']
    return redirect(url_for('/register'))
def delete(watchlist):
    del watch[watchlist]
    return redirect(url_for('/'))'''

@app.route('/register', methods=['POST', 'GET'])
def register():
    
    
    form=registerForm()
 
    GOOGLE_VERIFY_URL='https://www.google.com/recaptcha/api/siteverify'
    if request.method == 'POST':
        if form.validate_on_submit():
            print('form validated')
            username=str(form.username.data)
            password=bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            print(password)
            user=User(username, password)
            
            gsecret = request.form['g-recaptcha-response']
            gresponse=requests.post(url=f'{GOOGLE_VERIFY_URL}?secret={GOOGLE_RECAPTCHA_SECRET_KEY}&response={gsecret}').json()
           
            print(gresponse)
            if not gresponse['success'] or gresponse['score'] < 0.5:
                print('fail')
                ('captcha failed please try again')
                redirect(url_for('hmpg'))
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('hmpg'))
    return render_template('register.html', form=form, site_key=GOOGLE_RECAPTCHA_SITE_KEY)

@app.route('/profile', methods=['POST', 'GET'])
@login_required
def profile():
    
    url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin%2Cethereum&vs_currencies=usd&include_market_cap=false&include_24hr_vol=false&include_24hr_change=false&include_last_updated_at=false&precision=0"
    #https://api.coingecko.com/api/v3/simple/price?ids=${str}&vs_currencies=usd
    #GET RID OF RAW URLs
    headers = {"Authorization": ACCESS_TOKEN, "accept": "application/json"}
    response = requests.get(url, headers=headers)
    print(response,'33')
    if request.method=='GET':
        print((response.text))
        print(response, current_user)
        new = json.loads(response.text)
        
        cointlist=[]
        for i, v in enumerate(new):
            i = new[v]
            for j, b in enumerate(i):
                j = i[b]
                print(v, j)
                cointlist+=[(v,j)]
                #create list of tuples(coinid, price_in_usd)
                #return said list of tuples as test, seen below    
    if request.method=='POST':
        return'1'
    return render_template('profile.html', test=cointlist)

@app.route('/addcomment', methods=['GET','POST'])
@login_required
def addComment():
    form=commentForm()
    print(session['username'])
    print(form.username.raw_data, form.content.raw_data, form.slug.data)
    
    print('this far')
    if form.validate_on_submit():
        comment=Comments(user=form.username.data, content=form.content.data, slug=form.slug.data)
        #user = User.query.filter_by(username=form.username.data).first()
        #filter_by(id=current_user)  ??
        #form.username.data=''
        #form.content.data=''
        #form.slug.data=''
        db.session.add(comment)
        db.session.commit()
    return render_template('addcomment.html', form=form)

@app.route('/chart', methods=['POST', 'GET']) 
def render_dashboard():
    print('12313123123213')
    if 'username' in session:
        print(session['username'])
        return redirect('/pathname')
    return redirect(url_for('logout'))
#@server.route('/app1')
#def app1_route():
    #return app1.index()
df = pd.DataFrame({
    'coin':['bitcoin', 'ethereum'],
    '':['1','2'],
    'daterange': ['1','3'],
    'movingavg':['1', '2.9']
})
cf = pd.DataFrame({
    'coin':['bitcoin', 'ethereum'],
    '':['3','4'],
    'daterange': ['0','3']
})

board=Dash(__name__,requests_pathname_prefix="/advanced_view/") #server=app param ?

board.title='Financial Dashboard'
#board._favicon = ("favico.ico")
fig = px.line(df, x='daterange', y='')
fig.add_scatter(x=df['daterange'], y=df['movingavg'])


board.layout = html.Div(children=[
    html.H1(children='Financial Dashboard'),
    html.Div([
    dcc.Link('Go home', href='/forum'),
    html.Br()]),
 
    dbc.Container(html.Div(
    [
        html.Div("First item", className="bg-light border"),
        html.Div("Second item", className="bg-light border ms-auto"),
        html.Div("Third item", className="bg-light border")
    ], className="hstack gap-3"
    )),

    dcc.Graph(
        id='example-graph',
        figure=fig
        
    )],className="hstack gap-3",)
fig.layout.title.font.family="Verdana"
fig.update_xaxes(showgrid=True, gridwidth=1, gridcolor='gray')
fig.update_yaxes(showgrid=True, gridwidth=1, gridcolor='gray')
fig.update_layout(title_font_family="Verdana",template='plotly_dark',margin_t=0, margin_r=0, margin_l=0, margin_b=0,paper_bgcolor='rgba(0,0,0,0)')
#@board.callback(
 #   Output("graph", "figure"), 
  #  Input('slider', 'value'))

@board.callback(
    Output("user", "children"),
    Input("url", "pathname"),
)

def update_authentication_status(_):
    if current_user.is_authenticated:
        return dcc.Link("logout", href="/logout")
    return dcc.Link("login", href="/login")

#server.config.update(
 #   SECRET_KEY=os.urandom(12),
  #  SQLALCHEMY_DATABASE_URI=config.get('database', 'con'),
   # SQLALCHEMY_TRACK_MODIFICATIONS=False
#)
#1: get session id of user and compare that against the session id they received at time of login. if true == response 200
application = DispatcherMiddleware(
    app,
    {"/advanced_view": board.server}
)

if __name__== '__main__':
    #dash.run(debug=True)
    run_simple("localhost", 8050, application, use_reloader=True)