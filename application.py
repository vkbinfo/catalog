#!/usr/bin/python

from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
from flask import session as login_session, g

from flask_login import LoginManager, login_user, logout_user, current_user, login_required
import random, string

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, Category, CategoryItem, User

#imports for the google thrid party sign in
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

#for ordrered dictionary
import collections

app = Flask(__name__)
login_manager=LoginManager()
login_manager.init_app(app)
# setting login view for unauthorized access in flask with the help of
# login_manager
login_manager.login_view= 'login'

client_id="575334475222-jp8jmuvk13k67aek18sig53dececue27.apps.googleusercontent.com"
client_secret= "ONHd7Y49x1nffhRCM3ezy4Z8"

APPLICATION_NAME = "Catalog Item Application"

# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@login_manager.user_loader
def load_user(user_id):
    try:
        return session.query(User).filter_by(id=user_id).first()
    except:
        return None

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # validate state token
    if request.args.get('state')!=login_session['state']:
        response=make_response(json.dump("Invalid state token.."),401)
        response.headers['content-type']='application/json'
        return response

    # If our state is true no anti-forgery, we will retrieve one time code
    one_time_code = request.data

    # Now we call google+ server for ceredentail object(contains authorize code
    # and one time access code  with the help of one time token
    try:
        oauth_flow=flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentails=oauth_flow.step2_exchange(one_time_code)
    except FlowExchangeError:
        response=make_response(json.dump("failed to acquire authorization"
                                         " code"), 401)
        response.headers['content-type'] = 'application/json'
        return response
    # In above lines we have received the credentials that contains the access
    # code and refresh code this is valid for some time normally 3600 seconds
    # access code is used for get info from google plus server.

    access_token = credentails.access_token
    #let's check that our access code is a valid access code
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    resultList=h.request(url, 'GET')
    result=json.loads(resultList[1])
    #now see token is valid
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # so far our state is right, our access token is right

    # now let's see that we got google plus id in result is same we got in
    # credentials
    gplus_id = credentails.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # oh sh*t the user id of credentials doesn't match with result's user id
    # if we didn't reach till this line

    # Now lets check that result is targated(for use) to our app
    if result['issued_to'] != client_id:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print
        "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    # if we have reached here than life is good and awesome. and we are not
    # reaching till here then Ok there is something to learn about aouth2.

    # So we have reached here and life is good, so lets check for previous set
    # session login details see that our user is already log in or not

    stored_access_token=login_session.get('access_token')
    stored_gplus_id=login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected., '),
            200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # If we are still reaching here than user's life is good, he is doing
    # logging on our website.

    login_session['access_token']=credentails.access_token
    login_session['gplus_id']=gplus_id

    # Now let's see how our user look like in his/her google plus picture,
    # so we need user info right now...

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentails.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    # lets our data in json form,
    #  you can ask why?..Dude because json is awesome.
    data = answer.json()

    #checking that if user already exist
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    #let's check bhaisabh already exist or not
    user_id = session.query(User).filter_by(email=data['email']).first()
    print(user_id)
    if not user_id:
        user_obj=User(username=login_session['username'],email=login_session['email'])
        session.add(user_obj)
        session.commit()
    user_obj = session.query(User).filter_by(email=data['email']).first()
    login_user(user_obj)
    login_session['user_id'] = user_obj.id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


#let's build up sign up functionality
@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST' and \
                    login_session['state'] == request.form['state']:
        username=request.form['username']
        email=request.form['email']
        password=request.form['password']
        userObj=User(username=username, email=email)
        userObj.hash_password(password)
        try:
            session.add(userObj)
            session.commit()
        except :
            return "Something went wrong, Either your email address " \
                   "already exist or database doesn't like your username..HAha"
        flash("You have successfully signed up.")
        login_session['username']=username
        login_session['email']=email
        user=session.query(User).filter_by(email=email).first()
        login_user(user)
        return redirect(url_for('index'))
    else:
        # we are creating session token for anti-frogery state token
        state = ''.join(
            random.choice(string.ascii_lowercase + string.ascii_uppercase
                          ) for x in range(32))
        login_session['state'] = state
        return render_template('signup.html', STATE=state)

# let's build login functionality
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST' and \
                    login_session['state'] == request.form['state']:
        username=request.form['username']
        password=request.form['password']
        try:
            userObj=session.query(User).filter_by(username=username).first()
        except :
            flash("user doesn't exist")
            state = ''.join(
                random.choice(string.ascii_lowercase + string.ascii_uppercase
                              ) for x in range(32))
            login_session['state'] = state
            return render_template('login.html', STATE=state)
        if userObj and userObj.verify_password(password):
            flash("You have successfully signed up.")
            login_session['username']=username
            login_user(userObj)
            return redirect(url_for('index'))
        else:
            flash("Login Details are wrong.")
            state = ''.join(
                random.choice(string.ascii_lowercase + string.ascii_uppercase
                              ) for x in range(32))
            login_session['state'] = state
            return render_template('login.html', STATE=state)

    else:
        # we are creating session token for anti-frogery state token
        state = ''.join(
            random.choice(string.ascii_lowercase + string.ascii_uppercase
                          ) for x in range(32))
        login_session['state'] = state
        return render_template('login.html', STATE=state)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    if 'provider' in login_session:
        if login_session['provider']=='google':
            url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
            h = httplib2.Http()
            result = h.request(url, 'GET')[0]
            if result['status']=='200':
                del login_session['gplus_id']
                del login_session['access_token']
                del login_session['provider']
                del login_session['picture']
    del login_session['username']
    del login_session['email']
    flash("You are now logged out.")
    return redirect(url_for('index'))

# CRUD operations on category model.
@app.route('/')
@app.route('/category')
def index():
    """Reads all the category from database"""
    all_categories = session.query(Category).all()
    last_ten_items = session.query(CategoryItem)\
        .order_by(CategoryItem.id.desc()).limit(10).all()
    login=False
    if login_session.get('username'):
        login=True
    return render_template('categories.html',categories=all_categories,
                           last_ten_items=last_ten_items, login=login)


@app.route('/category/new', methods=['GET','POST'])
@login_required
def newCategory():
    """creates a category in database"""
    if request.method == "POST":
        newCategoryObj = Category(name=request.form['name'], user_id=current_user.id)
        session.add(newCategoryObj)
        session.commit()
        return redirect(url_for('index'))
    return render_template('newCategory.html',login=login_session['username'])


@app.route('/category/<int:category_id>/edit', methods=['GET','POST'])
@login_required
def editCategory(category_id):
    """Updates a category in database"""
    if request.method=='POST':
        category_obj=session.query(Category).filter_by(id=category_id).first()
        category_obj.name=request.form['name']
        session.add(category_obj)
        session.commit()
        flash("The Category name is updated, so be cool now.")
        return redirect(url_for('index'))
    category_obj=session.query(Category).filter_by(id=category_id).first()
    if category_obj.user_id==current_user.id:
        return render_template('EditCategory.html', category_object=category_obj)
    else:
        flash("You need to be owner of the Category to edit it.")
        return redirect(url_for('index'))


@app.route('/category/<int:category_id>/delete', methods=['GET','POST'])
@login_required
def deleteCategory(category_id):
    """deletes a category in database"""
    if request.method=='POST':
        if request.form['submit']== "Delete":
            category_obj=session.query(Category).filter_by(
                id=category_id).first()
            session.delete(category_obj)
            session.commit()
            items_in_category =session.query(CategoryItem).filter_by(
                category_id=category_id).all()
            for item in items_in_category:
                session.delete(item)
                session.commit()
            flash("The Category Entry is Deleted, so be cool now.")
            return redirect(url_for('index'))
        else:
            return redirect(url_for('index'))
    category_obj=session.query(Category).filter_by(id=category_id).first()
    if category_obj.user_id==current_user.id:
        return render_template('DeleteCategory.html',
                               category_object=category_obj,login=True)
    else:
        flash("You need to be owner of the Category to Delete it.")
        return redirect(url_for('index'))


# CRUD operations on category items of a category.
@app.route('/category/<int:category_id>')
def itemsInCategory(category_id):
    """Reads all the items in a category from database"""
    itemObjects=session.query(CategoryItem).filter_by(category_id=category_id).all()
    categories=session.query(Category).all()
    categoryObj=session.query(Category).filter_by(id=category_id).one()
    can_add_item=False
    try:
        if categoryObj.user_id==current_user.id:
            can_add_item = True
    except :
        pass
    return render_template('itemsInCategory.html', categories=categories,
                           categoryObj=categoryObj, items=itemObjects,
                           login=login_session.get('username',None),
                           can_add_item=can_add_item, )


@app.route('/category/<int:category_id>/<int:item_id>/')
def itemDescription(category_id, item_id):
    """Reads all the items in a category from database"""
    can_edit_item = False
    user_id=0
    if login_session.get('username'):
        print(login_session['username'])
        user_id=session.query(User).filter_by(email=login_session.get('email')).first().id
        print(user_id)
    itemObj=session.query(CategoryItem).filter_by(id=item_id).first()
    print(itemObj.user_id)
    if itemObj.user_id == user_id:
        can_edit_item =True
    print(can_edit_item)
    return render_template('itemDetails.html', item = itemObj,
                           login=login_session.get('username',0),
                           can_edit_item=can_edit_item)


@app.route('/category/<int:category_id>/new', methods=['GET','POST'])
@login_required
def newItemInCategory(category_id):
    """creates a new item in a category in database."""
    if request.method == 'POST':
        name=request.form['name']
        description=request.form['description']
        category_id=request.form['category_id']
        itemObj= CategoryItem(name=name,
                              description=description,
                              category_id=category_id,
                              user_id=current_user.id)
        session.add(itemObj)
        session.commit()
        flash("Successfully added Item in Category")
        return redirect(url_for('index'))
    # we need to get the category_id accoring to login after some time
    categoriesObjects=session.query(Category)\
        .filter_by(user_id=current_user.id).all()
    return render_template('newCategoryItem.html',
                           categories=categoriesObjects,
                           login=login_session.get('username',0))


@app.route('/category/<int:category_id>/<int:item_id>/edit',
           methods=['GET','POST'])
@login_required
def editItemInCategory(category_id, item_id):
    """Updates a item in a category in database"""
    if request.method=="POST":
        if request.form['submit']== 'Edit':
            item_obj=session.query(CategoryItem).filter_by(id=item_id).first()
            print(item_obj)
            item_obj.name=request.form['name']
            item_obj.description=request.form['description']
            session.add(item_obj)
            session.commit()
            flash("you have successfully edited the item, now you can"
                  "go gor a walk")
            return redirect(url_for('index'))
        else :
            flash("It's good that sometimes, we don't edit stuff")
            redirect(url_for('index'))
    item_obj=session.query(CategoryItem).filter_by(id=item_id).first()
    return render_template('editCategoryItem.html',
                           login=True, item_obj=item_obj )


@app.route('/category/<int:category_id>/<int:item_id>/delete', methods=['GET','POST'])
@login_required
def deleteItemInCategory(category_id, item_id):
    """deletes a item in a category in database"""
    if request.method=='POST':
        if request.form['submit']== "Delete":
            item_obj=session.query(CategoryItem).filter_by(id=item_id).first()
            session.delete(item_obj)
            session.commit()
            flash("The CategoryItem Entry is Deleted, so be cool now.")
            return redirect(url_for('index'))
        else:
            return redirect(url_for('index'))
    item_obj=session.query(CategoryItem).filter_by(id=item_id).first()
    if item_obj.user_id==current_user.id:
        return render_template('DeleteCategoryItem.html',
                               item_object=item_obj,login=True)
    else:
        flash("You need to be owner of the Category to Delete it.")
        return redirect(url_for('index'))

#API endpoints

@app.route('/api/category')
def info_category_json():
    all_categories=session.query(Category).all()
    list_category=[]
    for category in all_categories:
        name=category.name
        id=category.id
        all_items_in_category=session.query(CategoryItem).filter_by(
            category_id=id
        ).all()
        item_list=[]
        for item in all_items_in_category:
            item_list.append(item.serialize)
        #using collection orderdict to get items from a dictionary in the
        # order they were inserted.
        d=collections.OrderedDict()
        d['name']=name
        d['id']=id
        d['items']=item_list
        list_category.append(d)
    return jsonify(category=list_category)

if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)