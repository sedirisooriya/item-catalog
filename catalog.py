from flask import Flask, render_template, send_from_directory, request, redirect, jsonify, url_for

from sqlalchemy import create_engine, asc
from database_setup import Category, Item
from sqlalchemy.orm import sessionmaker

from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json

from functools import wraps
from utils import *
import logging


app = Flask(__name__)


def login_required(app_function):
    @wraps(app_function)
    def wrapper(*args, **kwargs):
        if 'username' in login_session:
            return app_function(*args, **kwargs)
        else:
            flash('You must be logged to add a new item.')
            return redirect('/login')
    return wrapper


@app.route('/login')
def show_login():
    """
    Create anti-forgery state token
    :return:
    """
    state = ''.join(
        random.choice(string.ascii_uppercase + string.digits) for x in
        range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def connect_to_google():
    """
    Connect to Google
    :return:
    """    
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data
    
    try:
        oauth_flow = flow_from_clientsecrets(
            'client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response1 = make_response(
            json.dumps('Failed while updating the authorization code.'), 401)
        response1.headers['Content-Type'] = 'application/json'
        return response1

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()
    result = json.loads((h.request(url, 'GET')[1]).decode())
            # For any error in the access token info, abort.
    if result.get('error') is not None:
        response2 = make_response(json.dumps(result.get('error')), 500)
        response2.headers['Content-Type'] = 'application/json'
       # Verification of the access token against user
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response3 = make_response(
        json.dumps("Token's user ID doesn't match given user ID."), 401)
        response3.headers['Content-Type'] = 'application/json'
        return response3
    # Verification of the access token against app
    if result['issued_to'] != CLIENT_ID:
     response4 = make_response(
        json.dumps("Token's client ID does not match app's."), 401)
     response4.headers['Content-Type'] = 'application/json'

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response5 = make_response(
            json.dumps('User already logged in.'),
            200)
        response5.headers['Content-Type'] = 'application/json'
    # Store the access token in the session for later use.  
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # See if the user exists. If it doesn't, make a new one.
    user_id = get_user_id(data["email"])
    if not user_id:
        user_id = create_user(login_session)
    login_session['user_id'] = user_id

    # Show a welcome screen upon successful login.
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'\
              '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'] % data)
    return output


@app.route('/gdisconnect')
def logout_the_user():
    """
    Logut the current user and reset its session
    :return:
    """
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('User not logged in.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']

        response = make_response(json.dumps('Logout Successful.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash("You have been successfully logged out!")
        return redirect('/')
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON APIs
@app.route('/category/<int:category_id>/items/json')
def get_catalog_items_json(category_id):
    """
    JSON API to get items from one category
    :param category_id:
    :return:
    """
    items = session.query(Item).filter_by(
        category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/category/<int:category_id>/item/<int:item_id>/json')
def get_item_json(category_id, item_id):
    """
    JSON API to get a particular item from a category
    :param category_id:
    :param item_id:
    :return:
    """
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(Item=item.serialize)


@app.route('/catalog/json')
def get_categories_json():
    """
    Get All categories
    :return:
    """
    categories = session.query(Category).all()
    return jsonify(categories=[r.serialize for r in categories])


@app.route('/')
@app.route('/catalog/categories')
def show_all_categories():
    """
    Show all Categories
    :return:
    """
    categories = session.query(Category).order_by(asc(Category.name))
    if 'username' not in login_session:
        return render_template('public_categories.html', categories=categories,
                               login=False)
    else:
        return render_template('categories.html', categories=categories,
                               login=True)


@app.route('/category/new/', methods=['GET', 'POST'])
@login_required
def create_new_category():
    """
    Create a new Category
    :return:
    """
    if request.method == 'POST':
        category = session.query(Category).\
            filter_by(name=request.form['name']).first()
        if category is not None:
            flash('The entered category already exists.')
            return redirect(url_for('add_category'))
        new_category = Category(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(new_category)
        flash('New Category %s Successfully Created' % new_category.name)
        session.commit()
        return redirect(url_for('show_all_categories'))
    else:
        return render_template('new_category.html', login=True)


@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    """
    Edit a Category
    :param category_id:
    :return:
    """
    edited_category = session.query(
        Category).filter_by(id=category_id).one()

    if edited_category.user_id != login_session['user_id']:
        return "<script>function createAlert() {alert('You are not " \
               "authorized to edit this category. " \
               "Please create your own category in order to edit.');" \
               "}</script><body onload='createAlert()''>"
    if request.method == 'POST':
        if request.form['name']:
            edited_category.name = request.form['name']
            flash('Category Successfully Edited %s' % edited_category.name)
            return redirect(url_for('show_all_categories'))
    else:
        return render_template('edit_category.html', category=edited_category,
                               login=True)


@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
@login_required
def delete_category(category_id):
    """
    Delete a Category
    :param category_id:
    :return:
    """
    category_to_delete = session.query(
        Category).filter_by(id=category_id).one()

    if category_to_delete.user_id != login_session['user_id']:
        return "<script>function createAlert() {alert('You are not " \
               "authorized to delete this category. " \
               "Please create your own category in order to delete.');}" \
               "</script><body onload='createAlert()''>"
    if request.method == 'POST':
        session.delete(category_to_delete)
        flash('%s Deleted successfuly: ' % category_to_delete.name)
        session.commit()
        return redirect(
            url_for('show_all_categories', category_id=category_id))
    else:
        return render_template('delete_category.html',
                               category=category_to_delete, login=True)


@app.route('/catalog/<int:category_id>/')
@app.route('/catalog/<int:category_id>/items/')
def show_catalog_items_by_category(category_id):
    """
    Show Catalog items from category
    :param category_id:
    :return:
    """
    category = session.query(Category).filter_by(id=category_id).one()
    creator = get_user_details(category.user_id)
    items = session.query(Item).filter_by(category_id=category_id).all()
    if 'username' not in login_session:
        return render_template('public_items.html', items=items,
                               category=category, creator=creator, login=False,
                               editable=False)
    elif creator.id != login_session['user_id']:
        return render_template('items.html', items=items, category=category,
                               creator=creator, login=True,
                               editable=False)
    else:
        return render_template('items.html', items=items, category=category,
                               creator=creator, login=True, editable=True)


@app.route('/category/<int:category_id>/item/new/', methods=['GET', 'POST'])
@login_required
def create_new_item(category_id):
    """
    Create a new item in a category
    :param category_id:
    :return:
    """
    category = session.query(Category).filter_by(id=category_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function createAlert() {alert('You are not " \
               "authorized to add items to this category. " \
               "Please create your own category in order to add items.');}" \
               "</script><body onload='createAlert()''>"
    if request.method == 'POST':
        new_item = Item(name=request.form['name'],
                        description=request.form['description'],
                        category_id=category_id,
                        user_id=category.user_id)
        session.add(new_item)
        session.commit()
        flash('New %s Item Successfully Created' % new_item.name)
        return redirect(
            url_for('show_catalog_items_by_category', category_id=category_id))
    else:
        return render_template('new_item.html', category_id=category_id,
                               login=True)


@app.route('/category/<int:category_id>/item/<int:item_id>/edit',
           methods=['GET', 'POST'])
@login_required
def edit_item(category_id, item_id):
    """
    Edit an Item from a category
    :param category_id:
    :param item_id:
    :return:
    """
    edited_item = session.query(Item).filter_by(id=item_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function createAlert() {alert('You are not " \
               "authorized to edit items to this category. " \
               "Please create your own category in order to edit items.');}" \
               "</script><body onload='createAlert()''>"
    if request.method == 'POST':
        if request.form['name']:
            edited_item.name = request.form['name']
        if request.form['description']:
            edited_item.description = request.form['description']
        session.add(edited_item)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(
            url_for('show_catalog_items_by_category', category_id=category_id))
    else:
        return render_template('edit_item.html', category_id=category_id,
                               item_id=item_id, item=edited_item, login=True,
                               editable=True)


@app.route('/category/<int:category_id>/item/<int:item_id>/delete',
           methods=['GET', 'POST'])
@login_required
def delete_item(category_id, item_id):
    """
    Delete an item
    :param category_id:
    :param item_id:
    :return:
    """
    category = session.query(Category).filter_by(id=category_id).one()
    to_delete = session.query(Item).filter_by(id=item_id).one()
    if login_session['user_id'] != category.user_id:
        return "<script>function createAlert() {alert('You are not " \
               "authorized to delete items to this category. " \
               "Please create your own category in order to delete items.')" \
               ";}</script><body onload='createAlert()''>"
    if request.method == 'POST':
        session.delete(to_delete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(
            url_for('show_catalog_items_by_category', category_id=category_id))
    else:
        return render_template('delete_item.html', item=to_delete, login=True,
                               editable=True)


if __name__ == '__main__':
    app.secret_key = 'udacity item catalog'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
