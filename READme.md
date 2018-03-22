# Udacity Catalog_Backend Project
## Necessary Steps:-
1. First run models.py to set up database and tables.
2. Second run application.py to start the server and to see how my application
    works
3. Go to localhost:5000 to do all these follow operation.(plase use domain name localhost otherwise google oauth will reject your request.)

## Routes for different operation:-

### CRUD operation on Category:-
1. HomePage:-"/" or "/category"
2. for new Category:- '/category/new'
3. For edit Category:-'/category/<int:category_id>/edit'
4. For delete Category:-'/category/<int:category_id>/delete'
5. Items in a category:-'/category/<int:category_id>'

### CRUD operation on Items in Category:-
1. item description:-'/category/<int:category_id>/<int:item_id>/'
2. new item in category:-"/category/<int:category_id>/new"
3. edit item in a category:-"/category/<int:category_id>/<int:item_id>/edit"
4. Delete item in a category:-"/category/<int:category_id>/<int:item_id>/delete"

### API endpoint for all the info of restaurant and details:-
1. route for api endpoint:-'/api/category'
