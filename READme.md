# Udacity Catalog_Backend Project part of Full Stack Web Developer Nanodegree.
## Necessary Steps:-
1. Install all the dependencies for this project with pip from requirement.txt file. by using this command:- $pip install -r requirements.txt
2. First run models.py to set up database and tables.use command:$python models.py
3. Second run application.py to start the server and to see how my application works.use command: $python models.py
4. Go to localhost:5000 to do all these follow operation.(plase use domain name localhost otherwise google oauth will reject your request.)

## Web routes for different operation:-

## CRUD operation on Category:-
1. first you need to visite HomePage of the website by going this endpoint:-"/" or "/category" example:localhost:5000/category
2. You need to first sign up or logged in to create a category and after that for insert items so for that go to end point "/signup" and "/login"
3. for new Category, If you want to add a new category go to end point:- '/category/new'
4. If you want to edit a category, go to end point:-'/category/<int:category_id>/edit'
5. If you want to delete a Category, go to this end point:-'/category/<int:category_id>/delete'
6. To see Items in a category, got to endpoint:-'/category/<int:category_id>'

## CRUD operation on Items in Category:-
1. To get item description of a item, go to this endpoint:-'/category/<int:category_id>/<int:item_id>/'
2. If you want to enter a new item in category, go to this endpoint:-"/category/<int:category_id>/new"
3. If you want to edit item in a category, Go to this endpoint:-"/category/<int:category_id>/<int:item_id>/edit"
4. If you want to Delete item in a category, then go to this endpoint:-"/category/<int:category_id>/<int:item_id>/delete"

## API endpoint for all the info of restaurant and details:-
### route for api endpoint:-
1. To get all the categories in the db use the end point '/api/category'
2. To get all the items in a category, use the end point '/api/<int:category_id>'
3. To get the information about a item in a category, use the end point '/api/<int:category_id>/<int:item_id>'
