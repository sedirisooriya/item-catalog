** Item Catalog **
==================
This project is a RESTful web application which uses Flask framework to access SQL database that lists categories and their items. OAuth2 provides authentication for further CRUD functionality on the application. Currently OAuth2 is implemented for Google Accounts.

Technologies Used:
==================
1). Python 3.5.2
2). HTML
3). Javascript
4). CSS
5). SQL
6). OAuth for Google
7). Flask Framework

Steps to setup the applicaation:
================================

1). Install Vagrant and Virtual Box to your PC.

2). Download/clone 'fullstack-nanodegree-vm' from 'https://github.com/udacity/fullstack-nanodegree-vm'

3). go to 'vagrant/catalog' folder inside the cloned vm and replace the contents of this repository.

Steps to launch project:
========================
1). Open bash or any command line editor and cd into the item-catalog folder

2). Provide 'vagrant up' followed by 'vagrant ssh' to make the VM up and running

3). To setup the database, run '$python3 databse_setup.py'

4). To add sample data, run '$pythn3 dummy_data.py'

5). To run the application, run '$python3 catalog.py'

6). To view the catalog on browser go to 'http://localhost:5000/'

Supporting JSON EndPoints:
==========================
1). Get All categories: "/catalog/json"

2). Get items from one category: "/category/<int:category_id>/items/json"

3). Get an item from a category: "/category/<int:category_id>/item/<int:item_id>/json"
