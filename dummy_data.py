from database_setup import User, Base, Item, Category
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine


engine = create_engine('sqlite:///itemcatalog.db',
                       connect_args={'check_same_thread': False})

# Bind the above engine to a session.
Session = sessionmaker(bind=engine)

# Create a Session object.
session = Session()

user1 = User(
    name='Sammani',
    email='myemail@gmail.com',
    picture='https://img.com/sdf'
)

session.add(user1)
session.commit()

category1 = Category(
    name='Christmas Decos',
    user=user1
)

session.add(category1)
session.commit()

item1 = Item(
    name='Christmas Trees',
    description='A Christmas tree is a decorated tree, usually an evergreen conifer, such as a spruce, pine, or fir, or an artificial tree of similar appearance, associated with the celebration of Christmas.',
    category=category1,
    user=user1
)

item2 = Item(
    name='christmas candles',
    description='These festive, holiday-scented, decorative Christmas candles will make this season extra special!,
    category=category1,
    user=user1
)

session.add(item1)
session.add(item2)
session.commit()

print('Finished populating the database!')
