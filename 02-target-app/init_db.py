import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'travelbird.db')

def init():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('DROP TABLE IF EXISTS users')
    c.execute('DROP TABLE IF EXISTS packages')
    c.execute('DROP TABLE IF EXISTS bookings')
    c.execute('DROP TABLE IF EXISTS reviews')

    # users table - yeah storing plaintext passwords, will fix later
    c.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        fullname TEXT,
        phone TEXT,
        role TEXT DEFAULT 'user'
    )''')

    # holiday packages
    c.execute('''CREATE TABLE packages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        destination TEXT,
        description TEXT,
        price REAL,
        duration_days INTEGER,
        image_url TEXT
    )''')

    c.execute('''CREATE TABLE bookings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        package_id INTEGER,
        booking_date TEXT,
        status TEXT DEFAULT 'confirmed'
    )''')

    c.execute('''CREATE TABLE reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        package_id INTEGER,
        content TEXT,
        rating INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # seed users
    users = [
        ('admin', 'admin123', 'admin@travelbird.com', 'Admin User', '+31612345678', 'admin'),
        ('john', 'password', 'john@example.com', 'John de Vries', '+31687654321', 'user'),
        ('sarah', 'sarah2024', 'sarah@example.com', 'Sarah Johnson', '+44771234567', 'user'),
        ('mike', 'travel99', 'mike@example.com', 'Mike Chen', '+1555123456', 'user'),
        ('emma', 'emma_pass', 'emma@example.com', 'Emma Williams', '+49151789012', 'user'),
        ('lucas', 'qwerty', 'lucas@example.com', 'Lucas Mueller', '+49170345678', 'user'),
    ]
    c.executemany('INSERT INTO users (username, password, email, fullname, phone, role) VALUES (?,?,?,?,?,?)', users)

    # seed packages
    packages = [
        ('Bali Paradise Retreat', 'Bali, Indonesia', 'Experience the magic of Bali with luxury villas, rice terraces, and ancient temples. Includes airport transfer and daily breakfast.', 1299.00, 10, '/static/placeholder.jpg'),
        ('Greek Island Hopper', 'Santorini & Mykonos, Greece', 'Island hop through the best of Greece. White-washed buildings, crystal clear water, amazing nightlife.', 1599.00, 8, '/static/placeholder.jpg'),
        ('Tokyo City Break', 'Tokyo, Japan', 'Explore the neon-lit streets of Shibuya, traditional temples, and incredible street food scene.', 1899.00, 7, '/static/placeholder.jpg'),
        ('Safari Adventure', 'Serengeti, Tanzania', 'Witness the great migration up close. All-inclusive safari lodge with game drives twice daily.', 2499.00, 6, '/static/placeholder.jpg'),
        ('Northern Lights Chase', 'Tromsø, Norway', 'Chase the aurora borealis from a cozy glass igloo. Includes husky sledding and fjord cruise.', 1799.00, 5, '/static/placeholder.jpg'),
        ('Amalfi Coast Dream', 'Amalfi, Italy', 'Drive the stunning coastal roads, eat fresh pasta, drink limoncello. La dolce vita at its finest.', 1399.00, 7, '/static/placeholder.jpg'),
        ('Machu Picchu Trek', 'Cusco, Peru', 'Hike the Inca Trail to the ancient citadel. Includes guide, camping gear, and meals on trek.', 1199.00, 9, '/static/placeholder.jpg'),
        ('Maldives Overwater Villa', 'Malé, Maldives', 'Ultimate luxury in an overwater bungalow. Snorkeling, spa treatments, and sunset dolphin cruises.', 3299.00, 6, '/static/placeholder.jpg'),
        ('Iceland Ring Road', 'Reykjavik, Iceland', 'Self-drive adventure around the entire island. Waterfalls, geysers, volcanic landscapes, hot springs.', 1649.00, 10, '/static/placeholder.jpg'),
        ('Marrakech Medina', 'Marrakech, Morocco', 'Get lost in the souks, stay in a traditional riad, ride camels in the Sahara.', 899.00, 5, '/static/placeholder.jpg'),
        ('Patagonia Explorer', 'Torres del Paine, Chile', 'Hike among glaciers and granite towers in one of the worlds last wild places.', 2199.00, 12, '/static/placeholder.jpg'),
        ('Vietnam by Motorbike', 'Hanoi to Ho Chi Minh', 'Ride the length of Vietnam. Street food, karst mountains, rice paddies, and hidden beaches.', 999.00, 14, '/static/placeholder.jpg'),
    ]
    c.executemany('INSERT INTO packages (name, destination, description, price, duration_days, image_url) VALUES (?,?,?,?,?,?)', packages)

    # seed some reviews
    reviews = [
        (2, 1, 'Amazing trip, Bali was incredible. The villa had a private pool and the staff were so friendly.', 5),
        (3, 2, 'Santorini sunsets are even better in person. Mykonos nightlife was a bit too crazy for me though.', 4),
        (4, 3, 'Tokyo blew my mind. The food alone is worth the trip. Tsukiji market at 5am was unforgettable.', 5),
        (5, 6, 'Amalfi coast is beautiful but so crowded in August. Go in shoulder season if you can.', 3),
        (2, 4, 'Saw a leopard on the first day. Guide was incredibly knowledgeable about the wildlife.', 5),
        (6, 10, 'Marrakech is sensory overload in the best way. The riad we stayed in was gorgeous.', 4),
        (3, 7, 'The Inca Trail was tough but so worth it. Seeing Machu Picchu at sunrise was emotional.', 5),
        (4, 5, 'We didnt see the northern lights due to clouds but the husky sledding made up for it.', 3),
    ]
    c.executemany('INSERT INTO reviews (user_id, package_id, content, rating, created_at) VALUES (?,?,?,?, datetime("now"))', reviews)

    conn.commit()
    conn.close()
    print('database initialized')

if __name__ == '__main__':
    init()
