var url = require("url");
var sqlite3 = require("sqlite3").verbose(); // Verbose for more detailed stack trace
var db = new sqlite3.Database("data/bookclub.db"); // Database of users and reviews
var fetch = require("node-fetch");

// Initializes Tables and Admin User
db.serialize(function(){
	// User Table
	db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT DEFAULT 'guest')`);

	// Create Admin
	db.run(`INSERT OR REPLACE INTO users (username, password, role) VALUES ('admin', 'admin', 'admin')`);
    
	// Book Table
	db.run(`CREATE TABLE IF NOT EXISTS books (id INTEGER PRIMARY KEY AUTOINCREMENT, googleID TEXT, title TEXT NOT NULL, author TEXT, cover TEXT)`);

	// Reviews Table
	db.run(`CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, userID INTEGER NOT NULL, bookID INTEGER NOT NULL, rating INTEGER CHECK (rating BETWEEN 1 AND 5), 
		comment TEXT, createdAt DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(userID) REFERENCES users(id), FOREIGN KEY(bookID) REFERENCES books(id))`);
});

// Middleware for Basic http 401 Authentication
exports.authenticate = function(request, response, next) {

	if (request.path === "/login" || request.path === "/register") {
        return next();
    }

	let auth = request.headers.authorization

	if (!auth) {
		if (!request.session || !request.session.user) {
			return response.redirect("/login");
		} else {
			request.user = request.session.user;
			request.user_role = request.session.user.role;
			return next();
		}
	} else {
		console.log("Authorization Header: " + auth)
		var tmp = auth.split(' ')
		var buf = Buffer.from(tmp[1], "base64");
		var plain_auth = buf.toString()
		console.log("Decoded Authorization ", plain_auth)
		var credentials = plain_auth.split(':')
		var username = credentials[0]
		var password = credentials[1]
		console.log("User: ", username)
		console.log("Password: ", password)
  
	  	var authorized = false
	  	db.all("SELECT id, username, password, role FROM users", function(err, rows) {
			for (var i = 0; i < rows.length; i++) {
				if (rows[i].username == username && rows[i].password == password) {
					authorized = true;
					retrieved_user_role = rows[i].role;
					request.user = {
						id: rows[i].id,
						username: rows[i].username,
						role: rows[i].role
					};
				}
			}
			if (authorized == false) {
				response.setHeader('WWW-Authenticate", "Basic realm="need to login"')
				response.writeHead(401, {'Content-Type': 'text/html'})
				response.end()
			} 
			request.user_role = retrieved_user_role;
			next();
		})
	}	  
}

// Function for when /users is called
exports.users = function(request, response) {
	console.log("USER ROLE: " + request.user_role)
	if (request.user_role !== 'admin') {
		response.writeHead(403, {'Content-Type': 'text/html'});
		return response.end('<h1>ERROR: Admin Privileges Required To See Users</h1>');
	}
	db.all("SELECT id, username, role FROM users", function(err, rows) {
		response.render('users', {title : 'Users:', userEntries: rows})
	})
}

exports.login = function(request, response) {
	response.render('login', { 
		title: 'Login',
		error: request.query.error 
	});
};

// Login user
exports.loginUser = function(request, response) {
	const { username, password } = request.body;
		
	db.get("SELECT id, username, password, role FROM users WHERE username = ?", [username], function(err, user) {
		if (err || !user || user.password !== password) {
			return;
		}
			
		request.session.user = {
			id: user.id,
			username: user.username,
			role: user.role
		};
		response.redirect('/');
	});
};

exports.logout = function(request, response) {
	request.session.destroy(err => {
		if (err) {
			return;
		}
		response.redirect('/login');
	});
};

exports.showRegistration = function(request, response) {
	response.render('register', { title: 'Register' });
};

// Register new user
exports.registerUser = function(request, response) {
	const {username, password} = request.body;
		
	if(!username || !password) {
		return response.status(400).render('register', { 
			error: 'Username and password required',
			title: 'Register'
		});
	}

	db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, password],
		function(err) {
			if(err) {
				return response.status(400).render('register', { 
					error: 'Username already exists',
					title: 'Register'
				});
			}
			response.redirect('/');
		}
	);
};

// Homepage with book search option
exports.index = function(request, response) {
	db.all("SELECT * FROM books ORDER BY id DESC LIMIT 12", function(err, books) {
		response.render('index', { 
			title: 'Book Club',
			user: request.user,
		});
	});
};

// Book search submission
exports.searchBooks = function(request, response) {
	var urlObj = url.parse(request.url, true);
	var query = urlObj.query.q;

	if (!query) {
		return;
	}

	var encoded = encodeURIComponent(query);

	fetch(`https://www.googleapis.com/books/v1/volumes?q=${encoded}`)
		.then(response => response.json())
		.then(data => {
			const books = data.items.map(book => ({
				googleID: book.id,
				title: book.volumeInfo.title || 'No title',
				author: book.volumeInfo.authors ? book.volumeInfo.authors.join(', ') : 'Unknown author',
				cover: book.volumeInfo.imageLinks?.thumbnail || ''
		}));

		books.forEach(book => db.prepare(`INSERT OR IGNORE INTO books (googleID, title, author, cover) VALUES (?, ?, ?, ?)`)
			.run([book.googleID, book.title, book.author, book.cover]).finalize());
		response.json(books);
	})
	.catch(error => {
		console.error("Search failed:", error);
		response.status(500).json({
			error: "Failed to search books",
			details: error.message
		});
	});
}

// Book details and reviews
exports.bookDetails = function(request, response) {
	var bookId = request.params.id;
	console.log("Looking for book with ID:", bookId); 
		
	db.get("SELECT * FROM books WHERE id = ? OR googleID = ?", [bookId, bookId], function(err, book) {
		
		if (err) {
			return;
		}
				
		if (!book) {
			console.log("No book found with ID:", bookId);
			return response.status(404).render('error', {message: "Book not found"});
		}
				
		db.all(`SELECT r.id, r.rating, r.comment, r.createdAt, u.username FROM reviews r JOIN users u ON r.userID = u.id WHERE r.bookID = ? ORDER BY r.createdAt DESC`,[book.id],
			function(err, reviews) {
				if (err) {
					console.error("Error fetching reviews:", err);
					return response.status(500).render('error', {message: "Error fetching reviews"});
				}
						
				response.render('book', {
					title: book.title,
					book: book,
					reviews: reviews || [],
					user: request.user
				});
			}
		);
	});
};

// Submit review
exports.submitReview = function(request, response) {
	if (!request.user) {
		return response.status(401).json({ error: "Unauthorized" });
	}

	const bookId = request.params.id;
	const { rating, comment } = request.body;

	if (!rating || !comment) {
		return response.status(400).json({ error: "Rating and comment are required" });
	}

	db.run(
		"INSERT INTO reviews (userID, bookID, rating, comment) VALUES (?, ?, ?, ?)", [request.user.id, bookId, rating, comment],
		function(err) {
			if (err) {
				return;
			}
			response.redirect(`/book/${bookId}`);
		}
	);
};

const hbs = require("hbs");

// Handlebar helpers
hbs.registerHelper('eq', function(a, b, options) {
    return a === b ? options.fn(this) : options.inverse(this);
});

hbs.registerHelper('formatDate', function(date) {
    return new Date(date).toLocaleString();
});
