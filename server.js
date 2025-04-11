var express = require("express");
var path = require("path");
var logger = require("morgan");
var app = express();
var session = require("express-session");
var bodyParser = require("body-parser");

app.use(bodyParser.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "hbs");
app.locals.pretty = true;
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
	secret: 'secret key',
	resave: false,
	saveUninitialized: true,
	cookie: { secure: false }
}));

var routes = require("./routes/index");

app.use(routes.authenticate);
app.use(logger('dev'));

app.get('/', routes.index);
app.get('/index.html', routes.index);
app.get('/users', routes.users);
app.get('/api/books', routes.searchBooks);
app.get('/book/:id', routes.bookDetails);
app.post('/book/:id/review', routes.submitReview);

app.get('/register', routes.showRegistration);
app.post('/register', routes.registerUser);

app.get('/login', routes.login);
app.post('/login', routes.loginUser);
app.get('/logout', routes.logout);

// Start Server
app.listen(PORT, err => {
	if(err) {
		console.log(err);
	}
	else {
		console.log(`Server listening on port: ${PORT} CNTL:-C to stop`);
		console.log(`To Test:`);
		console.log('Admin User: admin Password: admin');
		console.log('http://localhost:3000/');
	}
});