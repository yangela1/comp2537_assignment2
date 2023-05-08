
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

const { ObjectId } = require('mongodb');


const expireTime = 60 * 60 * 1000; //expires after 1 hr (minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}


app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        res.render("index", {username: ""});
    } else {
        res.render("index", {username: req.session.username});

    }


});


app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req, res) => {
    var color = req.query.color;

    res.send("<h1 style='color:" + color + ";'>Angela Yu</h1>");
});

app.get('/contact', (req, res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req, res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: " + email);
    }
});


app.get('/signup', (req, res) => {
   res.render("signup", {errorMessage: ""});
});

app.get('/login', (req, res) => {
    res.render("login", {errorMessage: ""});
});


app.post('/signupSubmit', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().required(),
            password: Joi.string().required(),

        });

    const validationResult = schema.validate({ username, password, email });

    if (validationResult.error != null) {
        const errorMessage = validationResult.error.message;
        //look at terminal to see error message
        console.log(validationResult.error);

        if (errorMessage.includes('"username"')) {
            const errorMessage = 'Name is required';
            res.render("signup", {errorMessage: errorMessage});
            // res.send("Name is required.<br/> <br/><a href='/signup'>Try again</a>");
            return;
        }

        if (errorMessage.includes('"email"')) {
            const errorMessage = 'Email is required.';
            res.render("signup", {errorMessage: errorMessage});
            // res.send("Email is required.<br/><br/> <a href='/signup'>Try again</a>");
            return;
        }

        if (errorMessage.includes('"password"')) {
            const errorMessage = 'Password is required.';
            res.render("signup", {errorMessage: errorMessage});
            // res.send("Password is required.<br/><br/> <a href='/signup'>Try again</a>");
            return;
        }
       
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, email: email, password: hashedPassword, user_type: 'user'});
    console.log("Inserted user");

    //create a session and redirect to members page
    req.session.user = {
        username: username,
        email: email,
    };
    
    //sets authentication to true 
    req.session.authenticated = true;

    //sets their username
    req.session.username = username;
   
    res.redirect('/members');

});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;


    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(email, password);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        const errorMessage = 'User not found.';
        res.render('login', {errorMessage: errorMessage});
        return;
    }

    const result = await userCollection.find({ email: email }).project({ email: 1, password: 1, username: 1, _id: 1, user_type: 1, }).toArray();

    console.log(result);

    if (result.length !=1) {
    	console.log("user not found");
        const errorMessage = 'User not found.';
        res.render('login', {errorMessage: errorMessage});
    	return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = result[0].username;
        req.session.cookie.maxAge = expireTime;
        req.session.user_type = result[0].user_type;

        res.redirect('/members');
        return;
    }
    else {
        console.log("incorrect password");
        const errorMessage = 'Invalid email/password combination.';
        res.render('login', {errorMessage: errorMessage});
        return;
    }
});


app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        console.log("no user");
        res.redirect('/');
    }
    else{

    //randomly picks number between 1 and 3  
    // const rand = Math.floor(Math.random() * 3) + 1;
    res.render("cats", {username: req.session.username});
    }
});

app.get('/admin', sessionValidation, adminAuthorization, async (req,res) => {
    const users = await userCollection.find().project({username: 1, _id: 1, user_type: 1}).toArray();
    res.render('admin', {users: users});
});

app.post('/promoteUser', async (req, res) => {
    const userId = req.body.userID;
    const user = await userCollection.findOne({ _id: ObjectId(userId) });
 
    await userCollection.updateOne({ _id: ObjectId(userId)}, { $set: { user_type: 'admin' } });
    console.log("promoted to admin");
    console.log(user);
    res.redirect('/admin');
    
});

app.post('/demoteUser', async (req, res) => {
    const userId = req.body.userID;
    const user = await userCollection.findOne({_id: ObjectId(userId)});

    await userCollection.updateOne({_id:ObjectId(userId)}, { $set: { user_type: 'user' }});
    console.log("demoted to user");
    console.log(user);
    res.redirect('/admin');
    
})
         

app.get('/cat/:id', (req, res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("Fluffy: <img src='/cat1.gif' style='width:250px;'>");
    }
    else if (cat == 2) {
        res.send("Socks: <img src='/cat2.gif' style='width:250px;'>");
    }
    else if (cat == 3) {
        res.send("Meow: <img src='/cat3.gif' style='width:250px;'>");
    }
    else {
        res.send("Invalid cat id: " + cat);
    }
});


app.get('/logout', (req, res) => {
    req.session.destroy();
    console.log("user logged out");
    res.redirect('/');
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 