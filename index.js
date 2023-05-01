
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

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        res.send("<form action='/signup' method='get'><button>Sign up</button></form><form action='/login' method='get'><button>Log in</button></form> ");
    } else {
        res.send("Hello, " + req.session.username + "<br/><form action='/members' method='get'><button>Go to Members area</button></form><form action ='/logout' method='get'><button>Log out</button></form>");

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
    var html = `
    create user
    <form action='/signupSubmit' method='post'>
    <input name='username' type='text' placeholder='username'><br/>
    <input name='email' type='text' placeholder='email'><br/>
    <input name='password' type='text' placeholder='password'><br/>
    <button>Sign Up</button>
    </form>
    `;
    res.send(html);
});

app.get('/login', (req, res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'><br/>
    <input name='password' type='password' placeholder='password'><br/>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
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
            res.send("Name is required.<br/> <br/><a href='/signup'>Try again</a>");
            return;
        }

        if (errorMessage.includes('"email"')) {
            res.send("Email is required.<br/><br/> <a href='/signup'>Try again</a>");
            return;
        }

        if (errorMessage.includes('"password"')) {
            res.send("Password is required.<br/><br/> <a href='/signup'>Try again</a>");
            return;
        }
       
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, email: email, password: hashedPassword });
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
        res.send("User not found.<br/><br/> <a href='/login'>Try again</a>");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ email: 1, password: 1, username: 1, _id: 1 }).toArray();

    console.log(result);

    if (result.length !=1) {
    	console.log("user not found");
    	res.send("User not found.<br/><br/> <a href='/login'>Try again</a>");
    	return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = result[0].username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }
    else {
        console.log("incorrect password");
        res.send("Invalid email/password combination.<br/><br/> <a href='/login'>Try again</a>");
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
    const rand = Math.floor(Math.random() * 3) + 1;

    var html = `
    <p style="font-size: 35px;"><b>Hello ${req.session.username}!</b></p>
    <img src='/cat${rand}.gif' style='width:250px;'><br/>
    <form action = '/logout' method='get'><button>Sign out</button></form>
    `;
    res.send(html);
    }
});


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
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 