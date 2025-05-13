require("./utils.js");
require("dotenv").config();


const express = require("express");
const session = require("express-session");

// Initialize the app
const app = express();
app.set('view engine', 'ejs');

const Joi = require("joi");
const bcrypt = require("bcrypt");
const saltRounds = 12;
const MongoStore = require("connect-mongo");
const expireTime = 1 * 60 * 60 * 1000; // 1 hour

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include("databaseConnection");

const userCollection = database.db(mongodb_database).collection("users");

// Start the server
const PORT = process.env.PORT || 3000;

// MongoDB connection
var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  })
);

//middleware
app.use(express.static(__dirname + "/public"));
app.use(express.urlencoded({ extended: false }));
app.use(express.json());


function isAuthenticated(req, res, next) {
  if (req.session.authenticated) {
    return next();
  }
  res.redirect("/login");
}

// Routes
app.get("/", (req, res) => {

  res.render('index');
});


app.get("/nosql-injection", async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(
      `<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});

app.post("/submitEmail", (req, res) => {
  var email = req.body.email;
  if (!email) {
    res.redirect("/contact?missing=1");
  } else {
    res.send("Thanks for subscribing with your email: " + email);
  }
});

// sign up
app.get("/createUser", (req, res) => {
  res.render("createUser");
});

// login
app.get("/login", (req, res) => {
  const error = req.query.error;
  res.render("login", { error: error });
});

// logging in
app.post("/loggingin", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Joi validation schema for username and password
  const schema = Joi.object({
    username: Joi.string().max(50).required(),
    password: Joi.string().max(20).required()
  });
  const validationResult = schema.validate({ username, password });
  if (validationResult.error) {
    return res.redirect("/login?error=invalid");
  }


  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, name: 1, user_type: 1, _id: 1 })
    .toArray();

  if (result.length === 1 && await bcrypt.compare(password, result[0].password)) {
    // User authenticated successfully
    req.session.authenticated = true;
    req.session.username = username;
    req.session.name = result[0].name;
    req.session.user_type = result[0].user_type;
    console.log("SESSION AFTER LOGIN:", req.session);

    req.session.cookie.maxAge = expireTime;

    return res.redirect("/loggedIn");
  } else {
    return res.redirect("/login?error=invalid");
  }
});

// logged in page
app.get("/loggedIn", (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }

  res.render("loggedIn", { name: req.session.name });
});

// submit user
app.post("/submitUser", async (req, res) => {
  const { name, username, password } = req.body;

  // Validate name, username, and password
  const schema = Joi.object({
    name: Joi.string().min(1).required(), // Ensure name is not empty
    username: Joi.string().email().required(),
    password: Joi.string().max(20).required(),
  });

  const validationResult = schema.validate({ name, username, password });
  if (validationResult.error != null) {
    console.log(validationResult.error);
    return res.send(`
        <p style="color: red;">Invalid input: ${validationResult.error.message}</p>
        <a href="/createUser">Go back to sign-up page</a>
      `);
  }

  // Hash the password and insert the user into the database
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({
    name: name,
    username: username,
    password: hashedPassword,
    user_type: "user",
  });
  console.log("Inserted user");

  // Authenticate the user and redirect to members page
  req.session.authenticated = true;
  req.session.username = username;
  req.session.name = name; // Use the user's name for the session
  req.session.cookie.maxAge = expireTime;
  req.session.user_type = "user";

  res.redirect("/members");
});


// logout
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    res.clearCookie("connect.sid");
    res.redirect("/");
  });
});

app.get("/members", isAuthenticated, (req, res) => {
  const pics = [
    '<img src="/pillow1.jpg" style="width: 250px;" />',
    '<img src="/pillow2.jpg" style="width: 250px;" />',
    '<img src="/pillow3.jpg" style="width: 250px;" />',
  ];
  const randomPic = pics[Math.floor(Math.random() * pics.length)];

  res.render("members", { randomPic: randomPic });
});

// Middleware to check admin authorization
function isAdmin(req, res, next) {
  console.log("Checking admin middleware:");
  console.log("Session data:", req.session);
  if (req.session.authenticated && req.session.user_type === "admin") {
    console.log("✅ Admin access granted");
    return next();
  }
  console.log("❌ Admin access denied");
  res.status(403).send("Not authorized - Admins only");
}


// Admin page
app.get("/admin", isAuthenticated, isAdmin, async (req, res) => {
  const users = await userCollection.find().project({ username: 1, user_type: 1 }).toArray();
  res.render("admin", { users: users });
});

// Promote user to admin
app.get("/promote/:username", isAuthenticated, isAdmin, async (req, res) => {
  const username = req.params.username;

  // Validate username to prevent NoSQL injection
  const schema = Joi.string().email().required();
  const validationResult = schema.validate(username);
  if (validationResult.error) {
    return res.status(400).send("Invalid username");
  }

  await userCollection.updateOne(
    { username: username },
    { $set: { user_type: "admin" } }
  );

  res.redirect("/admin");
});

// Demote admin to regular user
app.get("/demote/:username", isAuthenticated, isAdmin, async (req, res) => {
  const username = req.params.username;

  // Validate username
  const schema = Joi.string().email().required();
  const validationResult = schema.validate(username);
  if (validationResult.error) {
    return res.status(400).send("Invalid username");
  }

  await userCollection.updateOne(
    { username: username },
    { $set: { user_type: "user" } }
  );

  res.redirect("/admin");
});



app.use((req, res, next) => {
  console.log('Handling a non-existent route:', req.originalUrl);  // Debugging line
  res.status(404).render("404");
});



app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
