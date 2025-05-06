require("./utils.js");
require("dotenv").config();

const express = require("express");
const session = require("express-session");

// Initialize the app
const app = express();

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

// Middleware to check authentication
function isAuthenticated(req, res, next) {
  if (req.session.authenticated) {
    return next();
  }
  res.redirect("/login");
}

// Routes
app.get("/", (req, res) => {
  let html = `
    <form action = '/login' method='get'>
        <button>login</button>
    </form>
    <form action = '/createUser' method='get'>
        <button>sign Up</button>
    </form>
    `;

  res.send(html);
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
  var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='name' type='text' placeholder='name'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
  res.send(html);
});

// login
app.get("/login", (req, res) => {
  const error = req.query.error;
  let html = `
      <h2>Log in</h2>
      <form action='/loggingin' method='post'>
        <input name='username' type='text' placeholder='username'>
        <input name='password' type='password' placeholder='password'>
        <button>Submit</button>
      </form>
    `;

  if (error === "invalid") {
    html += "<p style='color:red;'>Invalid username or password.</p>";
  }

  res.send(html);
});

// logging in
app.post("/loggingin", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  const schema = Joi.string().max(50).required();
  const validationResult = schema.validate(username);
  if (validationResult.error != null) {
    return res.redirect("/login?error=invalid");
  }


  const result = await userCollection
    .find({ username: username })
    .project({ username: 1, password: 1, name: 1, _id: 1 })
    .toArray();

  if (result.length !== 1) {
    console.log("user not found");
    return res.redirect("/login?error=invalid");
  }

  if (await bcrypt.compare(password, result[0].password)) {
    req.session.authenticated = true;
    req.session.username = username;
    req.session.name = result[0].name; // Set the user's name in the session
    req.session.cookie.maxAge = expireTime;

    return res.redirect("/loggedIn");
  } else {
    console.log("incorrect password");
    return res.redirect("/login?error=invalid");
  }
});

// logged in page
app.get("/loggedIn", (req, res) => {
  if (!req.session.authenticated) {
    return res.redirect("/login");
  }

  let html = `
      <h1>Hello ${req.session.name}</h1>
      <form action='/members' method='get'>
      <button>Go to Members Area</button>
      </form>
      <form action='/logout' method='get'>
      <button>Logout</button>`;

  res.send(html); // ← Send the HTML back
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
    });
    console.log("Inserted user");
  
    // Authenticate the user and redirect to members page
    req.session.authenticated = true;
    req.session.username = username;
    req.session.name = name; // Use the user's name for the session
    req.session.cookie.maxAge = expireTime;
  
    res.redirect("/members");
  });
  

// logout
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.status(500).send("An error occurred while logging out.");
    }
    res.clearCookie("connect.sid"); // Clear the session cookie
    res.redirect("/");
  });
});

app.get("/members/:id", isAuthenticated, (req, res) => {
    const cat = req.params.id;
    let html = "";
  
    if (cat == 1) {
      html += 'cat 1: <img src="/pillow1.jpg" style="width: 250px;" />';
    } else if (cat == 2) {
      html += 'cat 2: <img src="/pillow2.jpg" style="width: 250px;" />';
    } else if (cat == 3) {
      html += 'cat 3: <img src="/pillow3.jpg" style="width: 250px;" />';
    } else {
      html += "invalid cat id: " + cat;
    }
  
    html += `
        <form action='/logout' method='get'>
          <button>Sign Out</button>
        </form>
      `;
  
    res.send(html);
  });

app.get("/members", isAuthenticated, (req, res) => {
  const gifs = [
    '<img src="/pillow1.jpg" style="width: 250px;" />',
    '<img src="/pillow2.jpg" style="width: 250px;" />',
    '<img src="/pillow3.jpg" style="width: 250px;" />',
  ];
  const randomGif = gifs[Math.floor(Math.random() * gifs.length)];

  let html = `
    ${randomGif}
    <form action='/logout' method='get'>
      <button>Sign Out</button>
    </form>
  `;

  res.send(html);
});

app.use((req, res) => {
  res.status(404).send("404: Page not found");
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
