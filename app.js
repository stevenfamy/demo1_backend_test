require("dotenv").config();
const express = require("express");
const cors = require("cors");

const app = express();
const PORT = 5000;

app.use(
  cors({
    origin: "*",
    methods: "*",
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Load the routes file
require("./apps/routes/auth.routes")(app);

const server = app.listen(PORT);
console.log(`Server started at port ${PORT}`);
module.exports = { app, server };
