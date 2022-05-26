require("dotenv").config();
const express = require("express");
const cors = require("cors");

const swaggerJsDoc = require("swagger-jsdoc");
const swaggerUI = require("swagger-ui-express");

const app = express();
const PORT = 5000;

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Authentication & User API (AHA TEST)",
      version: "0.0.1",
      description: "Details on the API for authentication and user operations",
    },
    servers: [
      {
        url: process.env.BACKEND_URL,
      },
    ],
  },
  apis: ["./apps/routes/*.js"],
};

const specs = swaggerJsDoc(options);

app.use(
  cors({
    origin: "*",
    methods: "*",
  })
);

app.use("/api-docs", swaggerUI.serve, swaggerUI.setup(specs));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Load the routes file
require("./apps/routes/auth.routes")(app);
require("./apps/routes/user.routes")(app);

const server = app.listen(PORT);
console.log(`Server started at port ${PORT}`);
module.exports = { app, server };
