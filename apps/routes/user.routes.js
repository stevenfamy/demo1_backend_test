/* eslint-disable global-require */
module.exports = (app) => {
  const router = require("express").Router();
  const auth = require("../controller/auth.controller");
  const user = require("../controller/user.controller");

  // List of user API routes
  router
    .get("/profile", auth.checkAuth, user.getProfile)
    .put("/profile", auth.checkAuth, user.putProfile);

  app.use("/user", router);
};
