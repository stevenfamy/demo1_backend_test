/* eslint-disable global-require */
module.exports = (app) => {
  const router = require("express").Router();
  const auth = require("../controller/auth.controller");
  const user = require("../controller/user.controller");

  // List of user API routes
  router
    .get("/profile", auth.checkAuth, user.getProfile)
    .put("/profile", auth.checkAuth, user.putProfile);

  router.post("/change-password", auth.checkAuth, user.changePassword);

  app.use("/user", router);
};
