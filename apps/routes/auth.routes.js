/* eslint-disable global-require */
module.exports = (app) => {
  const router = require("express").Router();
  const auth = require("../controller/auth.controller");

  // List of auth API routes
  router.post("/signup", auth.createNewAccount);
  router.post("/resend-verification-email", auth.resendVerification);
  router.post("/verifiy/:tokens", auth.verifyEmail);
  router.post("/login", auth.doLogin);
  router.post("/login-oauth", auth.doLoginOauth);
  router.post("/logout", auth.checkAuth, auth.doLogout);

  app.use("/", router);
};
