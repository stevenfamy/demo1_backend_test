/* eslint-disable global-require */
module.exports = (app) => {
  const router = require("express").Router();
  const auth = require("../controller/auth.controller");

  // List of auth API routes
  router.post("/signup", auth.createNewAccount);
  router.post("/resend-verification-email", auth.resendVerification);
  router.post("/verifiy/:tokens", auth.verifyEmail);

  app.use("/", router);
};
