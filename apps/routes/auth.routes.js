/* eslint-disable global-require */
module.exports = (app) => {
  const router = require("express").Router();
  const auth = require("../controller/auth.controller");

  router.post("/signup", auth.createNewAccount);
  router.post("/resend-verification-email", auth.resendVerification);

  app.use("/", router);
};
