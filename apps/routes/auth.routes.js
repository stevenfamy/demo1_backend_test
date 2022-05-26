/* eslint-disable global-require */
module.exports = (app) => {
  const router = require("express").Router();
  const auth = require("../controller/auth.controller");

  /**
   * @swagger
   * tags:
   *  name: Authentication
   *  description: Authentication API
   *
   */

  /**
   * @swagger
   * /signup:
   *  post:
   *    summary: Sign-up or Create new account using Email Address
   *    tags: [Authentication]
   *    requestBody:
   *      required: true
   *      content:
   *        application/json:
   *            schema:
   *                type: object
   *                properties:
   *                    email:
   *                        type: string
   *                    password:
   *                        type: string
   *                    firstName:
   *                        type: string
   *                    lastName:
   *                        type: string
   *                required:
   *                    - email
   *                    - password
   *                    - firstName
   *                    - lastName
   *                example:
   *                    email: steve.mailme@gmail.com
   *                    password: "aaaBBB!1"
   *                    firstName: "Steven"
   *                    lastName: "Famy"
   *    responses:
   *      200:
   *        description: Sign-up success
   *      400:
   *        description: Email already registered or Password validation failed
   *      500:
   *        description: Server Error
   *
   */
  router.post("/signup", auth.createNewAccount);

  /**
   * @swagger
   * /resend-verification-email:
   *  post:
   *    summary: API to ask server to resend the Account verification email if the user haven't verified his email.
   *    tags: [Authentication]
   *    requestBody:
   *      required: true
   *      content:
   *        application/json:
   *            schema:
   *                type: object
   *                properties:
   *                    email:
   *                        type: string
   *                required:
   *                    - email
   *                example:
   *                    email: steve.mailme@gmail.com
   *    responses:
   *      200:
   *        description: Success resend verification email
   *      400:
   *        description: User already verified or No previous verification email found
   *      404:
   *        description: Account not found!
   *
   */
  router.post("/resend-verification-email", auth.resendVerification);

  /**
   * @swagger
   * /verifiy/{token}:
   *  post:
   *    summary: API to verified email address using supplied token
   *    tags: [Authentication]
   *    parameters:
   *      - in: path
   *        name: token
   *        schema:
   *          type: string
   *        required: true
   *        description: Tokens supplied by the server via email to verified the account
   *    responses:
   *      200:
   *        description: Success verified the account; return authToken
   *      400:
   *        description: Invalid Tokens!
   *      500:
   *        description: Something Wrong, please try again!
   *
   */
  router.post("/verifiy/:tokens", auth.verifyEmail);

  /**
   * @swagger
   * /login:
   *  post:
   *    summary: Login with Email Address & Password
   *    tags: [Authentication]
   *    requestBody:
   *      required: true
   *      content:
   *        application/json:
   *            schema:
   *                type: object
   *                properties:
   *                    email:
   *                        type: string
   *                    password:
   *                        type: string
   *                required:
   *                    - email
   *                    - password
   *                example:
   *                    email: steve.mailme@gmail.com
   *                    password: "aaaBBB!1"
   *    responses:
   *      200:
   *        description: Login success; return authToken
   *      400:
   *        description: Password Account not match! or Email address & Password is required or Haven't verified your email account! or Account not active!
   *      404:
   *        description: Account not found
   *      500:
   *        description: Login Failed!, please try again
   *
   */
  router.post("/login", auth.doLogin);

  /**
   * @swagger
   * /login-oauth:
   *  post:
   *    summary: Login using Google or Facebook OAuth service
   *    tags: [Authentication]
   *    requestBody:
   *      required: true
   *      content:
   *        application/json:
   *            schema:
   *                type: object
   *                properties:
   *                    type:
   *                        type: string
   *                        description: Should be the OAuth type either "Google" or "Facebook"
   *                    jwtToken:
   *                        type: string
   *                        description: Google or Facebook supplied accessToken or credentialToken
   *                required:
   *                    - type
   *                    - jwtToken
   *                example:
   *                    type: Facebook
   *                    jwtToken: "EAAIPQeQZBjOsBANtNI0qXXlslD2NxK0Rynl5AWo8dwBZA1LaQ5XGZCsBVrUbzJRK5SMYIxEivDQOOZBqxtrFSZAFTSQ0Lz60NGYBftDse7gHDTaHUEdugLn5Wh4D6ZCSD56RVAFDzm7ZBhLA1jOIZBo0vGn8ZB9SlqdgqihW1SirPrbAAZCZAjerpXIrXLf9qHZAjcGLyIVEZBJtZAclnxCDbGXI0y"
   *    responses:
   *      200:
   *        description: Login success; return authToken
   *      400:
   *        description: Bad Request; because supplied token invalid
   *      500:
   *        description: Login Failed!, please try again
   *
   */
  router.post("/login-oauth", auth.doLoginOauth);

  /**
   * @swagger
   * /logout:
   *  post:
   *    summary: Logout from current sessions
   *    tags: [Authentication]
   *    parameters:
   *     - in: header
   *       name: authToken
   *       description: Get the authToken from result after success login
   *       schema:
   *        type: string
   *        format: jwt
   *       required: true
   *    responses:
   *      200:
   *        description: Logout success
   *      400:
   *        description: Bad Request; wrong jwt format
   *      401:
   *        description: Access Denied, authToken not found! or Unauthorized
   *      500:
   *        description: Server error
   *
   */
  router.post("/logout", auth.checkAuth, auth.doLogout);

  app.use("/", router);
};
