/* eslint-disable global-require */
module.exports = (app) => {
  const router = require("express").Router();
  const auth = require("../controller/auth.controller");
  const user = require("../controller/user.controller");

  // List of user API routes

  /**
   * @swagger
   * tags:
   *  - name: My Profile
   *    description: My Profile API
   *  - name: Password
   *    description: Password API
   *  - name: User Management
   *    description: User Management API
   *
   */

  /**
   * @swagger
   * /user/profile:
   *  get:
   *    summary: API to Get user own profile data
   *    tags: [My Profile]
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
   *        description: Success; return userProfile
   *      400:
   *        description: Bad Request; wrong jwt format
   *      401:
   *        description: Access Denied, authToken not found! or Unauthorized
   *
   */

  /**
   * @swagger
   * /user/profile:
   *  put:
   *    summary: API to Update user own profile
   *    tags: [My Profile]
   *    parameters:
   *     - in: header
   *       name: authToken
   *       description: Get the authToken from result after success login
   *       schema:
   *        type: string
   *        format: jwt
   *       required: true
   *    requestBody:
   *      required: true
   *      content:
   *        application/json:
   *            schema:
   *                type: object
   *                properties:
   *                    firstName:
   *                        type: string
   *                    lastName:
   *                        type: string
   *                required:
   *                    - firstName
   *                    - lastName
   *                example:
   *                    firstName: "Steven"
   *                    lastName: "Famy"
   *    responses:
   *      200:
   *        description: OK; Profile update success
   *      400:
   *        description: Bad Request; wrong jwt format or First Name & Last Name is required!
   *      401:
   *        description: Access Denied, authToken not found! or Unauthorized
   */
  router
    .get("/profile", auth.checkAuth, user.getProfile)
    .put("/profile", auth.checkAuth, user.putProfile);

  /**
   * @swagger
   * /user/has-password:
   *  get:
   *    summary: API to check if user has password, if login/signup using oauth account doesn't has password
   *    tags: [Password]
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
   *        description: Success; return password Boolean
   *      400:
   *        description: Bad Request; wrong jwt format
   *      401:
   *        description: Access Denied, authToken not found! or Unauthorized
   *
   */
  router.get("/has-password", auth.checkAuth, user.hasPassword);

  /**
   * @swagger
   * /user/change-password:
   *  post:
   *    summary: API to Update own password
   *    tags: [Password]
   *    parameters:
   *     - in: header
   *       name: authToken
   *       description: Get the authToken from result after success login
   *       schema:
   *        type: string
   *        format: jwt
   *       required: true
   *    requestBody:
   *      required: true
   *      content:
   *        application/json:
   *            schema:
   *                type: object
   *                properties:
   *                    password:
   *                        type: string
   *                        description: Current Password
   *                    newPassword:
   *                        type: string
   *                        description: New Password
   *                    confirmNewPassword:
   *                        type: string
   *                        description: New Password
   *                required:
   *                    - password
   *                    - newPassword
   *                    - confirmNewPassword
   *                example:
   *                    password: "aaaBBB!1"
   *                    newPassword: "aaaBBB!1"
   *                    confirmNewPassword: "aaaBBB!1"
   *    responses:
   *      200:
   *        description: OK; Password update success
   *      400:
   *        description: Bad Request; wrong jwt format or New password & confirm new password not match! or Current Password Account not match! or New password cannot be the same with current password! or Password Validation failed
   *      401:
   *        description: Access Denied, authToken not found! or Unauthorized
   */
  router.post("/change-password", auth.checkAuth, user.changePassword);

  /**
   * @swagger
   * /user/create-password:
   *  post:
   *    summary: API to Create new password if account doesn't have password
   *    tags: [Password]
   *    parameters:
   *     - in: header
   *       name: authToken
   *       description: Get the authToken from result after success login
   *       schema:
   *        type: string
   *        format: jwt
   *       required: true
   *    requestBody:
   *      required: true
   *      content:
   *        application/json:
   *            schema:
   *                type: object
   *                properties:
   *                    newPassword:
   *                        type: string
   *                        description: New Password
   *                    confirmNewPassword:
   *                        type: string
   *                        description: New Password
   *                required:
   *                    - newPassword
   *                    - confirmNewPassword
   *                example:
   *                    newPassword: "aaaBBB!1"
   *                    confirmNewPassword: "aaaBBB!1"
   *    responses:
   *      200:
   *        description: OK; Password created successfully
   *      400:
   *        description: Bad Request; wrong jwt format or New password & confirm new password not match! or Account already has password! or Password Validation failed
   *      401:
   *        description: Access Denied, authToken not found! or Unauthorized
   */
  router.post("/create-password", auth.checkAuth, user.createPassword);

  /**
   * @swagger
   * /user:
   *  get:
   *    summary: API to Get List of user that on the system
   *    tags: [User Management]
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
   *        description: Success; return userList
   *      400:
   *        description: Bad Request; wrong jwt format
   *      401:
   *        description: Access Denied, authToken not found! or Unauthorized
   *      404:
   *        description: Not Found
   *
   */
  router.get("/", auth.checkAuth, user.getUserList);

  /**
   * @swagger
   * /user/stat:
   *  get:
   *    summary: API to Get User statistic data
   *    tags: [User Management]
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
   *        description: Success; return totalSignup, totalActiveToday and totalActiveWeek
   *      400:
   *        description: Bad Request; wrong jwt format
   *      401:
   *        description: Access Denied, authToken not found! or Unauthorized
   *
   */
  router.get("/stat", auth.checkAuth, user.getUserStat);

  app.use("/user", router);
};
