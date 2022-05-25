const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const db = require("../models");

const { sequelize } = db;
const {
  checkPasswordRequirement,
  getUserByEmail,
} = require("../helpers/users.helper");
const {
  createConfirmationEmail,
  resendConfirmationEmail,
} = require("../helpers/email.helper");

const Users = db.users;
const UsersProfile = db.usersProfile;
const UsersTokens = db.usersTokens;
const UsersSession = db.usersSession;

const jwtSecret = "R1O8}_z!hE^TvcL";

const createJWToken = (userId) => {
  const rawToken = {
    selector: crypto.randomBytes(10).toString("hex"),
    token: crypto.randomBytes(25).toString("hex"),
    userId: userId,
  };
  const result = {
    rawToken: rawToken,
    jwtToken: jwt.sign({ rawToken }, jwtSecret),
  };

  return result;
};

exports.createNewAccount = async (req, res) => {
  const { email, password, firstName, lastName } = req.body;

  const existUser = await Users.findOne({
    where: {
      email,
    },
  });

  if (existUser)
    return res.status(400).send({
      Error: "Email already registered",
      Email_verification: existUser.verification,
    });

  const checkPasswordResult = await checkPasswordRequirement(password);
  if (checkPasswordResult.length)
    return res
      .status(400)
      .send({ validationFailed: true, checkPasswordResult });

  const hashedNewPwd = bcrypt.hashSync(password, 8);

  const transaction = await sequelize.transaction();
  let userData = {};
  try {
    userData = await Users.create(
      {
        email,
        password: hashedNewPwd,
      },
      { transaction }
    );

    await UsersProfile.create({
      user_id: userData.id,
      first_name: firstName,
      last_name: lastName,
    });

    await transaction.commit();
  } catch (e) {
    if (transaction) await transaction.rollback();
    console.log(e);
    return res.status(500).send({ error: e });
  }

  await createConfirmationEmail(userData.id);

  return res.sendStatus(200);
};

exports.resendVerification = async (req, res) => {
  const { email } = req.body;

  const userData = await Users.findOne({ where: { email: email } });
  if (!userData) return res.status(404).send({ error: "Account not found!" });

  const result = await resendConfirmationEmail(userData.id);
  if (result !== true) return res.status(400).send(result);

  return res.sendStatus(200);
};

exports.verifyEmail = async (req, res) => {
  const { tokens } = req.params;

  const tokenData = await UsersTokens.findOne({ where: { tokens } });

  if (!tokenData || tokenData.token_type !== "Email Verification")
    return res.status(400).send({ error: "Invalid Tokens!" });

  const userData = await Users.findOne({ where: { id: tokenData.user_id } });

  if (!userData)
    return res
      .status(500)
      .send({ error: "Something Wrong, please try again!" });

  userData.verification = 1;
  userData.status = 1;

  await userData.save();

  await tokenData.destroy();

  // Do auto login here
  const jwtResult = createJWToken(userData.id);

  await UsersSession.create({
    user_id: userData.id,
    selector: jwtResult.rawToken.selector,
    hashed_token: crypto
      .createHash("md5")
      .update(jwtResult.rawToken.token)
      .digest("hex"),
    created_on: Math.floor(new Date().getTime() / 1000),
    session_method: "Email",
  });

  return res.status(200).send({ authToken: jwtResult.jwtToken });
};

exports.doLogin = async (req, res) => {
  const { email, password } = req.body;

  if (!email && !password)
    return res
      .status(400)
      .send({ error: "Email address & Password is required" });

  const userData = await getUserByEmail(email);

  if (!userData) return res.status(404).send({ error: "Account not found!" });

  if (!userData.verification)
    return res.status(400).send({
      error: "Haven't verified your email account!",
      Email_verification: userData.verification,
    });

  if (!userData.status)
    return res.status(400).send({
      error: "Account not active!",
      Email_verification: userData.verification,
    });

  const checkPassword = bcrypt.compareSync(password, userData.password);

  if (!checkPassword)
    return res.status(400).send({ error: "Password Account not match!" });

  const jwtResult = createJWToken(userData.id);

  const sessionsData = await UsersSession.create({
    user_id: userData.id,
    selector: jwtResult.rawToken.selector,
    hashed_token: crypto
      .createHash("md5")
      .update(jwtResult.rawToken.token)
      .digest("hex"),
    created_on: Math.floor(new Date().getTime() / 1000),
    session_method: "Email",
  });

  if (!sessionsData)
    return res.status(500).send({ error: "Login Failed!, please try again" });

  return res.status(200).send({ authToken: jwtResult.jwtToken });
};

exports.checkAuth = async (req, res, next) => {
  const authToken = req.headers.authtoken;
  if (!authToken)
    return res
      .status(401)
      .send({ error: "Access Denied, authToken not found!" });

  let result = {};
  try {
    result = jwt.verify(authToken, jwtSecret);
  } catch (e) {
    return res.status(500).send();
  }

  if (!result) return res.sendStatus(401);

  const sessionData = await UsersSession.findOne({
    where: {
      selector: result.rawToken.selector,
      hashed_token: crypto
        .createHash("md5")
        .update(result.rawToken.token)
        .digest("hex"),
    },
  });

  if (!sessionData) return res.sendStatus(401);

  req.userId = sessionData.user_id;
  req.sessionsId = sessionData.id;

  sessionData.last_seen = Math.floor(new Date().getTime() / 1000);
  await sessionData.save();

  return next();
};

exports.doLogout = async (req, res) => {
  const { userId, sessionsId } = req;

  await UsersSession.destroy({
    where: {
      id: sessionsId,
      user_id: userId,
    },
  });

  return res.sendStatus(200);
};
