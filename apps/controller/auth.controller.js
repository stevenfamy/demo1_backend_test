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

  const checkPasswordResult = await checkPasswordRequirement(password);
  if (checkPasswordResult.length)
    return res.status(400).send(checkPasswordResult);

  const existUser = await Users.findAll({
    where: {
      email,
    },
  });

  if (existUser.length)
    return res.status(400).send({
      Error: "Email already registered",
      Email_verification: !!existUser.verification,
    });

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

  return res.sendStatus(200);
};
