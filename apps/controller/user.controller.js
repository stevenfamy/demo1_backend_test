const bcrypt = require("bcryptjs");
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
const UsersOauth = db.usersOauth;

exports.getProfile = async (req, res) => {
  const { userId } = req;

  const userProfileData = await UsersProfile.findOne({
    where: {
      user_id: userId,
    },
  });

  return res.status(200).send({
    userProfile: {
      firstName: userProfileData.first_name,
      lastName: userProfileData.last_name,
    },
  });
};

exports.putProfile = async (req, res) => {
  const { userId } = req;
  const { firstName, lastName } = req.body;

  if (!firstName || !lastName)
    return res
      .status(400)
      .send({ error: "First Name & Last Name is required!" });

  const userProfileData = await UsersProfile.findOne({
    where: {
      user_id: userId,
    },
  });

  userProfileData.first_name = firstName;
  userProfileData.last_name = lastName;
  await userProfileData.save();

  return res.sendStatus(200);
};

exports.hasPassword = async (req, res) => {};

exports.changePassword = async (req, res) => {
  const { userId } = req;
  const { password, newPassword, confirmNewPassword } = req.body;

  if (newPassword !== confirmNewPassword)
    return res
      .status(400)
      .send({ error: "New password & confirm new password not match!" });

  const userData = await Users.findOne({ where: { id: userId } });

  const checkPassword = bcrypt.compareSync(password, userData.password);

  if (!checkPassword)
    return res
      .status(400)
      .send({ error: "Current Password Account not match!" });

  if (password === newPassword)
    return res.status(400).send({
      error: "New password cannot be the same with current password!",
    });

  const checkPasswordResult = await checkPasswordRequirement(newPassword);
  if (checkPasswordResult.length)
    return res
      .status(400)
      .send({ validationFailed: true, checkPasswordResult });

  const hashedNewPwd = bcrypt.hashSync(newPassword, 8);

  userData.password = hashedNewPwd;
  await userData.save();

  return res.sendStatus(200);
};
