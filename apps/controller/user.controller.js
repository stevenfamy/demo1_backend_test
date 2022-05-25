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
const { convertTimestamp } = require("../helpers/general.helper");

const Users = db.users;
const UsersProfile = db.usersProfile;
const UsersTokens = db.usersTokens;
const UsersSession = db.usersSession;
const UsersOauth = db.usersOauth;

Users.hasOne(UsersProfile, { foreignKey: "user_id" });

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

exports.hasPassword = async (req, res) => {
  const { userId } = req;

  const userData = await Users.findOne({ where: { id: userId } });

  return res.status(200).send({ password: !!userData.password });
};

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

exports.createPassword = async (req, res) => {
  const { userId } = req;
  const { newPassword, confirmNewPassword } = req.body;

  if (newPassword !== confirmNewPassword)
    return res
      .status(400)
      .send({ error: "New password & confirm new password not match!" });

  const userData = await Users.findOne({ where: { id: userId } });

  if (userData.password)
    return res.status(400).send({ error: "Account already has password!" });

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

exports.getUserList = async (req, res) => {
  const usersList = await Users.findAll({
    include: [
      {
        model: UsersProfile,
        required: true,
        attributes: ["first_name", "last_name"],
      },
    ],
    attributes: ["id", "email", "last_login", "created_on", "total_login"],
  }).then(async (results) =>
    Promise.all(
      results.map(async ({ dataValues }) => ({
        ...dataValues,
        last_login: await convertTimestamp(dataValues.last_login),
        created_on: await convertTimestamp(dataValues.created_on),
      }))
    )
  );

  if (!usersList.length) return res.sendStatus(404);

  return res.status(200).send({ userList: usersList });
};
