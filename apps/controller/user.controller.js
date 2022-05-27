const { DateTime } = require("luxon");
const bcrypt = require("bcryptjs");
const Sequelize = require("sequelize");
const { Op } = require("sequelize");
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
Users.hasMany(UsersSession, { foreignKey: "user_id" });

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
      {
        model: UsersSession,
        required: false,
        attributes: ["last_seen"],
        sort: ["last_seen", "desc"],
      },
    ],
    attributes: ["id", "email", "last_login", "created_on", "total_login"],
  }).then(async (results) =>
    Promise.all(
      results.map(async ({ dataValues }) => ({
        ...dataValues,
        last_login: dataValues.last_login
          ? await convertTimestamp(dataValues.last_login)
          : null,
        created_on: dataValues.created_on
          ? await convertTimestamp(dataValues.created_on)
          : null,
        last_seen: dataValues.users_sessions.length
          ? await convertTimestamp(dataValues.users_sessions[0].last_seen)
          : null,
        total_sessions: dataValues.users_sessions.length,
      }))
    )
  );

  if (!usersList.length) return res.sendStatus(404);

  return res.status(200).send({ userList: usersList });
};

exports.getUserStat = async (req, res) => {
  const temp0 = DateTime.now().toISODate();
  const todayTimestamp = DateTime.fromISO(
    `${temp0}T00:00:00+00:00`
  ).toSeconds();
  const tommorowTimestamp =
    DateTime.fromSeconds(todayTimestamp).plus({ days: 1 }).toSeconds() - 1;

  const lastSevenTimestamp = DateTime.fromSeconds(todayTimestamp)
    .minus({ days: 7 })
    .toSeconds();

  const userCount = await Users.count();
  const totalActiveToday = await UsersSession.count({
    where: {
      last_seen: { [Op.between]: [todayTimestamp, tommorowTimestamp] },
    },
  });
  const totalActiveWeek = await UsersSession.count({
    where: {
      last_seen: { [Op.between]: [lastSevenTimestamp, tommorowTimestamp] },
    },
  });

  return res
    .status(200)
    .send({ totalSignup: userCount, totalActiveToday, totalActiveWeek });
};
