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
