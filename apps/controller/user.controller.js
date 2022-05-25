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
