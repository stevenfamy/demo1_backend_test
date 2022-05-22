const SibApiV3Sdk = require("sib-api-v3-sdk");
const crypto = require("crypto");
const db = require("../models");

const Users = db.users;
const UsersProfile = db.usersProfile;
const UsersTokens = db.usersTokens;

exports.createConfirmationEmail = async (userId) => {
  const defaultClient = SibApiV3Sdk.ApiClient.instance;
  const apiKey = defaultClient.authentications["api-key"];
  apiKey.apiKey = process.env.SENDINBLUE_APIKEY;

  const userData = await Users.findOne({
    where: {
      id: userId,
    },
  });

  if (!userData) return "User not found";
  if (userData.verification) return "User already verified";

  const userProfile = await UsersProfile.findOne({
    where: { user_id: userData.id },
  });

  const seed = crypto.randomBytes(256);
  const tokens = crypto.createHash("sha1").update(seed).digest("hex");

  const tokenData = await UsersTokens.create({
    user_id: userData.id,
    tokens: tokens,
    created_on: Math.floor(new Date().getTime() / 1000),
    expired_on: 0,
    token_type: "Email Verification",
  });

  if (!tokenData) return "Failed to send verification email";

  const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
  const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
  const verificationUrl = `${process.env.FRONTEND_URL}/verified-email/?tokens=${tokens}`;

  sendSmtpEmail.subject = "Email Verification";
  sendSmtpEmail.htmlContent = `<html><body><h1>Verify Your email</h1><br>Click this link to verified your email: <br> <a href="${verificationUrl}">${verificationUrl}</a> </body></html>`;
  sendSmtpEmail.sender = { name: "Support", email: "steve.mailme@gmail.com" };
  sendSmtpEmail.to = [
    {
      email: userData.email,
      name: `${userProfile.first_name} ${userProfile.last_name}`,
    },
  ];

  let sendEmail = {};
  try {
    sendEmail = await apiInstance.sendTransacEmail(sendSmtpEmail);
  } catch (e) {
    return e;
  }
  return sendEmail;
};

exports.resendConfirmationEmail = async (userId) => {
  const defaultClient = SibApiV3Sdk.ApiClient.instance;
  const apiKey = defaultClient.authentications["api-key"];
  apiKey.apiKey = process.env.SENDINBLUE_APIKEY;

  const userData = await Users.findOne({
    where: {
      id: userId,
    },
  });

  if (!userData) return "User not found";
  if (userData.verification) return "User already verified";

  const userProfile = await UsersProfile.findOne({
    where: { user_id: userData.id },
  });

  const tokenData = await UsersTokens.findOne({
    where: { user_id: userData.id },
  });

  if (!tokenData) return "No previous verification email found";

  const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
  const sendSmtpEmail = new SibApiV3Sdk.SendSmtpEmail();
  const verificationUrl = `${process.env.FRONTEND_URL}/verified-email/?tokens=${tokenData.tokens}`;

  sendSmtpEmail.subject = "Email Verification";
  sendSmtpEmail.htmlContent = `<html><body><h1>Verify Your email</h1><br>Click this link to verified your email: <br> <a href="${verificationUrl}">${verificationUrl}</a> </body></html>`;
  sendSmtpEmail.sender = { name: "Support", email: "steve.mailme@gmail.com" };
  sendSmtpEmail.to = [
    {
      email: userData.email,
      name: `${userProfile.first_name} ${userProfile.last_name}`,
    },
  ];

  try {
    await apiInstance.sendTransacEmail(sendSmtpEmail);
  } catch (e) {
    return e;
  }
  return true;
};
