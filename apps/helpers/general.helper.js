const { DateTime } = require("luxon");

exports.convertTimestamp = async (timestamp) =>
  DateTime.fromSeconds(timestamp, { zone: "Asia/Singapore" }).toISO();

exports.convertToTimestamp = async (dateTime) =>
  DateTime.fromISO(dateTime, { zone: "Asia/Singapore" }).toSeconds();
