const Sequelize = require("sequelize");
const dbConfig = require("../config/db.config");

const sequelize = new Sequelize(dbConfig.DB, dbConfig.USER, dbConfig.PASSWORD, {
  host: dbConfig.HOST,
  port: dbConfig.port,
  dialect: dbConfig.dialect,
  logging: process.env.ENV === "dev" ? console.log : false,
  pool: {
    max: dbConfig.pool.max,
    min: dbConfig.pool.min,
    acquire: dbConfig.pool.acquire,
    idle: dbConfig.pool.idle,
  },
});

const db = {};

db.Sequelize = Sequelize;
db.sequelize = sequelize;
db.users = require("./users.model")(sequelize, Sequelize);
db.usersProfile = require("./users_profile.model")(sequelize, Sequelize);
db.usersTokens = require("./users_tokens.model")(sequelize, Sequelize);
db.usersSession = require("./users_session.model")(sequelize, Sequelize);
db.usersOauth = require("./users_oauth.model")(sequelize, Sequelize);

module.exports = db;
