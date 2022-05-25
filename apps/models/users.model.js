module.exports = (sequelize, Sequelize) => {
  const user = sequelize.define(
    "users",
    {
      id: {
        type: Sequelize.STRING(36),
        primaryKey: true,
        defaultValue: Sequelize.UUIDV4,
      },
      email: {
        type: Sequelize.STRING(100),
      },
      password: {
        type: Sequelize.STRING(255),
      },
      verification: {
        type: Sequelize.TINYINT,
        defaultValue: 0,
      },
      last_login: {
        type: Sequelize.INTEGER,
        defaultValue: 0,
      },
      status: {
        type: Sequelize.TINYINT,
        defaultValue: 0,
      },
      created_on: {
        type: Sequelize.INTEGER,
        defaultValue: Math.floor(new Date().getTime() / 1000),
      },
      total_login: {
        type: Sequelize.INTEGER,
        defaultValue: 0,
      },
    },
    {
      freezeTableName: true,
      timestamps: false,
    }
  );

  return user;
};
