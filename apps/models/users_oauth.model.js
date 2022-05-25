module.exports = (sequelize, Sequelize) => {
  const usersOauth = sequelize.define(
    "users_oauth",
    {
      id: {
        type: Sequelize.STRING(36),
        primaryKey: true,
        defaultValue: Sequelize.UUIDV4,
      },
      user_id: {
        type: Sequelize.STRING(36),
      },
      type: {
        type: Sequelize.STRING(10),
      },
      oauth_user_id: {
        type: Sequelize.STRING(36),
      },
      connected_at: {
        type: Sequelize.INTEGER,
        defaultValue: 0,
      },
    },
    {
      freezeTableName: true,
      timestamps: false,
    }
  );

  return usersOauth;
};
