module.exports = (sequelize, Sequelize) => {
  const usersSession = sequelize.define(
    "users_session",
    {
      id: {
        type: Sequelize.STRING(36),
        primaryKey: true,
        defaultValue: Sequelize.UUIDV4,
      },
      user_id: {
        type: Sequelize.STRING(36),
      },
      selector: {
        type: Sequelize.STRING(255),
      },
      hashed_token: {
        type: Sequelize.STRING(255),
      },
      created_on: {
        type: Sequelize.INTEGER,
      },
      session_method: {
        type: Sequelize.STRING(10),
      },
      last_seen: {
        type: Sequelize.INTEGER,
        defaultValue: 0,
      },
    },
    {
      freezeTableName: true,
      timestamps: false,
    }
  );

  return usersSession;
};
