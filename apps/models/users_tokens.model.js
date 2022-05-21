module.exports = (sequelize, Sequelize) => {
  const usersTokens = sequelize.define(
    "users_tokens",
    {
      id: {
        type: Sequelize.STRING(36),
        primaryKey: true,
        defaultValue: Sequelize.UUIDV4,
      },
      user_id: {
        type: Sequelize.STRING(36),
      },
      tokens: {
        type: Sequelize.STRING(255),
      },
      created_on: {
        type: Sequelize.INTEGER,
      },
      expired_on: {
        type: Sequelize.INTEGER,
      },
      token_type: {
        type: Sequelize.STRING(20),
      },
    },
    {
      freezeTableName: true,
      timestamps: false,
    }
  );

  return usersTokens;
};
