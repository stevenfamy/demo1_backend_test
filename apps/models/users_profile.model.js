module.exports = (sequelize, Sequelize) => {
  const usersProfile = sequelize.define(
    "users_profile",
    {
      id: {
        type: Sequelize.STRING(36),
        primaryKey: true,
        defaultValue: Sequelize.UUIDV4,
      },
      user_id: {
        type: Sequelize.STRING(36),
      },
      first_name: {
        type: Sequelize.STRING(50),
      },
      last_name: {
        type: Sequelize.STRING(50),
      },
    },
    {
      freezeTableName: true,
      timestamps: false,
    }
  );

  return usersProfile;
};
