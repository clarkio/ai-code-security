const argon2 = require("argon2");
const { v4: uuidv4 } = require("uuid");

exports.seed = async function (knex) {
  // Deletes ALL existing entries
  await knex("notes").del();
  await knex("users").del();

  const password = "StrongPassw0rd!";
  const hash = await argon2.hash(password);
  const user = { id: uuidv4(), username: "demo", password_hash: hash };
  await knex("users").insert(user);

  await knex("notes").insert([
    {
      id: uuidv4(),
      owner_id: user.id,
      title: "Welcome",
      body: "This is your secure notes app.",
    },
  ]);
};
