exports.up = async function (knex) {
  await knex.schema.createTable("session", (table) => {
    table.string("sid").primary();
    table.json("sess").notNullable();
    table.timestamp("expire").notNullable();
  });
};

exports.down = async function (knex) {
  await knex.schema.dropTableIfExists("session");
};
