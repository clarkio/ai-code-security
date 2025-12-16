exports.up = async function (knex) {
  await knex.schema.createTable("users", (table) => {
    table.uuid("id").primary();
    table.string("username").notNullable().unique();
    table.string("password_hash").notNullable();
    table.timestamp("created_at").defaultTo(knex.fn.now());
  });

  await knex.schema.createTable("notes", (table) => {
    table.uuid("id").primary();
    table
      .uuid("owner_id")
      .notNullable()
      .references("id")
      .inTable("users")
      .onDelete("CASCADE");
    table.string("title", 255).notNullable();
    table.text("body").notNullable();
    table.timestamp("created_at").defaultTo(knex.fn.now());
    table.timestamp("updated_at").defaultTo(knex.fn.now());
  });
};

exports.down = async function (knex) {
  await knex.schema.dropTableIfExists("notes");
  await knex.schema.dropTableIfExists("users");
};
