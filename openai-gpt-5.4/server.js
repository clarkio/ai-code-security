const { createApp } = require("./src/app");
const { loadConfig } = require("./src/config");

const config = loadConfig();
const app = createApp(config);

app.listen(config.port, () => {
  process.stdout.write(`Secure notes app listening on port ${config.port}\n`);
});
