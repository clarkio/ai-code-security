const readline = require("node:readline/promises");
const { stdin, stdout, stderr } = require("node:process");

const { hashPassword } = require("../src/security");

async function main() {
  const rl = readline.createInterface({ input: stdin, output: stdout });

  try {
    const password = await rl.question("Password: ", { hideEchoBack: true });
    if (!password) {
      throw new Error("A password is required.");
    }

    stdout.write(`${hashPassword(password)}\n`);
  } finally {
    rl.close();
  }
}

main().catch((error) => {
  stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
