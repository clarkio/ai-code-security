// google-jules/jest.config.js
module.exports = {
    testEnvironment: 'node',
    // setupFilesAfterEnv: ['./tests/jest.setup.js'], // A file to run after test env is set up
    // globalSetup: './tests/testSetup.js', // We are not using globalSetup for this version
    // globalTeardown: './tests/testTeardown.js', // For global teardown if needed
    verbose: true, // Output more information
    // clearMocks: true, // Automatically clear mock calls and instances between every test
};
