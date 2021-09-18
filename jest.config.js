const path = require("path");

module.exports = {
    preset: "ts-jest",
    testEnvironment: path.resolve(__dirname, "./prisma-test-environment.ts"),
    verbose: true,
    clearMocks: true,
    setupFilesAfterEnv: ["./jest.setup.ts"],
    coveragePathIgnorePatterns: ["/node_modules/", "./src/test-utils/", "./src/scripts"],
    collectCoverageFrom: ["src/**/*.{ts,js}"],
    coverageReporters: ["text-summary", ["lcov", { projectRoot: "./" }]],
    coverageThreshold: {
        global: {
            branches: 100,
            functions: 100,
            lines: 100,
            statements: 100,
        },
    },
};