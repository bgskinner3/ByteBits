module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  verbose: true,
  coverageReporters: ['text', 'text-summary'],
  collectCoverageFrom: ['src/**/*.{ts,tsx}', '!src/utils/dev-only/**'],
  // collectCoverageFrom: ['src/custom-algos/kalo/*'],
};
