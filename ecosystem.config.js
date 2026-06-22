module.exports = {
  apps: [{
    name: 'revo-dashboard',
    script: './server.js',
    cwd: '/var/www/revo-dashboard',
    env: {
      PORT: 3002,
    },
  }],
}
