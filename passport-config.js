const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;

const users = require("./routes/auth").users;
const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_SECRET,
};

module.exports = (passport) => {
  passport.use(
    new JwtStrategy(opts, (jwt_payload, done) => {
      const user = users.find((u) => u.username === jwt_payload.username);
      console.log(users)
      if (user) {
        return done(null, user);
      }

      return done(null, false);
    })
  );
};
