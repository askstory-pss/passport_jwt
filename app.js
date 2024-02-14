const express = require("express");
const passport = require("passport");
require('dotenv').config();
require("./passport-config")(passport);
const { router } = require("./routes/auth");
const cors = require('cors');

const app = express();

const corsOptions = {
  credentials : true
};

app.use(cors(corsOptions));

app.use(express.json());
app.use("", router);
app.use(passport.initialize());

app.get(
  "/protected",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.send("You have accessed a protected route!");
  }
);

const PORT = process.env.PORT || 8888;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
