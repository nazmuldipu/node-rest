const _ = require("lodash");
const bcrypt = require("bcrypt");
const express = require("express");
const router = express.Router();
const { User, validate } = require("../models/user");
const validateObjectId = require("../middleware/validateObjectId");
const validator = require("../middleware/validate");
const auth = require("../middleware/auth");
const admin = require("../middleware/admin");

//------------------User profile-----------------
router.get("/me", auth, async (req, res) => {
  const user = await User.findById(req.user._id).select("-password");
  res.send(user);
});

//------------------REGISTER-----------------
router.post("/", [validator(validate)], async (req, res) => {
  let user = await User.findOne({ email: req.body.email });
  if (user)
    return res
      .status(400)
      .send(`User with this email \'${req.body.email}\'already register`);

  user = await User.findOne({ phone: req.body.phone });
  if (user)
    return res
      .status(400)
      .send(`User with this phone \'${req.body.phone}\'already register`);

  user = new User(_.pick(req.body, ["name", "email", "phone", "password"]));
  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(user.password, salt);
  user.roles = ["USER"];
  await user.save(user);

  const token = user.generateAuthToken();
  res
    .header("x-auth-token", token)
    .send(_.pick(user, ["_id", "name", "phone", "email"]));
});

/*Update a User for request with id, method = PUT*/
router.put(
  "/:id",
  [auth, admin, validateObjectId, validator(validate)],
  async (req, res) => {
    let user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send("The User with the given ID was not found");
    }
    user = await User.updateOne(
      { _id: user._id },
      {
        $set: {
          name: req.body.name,
          email: req.body.email,
          phone: req.body.phone,
        },
      }
    );
    res.send(user);
  }
);

/*READ all user for request with method = GET*/
router.get("/", [auth, admin], async (req, res) => {
  const users = await User.find({}, "name phone email roles");
  return res.send(users);
});

/*READ a User for request with id, method = GET*/
router.get("/:id", [auth, admin, validateObjectId], async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user)
    return res.status(404).send("The user with the given ID was not found");
  res.send(user);
});

/*CHANGE password from admin with method = PATCH*/
router.patch(
  "/change-password/:id",
  [auth, admin, validateObjectId],
  async (req, res) => {
    const user = await User.findById(req.params.id);

    if (!user)
      return res.status(404).send("The user with the given ID was not found");

    const newPassword = req.body.password;
    if (!newPassword) return res.status(400).send("New password required");

    //Change password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(req.body.password, salt);
    await user.save(user);

    res.send(_.pick(user, ["_id", "name", "phone", "email"]));
  }
);

/*CHANGE password from user himself with method = PUT*/
router.patch("/changePassword", [auth], async (req, res) => {
  if (!req.body.oldPassword || !req.body.newPassword)
    return res
      .status(404)
      .send("Request parameter oldPassword or newPassword is missing");

  const user = await User.findById(req.user._id);
  if (!user || user._name) {
    return res.status(404).send("The user with the token was not found");
  }

  const validPassword = await bcrypt.compare(
    req.body.oldPassword,
    user.password
  );
  if (!validPassword) {
    return res.status(401).send("Old Password not correct");
  }

  const salt = await bcrypt.genSalt(10);
  user.password = await bcrypt.hash(req.body.newPassword, salt);
  await user.save(user);

  res.send(user);
});

module.exports = router;
