module.exports = function (req, res, next) {
  let roles = req.user.roles;
  if (!roles.includes("ADMIN")) return res.status(403).send("Access denied");
  next();
};
