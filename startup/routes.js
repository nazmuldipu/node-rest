const express = require("express");
const userRoutes = require("../routes/users");
const error = require("../middleware/error");
const authRoutes = require("../routes/auth");

module.exports = function (app) {
  app.use(express.json());
  app.use("/api/auth", authRoutes);
  app.use("/api/users", userRoutes);
  app.use(error);
};
