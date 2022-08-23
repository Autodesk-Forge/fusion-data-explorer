import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import axios from "axios";
import cookieSession from "cookie-session";
import { url } from "inspector";

let app = express();

app.use(
  cookieSession({
    name: "forge_session",
    keys: ["forge_secure_key"],
    maxAge: 60 * 60 * 1000 // 1 hour like the token (changes to cookie content resets the timer)
  })
);

let clientId = process.env.FORGE_CLIENT_ID || "YOUR CLIENT ID";
let clientSecret = process.env.FORGE_CLIENT_SECRET || "YOUR CLIENT SECRET";
let serverPort = process.env.PORT || 3000;
let serverUrl = process.env.BASE_URL || "localhost";
let callbackUrl =
  process.env.FORGE_CALLBACK_URL || `${serverUrl}/callback/oauth`;

app.get("/callback/oauth", async (req, res) => {
  console.log("/callback/oauth", req.session);

  const { code } = req.query;

  try {
    let cId = req.session.client_id ? req.session.client_id : clientId;
    let cSecret = req.session.client_secret ? req.session.client_secret : clientSecret;

    const response = await axios({
      method: "POST",
      url: "https://developer.api.autodesk.com/authentication/v1/gettoken",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      data: `client_id=${cId}&client_secret=${cSecret}&grant_type=authorization_code&code=${code}&redirect_uri=${callbackUrl}`
    });

    req.session = req.session || {};
    req.session.access_token = response.data.access_token;
    req.session.refresh_token = response.data.refresh_token;

    if (req.session.client_id && req.session.client_secret) {
      res.redirect(`/?client_id=${req.session.client_id}&client_secret=${req.session.client_secret}`);
    } else {
      res.redirect(`/`);
    }
  } catch (error) {
    console.log(error);
    res.end();
  }
});

app.get("/oauth/token", async (req, res) => {
  console.log("/oauth/token", req.session);

  if (req.query.client_id && req.query.client_secret) {
    // If credentials changed
    if (req.query.client_id !== req.session.client_id) {
      req.session = {
        client_id: req.query.client_id,
        client_secret: req.query.client_secret
      };
      res.status(401).end();
      return;
    }
  } else {
    // If credentials changed
    if (req.session.client_id) {
      req.session = null;
      res.status(401).end();
      return;
    }
  }

  if (!req.session?.access_token) {
    res.status(401).end();
    return;
  }

  let access_token = req.session.access_token;

  if (req.query.refresh) {
    let cId = req.session.client_id ? req.session.client_id : clientId;
    let cSecret = req.session.client_secret ? req.session.client_secret : clientSecret;
    let rToken = req.session.refresh_token;
    const response = await axios({
      method: "POST",
      url: "https://developer.api.autodesk.com/authentication/v1/refreshtoken",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      data: `client_id=${cId}&client_secret=${cSecret}&grant_type=refresh_token&refresh_token=${rToken}`
    });

    req.session = req.session || {};
    req.session.access_token = response.data.access_token;
    req.session.refresh_token = response.data.refresh_token;

    access_token = response.data.access_token;
  }

  res.end(access_token);
});

app.get("/oauth/url", (req, res) => {
  console.log("/oauth/url", req.session);

  let cId = req.session.client_id ? req.session.client_id : clientId;

  const url =
    "https://developer.api.autodesk.com" +
    "/authentication/v1/authorize?response_type=code" +
    "&client_id=" +
    cId +
    "&redirect_uri=" +
    callbackUrl +
    "&scope=data:read data:write data:create";

  res.end(url);
});

app.use(
  express.static(
    path.join(path.dirname(fileURLToPath(import.meta.url)), "public")
  )
);

app.listen(serverPort);

console.log(
  `Open ${serverUrl} in a web browser in order to log in with your Autodesk account!`
);
