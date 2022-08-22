import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import axios from "axios";
import cookieSession from "cookie-session";

let app = express();

app.use(
  cookieSession({
    name: "forge_session",
    keys: ["forge_secure_key"],
    maxAge: 60 * 60 * 1000 // 1 hour like the token
  })
);

let clientId = process.env.FORGE_CLIENT_ID || "YOUR CLIENT ID";
let clientSecret = process.env.FORGE_CLIENT_SECRET || "YOUR CLIENT SECRET";
let serverPort = process.env.PORT || 3000;
let serverUrl = process.env.BASE_URL || "localhost";
let callbackUrl =
  process.env.FORGE_CALLBACK_URL || `${serverUrl}/callback/oauth`;

app.get("/callback/oauth", async (req, res) => {
  const { code } = req.query;

  try {
    let cId = clientId;
    let cSecret = clientSecret;
    if (req.session.client_id && req.session.client_secret) {
      cId = req.session.client_id;
      cSecret = req.session.client_secret;
    }

    const response = await axios({
      method: "POST",
      url: "https://developer.api.autodesk.com/authentication/v1/gettoken",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      data: `client_id=${cId}&client_secret=${cSecret}&grant_type=authorization_code&code=${code}&redirect_uri=${callbackUrl}`
    });

    req.session = {
      access_token: response.data.access_token
    };

    res.redirect("/");
  } catch (error) {
    console.log(error);
    res.end();
  }
});

app.get("/oauth/token", async (req, res) => {
  console.log(req.session);
  if (!req.session?.access_token) {
    res.status(401).end();
    return;
  }

  res.end(req.session.access_token);
});

app.get("/oauth/url", (req, res) => {
  let cId = clientId;
  let cSecret = clientSecret;
  if (req.query.client_id && req.query.client_secret) {
    cId = req.query.client_id;
    cSecret = req.query.client_secret;
    req.session = {
      client_id: cId,
      client_secret: cSecret
    };
  } 

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
