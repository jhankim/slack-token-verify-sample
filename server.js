require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const app = express();
const port = 3000;
const slackSecret = process.env.SLACK_SIGNING_SECRET;

app.use(
  bodyParser.json({
    // nifty trick to save request body as string
    verify: (req, res, buf) => {
      req.rawBody = buf.toString('utf8');
    },
  })
);

app.post('/slack/event', (req, res) => {
  const timestamp = req.headers['x-slack-request-timestamp'];
  const signature = req.headers['x-slack-signature'];
  const [version, hash] = signature.split('=');
  const concatStr = `${version}:${timestamp}:${req.rawBody}`;

  // create HMAC instance & update it with the concatenated value
  const hmac = crypto.createHmac('sha256', slackSecret);
  hmac.update(concatStr);

  // check for signed value vs hash provided in the header
  if (hmac.digest('hex') === hash) {
    // if signed values are both equal, send back the challenge as json
    res.json({
      challenge: req.body.challenge,
    });
  } else {
    res.status(401).json({
      msg: 'Unable to verify that the request is coming from Slack',
    });
  }
});

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
